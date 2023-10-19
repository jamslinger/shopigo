package shopigo

import (
	"fmt"
	"github.com/gin-gonic/gin"
	log "log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	defaultTLDs  = []string{"myshopify.com", "shopify.com", "myshopify.io"}
	subDomainReg = "[a-zA-Z0-9][a-zA-Z0-9-_]*"
	TraceIDKey   = "KeyTraceID"
)

type App struct {
	*AppConfig
	*Client
	SessionStore
}

func NewAppConfig() *AppConfig {
	return &AppConfig{Credentials: &Credentials{}}
}

type AppConfig struct {
	*Credentials
	HostURL string

	embedded                 bool
	withTraceID              bool
	authBeginEndpoint        string
	authCallbackPath         string
	authCallbackURL          string
	scopes                   string
	uninstallWebhookEndpoint string
	shopRegexp               *regexp.Regexp

	installHook   HookInstall
	sessionIDHook HookSessionID
}

type Credentials struct {
	ClientID     string
	ClientSecret string
}

func NewApp(c *AppConfig, opts ...Opt) (*App, error) {
	if err := validate(c); err != nil {
		return nil, err
	}
	app := &App{
		AppConfig: c,
		Client:    NewShopifyClient(&ClientConfig{hostURL: c.HostURL, clientID: c.ClientID}),
	}
	applyDefaults(app)
	for _, opt := range opts {
		opt(app)
	}
	return app, nil
}

func validate(c *AppConfig) error {
	_, err := url.Parse(c.HostURL)
	return err
}

func applyDefaults(a *App) {
	a.v = VLatest
	a.embedded = true
	a.authBeginEndpoint = "/auth/begin"
	a.authCallbackPath = "/auth/install"
	authCallbackURL, _ := url.JoinPath(a.HostURL, a.authCallbackPath)
	a.authCallbackURL = authCallbackURL
	a.SessionStore = InMemSessionStore
	a.shopRegexp = regexp.MustCompile(fmt.Sprintf("^%s.(%s)/*$", subDomainReg, strings.Join(defaultTLDs, "|")))
}

func (a *App) logger(c *gin.Context) *log.Logger {
	if a.withTraceID {
		return log.With("trace", c.MustGet(TraceIDKey))
	}
	return log.Default()
}

type Opt = func(a *App)

func WithVersion(v Version) Opt {
	return func(a *App) {
		switch v {
		case V202304:
			a.v = v
		case V202307:
			a.v = v
		default:
			a.v = VLatest
		}
	}
}

func WithRetry(n int) Opt {
	return func(a *App) {
		a.retries = n
	}
}

func WithDefaultAuth(s *Shop) Opt {
	return func(a *App) {
		a.defaultShop = s
	}
}

func WithScopes(s []string) Opt {
	return func(a *App) {
		scopes := make([]string, len(s))
		copy(scopes, s)
		sort.Slice(scopes, func(i, j int) bool {
			return scopes[i] < scopes[j]
		})
		a.scopes = strings.Join(scopes, ",")
	}
}

func WithTraceID() Opt {
	return func(a *App) {
		a.withTraceID = true
	}
}

func WithAuthBeginEndpoint(s string) Opt {
	return func(a *App) {
		a.authBeginEndpoint = s
	}
}

func WithAuthCallbackEndpoint(s string) Opt {
	return func(a *App) {
		a.authCallbackPath = s
		authCallbackURL, err := url.JoinPath(a.HostURL, a.authCallbackPath)
		if err != nil {
			panic(err)
		}
		a.authCallbackURL = authCallbackURL
	}
}

func WithSessionStore(sess SessionStore) Opt {
	return func(a *App) {
		a.SessionStore = sess
	}
}

func WithUninstallWebhookEndpoint(path string) Opt {
	return func(a *App) {
		a.uninstallWebhookEndpoint = path
	}
}

func WithIsEmbedded(e bool) Opt {
	return func(a *App) {
		a.embedded = e
	}
}

func WithCustomShopDomains(domains ...string) Opt {
	return func(a *App) {
		a.shopRegexp = regexp.MustCompile(fmt.Sprintf("^%s.(%s)/*$", subDomainReg, strings.Join(append(defaultTLDs, domains...), "|")))
	}
}

type Hook interface {
	hook()
}

type HookInstall func()
type HookSessionID func() (string, string, error)

func (hi HookInstall) hook()   {}
func (hs HookSessionID) hook() {}

func WithHooks(hooks ...Hook) Opt {
	return func(a *App) {
		for _, hook := range hooks {
			switch h := hook.(type) {
			case HookInstall:
				a.installHook = h
			case HookSessionID:
				a.sessionIDHook = h
			default:
				panic(fmt.Sprintf("%T is not a valid hook", hook))
			}
		}
	}
}
