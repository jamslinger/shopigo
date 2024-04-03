package shopigo

import (
	"fmt"
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
	*log.Logger
}

func NewApp(c *AppConfig, opts ...Opt) (*App, error) {
	if err := validate(c); err != nil {
		return nil, err
	}
	app := &App{
		AppConfig: c,
		Client:    NewShopifyClient(&ClientConfig{hostURL: c.HostURL, clientID: c.Credentials.ClientID}),
	}
	applyDefaults(app)
	for _, opt := range opts {
		opt(app)
	}
	return app, nil
}

func validate(c *AppConfig) error {
	if c == nil {
		return fmt.Errorf("please provide a configuration")
	} else if c.Credentials == nil || c.Credentials.ClientID == "" || c.Credentials.ClientSecret == "" {
		return fmt.Errorf("please provide valid app credentials")
	}
	if _, err := url.Parse(c.HostURL); err != nil {
		return fmt.Errorf("please provide a valid host URL: %w", err)
	}
	return nil
}

func applyDefaults(a *App) {
	a.v = VLatest
	a.Logger = log.Default()
	a.authBeginEndpoint = "/auth/begin"
	a.authCallbackPath = "/auth/install"
	authCallbackURL, _ := url.JoinPath(a.HostURL, a.authCallbackPath)
	a.authCallbackURL = authCallbackURL
	a.SessionStore = InMemSessionStore
	a.shopRegexp = regexp.MustCompile(fmt.Sprintf("^%s.(%s)/*$", subDomainReg, strings.Join(defaultTLDs, "|")))
}

type Opt = func(a *App)

func WithVersion(v Version) Opt {
	return func(a *App) {
		if v != "" {
			a.v = v
		} else {
			a.v = VLatest
		}
	}
}

// WithLogger sets the app's logger. If nil, log.Default() will be used.
func WithLogger(logger *log.Logger) Opt {
	return func(a *App) {
		if logger != nil {
			a.Logger = logger
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

func WithInsecureClient() Opt {
	return func(a *App) {
		a.Client.insecure = true
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

func WithCustomShopDomains(domains ...string) Opt {
	return func(a *App) {
		a.shopRegexp = regexp.MustCompile(fmt.Sprintf("^%s.(%s)/*$", subDomainReg, strings.Join(append(defaultTLDs, domains...), "|")))
	}
}

type Hook interface {
	hook()
}

func WithHooks(hooks ...Hook) Opt {
	return func(a *App) {
		for _, hook := range hooks {
			switch hook.(type) {
			default:
				panic(fmt.Sprintf("%T is not a valid hook", hook))
			}
		}
	}
}
