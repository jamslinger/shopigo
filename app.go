package shopigo

import (
	"net/url"
	"sort"
	"strings"
)

type App struct {
	*AppConfig
	*Client
	SessionStore
}

type AppConfig struct {
	*Credentials

	HostURL string

	redirectURL   string
	scopes        string
	cookieSignKey string
}

type Credentials struct {
	ClientID     string
	ClientSecret string
}

func NewApp(c *AppConfig, opts ...Opt) (*App, error) {
	if err := validate(c); err != nil {
		return nil, err
	}
	client, err := NewShopifyClient(&ClientConfig{hostURL: c.HostURL, clientID: c.ClientID})
	if err != nil {
		return nil, err
	}
	app := &App{AppConfig: c, Client: client}
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
	a.v = V_Latest
	redirectURL, _ := url.JoinPath(a.HostURL, "/auth/install")
	a.redirectURL = redirectURL
	a.SessionStore = InMemSessionStore
}

type Opt = func(a *App)

func WithVersion(v Version) Opt {
	return func(a *App) {
		switch v {
		case V_2023_04:
			a.v = v
		default:
			a.v = V_Latest
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

func WithRedirectEndpoint(s string) Opt {
	return func(a *App) {
		redirectURL, _ := url.JoinPath(a.HostURL, s)
		a.redirectURL = redirectURL
	}
}

func WithSessionStore(sess SessionStore) Opt {
	return func(a *App) {
		a.SessionStore = sess
	}
}
