package shopigo

import "regexp"

type AppConfig struct {
	HostURL string

	Credentials *Credentials

	authBeginEndpoint        string
	authCallbackPath         string
	authCallbackURL          string
	scopes                   string
	uninstallWebhookEndpoint string
	shopRegexp               *regexp.Regexp
	installHook              HookInstall
}

type Credentials struct {
	ClientID     string
	ClientSecret string
}
