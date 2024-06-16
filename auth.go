package shopigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	log "log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	exitFrameRegexp = regexp.MustCompile("^(?i)/exitiframe")

	errSessionNotFound = errors.New("session not found")
)

const (
	appStateCookie    = "shopify_app_state"
	appStateCookieSig = "shopify_app_state.sig"
)

func (a *App) EnsureInstalledOnShop(w http.ResponseWriter, r *http.Request) {
	shop, err := a.sanitizeShop(r.URL.Query().Get("shop"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		AbortWithError(r, err)
		return
	}
	setShop(r, shop)

	logger := a.Logger.With(log.String("shop", shop))
	setLogger(r, logger)

	logger.Debug("check if app is installed")

	sess, err := a.SessionStore.Get(r.Context(), GetOfflineSessionID(shop))
	if IsNotFound(err) {
		logger.Debug("no session found")
		if !exitFrameRegexp.MatchString(r.RequestURI) {
			logger.Debug("not in /exitframe, redirecting to auth")
			a.redirectToAuth(w, r)
			return
		}
		logger.Debug("in /exitframe, serve frame")
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		AbortWithError(r, fmt.Errorf("failed to retrieve session: %w", err))
		return
	}
	if !isEmbedded(r) {
		logger.Debug("tried to use embedded app in non-embedded context, validate session")
		if !a.sessionValid(r, sess) {
			logger.Debug("session is invalid, redirecting to auth")
			a.redirectToAuth(w, r)
			return
		}
		logger.Debug("session validated, attempt embed")
		a.embedAppIntoShopify(w, r)
		return
	}
	logger.Debug("app is installed and ready to load")
}

func (a *App) ValidateAuthenticatedSession(w http.ResponseWriter, r *http.Request) {
	sessID, shop, err := a.getSessionID(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		AbortWithError(r, fmt.Errorf("failed to retrieve session ID: %w", err))
		return
	}
	setShop(r, shop)

	logger := a.Logger.With(log.String("shop", shop))
	setLogger(r, logger)

	sess, err := a.SessionStore.Get(r.Context(), sessID)
	if IsNotFound(err) {
		if shop != "" {
			logger.Debug("session not found but shop in bearer token, redirecting to auth")
			redirect, err := url.JoinPath(a.HostURL,
				fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {shop}}.Encode()))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				AbortWithError(r, fmt.Errorf("failed to construct redirect uri: %w", err))
				return
			}
			a.redirectOutOfApp(w, r, redirect)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		AbortWithError(r, errSessionNotFound)
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		AbortWithError(r, fmt.Errorf("failed to retrieve session: %w", err))
		return
	}
	if shop, err = a.sanitizeShop(r.URL.Query().Get("shop")); err == nil && shop != sess.Shop {
		logger.With(log.String("request-shop", shop)).Debug("session found but for different shop as in request, redirecting to auth")
		a.redirectToAuth(w, r)
		return
	}
	if !a.sessionValid(r, sess) {
		logger.Debug("session is invalid, redirecting to auth")
		redirect, err := url.JoinPath(a.HostURL,
			fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {sess.Shop}}.Encode()))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			AbortWithError(r, fmt.Errorf("failed to construct redirect uri: %w", err))
			return
		}
		a.redirectOutOfApp(w, r, redirect)
		return
	}
	setSession(r, sess)
}

func (a *App) Begin(w http.ResponseWriter, r *http.Request) {
	shop, err := a.sanitizeShop(r.URL.Query().Get("shop"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		AbortWithError(r, fmt.Errorf("failed to sanitize shop: %w", err))
		return
	}
	setShop(r, shop)

	logger := a.Logger.With(log.String("shop", shop))
	setLogger(r, logger)

	logger.Debug("beginning app install")

	nonce := strconv.FormatInt(rand.Int63(), 10)
	query := url.Values{
		"client_id":    {a.Credentials.ClientID},
		"scope":        {a.scopes},
		"redirect_uri": {a.authCallbackURL},
		"state":        {nonce},
	}
	expires := time.Now().Add(time.Hour)
	setSignedCookie(w, a.Credentials.ClientSecret, appStateCookie, nonce, a.authCallbackPath, &expires)

	redirect := fmt.Sprintf("https://%s/admin/oauth/authorize?%s", shop, query.Encode())
	logger.With(log.String("redirect", redirect)).Debug("beginning auth")
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (a *App) Install(w http.ResponseWriter, r *http.Request) {
	shop, err := a.sanitizeShop(r.URL.Query().Get("shop"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		AbortWithError(r, fmt.Errorf("failed to sanitize shop: %w", err))
		return
	}
	setShop(r, shop)

	logger := a.Logger.With(log.String("shop", shop))
	setLogger(r, logger)

	logger.Debug("installing app")

	state := r.URL.Query().Get("state")
	defer deleteCookies(w, appStateCookie, appStateCookieSig)
	if ok, err := compareSignedCookie(r, a.Credentials.ClientSecret, appStateCookie, state); err != nil {
		w.WriteHeader(http.StatusForbidden)
		AbortWithError(r, fmt.Errorf("app state cookie mismatch: %w", err))
		return
	} else if !ok {
		w.WriteHeader(http.StatusForbidden)
		AbortWithError(r, fmt.Errorf("app state cookie mismatch: %w", err))
		return
	}

	if !a.ValidHmac(r) {
		w.WriteHeader(http.StatusForbidden)
		AbortWithError(r, errors.New("hmac validation failed"))
		return
	}

	code := r.URL.Query().Get("code")
	token, err := a.AccessToken(shop, code)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		AbortWithError(r, fmt.Errorf("failed to retrieve access token: %w", err))
		return
	}

	logger.Debug("creating new session")
	sess := a.createSession(shop, state, token)

	if a.installHook != nil {
		logger.Debug("calling install hook")
		if err = a.installHook(r.Context(), a, sess); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			AbortWithError(r, fmt.Errorf("install hook failed: %w", err))
			return
		}
	} else {
		var id int
		if a.uninstallWebhookEndpoint != "" {
			wh := Webhook{
				Topic:   "app/uninstalled",
				Address: a.uninstallWebhookEndpoint,
				Fields:  []string{"domain"},
			}
			logger.With("webhook", wh).Debug("registering uninstall webhook")
			if id, err = a.Client(VLatest, sess, nil).RegisterWebhook(r.Context(), &wh); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				AbortWithError(r, fmt.Errorf("failed to register uninstall webhook: %w", err))
				return
			}
		}
		err = a.SessionStore.Store(r.Context(), sess)
		if err != nil {
			if id != 0 {
				err = errors.Join(err, a.Client(VLatest, sess, nil).DeleteWebhook(r.Context(), id))
			}
			w.WriteHeader(http.StatusInternalServerError)
			AbortWithError(r, fmt.Errorf("failed to store session: %w", err))
			return
		}
	}
	setSession(r, sess)
	redirect := "/?" + r.URL.Query().Encode()
	logger.With(log.String("redirect", redirect)).Debug("app installed, redirecting to app")
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (a *App) getSessionID(r *http.Request) (string, string, error) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return "", "", errors.New("missing 'Authorization' header")
	}
	return a.parseJWTSessionID(token)
}

func (a *App) sessionValid(r *http.Request, sess *Session) bool {
	if sess == nil {
		a.Debug("session invalid: nil")
		return false
	}
	if sess.AccessToken == "" {
		GetLogger(r).Debug("session invalid: empty access token")
		return false
	}
	if sess.Scopes != a.scopes {
		GetLogger(r).Debug("session invalid: scopes changed")
		return false
	}
	if sess.Expires != nil && time.Now().After(*sess.Expires) {
		GetLogger(r).Debug("session invalid: expired")
		return false
	}
	cl := a.GraphQLClient(VLatest, sess, nil)
	var query struct {
		Shop struct {
			Name string `json:"name"`
		} `graphql:"shop"`
	}
	err := cl.Query(r.Context(), "shop", &query, nil)
	if err != nil {
		GetLogger(r).Debug("session invalid", "error", err)
		return false
	}
	return true
}

func (a *App) createSession(shop string, state string, token *AccessToken) *Session {
	return &Session{
		ID:          GetOfflineSessionID(shop),
		Shop:        shop,
		State:       state,
		AccessToken: token.Token,
		Scopes:      token.Scopes,
		Expires:     &time.Time{}, // TODO: should this expire?
	}
}

func (a *App) ValidHmac(r *http.Request) bool {
	h, err := hex.DecodeString(r.URL.Query().Get("hmac"))
	if err != nil {
		return false
	}
	q := r.URL.Query()
	q.Del("hmac")
	message, _ := url.QueryUnescape(q.Encode())
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	hash.Write([]byte(message))
	validMac := hash.Sum(nil)
	return hmac.Equal(h, validMac)
}

func (a *App) VerifyShopifyOrigin(w http.ResponseWriter, r *http.Request) {
	if !exitFrameRegexp.MatchString(r.RequestURI) && !a.ValidHmac(r) {
		w.WriteHeader(http.StatusUnauthorized)
		AbortWithError(r, errors.New("hmac validation failed"))
		return
	}
}

func (a *App) ContentSecurity(w http.ResponseWriter, r *http.Request) {
	shop := r.URL.Query().Get("shop")
	w.Header().Add("Content-Security-Policy", fmt.Sprintf("frame-ancestors https://%s https://admin.shopify.com", shop))
}

func isEmbedded(r *http.Request) bool {
	return r.URL.Query().Get("embedded") == "1"
}

func (a *App) redirectToAuth(w http.ResponseWriter, r *http.Request) {
	if isEmbedded(r) {
		host, err := a.sanitizeHost(r.URL.Query().Get("host"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			AbortWithError(r, fmt.Errorf("failed to sanitize host: %w", err))
			return
		}
		redirect, err := url.JoinPath(a.HostURL,
			fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {MustGetShop(r)}, "host": {host}}.Encode()))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			AbortWithError(r, fmt.Errorf("failed to construct redirect uri: %w", err))
			return
		}
		GetLogger(r).With(log.String("redirect", redirect)).Debug("redirecting out of app")
		a.redirectOutOfApp(w, r, redirect)
		return
	}
	GetLogger(r).Debug("app is not embedded, begin auth")
	a.Begin(w, r)
}

func (a *App) redirectOutOfApp(w http.ResponseWriter, r *http.Request, redirect string) {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && token != "" {
		GetLogger(r).Debug("bearer token found, performing app bridge header redirect")
		a.appBridgeHeaderRedirect(w, redirect)
	} else if isEmbedded(r) {
		GetLogger(r).Debug("app is embedded, performing exitiframe redirect")
		query := r.URL.Query()
		query.Add("redirectUri", redirect)
		http.Redirect(w, r, "/exitiframe?"+query.Encode(), http.StatusFound)
	} else {
		GetLogger(r).Debug("app is not embedded, performing direct redirect")
		http.Redirect(w, r, redirect, http.StatusFound)
	}
	Abort(r)
}

func (a *App) appBridgeHeaderRedirect(w http.ResponseWriter, redirect string) {
	w.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize")
	w.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize-Url")
	w.Header().Add("X-Shopify-API-Request-Failure-Reauthorize", "1")
	w.Header().Add("X-Shopify-API-Request-Failure-Reauthorize-Url", redirect)
	w.WriteHeader(http.StatusForbidden)
}

func (a *App) embedAppIntoShopify(w http.ResponseWriter, r *http.Request) {
	decodedHost, err := decodeHost(r.URL.Query().Get("host"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		AbortWithError(r, fmt.Errorf("failed to sanitize host: %w", err))
		return
	}
	u, err := url.JoinPath("https://", decodedHost, "apps", a.AppConfig.Credentials.ClientID, r.URL.Path)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		AbortWithError(r, fmt.Errorf("failed to construct redirect URL: %w", err))
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}
