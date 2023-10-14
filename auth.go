package shopigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
)

const (
	metadataKey       = "metadataKey"
	ShopSessionKey    = "ShopifyShopSessionKey"
	AppStateCookie    = "shopify_app_state"
	AppStateCookieSig = "shopify_app_state.sig"
	SessionCookie     = "shopify_app_session"
	SessionCookieSig  = "shopify_app_session.sig"
)

func (a *App) EnsureInstalledOnShop(c *gin.Context) {
	logger := log.With("action", "EnsureInstalledOnShop")
	if !a.embedded {
		logger.Debug("app is not embedded, validating session")
		a.ValidateAuthenticatedSession(c)
		return
	}
	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	setShop(c, shop)
	logger = logger.With(log.String("shop", shop))
	logger.Debug("check if app is installed")
	sess, err := a.SessionStore.Get(c.Request.Context(), GetOfflineSessionID(shop))
	if IsNotFound(err) {
		if !exitFrameRegexp.MatchString(c.Request.RequestURI) {
			logger.Debug("no session found, redirecting to auth")
			a.redirectToAuth(c)
			return
		}
	} else if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if a.embedded && !isEmbedded(c) {
		logger.Debug("tried to use embedded app in non-embedded context, attempt embed")
		if !a.sessionValid(sess) {
			logger.Debug("session is invalid, redirecting to auth")
			a.redirectToAuth(c)
			return
		}
		a.embedAppIntoShopify(c)
		return
	}
	logger.Debug("app is installed and ready to load")
}

func (a *App) ValidateAuthenticatedSession(c *gin.Context) {
	log.Debug("retrieve session ID")
	sessID, shop, err := a.getSessionID(c)
	if err != nil {
		_ = c.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	log.Debug("retrieve session")
	sess, err := a.SessionStore.Get(c.Request.Context(), sessID)
	if IsNotFound(err) {
		if shop != "" {
			log.With(log.String("shop", shop)).
				Debug("session not found but shop in bearer token, redirecting to auth")
			setShop(c, shop)
			redirect, err := url.JoinPath(a.HostURL,
				fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {shop}}.Encode()))
			if err != nil {
				_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to construct redirect uri: %w", err))
				return
			}
			setRedirectUri(c, redirect)
			a.redirectOutOfApp(c)
			return
		}
		_ = c.AbortWithError(http.StatusUnauthorized, err)
		return
	} else if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if shop, err = a.sanitizeShop(c.Query("shop")); err == nil && shop != sess.Shop {
		log.With(log.String("shop", sess.Shop), log.String("request-shop", shop)).
			Debug("session found but for different shop as in request, redirecting to auth")
		setShop(c, shop)
		a.redirectToAuth(c)
		return
	}
	if !a.sessionValid(sess) {
		log.With(log.String("shop", sess.Shop)).
			Debug("session is invalid, redirecting to auth")
		setShop(c, sess.Shop)
		redirect, err := url.JoinPath(a.HostURL,
			fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {sess.Shop}}.Encode()))
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to construct redirect uri: %w", err))
			return
		}
		setRedirectUri(c, redirect)
		a.redirectOutOfApp(c)
		return
	}
	c.Set(ShopSessionKey, sess)
}

func (a *App) Begin(c *gin.Context) {
	shop := getShop(c)
	if shop == "" {
		var err error
		if shop, err = a.sanitizeShop(c.Query("shop")); err != nil {
			_ = c.AbortWithError(http.StatusBadRequest, err)
			return
		}
	}

	logger := log.With(log.String("shop", shop))
	logger.Debug("beginning auth")

	nonce := strconv.FormatInt(rand.Int63(), 10)
	// online access tokens: grantOptions = "per-user" (not implemented)
	var grantOptions string
	query := url.Values{
		"client_id":       {a.Credentials.ClientID},
		"scope":           {a.scopes},
		"redirect_uri":    {a.authCallbackURL},
		"state":           {nonce},
		"grant_options[]": {grantOptions},
	}
	expires := time.Now().Add(time.Hour)
	SetSignedCookie(c, a.Credentials.ClientSecret, AppStateCookie, nonce, a.authCallbackPath, &expires)

	redirect := fmt.Sprintf("https://%s/admin/oauth/authorize?%s", shop, query.Encode())
	logger.With(log.String("redirect", redirect)).Debug("beginning auth, redirecting")
	c.Redirect(http.StatusFound, redirect)
	c.Abort()
}

func (a *App) Install(c *gin.Context) {
	logger := log.With(log.String("shop", c.Query("shop")))
	logger.Debug("performing install")

	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	state := c.Query("state")
	defer DeleteCookies(c, AppStateCookie, AppStateCookieSig)
	if ok, err := CompareSignedCookie(c, a.Credentials.ClientSecret, AppStateCookie, state); !ok {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("app state cookie mismatch"))
		return
	} else if err != nil {
		_ = c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("app state cookie mismatch: %w", err))
		return
	}

	if !a.ValidHmac(c) {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("hmac validation failed"))
		return
	}

	token, err := a.AccessToken(shop, c.Query("code"))
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to retrieve access token: %w", err))
		return
	}

	logger.Debug("creating new session")
	sess := a.createSession(shop, state, token)
	if !a.embedded {
		SetSignedCookie(c, a.Credentials.ClientSecret, SessionCookie, sess.ID, "/", sess.Expires)
	}
	err = a.SessionStore.Store(c.Request.Context(), sess)
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to store session: %w", err))
		return
	}

	if a.uninstallWebhookEndpoint != "" {
		wh := Webhook{
			Topic:   "app/uninstalled",
			Address: a.uninstallWebhookEndpoint,
			Fields:  []string{"domain"},
		}
		logger.With("webhook", wh).Debug("registering uninstall webhook")

		// A possible error is "already exists" if we only update scopes during
		// this install. However, shopify makes it really hard to reliably check
		// for concrete errors, so rather assume this won't fail in case the hook
		// didn't exist yet.
		// https://community.shopify.com/c/shopify-apps/api-error-response-types/td-p/2268179
		if _, err = a.RegisterWebhook(&wh, sess); err != nil {
			logger.With("webhook", wh, "error", err).Debug("registering uninstall webhook failed")
		}
	}
	if a.installHook != nil {
		logger.Debug("calling install hook")
		a.installHook()
	}
	redirect := "/?" + c.Request.URL.Query().Encode()
	logger.With(log.String("redirect", redirect)).Debug("app installed, redirecting to app")
	c.Redirect(http.StatusFound, redirect)
	c.Abort()
}

func (a *App) getSessionID(c *gin.Context) (string, string, error) {
	if a.sessionIDHook != nil {
		return a.sessionIDHook()
	}
	if a.embedded {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" {
			return "", "", errors.New("missing 'Authorization' header")
		}
		return a.parseJWTSessionID(token, false)
	}
	id, err := a.getSessionIDFromCookie(c)
	return id, "", err
}

func (a *App) getSessionIDFromCookie(c *gin.Context) (string, error) {
	if err := ValidateCookieSignature(c, a.Credentials.ClientSecret, SessionCookie); err != nil {
		DeleteCookies(c, SessionCookie, SessionCookieSig)
		return "", err
	}
	return c.Cookie(SessionCookie)
}

func (a *App) sessionValid(sess *Session) bool {
	if sess == nil {
		return false
	}
	// TODO: do test request against TEST_GRAPHQL_QUERY? kinda strange...
	return sess.Scopes == a.scopes && sess.AccessToken != "" && (sess.Expires == nil || time.Now().After(*sess.Expires))
}

func (a *App) createSession(shop string, state string, token *AccessToken) *Session {
	var isOnline bool
	if token.OnlineAccessInfo != nil && token.OnlineAccessInfo.User != nil {
		isOnline = true
	}
	var exp *time.Time
	var sessID string

	if isOnline {
		expires := time.Now().Add(time.Duration(token.OnlineAccessInfo.Exp * int64(time.Second)))
		exp = &expires
		if a.embedded {
			sessID = GetOnlineSessionID(shop, strconv.Itoa(token.OnlineAccessInfo.User.ID))
		} else {
			sessID = uuid.New().String()
		}
	} else {
		sessID = GetOfflineSessionID(shop)
	}
	return &Session{
		ID:               sessID,
		Shop:             shop,
		State:            state,
		IsOnline:         isOnline,
		AccessToken:      token.Token,
		Scopes:           token.Scopes,
		Expires:          exp,
		OnlineAccessInfo: token.OnlineAccessInfo,
	}
}

func (a *App) ValidHmac(c *gin.Context) bool {
	h, err := hex.DecodeString(c.Query("hmac"))
	if err != nil {
		return false
	}
	q := c.Request.URL.Query()
	q.Del("hmac")
	message, _ := url.QueryUnescape(q.Encode())
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	hash.Write([]byte(message))
	validMac := hash.Sum(nil)
	return hmac.Equal(h, validMac)
}

func (a *App) VerifyShopifyOrigin(c *gin.Context) {
	if !exitFrameRegexp.MatchString(c.Request.RequestURI) && !a.ValidHmac(c) {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("failed hmac validation"))
		return
	}
}

func (a *App) ContentSecurity(c *gin.Context) {
	shop := c.Query("shop")
	c.Header("Content-Security-Policy", fmt.Sprintf("frame-ancestors https://%s https://admin.shopify.com", shop))
}

func isEmbedded(c *gin.Context) bool {
	return c.Query("embedded") == "1"
}

func (a *App) redirectToAuth(c *gin.Context) {
	shop := mustGetShop(c)
	logger := log.With(log.String("shop", shop))
	if isEmbedded(c) {
		host, err := a.sanitizeHost(c.Query("host"))
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		redirect, err := url.JoinPath(a.HostURL,
			fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {shop}, "host": {host}}.Encode()))
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to construct redirect uri: %w", err))
			return
		}
		setRedirectUri(c, redirect)
		logger.With(log.String("redirect", redirect)).Debug("redirecting out of app")
		a.redirectOutOfApp(c)
		return
	}
	logger.Debug("app is not embedded, begin auth")
	a.Begin(c)
}

func (a *App) redirectOutOfApp(c *gin.Context) {
	shop := mustGetShop(c)
	logger := log.With(log.String("shop", shop))

	if token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer "); ok && token != "" {
		logger.Debug("bearer token found, performing app bridge header redirect")
		a.appBridgeHeaderRedirect(c)
	} else if isEmbedded(c) {
		logger.Debug("app is embedded, performing exitiframe redirect")
		query := c.Request.URL.Query()
		query.Add("redirectUri", mustGetRedirectUri(c))
		c.Redirect(http.StatusFound, "/exitiframe?"+query.Encode())
	} else {
		logger.Debug("app is not embedded, performing direct redirect")
		c.Redirect(http.StatusFound, mustGetRedirectUri(c))
	}
	c.Abort()
}

func (a *App) appBridgeHeaderRedirect(c *gin.Context) {
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize")
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize-Url")
	c.Header("X-Shopify-API-Request-Failure-Reauthorize", "1")
	c.Header("X-Shopify-API-Request-Failure-Reauthorize-Url", mustGetRedirectUri(c))
	c.AbortWithStatus(http.StatusForbidden)
}

func (a *App) embedAppIntoShopify(c *gin.Context) {
	decodedHost, err := decodeHost(c.Query("host"))
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to embed app: %w", err))
		return
	}
	u, err := url.JoinPath("https://", decodedHost, "apps", a.AppConfig.Credentials.ClientID, c.Request.URL.Path)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to embed app: %w", err))
		return
	}
	c.Redirect(http.StatusFound, u)
	c.Abort()
}
