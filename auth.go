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
	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	setShop(c, shop)

	logger := log.With(log.String("shop", shop))
	logger.Debug("check if app is installed")

	if !a.embedded {
		logger.Debug("app is not embedded, validating session")
		a.ValidateAuthenticatedSession(c)
		return
	}

	logger.Debug("check for valid session")
	sess, err := a.SessionStore.Get(c.Request.Context(), GetOfflineSessionID(shop))
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	if sess == nil && !exitFrameRegexp.MatchString(c.Request.RequestURI) {
		logger.Debug("no session found, redirecting to auth")
		a.redirectToAuth(c)
		return
	}

	if !a.sessionValid(sess) {
		logger.Debug("session is invalid, redirecting to auth")
		a.redirectToAuth(c)
	}

	if a.embedded && !isEmbedded(c) {
		logger.Debug("tried to use embedded app in non-embedded context, attempt embed")
		a.embedAppIntoShopify(c)
		return
	}
	logger.Debug("app is installed and ready to load")
}

func (a *App) ValidateAuthenticatedSession(c *gin.Context) {
	logger := log.With(log.String("shop", c.Query("shop")))

	logger.Debug("retrieve session ID")
	sessID, err := a.getSessionID(c)
	if err != nil {
		logger.With("error", err).Error("failed to retrieve session ID, redirecting to auth")
		a.redirectToAuth(c)
		return
	}

	logger.Debug("check for valid session")
	sess, err := a.SessionStore.Get(c.Request.Context(), sessID)
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	if sess == nil {
		logger.Debug("no session found, redirecting to auth")
		a.redirectToAuth(c)
		return
	}

	if !a.sessionValid(sess) {
		logger.Debug("session is invalid, redirecting to auth")
		a.redirectToAuth(c)
		return
	}
	c.Set(ShopSessionKey, sess)
}

func (a *App) Begin(c *gin.Context) {
	logger := log.With(log.String("shop", c.Query("shop")))
	logger.Debug("beginning auth")

	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}

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
		if _, err = a.RegisterWebhook(&wh, sess); err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to register uninstall webhook: %w", err))
			logger.Debug("rolling back session creating")
			if err = a.SessionStore.Delete(c.Request.Context(), sess.ID); err != nil {
				_ = c.Error(fmt.Errorf("failed to delete session: %w", err))
				return
			}
			return
		}
	}
	if a.installHook != nil {
		logger.Debug("calling install hook")
		a.installHook()
	}
	redirect := "/?" + c.Request.URL.Query().Encode()
	logger.With(log.String("redirect", redirect)).Debug("app installed, redirecting to app")
	c.Redirect(http.StatusFound, redirect)
}

func (a *App) getSessionID(c *gin.Context) (string, error) {
	if a.sessionIDHook != nil {
		return a.sessionIDHook()
	}
	if a.embedded {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" {
			return "", errors.New("missing 'Authorization' header")
		}
		return a.parseJWTSessionID(token, false)
	}
	return a.getSessionIDFromCookie(c)
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
		redirect, err := url.JoinPath(a.HostURL, fmt.Sprintf("%s?shop=%s&host=%s", a.authBeginEndpoint, shop, host))
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
}
