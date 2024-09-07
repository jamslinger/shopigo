package shopigo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
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
)

func (a *App) EnsureInstalledOnShop(c *gin.Context) {
	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		log.Warn("failed to sanitize shop", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	setShop(c, shop)
	logger := a.Logger.With(log.String("shop", shop))
	logger.Debug("check if app is installed")
	sess, err := a.SessionStore.Get(c.Request.Context(), GetOfflineSessionID(shop))
	if IsNotFound(err) {
		logger.Debug("no session found")
		if !exitFrameRegexp.MatchString(c.Request.RequestURI) {
			logger.Debug("not in exitframe")
			a.redirectToAuth(logger, c)
			return
		}
		logger.Debug("we are in an /exitframe request, serve app")
	} else if err != nil {
		logger.Error("failed to retrieve session", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if !isEmbedded(c) {
		logger.Debug("tried to use embedded app in non-embedded context, validate session")
		if !a.sessionValid(c, sess) {
			logger.Debug("session is invalid, redirecting to auth")
			a.redirectToAuth(logger, c)
			return
		}
		logger.Debug("session validated, attempt embed")
		a.embedAppIntoShopify(logger, c)
		return
	}
	logger.Debug("app is installed and ready to load")
}

func (a *App) ValidateAuthenticatedSession(c *gin.Context) {
	logger := a.Logger
	sessID, shop, err := a.getSessionID(c)
	if err != nil {
		logger.Warn("failed to retrieve session ID", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	logger = logger.With("shop", shop)

	sess, err := a.SessionStore.Get(c.Request.Context(), sessID)
	if IsNotFound(err) {
		if shop != "" {
			logger.Debug("session not found but shop in bearer token, redirecting to auth")
			setShop(c, shop)
			redirect, err := url.JoinPath(a.HostURL,
				fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {shop}}.Encode()))
			if err != nil {
				logger.Warn("failed to construct redirect uri", "error", err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			setRedirectURI(c, redirect)
			a.redirectOutOfApp(c)
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
		return
	} else if err != nil {
		logger.Warn("failed to retrieve session", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if shop, err = a.sanitizeShop(c.Query("shop")); err == nil && shop != sess.Shop {
		logger.With(log.String("shop", sess.Shop), log.String("request-shop", shop)).
			Debug("session found but for different shop as in request, redirecting to auth")
		setShop(c, shop)
		a.redirectToAuth(logger, c)
		return
	}
	if !a.sessionValid(c, sess) {
		logger.With(log.String("shop", sess.Shop)).
			Debug("session is invalid, redirecting to auth")
		setShop(c, sess.Shop)
		redirect, err := url.JoinPath(a.HostURL,
			fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {sess.Shop}}.Encode()))
		if err != nil {
			logger.Warn("failed to construct redirect uri", "error", err)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		setRedirectURI(c, redirect)
		a.redirectOutOfApp(c)
		return
	}
	c.Set(ShopSessionKey, sess)
}

func (a *App) ValidateHMAC(c *gin.Context) {
	hmacHeader := c.GetHeader(XHmacHeader)
	if hmacHeader == "" {
		_ = c.AbortWithError(http.StatusBadRequest, errors.New("HMAC header missing"))
		return
	}
	bs, err := io.ReadAll(c.Request.Body)
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(bs))
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	if _, err = hash.Write(bs); err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	mac := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	if !hmac.Equal([]byte(mac), []byte(hmacHeader)) {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("invalid webhook header"))
		return
	}
}

func (a *App) Begin(c *gin.Context) {
	logger := a.Logger

	shop := getShop(c)
	if shop == "" {
		var err error
		if shop, err = a.sanitizeShop(c.Query("shop")); err != nil {
			logger.Warn("failed to sanitize shop", "error", err)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	logger = logger.With(log.String("shop", shop))

	nonce := strconv.FormatInt(rand.Int63(), 10)
	query := url.Values{
		"client_id":    {a.Credentials.ClientID},
		"scope":        {a.scopes},
		"redirect_uri": {a.authCallbackURL},
		"state":        {nonce},
	}
	expires := time.Now().Add(time.Hour)
	SetSignedCookie(c, a.Credentials.ClientSecret, AppStateCookie, nonce, a.authCallbackPath, &expires)

	redirect := fmt.Sprintf("https://%s/admin/oauth/authorize?%s", shop, query.Encode())
	logger.With(log.String("redirect", redirect)).Debug("beginning auth")
	c.Redirect(http.StatusFound, redirect)
	c.Abort()
}

func (a *App) Install(c *gin.Context) {
	logger := a.Logger.With(log.String("shop", c.Query("shop")))
	logger.Debug("beginning install")

	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		logger.Warn("failed to sanitize shop", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	state := c.Query("state")
	defer DeleteCookies(c, AppStateCookie, AppStateCookieSig)
	if ok, err := CompareSignedCookie(c, a.Credentials.ClientSecret, AppStateCookie, state); err != nil {
		logger.Warn("app state cookie mismatch", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	} else if !ok {
		logger.Warn("app state cookie mismatch")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	if !a.ValidHmac(c) {
		logger.Warn("hmac validation failed")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	token, err := a.AccessToken(shop, c.Query("code"))
	if err != nil {
		logger.Warn("failed to retrieve access token", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	logger.Debug("creating new session")
	sess := a.createSession(shop, state, token)

	if a.installHook != nil {
		logger.Debug("calling install hook")
		if err = a.installHook(c.Request.Context(), a, sess); err != nil {
			logger.Warn("install hook failed", "error", err)
			c.AbortWithStatus(http.StatusForbidden)
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
			if id, err = a.Client(VLatest, sess, nil).RegisterWebhook(c.Request.Context(), &wh); err != nil {
				logger.Warn("failed to register uninstall webhook", "error", err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		err = a.SessionStore.Store(c.Request.Context(), sess)
		if err != nil {
			if id != 0 {
				err = errors.Join(err, a.Client(VLatest, sess, nil).DeleteWebhook(c.Request.Context(), id))
			}
			logger.Warn("failed to store session", "error", err)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	c.Set(ShopSessionKey, sess)
	redirect := "/?" + c.Request.URL.Query().Encode()
	logger.With(log.String("redirect", redirect)).Debug("app installed, redirecting to app")
	c.Redirect(http.StatusFound, redirect)
}

func (a *App) getSessionID(c *gin.Context) (string, string, error) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		return "", "", errors.New("missing 'Authorization' header")
	}
	return a.parseJWTSessionID(token)
}

func (a *App) sessionValid(c *gin.Context, sess *Session) bool {
	logger := a.Logger
	if sess == nil {
		a.Debug("session invalid: nil")
		return false
	}
	if sess.AccessToken == "" {
		logger.Debug("session invalid: empty access token")
		return false
	}
	if sess.Scopes != a.scopes {
		logger.Debug("session invalid: scopes changed")
		return false
	}
	if sess.Expires != nil && time.Now().After(*sess.Expires) {
		logger.Debug("session invalid: expired")
		return false
	}
	cl := a.GraphQLClient(VLatest, sess, nil)
	var query struct {
		Shop struct {
			Name string `json:"name"`
		} `graphql:"shop"`
	}
	err := cl.Query(c.Request.Context(), "shop", &query, nil)
	if err != nil {
		logger.Debug(fmt.Sprintf("session invalid: %s", err.Error()))
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
		Expires:     nil, // TODO: should this expire?
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

func (a *App) VerifyShopifyOrigin(logger *log.Logger, c *gin.Context) {
	if !exitFrameRegexp.MatchString(c.Request.RequestURI) && !a.ValidHmac(c) {
		logger.Error("failed hmac validation")
		c.AbortWithStatus(http.StatusForbidden)
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

func (a *App) redirectToAuth(logger *log.Logger, c *gin.Context) {
	shop := mustGetShop(c)
	if isEmbedded(c) {
		host, err := a.sanitizeHost(c.Query("host"))
		if err != nil {
			logger.Error("failed to sanitize host", "error", err)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		redirect, err := url.JoinPath(a.HostURL,
			fmt.Sprintf("%s?%s", a.authBeginEndpoint, url.Values{"shop": {shop}, "host": {host}}.Encode()))
		if err != nil {
			logger.Error("failed to construct redirect uri", "error", err)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		setRedirectURI(c, redirect)
		logger.With(log.String("redirect", redirect)).Debug("redirecting out of app")
		a.redirectOutOfApp(c)
		return
	}
	logger.Debug("app is not embedded, begin auth")
	a.Begin(c)
}

func (a *App) redirectOutOfApp(c *gin.Context) {
	shop := mustGetShop(c)
	logger := a.Logger.With(log.String("shop", shop))
	if token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer "); ok && token != "" {
		logger.Debug("bearer token found, performing app bridge header redirect")
		a.appBridgeHeaderRedirect(c)
	} else if isEmbedded(c) {
		logger.Debug("app is embedded, performing exitiframe redirect")
		query := c.Request.URL.Query()
		query.Add("redirectUri", mustGetRedirectURI(c))
		c.Redirect(http.StatusFound, "/exitiframe?"+query.Encode())
	} else {
		logger.Debug("app is not embedded, performing direct redirect")
		c.Redirect(http.StatusFound, mustGetRedirectURI(c))
	}
	c.Abort()
}

func (a *App) appBridgeHeaderRedirect(c *gin.Context) {
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize")
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize-Url")
	c.Header("X-Shopify-API-Request-Failure-Reauthorize", "1")
	c.Header("X-Shopify-API-Request-Failure-Reauthorize-Url", mustGetRedirectURI(c))
	c.AbortWithStatus(http.StatusForbidden)
}

func (a *App) embedAppIntoShopify(logger *log.Logger, c *gin.Context) {
	decodedHost, err := decodeHost(c.Query("host"))
	if err != nil {
		logger.Error("failed to embed app", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	u, err := url.JoinPath("https://", decodedHost, "apps", a.AppConfig.Credentials.ClientID, c.Request.URL.Path)
	if err != nil {
		logger.Error("failed to embed app", "error", err)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Redirect(http.StatusFound, u)
	c.Abort()
}
