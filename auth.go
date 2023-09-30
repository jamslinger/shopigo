package shopigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
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
		a.RespondError(c, http.StatusBadRequest, err)
		return
	}
	setShop(c, shop)
	if !a.embedded {
		a.ValidateAuthenticatedSession(c)
		return
	}
	sess, err := a.SessionStore.Get(c.Request.Context(), GetOfflineSessionID(shop))
	if err != nil {
		log.Error(c.AbortWithError(http.StatusInternalServerError, err))
		return
	}
	if sess == nil && !exitFrameRegexp.MatchString(c.Request.RequestURI) {
		log.WithField("shop", shop).Debug("app installation was not found for shop, redirecting to auth")
		a.redirectToAuth(c)
		return
	}
	if a.embedded && !isEmbedded(c) {
		if a.sessionValid(sess) {
			log.WithField("shop", shop).Debug("embedding app...")
			a.embedAppIntoShopify(c)
			return
		}
		a.redirectToAuth(c)
		return
	}
	log.WithField("shop", shop).Debug("app is installed and ready to load")
}

func (a *App) ValidateAuthenticatedSession(c *gin.Context) {
	sessID, err := a.getSessionID(c)
	if err != nil {
		log.WithField("shop", c.Query("shop")).WithError(err).Error("failed to retrieve session id")
		a.redirectToAuth(c)
		return
	}
	sess, err := a.SessionStore.Get(c.Request.Context(), sessID)
	if err != nil {
		a.RespondError(c, http.StatusInternalServerError, err)
		return
	}
	if sess == nil || !a.sessionValid(sess) {
		a.redirectToAuth(c)
		return
	}
	log.WithField("shop", sess.Shop).Debug("session validated")
	c.Set(ShopSessionKey, sess)
}

func (a *App) Begin(c *gin.Context) {
	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		a.RespondError(c, http.StatusBadRequest, err)
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
	c.Redirect(http.StatusFound, fmt.Sprintf("https://%s/admin/oauth/authorize?%s", shop, query.Encode()))
	c.Abort()
	return
}

func (a *App) Install(c *gin.Context) {
	state := c.Query("state")
	defer DeleteCookies(c, AppStateCookie, AppStateCookieSig)
	if !CompareSignedCookie(c, a.Credentials.ClientSecret, AppStateCookie, state) {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if !a.ValidHmac(c) {
		log.Error("failed hmac validation")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	shop, err := a.sanitizeShop(c.Query("shop"))
	if err != nil {
		a.RespondError(c, http.StatusBadRequest, err)
		return
	}
	token, err := a.AccessToken(shop, c.Query("code"))
	if err != nil {
		log.Error(c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to retrieve access token: %w", err)))
		return
	}
	sess := a.createSession(shop, state, token)
	if !a.embedded {
		SetSignedCookie(c, a.Credentials.ClientSecret, SessionCookie, sess.ID, "/", sess.Expires)
	}
	err = a.SessionStore.Store(c.Request.Context(), sess)
	if err != nil {
		a.RespondError(c, http.StatusInternalServerError, fmt.Errorf("failed to store session: %w", err))
		return
	}
	if a.uninstallWebhookEndpoint != "" {
		wh := Webhook{
			Topic:   "app/uninstalled",
			Address: a.uninstallWebhookEndpoint,
			Fields:  []string{"domain"},
		}
		_, err = a.RegisterWebhook(&wh, sess)
		if err != nil {
			log.WithField("webhook", wh).
				Error(fmt.Errorf("failed to register uninstall webhook for %s: %w", shop, err))
		}
	}
	if a.installHook != nil {
		a.installHook()
	}
	c.Redirect(http.StatusFound, "/?"+c.Request.URL.Query().Encode())
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

func MustGetShopSession(c *gin.Context) *Session {
	sess, ok := c.Get(ShopSessionKey)
	if !ok {
		log.Panic("context doesn't hold session")
	}
	s, ok := sess.(*Session)
	if !ok {
		log.Panic("context doesn't hold session")

	}
	return s
}

func MustGetShop(c *gin.Context) string {
	sess, ok := c.Get(ShopSessionKey)
	if !ok {
		shop := c.GetHeader(XDomainHeader)
		if shop == "" {
			log.Panic("context doesn't hold session")
		}
		return shop
	}
	s, ok := sess.(*Session)
	if !ok {
		log.Panic("context doesn't hold session")
	}
	return s.Shop
}

func isEmbedded(c *gin.Context) bool {
	return c.Query("embedded") == "1"
}

func (a *App) redirectToAuth(c *gin.Context) {
	if isEmbedded(c) {
		shop := mustGetShop(c)
		host, err := a.sanitizeHost(c.Query("host"))
		if err != nil {
			a.RespondError(c, http.StatusInternalServerError, err)
			return
		}
		redirectUri, err := url.JoinPath(a.HostURL, fmt.Sprintf("%s?shop=%s&host=%s", a.authBeginEndpoint, shop, host))
		if err != nil {
			log.Error("failed to construct redirect uri")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		setRedirectUri(c, redirectUri)
		a.redirectOutOfApp(c)
		return
	}
	a.Begin(c)
}

func (a *App) redirectOutOfApp(c *gin.Context) {
	if token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer "); ok && token != "" {
		a.appBridgeHeaderRedirect(c)
	} else if isEmbedded(c) {
		query := c.Request.URL.Query()
		query.Add("redirectUri", mustGetRedirectUri(c))
		c.Redirect(http.StatusFound, "/exitiframe?"+query.Encode())
	} else {
		c.Redirect(http.StatusFound, mustGetRedirectUri(c))
	}
}

func (a *App) appBridgeHeaderRedirect(c *gin.Context) {
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize")
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-Shopify-Api-Request-Failure-Reauthorize-Url")
	c.Header("X-Shopify-API-Request-Failure-Reauthorize", "1")
	c.Header("X-Shopify-API-Request-Failure-Reauthorize-Url", c.Query("redirectUri"))
	c.AbortWithStatus(http.StatusForbidden)
}

func (a *App) VerifyShopifyOrigin(c *gin.Context) {
	if !exitFrameRegexp.MatchString(c.Request.RequestURI) && !a.ValidHmac(c) {
		log.Error("failed hmac validation")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

func (a *App) ContentSecurity(c *gin.Context) {
	shop := c.Query("shop")
	c.Header("Content-Security-Policy", fmt.Sprintf("frame-ancestors https://%s https://admin.shopify.com", shop))
}

func (a *App) embedAppIntoShopify(c *gin.Context) {
	decodedHost, err := decodeHost(c.Query("host"))
	if err != nil {
		a.RespondError(c, http.StatusBadRequest, fmt.Errorf("failed to embed app: %w", err))
		return
	}
	u, err := url.JoinPath("https://", decodedHost, "apps", a.AppConfig.Credentials.ClientID, c.Request.URL.Path)
	if err != nil {
		a.RespondError(c, http.StatusBadRequest, fmt.Errorf("failed to embed app: %w", err))
		return
	}
	c.Redirect(http.StatusFound, u)
}
