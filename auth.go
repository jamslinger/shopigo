package shopify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnauthorizedRequest = errors.New("unauthorized request")
)

const (
	ShopSessionKey = "ShopifyShopSessionKey"
	AppStateCookie = "shopify_app_state"
)

// Authenticate checks the online token to retrieve the offline token.
//
// https://shopify.dev/docs/apps/auth/oauth/session-tokens/getting-started
// https://shopify.dev/docs/apps/auth#api-access-modes
func (a *App) Authenticate(c *gin.Context) {
	tok, err := jwt.Parse(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "), func(token *jwt.Token) (interface{}, error) {
		return []byte(a.Credentials.ClientSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		log.Error(c.AbortWithError(http.StatusUnauthorized, err))
		return
	}
	exp, err := tok.Claims.GetExpirationTime()
	if err != nil || time.Now().After(exp.Time) {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("token expired")))
		return
	}
	nbf, err := tok.Claims.GetNotBefore()
	if err != nil || time.Now().Before(nbf.Time) {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("token not yet valid")))
		return
	}
	iss, err := tok.Claims.GetIssuer()
	if err != nil {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("invalid issuer")))
		return
	}
	issURL, err := url.Parse(iss)
	if err != nil {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("failed to parse issue ShopURL")))
		return
	}
	claimsMap, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("failed to parse claim map")))
		return
	}
	dest, ok := claimsMap["dest"].(string)
	if !ok {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("failed to read claim's dest")))
		return
	}
	destURL, err := url.Parse(dest)
	if err != nil {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("failed to parse dest ShopURL")))
		return
	}
	if issURL.Hostname() != destURL.Hostname() {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("iss and dest host not matching")))
		return
	}
	aud, err := tok.Claims.GetAudience()
	if err != nil || !in(aud, a.Credentials.ClientID) {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("invalid client id")))
		return
	}
	a.checkSession(c, destURL.Hostname())
}

func in(sl []string, s string) bool {
	for i := range sl {
		if sl[i] == s {
			return true
		}
	}
	return false
}

func (a *App) VerifyShopifyOrigin(c *gin.Context) {
	if !a.ValidHmac(c) {
		log.Error(c.AbortWithError(http.StatusUnauthorized, ErrUnauthorizedRequest))
		return
	}
}

func (a *App) IsInstalled(c *gin.Context) {
	a.checkSession(c, c.Query("shop"))
}

func (a *App) ContentSecurity(c *gin.Context) {
	shop := c.Query("shop")
	c.Header("Content-Security-Policy", fmt.Sprintf("frame-ancestors https://%s https://admin.shopify.com", shop))
}

func (a *App) checkSession(c *gin.Context, shop string) {
	sess, err := a.SessionStore.Get(c.Request.Context(), shop)
	if err != nil || sess.Scopes != a.scopes {
		log.WithError(err).Error("invalid session")
		nonce := strconv.FormatInt(rand.Int63(), 10)
		query := url.Values{
			"client_id":    {a.Credentials.ClientID},
			"scope":        {a.scopes},
			"redirect_uri": {a.redirectURL},
			"state":        {nonce},
		}
		SetSignedCookie(c, a.cookieSignKey, AppStateCookie, nonce, "/auth/install")
		c.Redirect(http.StatusFound, fmt.Sprintf("https://%s/admin/oauth/authorize?%s", shop, query.Encode()))
		c.Abort()
		return
	}
	c.Set(ShopSessionKey, sess)
}

func (a *App) Install(c *gin.Context) {
	if !CompareSignedCookie(c, a.cookieSignKey, AppStateCookie, c.Query("state")) {
		log.Error(c.AbortWithError(http.StatusUnauthorized, ErrUnauthorizedRequest))
		return
	}
	shop := c.Query("shop")
	code := c.Query("code")
	token, err := a.AccessToken(shop, code)
	if err != nil {
		log.Error(c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to retrieve access token: %w", err)))
		return
	}
	sess := &Session{
		ID:          shop,
		AccessToken: token.Token,
		Scopes:      token.Scopes,
	}
	err = a.SessionStore.Store(c.Request.Context(), sess)
	if err != nil {
		log.Error(c.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to store session: %w", err)))
		return
	}
	DeleteCookies(c, AppStateCookie, AppStateCookie+".sig")
	_, err = a.RegisterWebhook(&Webhook{
		Topic:   "app/uninstalled",
		Address: "/hooks/uninstall",
		Fields:  []string{},
	}, sess)
	if err != nil {
		log.Warning(fmt.Errorf("failed to register uninstall webhook for %s: %w", shop, err))
	}
	c.Redirect(http.StatusFound, fmt.Sprintf("https://%s/admin/apps/%s?%s", shop, a.Credentials.ClientID, c.Request.URL.Query().Encode()))
}

type AccessToken struct {
	Token  string `json:"access_token"`
	Scopes string `json:"scope"`
}

func (a *App) AccessToken(shop string, code string) (*AccessToken, error) {
	accessTokenPath := "admin/oauth/access_token"
	accessTokenEndPoint := fmt.Sprintf("https://%s/%s", shop, accessTokenPath)
	params, err := json.Marshal(map[string]string{
		"client_id":     a.Credentials.ClientID,
		"client_secret": a.Credentials.ClientSecret,
		"code":          code,
	})
	if err != nil {
		return nil, err
	}
	res, err := http.Post(accessTokenEndPoint, "application/json", bytes.NewBuffer(params))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var token AccessToken
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, err
	}
	scopes := strings.Split(token.Scopes, ",")
	sort.Slice(scopes, func(i, j int) bool { return i < j })
	token.Scopes = strings.Join(scopes, ",")
	return &token, nil
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
	return s.ID
}
