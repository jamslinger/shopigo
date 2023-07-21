package shopigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func (a *App) VerifyAppProxyRequest(c *gin.Context) {
	sorted := fmt.Sprintf("logged_in_customer_id=%spath_prefix=%sshop=%stimestamp=%s",
		c.Query("logged_in_customer_id"),
		c.Query("path_prefix"),
		c.Query("shop"),
		c.Query("timestamp"),
	)
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	hash.Write([]byte(sorted))
	calcSignature := []byte(hex.EncodeToString(hash.Sum(nil)))
	signature := []byte(c.Query("signature"))
	if !hmac.Equal(calcSignature, signature) {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	sess, err := a.SessionStore.Get(c.Request.Context(), c.Query("shop"))
	if err != nil {
		a.RespondError(c, http.StatusInternalServerError, fmt.Errorf("failed to retrieve session for %q: %w", c.Query("shop"), err))
		return
	}
	if sess == nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Set(ShopSessionKey, sess)
}
