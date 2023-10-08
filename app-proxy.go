package shopigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	log "log/slog"
	"net/http"
)

func (a *App) VerifyAppProxyRequest(c *gin.Context) {
	shop := c.Query("shop")
	logger := log.With(log.String("shop", shop))
	logger.Debug("verifying app proxy request")

	sorted := fmt.Sprintf("logged_in_customer_id=%spath_prefix=%sshop=%stimestamp=%s",
		c.Query("logged_in_customer_id"),
		c.Query("path_prefix"),
		shop,
		c.Query("timestamp"),
	)
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	hash.Write([]byte(sorted))
	calcSignature := []byte(hex.EncodeToString(hash.Sum(nil)))
	signature := []byte(c.Query("signature"))

	logger.Debug("checking hmac signature")
	if !hmac.Equal(calcSignature, signature) {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("hmac signature mismatch"))
		return
	}

	logger.Debug("retrieving session")
	sess, err := a.SessionStore.Get(c.Request.Context(), shop)
	if IsNotFound(err) {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("session not found"))
		return
	} else if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to retrieve session for: %w", err))
		return
	}
	c.Set(ShopSessionKey, sess)
}
