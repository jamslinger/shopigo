package shopigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	log "log/slog"
	"net/http"
)

func (a *App) VerifyAppProxyRequest(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	shop := q.Get("shop")
	logger := a.Logger.With(log.String("shop", shop))
	logger.Debug("verifying app proxy request")

	sorted := fmt.Sprintf("logged_in_customer_id=%spath_prefix=%sshop=%stimestamp=%s",
		q.Get("logged_in_customer_id"),
		q.Get("path_prefix"),
		shop,
		q.Get("timestamp"),
	)
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	hash.Write([]byte(sorted))
	calcSignature := []byte(hex.EncodeToString(hash.Sum(nil)))
	signature := []byte(r.URL.Query().Get("signature"))

	logger.Debug("checking hmac signature")
	if !hmac.Equal(calcSignature, signature) {
		w.WriteHeader(http.StatusUnauthorized)
		return errors.New("hmac signature mismatch")
	}

	logger.Debug("retrieving session")
	sess, err := a.SessionStore.Get(r.Context(), shop)
	if IsNotFound(err) {
		w.WriteHeader(http.StatusUnauthorized)
		return errors.New("session not found")
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("failed to retrieve session for: %w", err)
	}
	setSession(r, sess)
	return nil
}
