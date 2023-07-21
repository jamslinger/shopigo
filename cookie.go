package shopigo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

func SetSignedCookie(c *gin.Context, key string, name string, val string, path string, exp *time.Time) {
	sigName := name + ".sig"
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(val))
	sig := hex.EncodeToString(hash.Sum(nil))

	var expires time.Time
	if exp == nil {
		expires = time.Now().Add(365 * 24 * time.Hour)
	} else {
		expires = *exp
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     path,
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sigName,
		Value:    sig,
		Path:     path,
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
	})
}

func CompareSignedCookie(c *gin.Context, key string, name string, val string) bool {
	cookie, err := c.Cookie(AppStateCookie)
	if err != nil {
		log.WithError(err).Error("could not read state cookie")
		return false
	}
	if err = ValidateCookieSignature(c, key, name); err != nil {
		log.WithError(err).Error("invalid state cookie")
		return false
	}
	return cookie == val
}

func ValidateCookieSignature(c *gin.Context, key string, name string) error {
	cookie, err := c.Cookie(name)
	if err != nil {
		return errors.New("could not read cookie")
	}
	sigName := name + ".sig"
	sig, err := c.Cookie(sigName)
	if err != nil {
		return errors.New("could not read cookie signature")
	}
	mac, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("could not decode cookie signature")
	}
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(cookie))
	if bytes.Compare(hash.Sum(nil), mac) != 0 {
		return errors.New("invalid cookie signature")
	}
	return nil
}

func DeleteCookies(c *gin.Context, names ...string) {
	for _, name := range names {
		http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: "", Path: "/", Expires: time.Unix(0, 0)})
	}
}
