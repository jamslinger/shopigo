package shopigo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

func SetSignedCookie(c *gin.Context, key string, name string, val string, path string) {
	sigName := name + ".sig"
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(val))
	sig := hex.EncodeToString(hash.Sum(nil))

	exp := time.Now().Add(time.Hour)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     path,
		Expires:  exp,
		Secure:   true,
		HttpOnly: true,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sigName,
		Value:    sig,
		Path:     path,
		Expires:  exp,
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
	sigName := name + ".sig"
	sig, err := c.Cookie(sigName)
	if err != nil {
		log.WithError(err).Error("could not read state cookie signature")
		return false
	}
	mac, err := hex.DecodeString(sig)
	if err != nil {
		log.WithError(err).Error("could not decode state cookie signature")
		return false
	}
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(cookie))
	if bytes.Compare(hash.Sum(nil), mac) != 0 {
		return false
	}
	return cookie == val
}

func DeleteCookies(c *gin.Context, names ...string) {
	for _, name := range names {
		http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: "", Path: "/", Expires: time.Unix(0, 0)})
	}
}
