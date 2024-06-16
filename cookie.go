package shopigo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func setSignedCookie(w http.ResponseWriter, key string, name string, val string, path string, exp *time.Time) {
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
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     path,
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     sigName,
		Value:    sig,
		Path:     path,
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
	})
}

func compareSignedCookie(r *http.Request, key string, name string, val string) (bool, error) {
	cookie, err := r.Cookie(appStateCookie)
	if err != nil {
		return false, fmt.Errorf("could not read state cookie: %w", err)
	}
	if err = validateCookieSignature(r, key, name); err != nil {
		return false, fmt.Errorf("invalid state cookie: %w", err)
	}
	return cookie.Value == val, nil
}

func validateCookieSignature(r *http.Request, key string, name string) error {
	cookie, err := r.Cookie(name)
	if err != nil {
		return errors.New("could not read cookie")
	}
	sigName := name + ".sig"
	sig, err := r.Cookie(sigName)
	if err != nil {
		return errors.New("could not read cookie signature")
	}
	mac, err := hex.DecodeString(sig.Value)
	if err != nil {
		return errors.New("could not decode cookie signature")
	}
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(cookie.Value))
	if !bytes.Equal(hash.Sum(nil), mac) {
		return errors.New("invalid cookie signature")
	}
	return nil
}

func deleteCookies(w http.ResponseWriter, names ...string) {
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Expires: time.Unix(0, 0)})
	}
}
