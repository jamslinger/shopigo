package shopigo

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/url"
	"strings"
	"time"
)

func (a *App) parseJWTSessionID(token string) (string, string, error) {
	tok, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
		return []byte(a.Credentials.ClientSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse jwt: %w", err)
	}
	exp, err := tok.Claims.GetExpirationTime()
	if err != nil || time.Now().After(exp.Time) {
		return "", "", errors.New("token expired")
	}
	nbf, err := tok.Claims.GetNotBefore()
	if err != nil || time.Now().Before(nbf.Time) {
		return "", "", errors.New("token not yet valid")
	}
	iss, err := tok.Claims.GetIssuer()
	if err != nil {
		return "", "", errors.New("invalid issuer")
	}
	issURL, err := url.Parse(iss)
	if err != nil {
		return "", "", errors.New("failed to parse issue ShopURL")
	}
	claimsMap, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("failed to parse claim map")
	}
	dest, ok := claimsMap["dest"].(string)
	if !ok {
		return "", "", errors.New("failed to read claim's dest")
	}
	destURL, err := url.Parse(dest)
	if err != nil {
		return "", "", errors.New("failed to parse dest ShopURL")
	}
	if issURL.Hostname() != destURL.Hostname() {
		return "", "", errors.New("iss and dest host not matching")
	}
	aud, err := tok.Claims.GetAudience()
	in := func(sl []string, s string) bool {
		for i := range sl {
			if sl[i] == s {
				return true
			}
		}
		return false
	}
	if err != nil || !in(aud, a.Credentials.ClientID) {
		return "", "", errors.New("invalid client id")
	}
	shop := strings.ReplaceAll(destURL.Hostname(), "https://", "")
	return GetOfflineSessionID(shop), shop, nil
}
