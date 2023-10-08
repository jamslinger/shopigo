package shopigo

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

func (a *App) sanitizeShop(shop string) (string, error) {
	if !a.shopRegexp.MatchString(shop) {
		return "", fmt.Errorf("malformed shop: %s", shop)
	}
	return shop, nil
}

func (a *App) sanitizeHost(host string) (string, error) {
	host, err := decodeHost(host)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(fmt.Sprintf("https://%s", host))
	if err != nil {
		return "", fmt.Errorf("malformed host, invalid URL: %s", host)
	}
	if _, err = a.sanitizeShop(u.Hostname()); err != nil {
		return "", fmt.Errorf("malformed host, %w: %s", err, host)

	}
	return host, nil
}

func decodeHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("host must not be empty")
	}
	bs, err := base64.RawURLEncoding.DecodeString(host)
	return string(bs), err
}
