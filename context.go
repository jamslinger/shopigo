package shopigo

import (
	"context"
	"errors"
	log "log/slog"
	"net/http"
)

const (
	ShopKey    = "shopigo/shop-key"
	LoggerKey  = "shopigo/logger-key"
	SessionKey = "shopigo/session-key"
)

func Abort(r *http.Request) {
	if r.Context().Err() == nil {
		ctx, cancel := context.WithCancel(r.Context())
		*r = *r.WithContext(ctx)
		cancel()
	}
}

func AbortWithError(r *http.Request, err error) {
	if r.Context().Err() == nil {
		ctx, cancel := context.WithCancelCause(r.Context())
		*r = *r.WithContext(ctx)
		cancel(err)
	}
}

func setShop(r *http.Request, shop string) {
	*r = *r.WithContext(context.WithValue(r.Context(), ShopKey, shop))
}

func setLogger(r *http.Request, logger *log.Logger) {
	*r = *r.WithContext(context.WithValue(r.Context(), LoggerKey, logger))
}

func setSession(r *http.Request, sess *Session) {
	*r = *r.WithContext(context.WithValue(r.Context(), SessionKey, sess))
}

func GetShop(r *http.Request) (string, error) {
	shop, ok := r.Context().Value(ShopKey).(string)
	if ok && shop != "" {
		return shop, nil
	}
	sess, ok := r.Context().Value(SessionKey).(*Session)
	if ok && sess != nil {
		return sess.Shop, nil
	}
	if shop = r.Header.Get(XDomainHeader); shop != "" {
		return shop, nil
	}
	return "", errors.New("context doesn't hold session")
}

func MustGetShop(r *http.Request) string {
	shop, err := GetShop(r)
	if err != nil {
		panic(err)
	}
	return shop
}

func GetShopID(r *http.Request) (string, error) {
	shop, err := GetShop(r)
	if err != nil {
		panic(err)
	}
	return GetOfflineSessionID(shop), nil
}

func MustGetShopID(r *http.Request) string {
	id, err := GetShopID(r)
	if err != nil {
		panic(err)
	}
	return id
}

func MustGetSession(r *http.Request) *Session {
	sess, ok := r.Context().Value(SessionKey).(*Session)
	if !ok || sess == nil {
		panic("context doesn't hold session")
	}
	return sess
}

func MustGetSessionID(r *http.Request) string {
	sess, ok := r.Context().Value(SessionKey).(*Session)
	if ok && sess == nil {
		panic("context doesn't hold session")
	} else if ok {
		return sess.ID
	}
	shop := r.Header.Get(XDomainHeader)
	if shop == "" {
		panic("context doesn't hold session")
	}
	return GetOfflineSessionID(shop)
}

func GetLogger(r *http.Request) *log.Logger {
	return r.Context().Value(LoggerKey).(*log.Logger)
}

func GetSession(r *http.Request) *Session {
	return r.Context().Value(SessionKey).(*Session)
}
