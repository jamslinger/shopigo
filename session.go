package shopigo

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"time"
)

type Session struct {
	ID               string            `json:"id"`
	Shop             string            `json:"shop"`
	State            string            `json:"state"`
	IsOnline         bool              `json:"is_online"`
	AccessToken      string            `json:"access_token"`
	Scopes           string            `json:"scopes"`
	Expires          *time.Time        `json:"expires"`
	OnlineAccessInfo *OnlineAccessInfo `json:"online_access_info"`
}

type SessionStore interface {
	Get(ctx context.Context, ID string) (*Session, error)
	Store(ctx context.Context, session *Session) error
	Delete(ctx context.Context, ID string) error
}

var ErrNotFound = errors.New("session not found")

func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound)
}

var InMemSessionStore = &inMemSessionStore{}

type inMemSessionStore map[string]*Session

func (i inMemSessionStore) Get(_ context.Context, id string) (*Session, error) {
	sess, ok := i[id]
	if !ok {
		return nil, ErrNotFound
	}
	return sess, nil
}

func (i inMemSessionStore) Store(_ context.Context, session *Session) error {
	i[session.ID] = session
	return nil
}

func (i inMemSessionStore) Delete(_ context.Context, id string) error {
	delete(i, id)
	return nil
}

func GetOnlineSessionID(shop string, user string) string {
	return fmt.Sprintf("%s_%s", shop, user)
}

func GetOfflineSessionID(shop string) string {
	return fmt.Sprintf("offline_%s", shop)
}

func MustGetShopSession(c *gin.Context) *Session {
	sess, ok := c.Get(ShopSessionKey)
	if !ok {
		panic("context doesn't hold session")
	}
	s, ok := sess.(*Session)
	if !ok {
		panic("context doesn't hold session")

	}
	return s
}

func MustGetSessionID(c *gin.Context) string {
	sess, ok := c.Get(ShopSessionKey)
	if ok {
		if s, ok := sess.(*Session); ok {
			return s.ID
		} else {
			panic("context doesn't hold session")
		}
	}
	shop := c.GetHeader(XDomainHeader)
	if shop == "" {
		panic("context doesn't hold session")
	}
	return GetOfflineSessionID(shop)
}

func MustGetShop(c *gin.Context) string {
	sess, ok := c.Get(ShopSessionKey)
	if !ok {
		shop := c.GetHeader(XDomainHeader)
		if shop == "" {
			panic("context doesn't hold session")
		}
		return shop
	}
	s, ok := sess.(*Session)
	if !ok {
		panic("context doesn't hold session")
	}
	return s.Shop
}
