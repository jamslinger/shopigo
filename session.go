package shopigo

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"time"
)

type Session struct {
	ID               string
	Shop             string
	State            string
	IsOnline         bool
	AccessToken      string
	Scopes           string
	Expires          *time.Time
	OnlineAccessInfo *OnlineAccessInfo
}

type SessionStore interface {
	Get(ctx context.Context, ID string) (*Session, error)
	Store(ctx context.Context, session *Session) error
	Delete(ctx context.Context, ID string) error
}

var InMemSessionStore = &inMemSessionStore{}

type inMemSessionStore map[string]*Session

func (i inMemSessionStore) Get(_ context.Context, id string) (*Session, error) {
	sess, _ := i[id]
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
