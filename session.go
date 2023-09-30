package shopigo

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"strings"
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

func (a *App) getSessionID(c *gin.Context) (string, error) {
	if a.sessionIDHook != nil {
		return a.sessionIDHook.OnRetrieveSessionID()
	}
	if a.embedded {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" {
			return "", os.ErrNotExist
		}
		return a.parseJWTSessionID(token, false)
	}
	return a.getSessionIDFromCookie(c)
}

func (a *App) getSessionIDFromCookie(c *gin.Context) (string, error) {
	if err := ValidateCookieSignature(c, a.Credentials.ClientSecret, SessionCookie); err != nil {
		DeleteCookies(c, SessionCookie, SessionCookieSig)
		return "", err
	}
	return c.Cookie(SessionCookie)
}

func (a *App) sessionValid(sess *Session) bool {
	if sess == nil {
		return false
	}
	// TODO: do test request against TEST_GRAPHQL_QUERY? kinda strange...
	return sess.Scopes == a.scopes && sess.AccessToken != "" && (sess.Expires == nil || time.Now().After(*sess.Expires))
}
