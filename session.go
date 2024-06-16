package shopigo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Session struct {
	ID          string     `json:"id"`
	Shop        string     `json:"shop"`
	State       string     `json:"state"`
	AccessToken string     `json:"access_token"`
	Scopes      string     `json:"scopes"`
	Expires     *time.Time `json:"expires"`
	Custom      any        `json:"custom"`
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

func GetOfflineSessionID(shop string) string {
	return fmt.Sprintf("offline_%s", shop)
}

func GetShopFromOfflineSessionID(id string) string {
	return strings.TrimPrefix(id, "offline_")
}
