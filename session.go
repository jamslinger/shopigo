package shopify

import (
	"context"
	"errors"
)

type Session struct {
	ID          string
	AccessToken string
	Scopes      string
}

type SessionStore interface {
	Get(ctx context.Context, ID string) (*Session, error)
	Store(ctx context.Context, session *Session) error
}

var InMemSessionStore = &inMemSessionStore{}

type inMemSessionStore map[string]*Session

func (i inMemSessionStore) Get(_ context.Context, ID string) (*Session, error) {
	sess, ok := i[ID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return sess, nil
}

func (i inMemSessionStore) Store(_ context.Context, session *Session) error {
	i[session.ID] = session
	return nil
}
