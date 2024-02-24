package shopigo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type AccessToken struct {
	Token             string `json:"access_token"`
	Scopes            string `json:"scope"`
	*OnlineAccessInfo `json:",omitempty"`
}

type OnlineAccessInfo struct {
	Exp       int64  `json:"expires_in"`
	UserScope string `json:"associated_user_scope"`
	User      *User  `json:"associated_user,omitempty"`
}

type User struct {
	ID            int    `json:"id"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AccountOwner  bool   `json:"account_owner"`
	Locale        string `json:"locale"`
	Collaborator  bool   `json:"collaborator"`
}

func (a *App) AccessToken(shop string, code string) (*AccessToken, error) {
	accessTokenPath := "admin/oauth/access_token"
	accessTokenEndPoint := fmt.Sprintf("https://%s/%s", shop, accessTokenPath)
	params, err := json.Marshal(map[string]string{
		"client_id":     a.Credentials.ClientID,
		"client_secret": a.Credentials.ClientSecret,
		"code":          code,
	})
	if err != nil {
		return nil, err
	}
	res, err := http.Post(accessTokenEndPoint, "application/json", bytes.NewBuffer(params))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var token AccessToken
	if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
		return nil, err
	}
	scopes := strings.Split(token.Scopes, ",")
	sort.Slice(scopes, func(i, j int) bool { return i < j })
	token.Scopes = strings.Join(scopes, ",")
	return &token, nil
}
