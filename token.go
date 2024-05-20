package shopigo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

type AccessToken struct {
	Token  string `json:"access_token"`
	Scopes string `json:"scope"`
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
	resp, err := http.Post(accessTokenEndPoint, "application/json", bytes.NewBuffer(params))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status: %d, cause: %s", resp.StatusCode, string(bs))
	}
	var token AccessToken
	if err = json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}
	scopes := strings.Split(token.Scopes, ",")
	sort.Slice(scopes, func(i, j int) bool { return i < j })
	token.Scopes = strings.Join(scopes, ",")
	return &token, nil
}
