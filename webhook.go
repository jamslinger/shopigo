package shopigo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
)

const (
	XDomainHeader = "x-shopify-shop-domain"
	XHmacHeader   = "X-Shopify-Hmac-SHA256"
	XAccessToken  = "X-Shopify-Access-Token"
)

type WebhookRequest struct {
	Webhook *Webhook `json:"webhook"`
}

type Webhook struct {
	Topic   string   `json:"topic"`
	Address string   `json:"address"`
	Fields  []string `json:"fields,omitempty"`
	Format  string   `json:"format,omitempty"`
}

type Customer struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (c *Client) RegisterWebhook(wh *Webhook, sess *Session) (id int, err error) {
	wh.Address, err = url.JoinPath(c.hostURL, wh.Address)
	body, err := json.Marshal(WebhookRequest{Webhook: wh})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.ShopURL(sess.ID, "/webhooks.json"), bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(XAccessToken, sess.AccessToken)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("failed to register webhook, status: %d, cause: %s", resp.StatusCode, string(bs))
	}
	var whResp = struct {
		Webhook struct {
			ID int `json:"id"`
		} `json:"webhook"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&whResp); err != nil {
		return 0, err
	}
	return whResp.Webhook.ID, nil
}

func (c *Client) DeleteWebhook(id int, sess *Session) error {
	req, err := http.NewRequest(http.MethodDelete, c.ShopURL(sess.ID, fmt.Sprintf("/webhooks/%d.json", id)), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(XAccessToken, sess.AccessToken)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		log.Error(string(bs))
		return fmt.Errorf("status: %d, err: %s", resp.StatusCode, string(bs))
	}
	return nil
}

func (a *App) VerifyWebhook(c *gin.Context) {
	hash := hmac.New(sha256.New, []byte(a.ClientSecret))
	bs, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Error(c.AbortWithError(http.StatusInternalServerError, err))
		return
	}
	if _, err = hash.Write(bs); err != nil {
		log.Error(c.AbortWithError(http.StatusUnauthorized, err))
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(bs))
	mac := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	if !hmac.Equal([]byte(mac), []byte(c.GetHeader(XHmacHeader))) {
		log.Error(c.AbortWithError(http.StatusUnauthorized, errors.New("invalid webhook header")))
		return
	}
}
