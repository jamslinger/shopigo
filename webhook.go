package shopigo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
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

type WebhookResponse struct {
	Webhook WebhookID `json:"webhook"`
}

type WebhookID struct {
	ID int `json:"id"`
}

type Webhook struct {
	ID      int      `json:"id"`
	Topic   string   `json:"topic"`
	Address string   `json:"address"`
	Fields  []string `json:"fields,omitempty"`
	Format  string   `json:"format,omitempty"`
}

type WebhooksResponse struct {
	Webhooks []*Webhook `json:"webhooks"`
}

func (c *client) GetWebhooks(ctx context.Context) ([]*Webhook, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint("/webhooks.json"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(XAccessToken, c.sess.AccessToken)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to retrieve webhooks, status: %d, cause: %s", resp.StatusCode, string(bs))
	}
	var whs WebhooksResponse
	if err = json.NewDecoder(resp.Body).Decode(&whs); err != nil {
		return nil, err
	}
	return whs.Webhooks, nil
}

func (c *client) RegisterWebhook(ctx context.Context, wh *Webhook) (id int, err error) {
	whs, err := c.GetWebhooks(ctx)
	if err != nil {
		return 0, err
	}
	for i := range whs {
		if whs[i].Topic == wh.Topic {
			id = whs[i].ID
		}
	}
	wh.Address, err = url.JoinPath(c.config.hostURL, wh.Address)
	if err != nil {
		return 0, err
	}
	body, err := json.Marshal(WebhookRequest{Webhook: wh})
	if err != nil {
		return 0, err
	}
	var req *http.Request
	if id == 0 {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint("/webhooks.json"), bytes.NewBuffer(body))
		if err != nil {
			return 0, err
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPut, c.Endpoint(fmt.Sprintf("/webhooks/%d.json", id)), bytes.NewBuffer(body))
		if err != nil {
			return 0, err
		}
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(XAccessToken, c.sess.AccessToken)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("failed to register webhook, status: %d, cause: %s", resp.StatusCode, string(bs))
	}
	var whResp WebhookResponse
	if err = json.NewDecoder(resp.Body).Decode(&whResp); err != nil {
		return 0, err
	}
	return whResp.Webhook.ID, nil
}

func (c *client) DeleteWebhook(ctx context.Context, id int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Endpoint(fmt.Sprintf("/webhooks/%d.json", id)), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(XAccessToken, c.sess.AccessToken)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status: %d, err: %s", resp.StatusCode, string(bs))
	}
	return nil
}

func (a *App) VerifyWebhook(c *gin.Context) {
	hash := hmac.New(sha256.New, []byte(a.Credentials.ClientSecret))
	bs, err := io.ReadAll(c.Request.Body)
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if _, err = hash.Write(bs); err != nil {
		_ = c.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(bs))
	mac := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	if !hmac.Equal([]byte(mac), []byte(c.GetHeader(XHmacHeader))) {
		_ = c.AbortWithError(http.StatusUnauthorized, errors.New("invalid webhook header"))
		return
	}
}
