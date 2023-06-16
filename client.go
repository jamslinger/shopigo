package shopify

import (
	"fmt"
	"github.com/Khan/genqlient/graphql"
	"net/http"
	"net/url"
	"path"
	"time"
)

type Version string

func (v Version) String() string {
	return string(v)
}

const (
	V_2023_04 Version = "2023-04"
	V_Latest  Version = V_2023_04
)

type ClientConfig struct {
	v           Version
	clientID    string
	hostURL     string
	retries     int
	defaultShop *Shop
}

type Client struct {
	*ClientConfig
	http    *http.Client
	GraphQL graphql.Client
}

func NewShopifyClient(c *ClientConfig) (*Client, error) {
	cl := &Client{ClientConfig: c, http: &http.Client{}}
	if c.defaultShop != nil {
		gqlUrl, err := url.JoinPath(c.defaultShop.Address, "admin/api", c.v.String(), "graphql.json")
		if err != nil {
			return nil, err
		}
		cl.GraphQL = graphql.NewClient(gqlUrl, cl)
	}
	return cl, nil
}

func (c *Client) ShopURL(shop string, endpoint string) string {
	return fmt.Sprintf("https://%s/%s", shop, path.Join("admin/api", c.v.String(), endpoint))
}

func (c *Client) For(shop *Shop) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		req.SetBasicAuth(c.clientID, shop.Token)
		return c.Do(req)
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	backoff := time.Second
	attempt := 0
retry:
	attempt++
	resp, err := c.http.Do(req)
	if err != nil {
		if e, ok := err.(*url.Error); ok && e.Timeout() {
			if attempt > c.retries {
				return nil, fmt.Errorf("client.Do(%v): %w", req.URL, err)
			}
			goto retry
		}
		return nil, fmt.Errorf("client.Do(%v): %w", req.URL, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		SleepContext(req.Context(), backoff)
		if backoff < 8*time.Second {
			backoff *= 2
		}
		goto retry
	}
	return resp, nil
}
