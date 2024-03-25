package shopigo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

type Version string

func (v Version) String() string {
	return string(v)
}

const (
	VLatest Version = V202401
	V202401 Version = "2024-01"
	V202310 Version = "2023-10"
	V202307 Version = "2023-07"
	V202304 Version = "2023-04"
)

type ClientConfig struct {
	v           Version
	clientID    string
	hostURL     string
	insecure    bool
	retries     int
	defaultShop *Shop
}

type Client struct {
	*ClientConfig
	http *http.Client
}

func NewShopifyClient(c *ClientConfig) *Client {
	return &Client{ClientConfig: c, http: &http.Client{}}
}

func (c *Client) ShopURL(shop string, endpoint string) string {
	protocol := "https"
	if c.insecure {
		protocol = "http"
	}
	return fmt.Sprintf("%s://%s/%s", protocol, shop, path.Join("admin/api", c.v.String(), endpoint))
}

func (c *Client) For(session *Session) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		req.SetBasicAuth(c.clientID, session.AccessToken)
		return c.Do(req)
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	labels := []string{req.Host, req.URL.Path}
	backoff := time.Second
	attempt := 0
retry:
	now := time.Now()
	attempt++
	resp, err := c.http.Do(req)
	if err != nil {
		var e *url.Error
		if errors.As(err, &e) && e.Timeout() {
			responseTimeout.WithLabelValues(labels...).Inc()
			if attempt > c.retries {
				return nil, fmt.Errorf("client.Do(%v): %w", req.URL, err)
			}
			goto retry
		}
		return nil, fmt.Errorf("client.Do(%v): %w", req.URL, err)
	}

	// measure response size and times.
	responseSize.WithLabelValues(labels...).Observe(float64(resp.ContentLength))
	responseTime.WithLabelValues(append(labels, strconv.Itoa(resp.StatusCode))...).Observe(time.Since(now).Seconds())

	if resp.StatusCode == http.StatusTooManyRequests {
		SleepContext(req.Context(), backoff)
		if backoff < 8*time.Second {
			backoff *= 2
		}
		if attempt < c.retries {
			goto retry
		}
	}
	return resp, nil
}

func (c *Client) Get(ctx context.Context, sess *Session, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ShopURL(sess.Shop, endpoint), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := c.For(sess)(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("request failed, status: %d, detail: %s", resp.StatusCode, string(bs))
	}
	if out != nil {
		if err = json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func (c *Client) Create(ctx context.Context, sess *Session, endpoint string, in any, out any) (int, error) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return 0, fmt.Errorf("failed to encode request object: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ShopURL(sess.Shop, endpoint), &body)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.For(sess)(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("request failed, status: %d, detail: %s", resp.StatusCode, string(bs))
	}
	if out != nil {
		if err = json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func (c *Client) Update(ctx context.Context, sess *Session, endpoint string, in any, out any) (int, error) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return 0, fmt.Errorf("failed to encode request object: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.ShopURL(sess.Shop, endpoint), &body)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.For(sess)(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		bs, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("request failed, status: %d, detail: %s", resp.StatusCode, string(bs))
	}
	if out != nil {
		if err = json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

type PageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
	Total       int    `json:"total"`
}

type PaginationResponse[T any] struct {
	Data     []T      `json:"data"`
	PageInfo PageInfo `json:"pageInfo"`
}

type Error struct {
	Error string `json:"errors"`
}

type MultiError struct {
	Errors []string `json:"errors"`
}

var (
	responseTimeout = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_response_timeout_total",
		Help: "Number of response timeouts",
	}, []string{"shop", "endpoint"})

	responseTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "http_response_time_seconds",
		Help: "Histogram of response times for HTTP requests",
	}, []string{"shop", "endpoint", "status"})

	responseSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_size_bytes",
		Help:    "Histogram of response sizes for HTTP requests",
		Buckets: []float64{10 << 10, 20 << 10, 30 << 10, 40 << 10, 50 << 10, 75 << 10, 100 << 10, 250 << 10, 500 << 10, 1 << 20, 5 << 20},
	}, []string{"shop", "endpoint"})
)
