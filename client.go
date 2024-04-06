package shopigo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hasura/go-graphql-client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
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

func (c *ClientConfig) Endpoint(shop string, endpoint string) string {
	protocol := "https"
	if c.insecure {
		protocol = "http"
	}
	return fmt.Sprintf("%s://%s/%s", protocol, shop, path.Join("admin/api", c.v.String(), endpoint))
}

type ClientProvider struct {
	*ClientConfig
	http *http.Client
}

func NewShopifyClientProvider(c ClientConfig) *ClientProvider {
	return &ClientProvider{ClientConfig: &c, http: &http.Client{}}
}

type Client interface {
	Do(req *http.Request) (*http.Response, error)
	Get(ctx context.Context, endpoint string, out any) (int, error)
	Create(ctx context.Context, endpoint string, in any, out any) (int, error)
	Update(ctx context.Context, endpoint string, in any, out any) (int, error)

	WebhookClient
}

type WebhookClient interface {
	GetWebhooks(ctx context.Context) ([]*Webhook, error)
	RegisterWebhook(ctx context.Context, wh *Webhook) (id int, err error)
	DeleteWebhook(ctx context.Context, id int) error
}

type GraphQLClient interface {
	Mutate(ctx context.Context, name string, v any, variables map[string]any) error
	Query(ctx context.Context, name string, v any, variables map[string]any) error
}

func (p *ClientProvider) Client(sess *Session, limiter *rate.Limiter) Client {
	if sess == nil {
		panic("must provide client session")
	}
	return &client{config: p.ClientConfig, http: p.http, sess: sess, limiter: limiter}
}

func (p *ClientProvider) GraphQLClient(sess *Session, limiter *rate.Limiter) GraphQLClient {
	if sess == nil {
		panic("must provide client session")
	}
	return &graphQLClient{
		config: p.ClientConfig,
		gql: graphql.NewClient(p.ClientConfig.Endpoint(sess.Shop, "graphql.json"), p.http).
			WithRequestModifier(func(r *http.Request) {
				r.Header.Add("X-Shopify-Access-Token", sess.AccessToken)
			}),
		sess:    sess,
		limiter: limiter}
}

type graphQLClient struct {
	config  *ClientConfig
	gql     *graphql.Client
	sess    *Session
	limiter *rate.Limiter
}

type gqlType int

const (
	gqlQuery gqlType = iota
	gqlMutation
)

func (c *graphQLClient) Query(ctx context.Context, name string, v any, variables map[string]any) error {
	return c.do(ctx, gqlQuery, name, v, variables)
}

func (c *graphQLClient) Mutate(ctx context.Context, name string, v any, variables map[string]any) error {
	return c.do(ctx, gqlMutation, name, v, variables)
}

func (c *graphQLClient) do(ctx context.Context, typ gqlType, name string, v any, variables map[string]any) error {
	labels := []string{c.sess.Shop, "graphql/" + name}
	backoff := time.Second
	attempt := 0
retry:
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
	}
	attempt++
	now := time.Now()

	var bs []byte
	var err error
	switch typ {
	case gqlQuery:
		err = c.gql.Query(ctx, &v, variables)
	case gqlMutation:
		err = c.gql.Mutate(ctx, &v, variables)
	default:
		panic("unsupported graphql type")
	}

	// measure response size and times.
	responseSize.WithLabelValues(labels...).Observe(float64(len(bs)))
	responseTime.WithLabelValues(append(labels, "200")...).Observe(time.Since(now).Seconds())

	if err != nil {
		var errs graphql.Errors
		if errors.As(err, &errs) {
			for _, e := range errs {
				if e.Message == "Throttled" {
					SleepContext(ctx, backoff)
					if backoff < 8*time.Second {
						backoff *= 2
					}
					if attempt < c.config.retries {
						goto retry
					}
				}
			}
		}
		return err
	}
	return nil
}

type client struct {
	config  *ClientConfig
	http    *http.Client
	sess    *Session
	limiter *rate.Limiter
}

func (c *client) Do(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(c.config.clientID, c.sess.AccessToken)
	if req.Body != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	labels := []string{c.sess.Shop, req.URL.Path}
	backoff := time.Second
	attempt := 0
retry:
	now := time.Now()
	attempt++
	if c.limiter != nil {
		if err := c.limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var e *url.Error
		if errors.As(err, &e) && e.Timeout() {
			responseTimeout.WithLabelValues(labels...).Inc()
			if attempt > c.config.retries {
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
		if attempt < c.config.retries {
			goto retry
		}
	}
	return resp, nil
}

func (c *client) Get(ctx context.Context, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.Endpoint(c.sess.Shop, endpoint), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := c.Do(req)
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

func (c *client) Create(ctx context.Context, endpoint string, in any, out any) (int, error) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return 0, fmt.Errorf("failed to encode request object: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Endpoint(c.sess.Shop, endpoint), &body)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.Do(req)
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

func (c *client) Update(ctx context.Context, endpoint string, in any, out any) (int, error) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return 0, fmt.Errorf("failed to encode request object: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.config.Endpoint(c.sess.Shop, endpoint), &body)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.Do(req)
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
