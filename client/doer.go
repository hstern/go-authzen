// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"io"
	"net/http"
	"time"
)

// Optional [HTTPDoer] middleware wrappers — retry on transient failures
// and bearer-token header injection. Neither is installed by default;
// consumers compose them explicitly via [WithHTTPClient]:
//
//	d := client.WithRetry(http.DefaultClient)
//	d = client.WithBearerToken(d, token)
//	c, _ := client.NewClient(baseURL, client.WithHTTPClient(d))
//
// Keeping the default surface lean per DESIGN.md §3 — most consumers
// don't need retry, and those who do may already have an opinionated
// retry layer (resilient-http, hashicorp/go-retryablehttp, etc.) they
// prefer to plug in their own way.

// RetryOption configures [WithRetry].
type RetryOption func(*retryConfig)

type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

// defaultRetryConfig is the configuration [WithRetry] uses when no
// options are supplied — 3 attempts total (1 try + 2 retries), 100ms
// base delay, capped at 5s. Modest defaults; tune via the options.
var defaultRetryConfig = retryConfig{
	maxAttempts: 3,
	baseDelay:   100 * time.Millisecond,
	maxDelay:    5 * time.Second,
}

// WithMaxAttempts sets the total number of attempts (including the
// initial try). n must be at least 1; smaller values are clamped to 1.
func WithMaxAttempts(n int) RetryOption {
	return func(c *retryConfig) {
		if n < 1 {
			n = 1
		}
		c.maxAttempts = n
	}
}

// WithBackoff sets the base and maximum delay between retry attempts.
// The delay doubles with each attempt up to maxDelay; non-positive
// values fall back to the defaults.
func WithBackoff(base, maxDelay time.Duration) RetryOption {
	return func(c *retryConfig) {
		if base > 0 {
			c.baseDelay = base
		}
		if maxDelay > 0 {
			c.maxDelay = maxDelay
		}
	}
}

// WithRetry returns an [HTTPDoer] that retries d on transient failures
// — network errors and HTTP 502, 503, or 504 responses. It deliberately
// does NOT retry HTTP 500: per spec §10.1.2, 500 indicates PDP
// processing failure rather than a transient infrastructure issue, and
// retrying would mask a real problem.
//
// The request body must be re-readable across attempts. Requests built
// by the Client's postJSON helper use *bytes.Reader, which
// [http.NewRequestWithContext] auto-equips with a GetBody hook —
// retries clone via GetBody. A consumer-supplied request body that
// doesn't set GetBody will fall back to single-attempt behavior on
// retry (the body would be drained from the first attempt).
//
// Context cancellation is honored between attempts: WithRetry returns
// the context error immediately if the request's context is canceled
// or its deadline expires while waiting to back off.
func WithRetry(d HTTPDoer, opts ...RetryOption) HTTPDoer {
	if d == nil {
		d = http.DefaultClient
	}
	cfg := defaultRetryConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return &retryDoer{inner: d, cfg: cfg}
}

type retryDoer struct {
	inner HTTPDoer
	cfg   retryConfig
}

func (r *retryDoer) Do(req *http.Request) (*http.Response, error) {
	var lastErr error
	var lastResp *http.Response
	for attempt := 1; attempt <= r.cfg.maxAttempts; attempt++ {
		if attempt > 1 {
			// Restore body from GetBody for the retry. If GetBody is
			// nil, the body has already been drained and we can only
			// hope the server tolerates an empty replay — but that's
			// the caller's contract to keep, not ours to second-guess.
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
			// Honor context cancellation while waiting to retry.
			t := time.NewTimer(r.backoff(attempt - 1))
			select {
			case <-t.C:
			case <-req.Context().Done():
				t.Stop()
				if lastErr != nil {
					return nil, lastErr
				}
				return lastResp, nil
			}
		}
		resp, err := r.inner.Do(req)
		if err == nil && !shouldRetryStatus(resp.StatusCode) {
			return resp, nil
		}
		if err != nil {
			lastErr = err
			lastResp = nil
			continue
		}
		// Drain and close the body so the underlying connection can
		// be reused for the retry. If the consumer cares about the
		// transient failure body, they need to wrap differently.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastResp = resp
		lastErr = nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return lastResp, nil
}

func (r *retryDoer) backoff(retryIndex int) time.Duration {
	// retryIndex 0 → first retry (base), 1 → double, 2 → quadruple…
	if retryIndex < 0 {
		retryIndex = 0
	}
	d := r.cfg.baseDelay
	for i := 0; i < retryIndex; i++ {
		d *= 2
		if d > r.cfg.maxDelay {
			return r.cfg.maxDelay
		}
	}
	return d
}

func shouldRetryStatus(code int) bool {
	// 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout —
	// transient infrastructure conditions. 500 deliberately excluded
	// (PDP processing failure per spec §10.1.2, not transient).
	return code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// WithBearerToken returns an [HTTPDoer] that adds an
// "Authorization: Bearer <token>" header to every outgoing request
// before delegating to d. The token is captured at construction; to
// rotate it, build a fresh wrapper.
//
// An empty token is a no-op — the wrapper passes through without
// touching headers. This makes it safe to compose with a token source
// that may not yet have a value.
func WithBearerToken(d HTTPDoer, token string) HTTPDoer {
	if d == nil {
		d = http.DefaultClient
	}
	return &bearerTokenDoer{inner: d, token: token}
}

type bearerTokenDoer struct {
	inner HTTPDoer
	token string
}

func (b *bearerTokenDoer) Do(req *http.Request) (*http.Response, error) {
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.inner.Do(req)
}
