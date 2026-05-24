// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

// Package client implements the PEP side of the OpenID AuthZEN
// Authorization API 1.0 wire — an HTTP client that calls a PDP and
// returns the decoded responses.
//
// Construct a [Client] with [NewClient], then call the per-endpoint
// methods ([Client.Evaluate], [Client.Evaluations], the three Search
// variants). The default transport is [http.DefaultClient]; swap it
// with [WithHTTPClient] for retry, auth, instrumentation, or test
// scenarios.
//
// The contract DESIGN.md §wire-fidelity calls out: a policy-deny
// outcome — {"decision": false} — is HTTP 200, NOT a 4xx. The client
// returns the response unchanged with a nil error; consumers MUST
// NOT treat decision: false as a transport failure.
package client

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// HTTPDoer is the interface the client requires of its underlying
// transport — a single Do method matching the shape of
// [http.Client.Do]. Consumers can plug retry, auth-injecting, and
// instrumented transports by wrapping an [http.Client] (or any other
// HTTPDoer) and passing the wrapper via [WithHTTPClient]. This is the
// same shape [golang.org/x/oauth2] uses.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is a PEP-side handle to a PDP. Build one with [NewClient].
// The zero value is not usable; use the constructor.
//
// A Client is safe for concurrent use by multiple goroutines — every
// per-endpoint method builds its own request, so there is no shared
// mutable state after construction.
type Client struct {
	baseURL *url.URL
	doer    HTTPDoer
}

// Option customizes a [Client] at construction. Pass options to
// [NewClient]. All options are independent and order-insensitive.
type Option func(*Client)

// NewClient returns a Client that targets the PDP at baseURL. baseURL
// must be an absolute URL with a scheme and host (a relative path
// or an empty string is rejected). The library does not enforce
// HTTPS here so http://127.0.0.1:NNN URLs work in tests; production
// PEPs SHOULD pass an https:// URL per spec §11.
//
// The default transport is [http.DefaultClient]. Override with
// [WithHTTPClient].
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("authzen client: parse baseURL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("authzen client: baseURL must be an absolute URL with scheme and host")
	}
	c := &Client{
		baseURL: u,
		doer:    http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// WithHTTPClient swaps the [Client]'s underlying transport. d may be
// any value implementing [HTTPDoer] — an [http.Client] with a tuned
// Timeout, a retry-wrapping Doer, an auth-injecting Doer, an OTel-
// instrumented client, or a test fixture.
//
// Passing nil resets to the default ([http.DefaultClient]).
func WithHTTPClient(d HTTPDoer) Option {
	return func(c *Client) {
		if d == nil {
			c.doer = http.DefaultClient
			return
		}
		c.doer = d
	}
}
