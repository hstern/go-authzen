// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hstern/go-authzen/v1"
)

// FetchMetadata fetches the PDP's configuration document from
// [authzen.MetadataPath] under the Client's baseURL (spec §9.1),
// validates it, and returns the parsed [authzen.Metadata].
//
// Validation enforces spec §9.1.1 mix-up protection: by default
// the returned PolicyDecisionPoint MUST equal the Client's
// configured baseURL (modulo trailing slashes). A mismatch returns
// a typed [*MixUpError] without populating the cache — a mix-up
// attack must not poison subsequent reads.
//
// Mix-up validation is hard-fail by default per DESIGN.md §metadata.2:
// the consequences of a mix-up are an authorization bypass, so
// the library defaults to refusing rather than logging-and-proceeding.
// Opt out (explicitly, deliberately) via
// [WithRelaxedMetadataValidation] — the option name is ugly on
// purpose.
//
// FetchMetadata caches the parsed document per Client. Subsequent
// calls return the cached pointer without going to the network
// until expiry. The cache TTL is derived from the response's
// HTTP Cache-Control: max-age=N directive; when absent, the
// Client's default TTL (1 hour, settable via [WithMetadataTTL])
// is used. The cached pointer is shared across callers — consumers
// MUST NOT mutate the returned [authzen.Metadata].
//
// signed_metadata (spec §9.1, RFC 7515 JWS) is exposed verbatim
// on [authzen.Metadata.SignedMetadata] as opaque [json.RawMessage].
// v0.1 does NOT verify the JWS; a consumer that wants verification
// plugs its own JOSE library on the bytes. Mix-up validation in
// v0.1 checks only the plain-text PolicyDecisionPoint field; v0.2
// will add signed-metadata-aware validation.
func (c *Client) FetchMetadata(ctx context.Context) (*authzen.Metadata, error) {
	// Cache-snapshot under lock; release before going to network.
	c.metaMu.Lock()
	cached := c.metaCache
	c.metaMu.Unlock()
	if cached != nil && time.Now().Before(cached.expires) {
		return cached.doc, nil
	}

	doc, ttl, err := c.fetchMetadataRaw(ctx)
	if err != nil {
		return nil, err
	}

	c.metaMu.Lock()
	c.metaCache = &cachedMetadata{doc: doc, expires: time.Now().Add(ttl)}
	c.metaMu.Unlock()
	return doc, nil
}

// fetchMetadataRaw does the actual GET, validates mix-up, and
// computes the cache TTL from the response. Returned independently
// of the cache so concurrent callers can each fetch without
// holding the cache mutex across IO.
func (c *Client) fetchMetadataRaw(ctx context.Context) (*authzen.Metadata, time.Duration, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpointURL(authzen.MetadataPath), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("authzen client: build metadata request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpResp, err := c.doer.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("authzen client: fetch metadata: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("authzen client: read metadata body: %w", err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, 0, &StatusError{StatusCode: httpResp.StatusCode, Body: body}
	}
	var doc authzen.Metadata
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("authzen client: decode metadata (HTTP %d): %w", httpResp.StatusCode, err)
	}
	if !c.metaRelaxedMixUp {
		expected := strings.TrimRight(c.baseURL.String(), "/")
		got := strings.TrimRight(doc.PolicyDecisionPoint, "/")
		if expected != got {
			return nil, 0, &MixUpError{ExpectedPDP: expected, DocumentPDP: doc.PolicyDecisionPoint}
		}
	}
	ttl := parseMaxAge(httpResp.Header.Get("Cache-Control"))
	if ttl == 0 {
		ttl = c.metaDefaultTTL
	}
	return &doc, ttl, nil
}

// MixUpError is the typed error [Client.FetchMetadata] returns
// when the metadata document's policy_decision_point claim does
// not equal the Client's configured baseURL (spec §9.1.1
// mix-up protection). Match with [errors.As]:
//
//	var me *client.MixUpError
//	if errors.As(err, &me) { /* me.ExpectedPDP, me.DocumentPDP */ }
type MixUpError struct {
	// ExpectedPDP is the Client's configured base URL, trimmed of
	// trailing slashes — what the policy_decision_point claim
	// should have been.
	ExpectedPDP string

	// DocumentPDP is the policy_decision_point value the PDP
	// actually returned, verbatim.
	DocumentPDP string
}

func (e *MixUpError) Error() string {
	return fmt.Sprintf(
		"authzen client: metadata document mix-up — configured PDP %q does not equal policy_decision_point %q",
		e.ExpectedPDP, e.DocumentPDP,
	)
}

// WithMetadataTTL sets the default cache TTL used by
// [Client.FetchMetadata] when the PDP's response carries no
// Cache-Control max-age directive. The default is one hour; pass
// any positive duration to override. A non-positive value falls
// back to the one-hour default.
//
// Cache-Control max-age, when present on the response, always
// wins over this default.
func WithMetadataTTL(d time.Duration) Option {
	return func(c *Client) {
		if d <= 0 {
			return
		}
		c.metaDefaultTTL = d
	}
}

// WithRelaxedMetadataValidation disables the mix-up check
// [Client.FetchMetadata] performs by default. The option name is
// deliberately ugly: the consequences of a mix-up are an
// authorization bypass, so the library wants relaxing this to be
// a visible, deliberate choice — typically only for tests that
// stand up a metadata document with a fixed
// policy_decision_point or for redirect topologies the consumer
// has already verified out-of-band.
//
// Once set on a Client it stays set; rebuild the Client to
// re-enable strict validation.
func WithRelaxedMetadataValidation() Option {
	return func(c *Client) {
		c.metaRelaxedMixUp = true
	}
}

// parseMaxAge extracts the max-age directive from a
// Cache-Control header. Returns (duration, true) on a positive
// max-age, (0, false) otherwise. Other Cache-Control directives
// (no-cache, no-store, must-revalidate) are not honored in v0.1 —
// the spec is silent on which directives to respect, and v0.1
// keeps the surface minimal.
func parseMaxAge(header string) time.Duration {
	if header == "" {
		return 0
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "max-age=") {
			continue
		}
		secStr := strings.TrimPrefix(part, "max-age=")
		sec, err := strconv.Atoi(secStr)
		if err != nil || sec <= 0 {
			return 0
		}
		return time.Duration(sec) * time.Second
	}
	return 0
}
