// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-authzen/v1"
	"github.com/hstern/go-authzen/v1/client"
)

// jsonMetadataHandler is a per-test fixture that serves a metadata
// document; tests vary the returned body and headers per scenario.
func jsonMetadataHandler(t *testing.T, body string, headers map[string]string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != authzen.MetadataPath {
			t.Errorf("path = %q, want %q", r.URL.Path, authzen.MetadataPath)
		}
		w.Header().Set("Content-Type", "application/json")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	})
}

func TestFetchMetadata_Success(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = nil // will be set below
	srv.Start()
	t.Cleanup(srv.Close)

	doc := authzen.Metadata{
		PolicyDecisionPoint:      srv.URL,
		AccessEvaluationEndpoint: srv.URL + authzen.EvaluationEndpoint,
	}
	body, _ := json.Marshal(doc)
	srv.Config.Handler = jsonMetadataHandler(t, string(body), nil)

	c, _ := client.NewClient(srv.URL)
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if m.PolicyDecisionPoint != srv.URL {
		t.Errorf("PolicyDecisionPoint = %q, want %q", m.PolicyDecisionPoint, srv.URL)
	}
}

func TestFetchMetadata_MixUpRejected(t *testing.T) {
	// Server returns a document whose policy_decision_point points at
	// a DIFFERENT PDP. The library must reject with *MixUpError and
	// must NOT populate the cache (so a subsequent legit fetch can
	// succeed against an evicted cache).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"policy_decision_point":"https://attacker.example.com"}`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	_, err := c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("nil error on mix-up; want *MixUpError")
	}
	var me *client.MixUpError
	if !errors.As(err, &me) {
		t.Fatalf("error is not *MixUpError: %v", err)
	}
	if me.DocumentPDP != "https://attacker.example.com" {
		t.Errorf("DocumentPDP = %q, want %q", me.DocumentPDP, "https://attacker.example.com")
	}
}

func TestFetchMetadata_RelaxedAcceptsMixUp(t *testing.T) {
	// With WithRelaxedMetadataValidation, the mix-up check is
	// bypassed. Required for tests that stand up a metadata fixture
	// with a fixed PDP URL different from the test server's URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"policy_decision_point":"https://other.example.com","access_evaluation_endpoint":"/x"}`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL, client.WithRelaxedMetadataValidation())
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata with relaxed validation: %v", err)
	}
	if m.PolicyDecisionPoint != "https://other.example.com" {
		t.Errorf("PolicyDecisionPoint = %q, want %q", m.PolicyDecisionPoint, "https://other.example.com")
	}
}

func TestFetchMetadata_CacheHit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)

	doc, _ := json.Marshal(authzen.Metadata{
		PolicyDecisionPoint: srv.URL,
	})
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	})

	c, _ := client.NewClient(srv.URL)
	// Three successive calls — only one should hit the network.
	for i := 0; i < 3; i++ {
		if _, err := c.FetchMetadata(context.Background()); err != nil {
			t.Fatalf("FetchMetadata %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (cache should serve calls 2 and 3)", got)
	}
}

func TestFetchMetadata_HonorsMaxAge(t *testing.T) {
	// Cache-Control: max-age=1 means the cache expires in 1 second.
	// After sleeping past that, the second FetchMetadata should hit
	// the network again.
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	doc, _ := json.Marshal(authzen.Metadata{PolicyDecisionPoint: srv.URL})
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "max-age=1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	})
	c, _ := client.NewClient(srv.URL)
	if _, err := c.FetchMetadata(context.Background()); err != nil {
		t.Fatalf("first FetchMetadata: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := c.FetchMetadata(context.Background()); err != nil {
		t.Fatalf("second FetchMetadata: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2 (max-age expired between calls)", got)
	}
}

func TestFetchMetadata_DefaultTTLWhenNoCacheControl(t *testing.T) {
	// With WithMetadataTTL(10ms) and no Cache-Control on the response,
	// the cache expires after the configured default.
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	doc, _ := json.Marshal(authzen.Metadata{PolicyDecisionPoint: srv.URL})
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// no Cache-Control intentionally
		_, _ = w.Write(doc)
	})
	c, _ := client.NewClient(srv.URL, client.WithMetadataTTL(10*time.Millisecond))
	if _, err := c.FetchMetadata(context.Background()); err != nil {
		t.Fatalf("first FetchMetadata: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := c.FetchMetadata(context.Background()); err != nil {
		t.Fatalf("second FetchMetadata: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2 (custom TTL expired)", got)
	}
}

func TestFetchMetadata_Non2xxReturnsStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "boom")
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	_, err := c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("nil error on 500")
	}
	var se *client.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not *StatusError: %v", err)
	}
	if se.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", se.StatusCode)
	}
}

func TestFetchMetadata_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{not json`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	_, err := c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("nil error on malformed body")
	}
}

func TestFetchMetadata_MixUpDoesNotPoisonCache(t *testing.T) {
	// First fetch is a mix-up (rejected, cache empty). Switch the
	// server to return a legitimate document; second fetch should
	// succeed against the empty cache and populate it. This proves
	// the rejection path skips cache-store.
	var resp atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := resp.Load()
		_, _ = io.WriteString(w, *body)
	}))
	t.Cleanup(srv.Close)
	// 1) Bad mix-up response.
	badBody := `{"policy_decision_point":"https://attacker.example.com"}`
	resp.Store(&badBody)
	c, _ := client.NewClient(srv.URL)
	if _, err := c.FetchMetadata(context.Background()); err == nil {
		t.Fatal("expected *MixUpError on first fetch")
	}
	// 2) Legit response.
	goodBody := `{"policy_decision_point":"` + srv.URL + `","access_evaluation_endpoint":"` + srv.URL + `/access/v1/evaluation"}`
	resp.Store(&goodBody)
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("second fetch failed (cache poisoned by mix-up?): %v", err)
	}
	if m.PolicyDecisionPoint != srv.URL {
		t.Errorf("PolicyDecisionPoint = %q, want %q", m.PolicyDecisionPoint, srv.URL)
	}
}

func TestFetchMetadata_SignedMetadataPassThrough(t *testing.T) {
	// signed_metadata bytes round-trip verbatim — v0.1 does NOT
	// verify but exposes the field as opaque RawMessage. A
	// consumer that wants verify plugs their own JOSE library on
	// .SignedMetadata.
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	doc := authzen.Metadata{
		PolicyDecisionPoint: srv.URL,
		SignedMetadata:      json.RawMessage(`"eyJhbGciOiJIUzI1NiJ9.signed.bytes"`),
	}
	body, _ := json.Marshal(doc)
	srv.Config.Handler = jsonMetadataHandler(t, string(body), nil)

	c, _ := client.NewClient(srv.URL)
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if string(m.SignedMetadata) != `"eyJhbGciOiJIUzI1NiJ9.signed.bytes"` {
		t.Errorf("SignedMetadata = %s, want round-trip preserved", string(m.SignedMetadata))
	}
}
