// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/client"
)

func TestWithBearerToken_AddsHeader(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"decision":true}`)
	}))
	t.Cleanup(srv.Close)

	doer := client.WithBearerToken(http.DefaultClient, "secret-token-123")
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	if _, err := c.Evaluate(context.Background(), validEvalRequest()); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := "Bearer secret-token-123"
	if seenAuth != want {
		t.Errorf("Authorization = %q, want %q", seenAuth, want)
	}
}

func TestWithBearerToken_EmptyTokenIsNoop(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"decision":true}`)
	}))
	t.Cleanup(srv.Close)

	doer := client.WithBearerToken(http.DefaultClient, "")
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	if _, err := c.Evaluate(context.Background(), validEvalRequest()); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if seenAuth != "" {
		t.Errorf("Authorization = %q, want empty (no-op on empty token)", seenAuth)
	}
}

func TestWithRetry_RetriesOn503ThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "try again")
			return
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"decision":true}`)
	}))
	t.Cleanup(srv.Close)

	doer := client.WithRetry(http.DefaultClient,
		client.WithMaxAttempts(5),
		client.WithBackoff(time.Millisecond, 10*time.Millisecond),
	)
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	resp, err := c.Evaluate(context.Background(), validEvalRequest())
	if err != nil {
		t.Fatalf("Evaluate after retries: %v", err)
	}
	if !resp.Decision {
		t.Errorf("Decision = false, want true")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("server calls = %d, want 3 (2 failures + 1 success)", got)
	}
}

func TestWithRetry_DoesNotRetry500(t *testing.T) {
	// 500 is PDP processing failure per spec §10.1.2 — NOT transient.
	// WithRetry must NOT retry it; a single attempt then surface as
	// *StatusError.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "real error")
	}))
	t.Cleanup(srv.Close)

	doer := client.WithRetry(http.DefaultClient,
		client.WithMaxAttempts(5),
		client.WithBackoff(time.Millisecond, 10*time.Millisecond),
	)
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	_, err := c.Evaluate(context.Background(), validEvalRequest())
	if err == nil {
		t.Fatal("Evaluate on 500 returned nil error")
	}
	var se *client.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not *StatusError: %v", err)
	}
	if se.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", se.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("server calls = %d, want 1 (500 must not retry)", got)
	}
}

func TestWithRetry_GivesUpAfterMaxAttempts(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "still down")
	}))
	t.Cleanup(srv.Close)

	doer := client.WithRetry(http.DefaultClient,
		client.WithMaxAttempts(3),
		client.WithBackoff(time.Millisecond, 5*time.Millisecond),
	)
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	_, err := c.Evaluate(context.Background(), validEvalRequest())
	if err == nil {
		t.Fatal("Evaluate on persistent 502 returned nil error")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("server calls = %d, want 3 (max attempts)", got)
	}
}

func TestWithRetry_HonorsContextCancellation(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	// Long backoff so the cancellation reliably lands during the wait
	// rather than between attempts at-speed.
	doer := client.WithRetry(http.DefaultClient,
		client.WithMaxAttempts(10),
		client.WithBackoff(500*time.Millisecond, 2*time.Second),
	)
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	_, _ = c.Evaluate(ctx, validEvalRequest())
	// Whatever error came out, the loop must have stopped early — 10
	// attempts with 500ms backoffs would take seconds.
	if got := atomic.LoadInt32(&calls); got >= 5 {
		t.Errorf("server calls = %d, want context cancellation to short-circuit early", got)
	}
}

func TestWithRetry_NilInnerDefaultsToHTTPClient(t *testing.T) {
	// Smoke test: WithRetry(nil, ...) doesn't panic and uses
	// http.DefaultClient as fallback. We can't easily prove it's the
	// default, but at minimum the constructor must succeed.
	d := client.WithRetry(nil, client.WithMaxAttempts(1))
	if d == nil {
		t.Fatal("WithRetry(nil) returned nil")
	}
}

func TestWithRetry_PropagatesValidationError(t *testing.T) {
	// Validation runs BEFORE the Doer is invoked; even with retry
	// wrapping in place, an invalid request must short-circuit before
	// any network call. Combined with the empty server, this catches
	// any future regression that moves Validate after the Do call.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	doer := client.WithRetry(http.DefaultClient, client.WithMaxAttempts(5))
	c, _ := client.NewClient(srv.URL, client.WithHTTPClient(doer))
	_, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{})
	if err == nil {
		t.Fatal("nil error on invalid request")
	}
	if !strings.Contains(err.Error(), "subject.type") {
		t.Errorf("err = %v, want it to mention subject.type", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("server calls = %d, want 0 (validation precedes network)", got)
	}
}
