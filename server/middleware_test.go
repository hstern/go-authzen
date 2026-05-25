// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/client"
	"github.com/hstern/go-authzen/server"
)

func TestMiddleware_WithLogger_FiresOncePerRequest(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	var (
		mu     sync.Mutex
		events []server.LogEvent
	)
	url := newServer(t, d, server.WithLogger(func(e server.LogEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}))
	c, _ := client.NewClient(url)
	if _, err := c.Evaluate(context.Background(), validEvalReq()); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("got %d LogEvents, want 1", len(events))
	}
	e := events[0]
	if e.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", e.Method)
	}
	if e.Path != authzen.EvaluationEndpoint {
		t.Errorf("Path = %q, want %q", e.Path, authzen.EvaluationEndpoint)
	}
	if e.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", e.Status)
	}
	if e.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", e.Duration)
	}
}

func TestMiddleware_WithLogger_CapturesErrorStatus(t *testing.T) {
	// On a 501, the logger still fires and sees Status = 501.
	d := &staticDecider{evalErr: authzen.ErrNotImplemented}
	var captured atomic.Int32
	url := newServer(t, d, server.WithLogger(func(e server.LogEvent) {
		captured.Store(int32(e.Status))
	}))
	c, _ := client.NewClient(url)
	_, _ = c.Evaluate(context.Background(), validEvalReq())
	if got := captured.Load(); got != http.StatusNotImplemented {
		t.Errorf("captured Status = %d, want 501", got)
	}
}

func TestMiddleware_WithLogger_NilIsNoop(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	url := newServer(t, d, server.WithLogger(nil))
	c, _ := client.NewClient(url)
	if _, err := c.Evaluate(context.Background(), validEvalReq()); err != nil {
		t.Fatalf("Evaluate (nil logger should be safe): %v", err)
	}
}

func TestMiddleware_WithMetrics_FiresOncePerRequest(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	var calls atomic.Int32
	var lastStatus atomic.Int32
	url := newServer(t, d, server.WithMetrics(func(e server.MetricsEvent) {
		calls.Add(1)
		lastStatus.Store(int32(e.Status))
	}))
	c, _ := client.NewClient(url)
	for i := 0; i < 3; i++ {
		if _, err := c.Evaluate(context.Background(), validEvalReq()); err != nil {
			t.Fatalf("Evaluate %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("metrics calls = %d, want 3", got)
	}
	if got := lastStatus.Load(); got != 200 {
		t.Errorf("lastStatus = %d, want 200", got)
	}
}

func TestMiddleware_WithRequestIDEcho_PresentInResponse(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	srv := httptest.NewServer(server.NewHandler(d, server.WithRequestIDEcho()))
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"document","id":"doc-42"}}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+authzen.EvaluationEndpoint, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authzen.HTTPHeaderRequestID, "req-12345")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get(authzen.HTTPHeaderRequestID); got != "req-12345" {
		t.Errorf("X-Request-ID echo = %q, want req-12345", got)
	}
}

func TestMiddleware_WithRequestIDEcho_AbsentInAbsentOut(t *testing.T) {
	// No library-generated IDs — if the request didn't carry one,
	// the response MUST NOT carry one either.
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	srv := httptest.NewServer(server.NewHandler(d, server.WithRequestIDEcho()))
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"document","id":"doc-42"}}`)
	resp, err := http.Post(srv.URL+authzen.EvaluationEndpoint, "application/json", body)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get(authzen.HTTPHeaderRequestID); got != "" {
		t.Errorf("X-Request-ID = %q on absent inbound, want empty", got)
	}
}

func TestMiddleware_Composes_LoggerPlusEcho(t *testing.T) {
	// Both options together — logger fires and echo header is set.
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	var loggerHit atomic.Bool
	srv := httptest.NewServer(server.NewHandler(d,
		server.WithLogger(func(server.LogEvent) { loggerHit.Store(true) }),
		server.WithRequestIDEcho(),
	))
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"document","id":"doc-42"}}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+authzen.EvaluationEndpoint, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authzen.HTTPHeaderRequestID, "compose-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if !loggerHit.Load() {
		t.Error("logger did not fire when composed with echo")
	}
	if got := resp.Header.Get(authzen.HTTPHeaderRequestID); got != "compose-1" {
		t.Errorf("X-Request-ID = %q, want compose-1", got)
	}
}

func TestMiddleware_Ensure_ErrorsIsErrNotImplemented_StillMatches(t *testing.T) {
	// A defensive cross-check: middleware wrapping must not break the
	// downstream errors.Is(err, ErrNotImplemented) match — the 501
	// mapping depends on that. We exercise it by composing every
	// middleware option above an ErrNotImplemented-returning decider.
	d := &staticDecider{evalErr: authzen.ErrNotImplemented}
	url := newServer(t, d,
		server.WithLogger(func(server.LogEvent) {}),
		server.WithMetrics(func(server.MetricsEvent) {}),
		server.WithRequestIDEcho(),
	)
	c, _ := client.NewClient(url)
	_, err := c.Evaluate(context.Background(), validEvalReq())
	if err == nil {
		t.Fatal("nil error on ErrNotImplemented")
	}
	var se *client.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not *StatusError: %v", err)
	}
	if se.StatusCode != http.StatusNotImplemented {
		t.Errorf("StatusCode = %d, want 501 — middleware must not interfere with status mapping", se.StatusCode)
	}
}
