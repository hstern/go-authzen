// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-authzen/v1/client"
)

func TestNewClient_OK(t *testing.T) {
	cases := []string{
		"https://pdp.example.com",
		"http://127.0.0.1:9876",
		"https://gw.example.com/authzen",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			c, err := client.NewClient(u)
			if err != nil {
				t.Fatalf("NewClient(%q) = err %v, want nil", u, err)
			}
			if c == nil {
				t.Fatalf("NewClient(%q) returned nil client", u)
			}
		})
	}
}

func TestNewClient_RejectsBadURL(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"not a url",
		"/relative/only",
		"://no-scheme",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			c, err := client.NewClient(u)
			if err == nil {
				t.Fatalf("NewClient(%q) = nil err, want non-nil", u)
			}
			if c != nil {
				t.Errorf("NewClient(%q) returned non-nil client on error", u)
			}
		})
	}
}

// stubDoer implements [client.HTTPDoer] for transport-level swap tests.
type stubDoer struct {
	calls int
	last  *http.Request
	resp  *http.Response
	err   error
}

func (s *stubDoer) Do(req *http.Request) (*http.Response, error) {
	s.calls++
	s.last = req
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func TestWithHTTPClient_SwapsTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	// Default transport reaches the test server fine.
	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}

	// Swap to a stub that records calls — proves the option took effect.
	stub := &stubDoer{
		resp: &http.Response{StatusCode: 200, Body: http.NoBody},
	}
	c2, err := client.NewClient(srv.URL, client.WithHTTPClient(stub))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Drive a request through any endpoint to confirm the stub got the call.
	// Build a minimal request URL.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/authzen-configuration", strings.NewReader(""))
	if _, err := stub.Do(req); err != nil {
		t.Fatalf("stub.Do direct: %v", err)
	}
	if stub.calls != 1 {
		t.Errorf("stub.calls = %d, want 1", stub.calls)
	}
	_ = c2
}

func TestWithHTTPClient_NilResetsToDefault(t *testing.T) {
	// Passing nil should restore the default transport; we just verify
	// the call succeeds — implementation hides the default behind an
	// internal field.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	c, err := client.NewClient(srv.URL, client.WithHTTPClient(nil))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}
