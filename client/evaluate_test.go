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
	"strings"
	"testing"

	"github.com/hstern/go-authzen/v1"
	"github.com/hstern/go-authzen/v1/client"
)

// validEvalRequest returns a well-formed EvaluationRequest used by
// every Evaluate test that isn't specifically testing validation.
func validEvalRequest() *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	}
}

// validEvalsRequest returns a well-formed batch EvaluationsRequest.
func validEvalsRequest() *authzen.EvaluationsRequest {
	return &authzen.EvaluationsRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice"},
		Resource: &authzen.Resource{Type: "document", ID: "doc-42"},
		Evaluations: []authzen.EvaluationsItem{
			{Action: &authzen.Action{Name: "read"}},
			{Action: &authzen.Action{Name: "write"}},
		},
	}
}

// jsonResponse writes the given status + JSON body, asserting the
// request landed on the expected method and path.
func jsonResponse(t *testing.T, wantMethod, wantPath string, status int, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method = %q, want %q", r.Method, wantMethod)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestEvaluate_PermitRoundTrip(t *testing.T) {
	srv := httptest.NewServer(jsonResponse(t, http.MethodPost, authzen.EvaluationEndpoint, 200, `{"decision":true}`))
	t.Cleanup(srv.Close)

	c, _ := client.NewClient(srv.URL)
	resp, err := c.Evaluate(context.Background(), validEvalRequest())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !resp.Decision {
		t.Errorf("Decision = false, want true")
	}
}

func TestEvaluate_DenyIs200_NotError(t *testing.T) {
	// The wire-fidelity invariant: HTTP 200 with {"decision": false}
	// is a legal response. Evaluate MUST return the response with
	// Decision: false and nil error.
	srv := httptest.NewServer(jsonResponse(t, http.MethodPost, authzen.EvaluationEndpoint, 200, `{"decision":false}`))
	t.Cleanup(srv.Close)

	c, _ := client.NewClient(srv.URL)
	resp, err := c.Evaluate(context.Background(), validEvalRequest())
	if err != nil {
		t.Fatalf("Evaluate on deny returned error: %v (want nil)", err)
	}
	if resp == nil {
		t.Fatal("Evaluate on deny returned nil response (want non-nil)")
	}
	if resp.Decision {
		t.Errorf("Decision = true, want false")
	}
}

func TestEvaluate_Non2xxReturnsStatusError(t *testing.T) {
	cases := []int{400, 401, 403, 500, 501}
	for _, code := range cases {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
				_, _ = io.WriteString(w, "boom")
			}))
			t.Cleanup(srv.Close)
			c, _ := client.NewClient(srv.URL)
			_, err := c.Evaluate(context.Background(), validEvalRequest())
			if err == nil {
				t.Fatalf("Evaluate on HTTP %d returned nil error", code)
			}
			var se *client.StatusError
			if !errors.As(err, &se) {
				t.Fatalf("error is not *StatusError: %v", err)
			}
			if se.StatusCode != code {
				t.Errorf("StatusCode = %d, want %d", se.StatusCode, code)
			}
			if !strings.Contains(string(se.Body), "boom") {
				t.Errorf("Body = %q, want it to contain \"boom\"", string(se.Body))
			}
		})
	}
}

func TestEvaluate_MalformedResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{not json`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	_, err := c.Evaluate(context.Background(), validEvalRequest())
	if err == nil {
		t.Fatal("Evaluate on malformed JSON returned nil error")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("err = %v, want it to mention decoding", err)
	}
}

func TestEvaluate_ValidationFailsBeforeNetwork(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called++
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	bad := &authzen.EvaluationRequest{} // missing Subject.Type, Action.Name, Resource.Type
	_, err := c.Evaluate(context.Background(), bad)
	if err == nil {
		t.Fatal("Evaluate on invalid request returned nil error")
	}
	var ve *authzen.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is not *authzen.ValidationError: %v", err)
	}
	if called != 0 {
		t.Errorf("server was called %d times, want 0 (validation must fail before network)", called)
	}
}

func TestEvaluate_RequestBodyShape(t *testing.T) {
	var got authzen.EvaluationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("server decode: %v", err)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"decision":true}`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	want := validEvalRequest()
	if _, err := c.Evaluate(context.Background(), want); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Subject.ID != want.Subject.ID || got.Action.Name != want.Action.Name || got.Resource.ID != want.Resource.ID {
		t.Errorf("server saw %+v, want %+v", got, *want)
	}
}

func TestEvaluations_BatchRoundTrip(t *testing.T) {
	srv := httptest.NewServer(jsonResponse(t, http.MethodPost, authzen.EvaluationsEndpoint, 200,
		`{"evaluations":[{"decision":true},{"decision":false}]}`))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	resp, err := c.Evaluations(context.Background(), validEvalsRequest())
	if err != nil {
		t.Fatalf("Evaluations: %v", err)
	}
	if len(resp.Evaluations) != 2 {
		t.Fatalf("got %d items, want 2", len(resp.Evaluations))
	}
	if !resp.Evaluations[0].Decision || resp.Evaluations[1].Decision {
		t.Errorf("decisions = [%v, %v], want [true, false]", resp.Evaluations[0].Decision, resp.Evaluations[1].Decision)
	}
}

func TestEvaluations_DenyEntriesAreNotErrors(t *testing.T) {
	// Per-item deny lives as {Decision: false} in the response array,
	// NOT as an error.
	srv := httptest.NewServer(jsonResponse(t, http.MethodPost, authzen.EvaluationsEndpoint, 200,
		`{"evaluations":[{"decision":false},{"decision":false},{"decision":false}]}`))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	resp, err := c.Evaluations(context.Background(), validEvalsRequest())
	if err != nil {
		t.Fatalf("all-deny batch returned error: %v", err)
	}
	if len(resp.Evaluations) != 3 {
		t.Fatalf("got %d items, want 3", len(resp.Evaluations))
	}
	for i, e := range resp.Evaluations {
		if e.Decision {
			t.Errorf("item %d Decision = true, want false", i)
		}
	}
}

func TestEvaluations_EmptyEvaluationsArrayFailsValidation(t *testing.T) {
	c, _ := client.NewClient("https://pdp.example.com")
	_, err := c.Evaluations(context.Background(), &authzen.EvaluationsRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice"},
		Action:   &authzen.Action{Name: "read"},
		Resource: &authzen.Resource{Type: "document", ID: "doc-42"},
	})
	if err == nil {
		t.Fatal("empty Evaluations returned nil error")
	}
	var ve *authzen.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is not *ValidationError: %v", err)
	}
}
