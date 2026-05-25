// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

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
	"github.com/hstern/go-authzen/v1/server"
)

// staticDecider is the test PDP — programmable per test via the
// fields. Each method returns the corresponding (resp, err) when
// called; tests set whichever they need.
type staticDecider struct {
	server.NotImplementedDecider
	evalResp     *authzen.EvaluationResponse
	evalErr      error
	evalsResp    *authzen.EvaluationsResponse
	evalsErr     error
	searchSubR   *authzen.SubjectSearchResponse
	searchSubErr error
	searchResR   *authzen.ResourceSearchResponse
	searchResErr error
	searchActR   *authzen.ActionSearchResponse
	searchActErr error
	calls        int // simple counter for "did the decider get called?"
}

func (d *staticDecider) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	d.calls++
	return d.evalResp, d.evalErr
}

func (d *staticDecider) Evaluations(context.Context, *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	d.calls++
	return d.evalsResp, d.evalsErr
}

func (d *staticDecider) SearchSubject(context.Context, *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	d.calls++
	return d.searchSubR, d.searchSubErr
}

func (d *staticDecider) SearchResource(context.Context, *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	d.calls++
	return d.searchResR, d.searchResErr
}

func (d *staticDecider) SearchAction(context.Context, *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	d.calls++
	return d.searchActR, d.searchActErr
}

// newServer stands up an httptest server fronted by the library's
// handler. The Decider is supplied; t.Cleanup closes the server.
func newServer(t *testing.T, d server.Decider, opts ...server.HandlerOption) string {
	t.Helper()
	srv := httptest.NewServer(server.NewHandler(d, opts...))
	t.Cleanup(srv.Close)
	return srv.URL
}

func validEvalReq() *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	}
}

func TestE2E_EvaluatePermit(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	url := newServer(t, d)
	c, _ := client.NewClient(url)
	resp, err := c.Evaluate(context.Background(), validEvalReq())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !resp.Decision {
		t.Errorf("Decision = false, want true")
	}
	if d.calls != 1 {
		t.Errorf("Decider.Evaluate called %d times, want 1", d.calls)
	}
}

func TestE2E_EvaluateDenyIs200_NotError(t *testing.T) {
	// The wire-fidelity invariant end-to-end: a Decider returning
	// {Decision: false}, nil emits HTTP 200 with the JSON body, the
	// client sees Decision: false and a nil error.
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: false}}
	url := newServer(t, d)

	// Confirm wire status directly first so a server-side regression
	// (4xx-on-deny) shows up here, not just indirectly through the
	// client's interpretation.
	body := strings.NewReader(`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"document","id":"doc-42"}}`)
	httpResp, err := http.Post(url+authzen.EvaluationEndpoint, "application/json", body)
	if err != nil {
		t.Fatalf("raw POST: %v", err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	if httpResp.StatusCode != 200 {
		raw, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("deny returned HTTP %d (want 200): body=%s", httpResp.StatusCode, string(raw))
	}

	// And the client sees it as a non-error response.
	c, _ := client.NewClient(url)
	resp, err := c.Evaluate(context.Background(), validEvalReq())
	if err != nil {
		t.Fatalf("Evaluate on deny returned error: %v", err)
	}
	if resp.Decision {
		t.Errorf("Decision = true, want false")
	}
}

func TestE2E_EvaluationsMixedAllowDeny(t *testing.T) {
	// Per-item deny lives as {Decision: false} entries in the response
	// array, NOT as errors.
	d := &staticDecider{evalsResp: &authzen.EvaluationsResponse{
		Evaluations: []authzen.EvaluationResponse{
			{Decision: true},
			{Decision: false},
			{Decision: true},
		},
	}}
	url := newServer(t, d)
	c, _ := client.NewClient(url)
	resp, err := c.Evaluations(context.Background(), &authzen.EvaluationsRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice"},
		Action:   &authzen.Action{Name: "read"},
		Resource: &authzen.Resource{Type: "document", ID: "doc-42"},
		Evaluations: []authzen.EvaluationsItem{
			{}, {}, {},
		},
	})
	if err != nil {
		t.Fatalf("Evaluations: %v", err)
	}
	got := []bool{}
	for _, e := range resp.Evaluations {
		got = append(got, e.Decision)
	}
	if len(got) != 3 || !got[0] || got[1] || !got[2] {
		t.Errorf("decisions = %v, want [true, false, true]", got)
	}
}

func TestE2E_PartialDeciderReturns501_ForSearchVariants(t *testing.T) {
	// A Decider that only implements Evaluate (via NotImplementedDecider
	// embed) returns ErrNotImplemented from the search methods; the
	// handler maps that to HTTP 501. The client's StatusError carries
	// the code.
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	d.searchSubErr = authzen.ErrNotImplemented
	d.searchResErr = authzen.ErrNotImplemented
	d.searchActErr = authzen.ErrNotImplemented
	d.evalsErr = authzen.ErrNotImplemented
	url := newServer(t, d)
	c, _ := client.NewClient(url)

	cases := []struct {
		name string
		call func() error
	}{
		{"evaluations", func() error {
			_, err := c.Evaluations(context.Background(), &authzen.EvaluationsRequest{
				Subject:     &authzen.Subject{Type: "user", ID: "alice"},
				Action:      &authzen.Action{Name: "read"},
				Resource:    &authzen.Resource{Type: "document", ID: "doc-42"},
				Evaluations: []authzen.EvaluationsItem{{}},
			})
			return err
		}},
		{"search/subject", func() error {
			_, err := c.SearchSubject(context.Background(), &authzen.SubjectSearchRequest{
				Subject:  authzen.Subject{Type: "user"},
				Action:   authzen.Action{Name: "read"},
				Resource: authzen.Resource{Type: "document", ID: "doc-42"},
			})
			return err
		}},
		{"search/resource", func() error {
			_, err := c.SearchResource(context.Background(), &authzen.ResourceSearchRequest{
				Subject:  authzen.Subject{Type: "user", ID: "alice"},
				Action:   authzen.Action{Name: "read"},
				Resource: authzen.Resource{Type: "document"},
			})
			return err
		}},
		{"search/action", func() error {
			_, err := c.SearchAction(context.Background(), &authzen.ActionSearchRequest{
				Subject:  authzen.Subject{Type: "user", ID: "alice"},
				Resource: authzen.Resource{Type: "document", ID: "doc-42"},
			})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("nil error from partial Decider on unsupported endpoint")
			}
			var se *client.StatusError
			if !errors.As(err, &se) {
				t.Fatalf("error is not *StatusError: %v", err)
			}
			if se.StatusCode != http.StatusNotImplemented {
				t.Errorf("StatusCode = %d, want 501", se.StatusCode)
			}
		})
	}
}

func TestE2E_MalformedRequestBodyIs400(t *testing.T) {
	d := &staticDecider{}
	url := newServer(t, d)
	resp, err := http.Post(url+authzen.EvaluationEndpoint, "application/json", strings.NewReader(`{not json`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", resp.StatusCode)
	}
	if d.calls != 0 {
		t.Errorf("Decider called %d times on malformed body, want 0", d.calls)
	}
}

func TestE2E_DeciderError_ValidationIs400(t *testing.T) {
	d := &staticDecider{evalErr: &authzen.ValidationError{Field: "policy.rule", Reason: "internal validation"}}
	url := newServer(t, d)
	c, _ := client.NewClient(url)
	_, err := c.Evaluate(context.Background(), validEvalReq())
	if err == nil {
		t.Fatal("nil error")
	}
	var se *client.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not *StatusError: %v", err)
	}
	if se.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400 (Decider returned ValidationError)", se.StatusCode)
	}
}

func TestE2E_DeciderError_Generic500(t *testing.T) {
	d := &staticDecider{evalErr: errors.New("backend boom")}
	url := newServer(t, d)
	c, _ := client.NewClient(url)
	_, err := c.Evaluate(context.Background(), validEvalReq())
	if err == nil {
		t.Fatal("nil error")
	}
	var se *client.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not *StatusError: %v", err)
	}
	if se.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", se.StatusCode)
	}
}

func TestE2E_WrongMethodIs405Or404(t *testing.T) {
	// ServeMux with method-prefixed pattern returns 405 Method Not
	// Allowed when the path exists but method doesn't match. Pinning
	// at the wire level so a future routing change is visible.
	d := &staticDecider{}
	url := newServer(t, d)
	resp, err := http.Get(url + authzen.EvaluationEndpoint)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("StatusCode = %d, want 405", resp.StatusCode)
	}
}

func TestE2E_UnknownPathIs404(t *testing.T) {
	d := &staticDecider{}
	url := newServer(t, d)
	resp, err := http.Post(url+"/not-an-endpoint", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", resp.StatusCode)
	}
}

func TestE2E_ResponseHasJSONContentType(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	url := newServer(t, d)
	body := strings.NewReader(`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"document","id":"doc-42"}}`)
	resp, err := http.Post(url+authzen.EvaluationEndpoint, "application/json", body)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// Body decodes as the expected envelope.
	var out authzen.EvaluationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Decision {
		t.Errorf("Decision = false, want true")
	}
}
