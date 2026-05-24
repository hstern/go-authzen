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
	"testing"

	"github.com/hstern/go-authzen/v1"
	"github.com/hstern/go-authzen/v1/client"
)

func TestSearchSubject_Roundtrip(t *testing.T) {
	srv := httptest.NewServer(jsonResponse(t, http.MethodPost, authzen.SearchSubjectEndpoint, 200,
		`{"results":[{"type":"user","id":"alice"},{"type":"user","id":"bob"}],"page":{"next_token":""}}`))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	resp, err := c.SearchSubject(context.Background(), &authzen.SubjectSearchRequest{
		Subject:  authzen.Subject{Type: "user"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	if err != nil {
		t.Fatalf("SearchSubject: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Results))
	}
	if resp.Page == nil || resp.Page.NextToken != "" {
		t.Errorf("page = %+v, want non-nil with empty NextToken (end-of-results sentinel)", resp.Page)
	}
}

func TestSearchResource_Roundtrip(t *testing.T) {
	srv := httptest.NewServer(jsonResponse(t, http.MethodPost, authzen.SearchResourceEndpoint, 200,
		`{"results":[{"type":"document","id":"doc-1"},{"type":"document","id":"doc-2"}]}`))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	resp, err := c.SearchResource(context.Background(), &authzen.ResourceSearchRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document"},
	})
	if err != nil {
		t.Fatalf("SearchResource: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Results))
	}
}

func TestSearchAction_Roundtrip_NoActionKeyOnWire(t *testing.T) {
	// Spec §6.3.3 + DESIGN.md §wire-fidelity: the request body MUST
	// have no "action" field. The server-side recorder asserts on the
	// raw bytes to catch any regression.
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ = io.ReadAll(r.Body)
		if r.URL.Path != authzen.SearchActionEndpoint {
			t.Errorf("path = %q, want %q", r.URL.Path, authzen.SearchActionEndpoint)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"results":[{"name":"read"},{"name":"write"}]}`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	resp, err := c.SearchAction(context.Background(), &authzen.ActionSearchRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	if err != nil {
		t.Fatalf("SearchAction: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Results))
	}
	if strings.Contains(string(rawBody), `"action"`) {
		t.Errorf("request body leaked an \"action\" key: %s", string(rawBody))
	}
}

func TestSearch_Non2xxReturnsStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "pdp boom")
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)

	cases := []struct {
		name string
		call func() error
	}{
		{"subject", func() error {
			_, err := c.SearchSubject(context.Background(), &authzen.SubjectSearchRequest{
				Subject: authzen.Subject{Type: "user"}, Action: authzen.Action{Name: "read"},
				Resource: authzen.Resource{Type: "document", ID: "doc-42"},
			})
			return err
		}},
		{"resource", func() error {
			_, err := c.SearchResource(context.Background(), &authzen.ResourceSearchRequest{
				Subject: authzen.Subject{Type: "user", ID: "alice"}, Action: authzen.Action{Name: "read"},
				Resource: authzen.Resource{Type: "document"},
			})
			return err
		}},
		{"action", func() error {
			_, err := c.SearchAction(context.Background(), &authzen.ActionSearchRequest{
				Subject: authzen.Subject{Type: "user", ID: "alice"}, Resource: authzen.Resource{Type: "document", ID: "doc-42"},
			})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
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
		})
	}
}

func TestSearch_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `not even close to json`)
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	_, err := c.SearchSubject(context.Background(), &authzen.SubjectSearchRequest{
		Subject: authzen.Subject{Type: "user"}, Action: authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	if err == nil {
		t.Fatal("nil error on malformed body")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("err = %v, want it to mention decoding", err)
	}
}

func TestSearch_ValidationFailsBeforeNetwork(t *testing.T) {
	c, _ := client.NewClient("https://pdp.example.com")
	cases := []struct {
		name string
		call func() error
	}{
		{"subject missing resource.id", func() error {
			_, err := c.SearchSubject(context.Background(), &authzen.SubjectSearchRequest{
				Subject:  authzen.Subject{Type: "user"},
				Action:   authzen.Action{Name: "read"},
				Resource: authzen.Resource{Type: "document"},
			})
			return err
		}},
		{"resource missing subject.id", func() error {
			_, err := c.SearchResource(context.Background(), &authzen.ResourceSearchRequest{
				Subject:  authzen.Subject{Type: "user"},
				Action:   authzen.Action{Name: "read"},
				Resource: authzen.Resource{Type: "document"},
			})
			return err
		}},
		{"action missing resource.id", func() error {
			_, err := c.SearchAction(context.Background(), &authzen.ActionSearchRequest{
				Subject:  authzen.Subject{Type: "user", ID: "alice"},
				Resource: authzen.Resource{Type: "document"},
			})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("nil error on invalid request")
			}
			var ve *authzen.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("error is not *ValidationError: %v", err)
			}
		})
	}
}
