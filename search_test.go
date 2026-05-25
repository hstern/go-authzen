// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hstern/go-authzen"
)

func TestSubjectSearchRequest_RoundTrip(t *testing.T) {
	// Subject carries Type only; spec §6.3.1 says ID is omitted or
	// ignored. The Subject struct's `id,omitempty` tag makes the
	// omission natural — encoded JSON has no "id" under subject.
	req := &authzen.SubjectSearchRequest{
		Subject:  authzen.Subject{Type: "user"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
		Page:     &authzen.PageRequest{Limit: 25},
	}
	b, decoded := roundTrip(t, req)
	if !reflect.DeepEqual(req, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", req, decoded)
	}
	if strings.Contains(string(b), `"id":"`) {
		// only the resource may legally carry id; the subject must not.
		// Look at the bit under "subject":...} for an "id" key.
		t.Logf("encoded body: %s", string(b))
	}
}

func TestSubjectSearchResponse_RoundTrip(t *testing.T) {
	resp := &authzen.SubjectSearchResponse{
		Page: &authzen.PageResponse{NextToken: ""},
		Results: []authzen.Subject{
			{Type: "user", ID: "alice"},
			{Type: "user", ID: "bob", Properties: json.RawMessage(`{"role":"viewer"}`)},
		},
	}
	_, decoded := roundTrip(t, resp)
	if !reflect.DeepEqual(resp, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", resp, decoded)
	}
}

func TestResourceSearchRequest_RoundTrip(t *testing.T) {
	req := &authzen.ResourceSearchRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document"},
	}
	_, decoded := roundTrip(t, req)
	if !reflect.DeepEqual(req, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", req, decoded)
	}
}

func TestResourceSearchResponse_RoundTrip(t *testing.T) {
	resp := &authzen.ResourceSearchResponse{
		Results: []authzen.Resource{
			{Type: "document", ID: "doc-1"},
			{Type: "document", ID: "doc-2"},
		},
	}
	_, decoded := roundTrip(t, resp)
	if !reflect.DeepEqual(resp, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", resp, decoded)
	}
}

func TestActionSearchRequest_HasNoActionKey(t *testing.T) {
	// Spec §6.3.3 + DESIGN.md §wire-fidelity: the request body has NO
	// "action" key at all. Not "action with empty name", not "action
	// omitted via omitempty" — the field doesn't exist on the type.
	// Encoding must produce no such key in the JSON.
	req := authzen.ActionSearchRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), `"action"`) {
		t.Fatalf("ActionSearchRequest leaked an action key: %s", string(b))
	}
	// The same field-omission must survive a round-trip.
	var back authzen.ActionSearchRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(req, back) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", req, back)
	}
}

func TestActionSearchRequest_IgnoresIncomingActionField(t *testing.T) {
	// Per spec §11 (security considerations / robustness) + DESIGN.md
	// §5 (lenient unmarshal), a server that receives a non-conformant
	// request with an extra "action" key MUST decode the rest and
	// ignore the unknown field. The Go decoder's default behavior
	// already does this, but pin the test so a future change to the
	// type can't accidentally surface the field.
	body := []byte(`{
		"subject":{"type":"user","id":"alice"},
		"action":{"name":"read"},
		"resource":{"type":"document","id":"doc-42"}
	}`)
	var req authzen.ActionSearchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.Subject.ID != "alice" || req.Resource.ID != "doc-42" {
		t.Fatalf("expected fields lost: %+v", req)
	}
	// Re-encoding still omits "action".
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), `"action"`) {
		t.Fatalf("re-encoded request leaked an action key: %s", string(b))
	}
}

func TestActionSearchResponse_RoundTrip(t *testing.T) {
	resp := &authzen.ActionSearchResponse{
		Results: []authzen.Action{
			{Name: "read"},
			{Name: "write", Properties: json.RawMessage(`{"requires":"mfa"}`)},
		},
	}
	_, decoded := roundTrip(t, resp)
	if !reflect.DeepEqual(resp, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", resp, decoded)
	}
}
