// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hstern/go-authzen/v1"
)

// roundTrip marshals v, then unmarshals into a freshly zeroed copy of v
// and returns the JSON bytes plus the decoded value. Used by every
// per-type round-trip test below to keep them terse.
func roundTrip(t *testing.T, v any) ([]byte, any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := reflect.New(reflect.TypeOf(v).Elem()).Interface()
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("Unmarshal of %s: %v", string(b), err)
	}
	return b, out
}

func TestSubject_RoundTrip(t *testing.T) {
	s := &authzen.Subject{Type: "user", ID: "alice", Properties: json.RawMessage(`{"role":"admin"}`)}
	_, decoded := roundTrip(t, s)
	if !reflect.DeepEqual(s, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", s, decoded)
	}
}

func TestSubject_OmitsEmptyIDAndProperties(t *testing.T) {
	// Used by SubjectSearchRequest where the subject carries only Type.
	s := authzen.Subject{Type: "user"}
	b, _ := json.Marshal(s)
	got := string(b)
	if strings.Contains(got, `"id"`) {
		t.Errorf("empty ID must omit from JSON: got %s", got)
	}
	if strings.Contains(got, `"properties"`) {
		t.Errorf("empty Properties must omit from JSON: got %s", got)
	}
	if got != `{"type":"user"}` {
		t.Errorf("got %s, want {\"type\":\"user\"}", got)
	}
}

func TestResource_RoundTrip(t *testing.T) {
	r := &authzen.Resource{Type: "document", ID: "doc-42", Properties: json.RawMessage(`{"owner":"bob"}`)}
	_, decoded := roundTrip(t, r)
	if !reflect.DeepEqual(r, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", r, decoded)
	}
}

func TestAction_RoundTrip(t *testing.T) {
	a := &authzen.Action{Name: "read", Properties: json.RawMessage(`{"method":"GET"}`)}
	_, decoded := roundTrip(t, a)
	if !reflect.DeepEqual(a, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", a, decoded)
	}
}

func TestPageRequest_RoundTrip(t *testing.T) {
	p := &authzen.PageRequest{Token: "opaque-cursor", Limit: 50, Properties: json.RawMessage(`{"foo":1}`)}
	_, decoded := roundTrip(t, p)
	if !reflect.DeepEqual(p, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", p, decoded)
	}
}

func TestPageResponse_EmptyNextTokenSentinel(t *testing.T) {
	// Per spec §6.1.4 + DESIGN.md §wire-fidelity, an empty-string
	// NextToken is the end-of-results sentinel — NOT absent, NOT null.
	// Marshaling must emit `"next_token": ""` even though that's the
	// type's zero value.
	pr := authzen.PageResponse{NextToken: ""}
	b, err := json.Marshal(pr)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"next_token":""`) {
		t.Fatalf("end-of-results sentinel lost: encoded %s, want it to contain \"next_token\":\"\"", string(b))
	}
	var back authzen.PageResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.NextToken != "" {
		t.Fatalf("NextToken after round-trip = %q, want \"\"", back.NextToken)
	}
}

func TestPageResponse_RoundTripWithToken(t *testing.T) {
	pr := &authzen.PageResponse{NextToken: "next-cursor", Count: 10, Total: 100, Properties: json.RawMessage(`{}`)}
	_, decoded := roundTrip(t, pr)
	if !reflect.DeepEqual(pr, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", pr, decoded)
	}
}

func TestSubject_PropertiesByteStable(t *testing.T) {
	// Properties is json.RawMessage so the wire bytes round-trip
	// verbatim — Go's map iteration order would otherwise scramble
	// key order on every marshal. This is the load-bearing reason
	// DESIGN.md §6 picks RawMessage over map[string]any.
	rawIn := json.RawMessage(`{"z":1,"a":2,"m":3,"b":4}`)
	s := authzen.Subject{Type: "user", ID: "alice", Properties: rawIn}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"properties":{"z":1,"a":2,"m":3,"b":4}`)) {
		t.Fatalf("Properties byte-order not preserved on encode: got %s", string(b))
	}
	var back authzen.Subject
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(back.Properties, rawIn) {
		t.Fatalf("Properties bytes after round-trip = %s, want %s", string(back.Properties), string(rawIn))
	}
}

func TestDecodeJSON_NilAndEmpty(t *testing.T) {
	type ext struct{ K string }
	var v ext
	// Nil RawMessage → no-op, no error, v unchanged.
	if err := authzen.DecodeJSON(nil, &v); err != nil {
		t.Fatalf("DecodeJSON(nil) = %v, want nil", err)
	}
	if v.K != "" {
		t.Errorf("v changed on nil input: %+v", v)
	}
	// Whitespace-only RawMessage → also a no-op (matches stdlib's
	// "no document" semantics without surfacing them as errors).
	if err := authzen.DecodeJSON(json.RawMessage("   "), &v); err != nil {
		t.Fatalf("DecodeJSON(whitespace) = %v, want nil", err)
	}
	if v.K != "" {
		t.Errorf("v changed on whitespace input: %+v", v)
	}
}

func TestDecodeJSON_Populated(t *testing.T) {
	type ext struct {
		Role string `json:"role"`
	}
	var v ext
	if err := authzen.DecodeJSON(json.RawMessage(`{"role":"admin"}`), &v); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if v.Role != "admin" {
		t.Errorf("Role = %q, want %q", v.Role, "admin")
	}
}

func TestEncodeJSON_NilEmits_Nil(t *testing.T) {
	got, err := authzen.EncodeJSON(nil)
	if err != nil {
		t.Fatalf("EncodeJSON(nil) = err %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("EncodeJSON(nil) = %s, want nil RawMessage (omits under omitempty)", string(got))
	}
}

func TestEncodeJSON_Populated(t *testing.T) {
	type ext struct {
		Role string `json:"role"`
	}
	got, err := authzen.EncodeJSON(ext{Role: "admin"})
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	want := `{"role":"admin"}`
	if string(got) != want {
		t.Errorf("EncodeJSON = %s, want %s", string(got), want)
	}
}
