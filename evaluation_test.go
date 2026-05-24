// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hstern/go-authzen/v1"
)

func TestEvaluationRequest_RoundTrip(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
		Context:  json.RawMessage(`{"device":"mobile"}`),
	}
	_, decoded := roundTrip(t, req)
	if !reflect.DeepEqual(req, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", req, decoded)
	}
}

func TestEvaluationResponse_DenyIs200_NotError(t *testing.T) {
	// The wire-fidelity invariant DESIGN.md spells out: deny is
	// {"decision": false} — a legal, non-error response. The decoder
	// must surface false unchanged and the encoder must emit
	// "decision":false even though it's the zero value (no omitempty).
	resp := authzen.EvaluationResponse{Decision: false}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"decision":false`) {
		t.Fatalf("encoded deny lost the field: got %s", string(b))
	}
	var back authzen.EvaluationResponse
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Decision != false {
		t.Fatalf("Decision after round-trip = %v, want false", back.Decision)
	}
}

func TestEvaluationResponse_PermitRoundTrip(t *testing.T) {
	resp := &authzen.EvaluationResponse{Decision: true, Context: json.RawMessage(`{"reason":"role=admin"}`)}
	_, decoded := roundTrip(t, resp)
	if !reflect.DeepEqual(resp, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", resp, decoded)
	}
}

func TestEvaluationsRequest_RoundTrip(t *testing.T) {
	// Top-level defaults plus per-item overrides — the canonical batch
	// shape per spec §6.2.1.
	subj := &authzen.Subject{Type: "user", ID: "alice"}
	res := &authzen.Resource{Type: "document", ID: "doc-42"}
	req := &authzen.EvaluationsRequest{
		Subject:  subj,
		Resource: res,
		Evaluations: []authzen.EvaluationsItem{
			{Action: &authzen.Action{Name: "read"}},
			{Action: &authzen.Action{Name: "write"}},
			{Action: &authzen.Action{Name: "delete"}},
		},
		Options: &authzen.EvaluationsOptions{
			EvaluationsSemantic: authzen.EvaluationsSemanticDenyOnFirstDeny,
		},
	}
	_, decoded := roundTrip(t, req)
	if !reflect.DeepEqual(req, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", req, decoded)
	}
}

func TestEvaluationsRequest_OmittedDefaultsHaveNoEmptyObjects(t *testing.T) {
	// If no top-level Subject/Action/Resource is set, the encoded JSON
	// must NOT include empty {} objects under those keys (would be a
	// "set to zero-valued default" signal to the PDP). Pointers with
	// omitempty ensure they're absent.
	req := authzen.EvaluationsRequest{
		Evaluations: []authzen.EvaluationsItem{
			{Subject: &authzen.Subject{Type: "user", ID: "alice"}, Action: &authzen.Action{Name: "read"}, Resource: &authzen.Resource{Type: "document", ID: "doc-42"}},
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{`"subject":`, `"action":`, `"resource":`} {
		// Top-level shouldn't carry these — only the nested item should.
		// Find the index up to "evaluations" and check only that prefix.
		s := string(b)
		evIdx := strings.Index(s, `"evaluations":`)
		if evIdx == -1 {
			t.Fatalf("encoded body missing evaluations: %s", s)
		}
		if strings.Contains(s[:evIdx], key) {
			t.Errorf("top-level %s leaked into encoded body: %s", key, s)
		}
	}
}

func TestEvaluationsResponse_RoundTrip(t *testing.T) {
	resp := &authzen.EvaluationsResponse{
		Evaluations: []authzen.EvaluationResponse{
			{Decision: true},
			{Decision: false, Context: json.RawMessage(`{"reason":"denied"}`)},
			{Decision: true},
		},
	}
	_, decoded := roundTrip(t, resp)
	if !reflect.DeepEqual(resp, decoded) {
		t.Fatalf("round-trip mismatch:\n  orig: %+v\n  back: %+v", resp, decoded)
	}
}

func TestEvaluationsSemanticConstants(t *testing.T) {
	// Pin to the spec strings — a rename here is a wire-shape change.
	cases := map[authzen.EvaluationsSemantic]string{
		authzen.EvaluationsSemanticExecuteAll:          "execute_all",
		authzen.EvaluationsSemanticDenyOnFirstDeny:     "deny_on_first_deny",
		authzen.EvaluationsSemanticPermitOnFirstPermit: "permit_on_first_permit",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("EvaluationsSemantic = %q, want %q", string(got), want)
		}
	}
}
