// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/interop"
)

// TestExampleMatchesScenario is the conformance proof: drive every
// case from interop.Cases() through this example's Cedar-backed
// Decider and assert the decision matches the documented expectation.
//
// The Cases table is the same one interop's own scenario_pdp_test.go
// exercises against the library's in-memory Decider, and the same one
// the //go:build interop scenario_test.go drives against Topaz over
// the network. When all three layers agree, the example is a
// drop-in replacement for the library's reference Decider — any
// disagreement names exactly which layer is wrong.
func TestExampleMatchesScenario(t *testing.T) {
	d, err := newCedarDecider()
	if err != nil {
		t.Fatalf("build decider: %v", err)
	}
	ctx := t.Context()
	for _, c := range interop.Cases() {
		t.Run(c.Name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: interop.SubjectType, ID: c.SubjectID},
				Action:   authzen.Action{Name: c.Action},
				Resource: authzen.Resource{Type: c.ResourceType, ID: c.ResourceID, Properties: c.ResourceProperties},
			}
			resp, err := d.Evaluate(ctx, req)
			if err != nil {
				t.Fatalf("Evaluate transport error: %v", err)
			}
			if resp.Decision != c.ExpectedDecision {
				t.Errorf("Decision = %v, want %v (subject=%s action=%s resource=%s/%s)",
					resp.Decision, c.ExpectedDecision,
					c.SubjectID, c.Action, c.ResourceType, c.ResourceID)
			}
		})
	}
}

// TestExampleEvaluations confirms the batch endpoint applies the same
// per-item decision logic the spec's default execute_all semantic
// requires, and that top-level Subject defaults flow through to items
// that omit it.
func TestExampleEvaluations(t *testing.T) {
	d, err := newCedarDecider()
	if err != nil {
		t.Fatalf("build decider: %v", err)
	}

	// Rick (admin) reading every fixture user.
	rick := authzen.Subject{Type: interop.SubjectType, ID: "rick@the-citadel.com"}
	readUser := authzen.Action{Name: interop.ActionReadUser}
	req := &authzen.EvaluationsRequest{
		Subject: &rick,
		Action:  &readUser,
		Evaluations: []authzen.EvaluationsItem{
			{Resource: &authzen.Resource{Type: interop.ResourceTypeUser, ID: "morty@the-citadel.com"}},
			{Resource: &authzen.Resource{Type: interop.ResourceTypeUser, ID: "beth@the-smiths.com"}},
			{Resource: &authzen.Resource{Type: interop.ResourceTypeUser, ID: "jerry@the-smiths.com"}},
		},
	}
	resp, err := d.Evaluations(t.Context(), req)
	if err != nil {
		t.Fatalf("Evaluations: %v", err)
	}
	if got, want := len(resp.Evaluations), len(req.Evaluations); got != want {
		t.Fatalf("len(Evaluations) = %d, want %d", got, want)
	}
	for i, ev := range resp.Evaluations {
		if !ev.Decision {
			t.Errorf("item %d: Decision = false, admin should always permit", i)
		}
	}
}

// TestExampleDenyIsHTTP200 is a spec §5.1 invariant guard: a policy
// deny is a successful 200 response with {decision:false}, never an
// error return. This is the wire-fidelity rule that bites every
// AuthZEN implementer once.
func TestExampleDenyIsHTTP200(t *testing.T) {
	d, err := newCedarDecider()
	if err != nil {
		t.Fatalf("build decider: %v", err)
	}
	// Jerry (viewer) trying to create a todo — denied by policy.
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: interop.SubjectType, ID: "jerry@the-smiths.com"},
		Action:   authzen.Action{Name: interop.ActionCreateTodo},
		Resource: authzen.Resource{Type: interop.ResourceTypeTodo, ID: "todo-1"},
	}
	resp, err := d.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("policy deny must not be an error return: %v", err)
	}
	if resp.Decision {
		t.Fatalf("expected viewer.can_create_todo to be denied")
	}
}
