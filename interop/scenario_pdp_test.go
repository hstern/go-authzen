// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hstern/go-authzen/v1"
	"github.com/hstern/go-authzen/v1/client"
	"github.com/hstern/go-authzen/v1/interop"
	"github.com/hstern/go-authzen/v1/server"
)

// pdpTestTimeout caps each PDP-role test. The httptest server runs
// in-process so the only real source of slowness is the race detector;
// 30 seconds is enough headroom even on a contended runner.
const pdpTestTimeout = 30 * time.Second

// TestPDPRoleScenarioEvaluate stands the library's PDP-side handler in
// front of the in-memory Todo scenario decider, drives it with the
// library's PEP-side client, and asserts every scenario case round-
// trips with the expected decision.
//
// This is the load-bearing wire-fidelity test: a deny entry from the
// upstream rules MUST come back as HTTP 200 with {"decision": false}
// and a nil client error (spec §5.1; DESIGN.md §wire-fidelity). The
// loop body intentionally distinguishes "client returned an error"
// from "client returned the wrong decision" so a regression in the
// status-code mapping does not get reported as a policy disagreement.
func TestPDPRoleScenarioEvaluate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(server.NewHandler(interop.NewDecider()))
	t.Cleanup(srv.Close)

	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}

	cases := interop.Cases()
	if len(cases) == 0 {
		t.Fatal("interop.Cases() returned no cases")
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), pdpTestTimeout)
			defer cancel()

			req := evaluationRequestFor(tc)
			resp, err := c.Evaluate(ctx, req)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if resp == nil {
				t.Fatal("Evaluate returned nil response with nil error")
			}
			if resp.Decision != tc.ExpectedDecision {
				t.Errorf("decision = %v, want %v (subject=%s action=%s resource=%s/%s)",
					resp.Decision, tc.ExpectedDecision,
					tc.SubjectID, tc.Action, tc.ResourceType, tc.ResourceID)
			}
		})
	}
}

// TestPDPRoleScenarioEvaluationsBatch drives the batch endpoint with
// a slice of scenario cases in a single request and asserts the
// per-item decisions round-trip correctly, in order. The batch
// exercises the default [authzen.EvaluationsSemanticExecuteAll]
// semantic (spec §6.2.1) — explicit, to lock in that the library
// emits an option-less request and the server treats it as execute-
// all.
//
// A mix of permit and deny entries is selected so any regression that
// short-circuits the batch or transposes its order surfaces here
// instead of in a more confusing downstream test.
func TestPDPRoleScenarioEvaluationsBatch(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(server.NewHandler(interop.NewDecider()))
	t.Cleanup(srv.Close)

	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), pdpTestTimeout)
	defer cancel()

	batch := pickMixedBatch(interop.Cases())
	if len(batch) < 4 {
		t.Fatalf("pickMixedBatch returned %d cases, want at least 4 with mixed decisions", len(batch))
	}

	items := make([]authzen.EvaluationsItem, 0, len(batch))
	for _, tc := range batch {
		req := evaluationRequestFor(tc)
		subj := req.Subject
		act := req.Action
		res := req.Resource
		items = append(items, authzen.EvaluationsItem{
			Subject:  &subj,
			Action:   &act,
			Resource: &res,
		})
	}
	req := &authzen.EvaluationsRequest{Evaluations: items}

	resp, err := c.Evaluations(ctx, req)
	if err != nil {
		t.Fatalf("Evaluations returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("Evaluations returned nil response with nil error")
	}
	if got, want := len(resp.Evaluations), len(batch); got != want {
		t.Fatalf("response items = %d, want %d (execute_all default; no short-circuit expected)", got, want)
	}
	for i, tc := range batch {
		if resp.Evaluations[i].Decision != tc.ExpectedDecision {
			t.Errorf("batch[%d] (%s): decision = %v, want %v",
				i, tc.Name, resp.Evaluations[i].Decision, tc.ExpectedDecision)
		}
	}
}

// evaluationRequestFor builds an [authzen.EvaluationRequest] from a
// scenario Case. The Subject.Type uses the scenario's "user" constant;
// the Resource.Properties is carried verbatim so byte-stable round-
// trip (DESIGN.md §wire-fidelity) is preserved end-to-end.
func evaluationRequestFor(c interop.Case) *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: interop.SubjectType,
			ID:   c.SubjectID,
		},
		Action: authzen.Action{Name: c.Action},
		Resource: authzen.Resource{
			Type:       c.ResourceType,
			ID:         c.ResourceID,
			Properties: c.ResourceProperties,
		},
	}
}

// pickMixedBatch selects a small batch of scenario cases guaranteed to
// contain at least one permit and one deny so the batch test exercises
// both outcomes in a single request. It walks Cases deterministically
// and stops once both polarities are represented and the batch is at
// least four items long, so the test does not become a full Cases
// enumeration (Evaluate already covers that).
func pickMixedBatch(cases []interop.Case) []interop.Case {
	out := make([]interop.Case, 0, 6)
	havePermit, haveDeny := false, false
	for _, c := range cases {
		switch {
		case c.ExpectedDecision && !havePermit:
			out = append(out, c)
			havePermit = true
		case !c.ExpectedDecision && !haveDeny:
			out = append(out, c)
			haveDeny = true
		case len(out) < 6:
			out = append(out, c)
		}
		if len(out) >= 6 && havePermit && haveDeny {
			break
		}
	}
	return out
}
