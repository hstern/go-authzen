//go:build interop

// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hstern/go-authzen/client"
	"github.com/hstern/go-authzen/interop"
)

// TestPEPRoleScenarioEvaluate exercises the PEP role against the live
// OpenID AuthZEN Todo PDP at [interop.PublicPDPBaseURL]. For every
// scenario case the library's client sends an Evaluate request, the
// live PDP returns a decision, and the test asserts the decision
// matches what [interop.Decide] computes from the documented rules.
//
// A live deny (HTTP 200, {"decision": false}) is a normal outcome and
// must NOT be treated as a transport error (spec §5.1; DESIGN.md
// §wire-fidelity). A live disagreement on a case — the PDP returning a
// decision opposite to [interop.Decide] — fails the test with a
// message naming the case and both sides of the discrepancy so the
// refresh procedure in interop/README.md can be applied (the live PDP
// wins; update fixtures and rerun).
//
// The test carries the `interop` build tag and is skipped when the
// public endpoint is unreachable. Reach the live tests with
//
//	go test -tags interop ./interop/...
func TestPEPRoleScenarioEvaluate(t *testing.T) {
	probeLivePDP(t)

	c, err := client.NewClient(interop.PublicPDPBaseURL)
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	cases := interop.Cases()
	if len(cases) == 0 {
		t.Fatal("interop.Cases() returned no cases")
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			req := evaluationRequestFor(tc)
			resp, err := c.Evaluate(ctx, req)
			if err != nil {
				// A transport error here is a real failure; the live
				// PDP only returns a non-2xx for malformed requests or
				// outages. Distinguish from a decision disagreement
				// (the next branch) so the failure message points at
				// the right layer.
				t.Fatalf("Evaluate transport error: %v", err)
			}
			if resp == nil {
				t.Fatal("Evaluate returned nil response with nil error")
			}
			if resp.Decision != tc.ExpectedDecision {
				t.Errorf("live PDP disagrees with interop.Decide: "+
					"case %q: live=%v, expected=%v "+
					"(subject=%s action=%s resource=%s/%s) — "+
					"if upstream policy changed, refresh fixtures per interop/README.md",
					tc.Name, resp.Decision, tc.ExpectedDecision,
					tc.SubjectID, tc.Action, tc.ResourceType, tc.ResourceID)
			}
		})
	}
}

// probeLivePDP issues a short HEAD against the public PDP base URL and
// skips the test (rather than failing it) when the endpoint is
// unreachable — captive networks, offline laptops, runners with no
// outbound HTTPS. A skip with a descriptive message is the right
// signal for "network unreachable", as opposed to the confusing
// connect-timeout failure a bare client call would surface several
// seconds later inside the first subtest.
//
// A non-2xx HEAD response is treated as reachable: some upstream load
// balancers reject HEAD with 405 but accept the POSTs the real test
// then issues. Only network-level failures (DNS, connect, timeout)
// trigger the skip.
func probeLivePDP(t *testing.T) {
	t.Helper()
	u, err := url.Parse(interop.PublicPDPBaseURL)
	if err != nil {
		t.Fatalf("parse PublicPDPBaseURL: %v", err)
	}
	probe := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodHead, u.String(), nil)
	if err != nil {
		t.Fatalf("build probe request: %v", err)
	}
	resp, err := probe.Do(req)
	if err != nil {
		t.Skipf("live PDP %s unreachable: %v", interop.PublicPDPBaseURL, err)
	}
	_ = resp.Body.Close()
}
