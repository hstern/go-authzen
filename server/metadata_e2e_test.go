// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hstern/go-authzen/v1"
	"github.com/hstern/go-authzen/v1/client"
	"github.com/hstern/go-authzen/v1/server"
)

// TestE2E_PartialDecider_MetadataAdvertisesOnlyImplemented is the
// AUTHZEN-26 acceptance scenario: a partial Decider that ships
// Evaluate + Evaluations only. The handler returns 501 for the
// search endpoints AND the metadata document advertises only the
// two implemented endpoints. The client's FetchMetadata sees the
// right endpoint set and rejects a mix-up attack against the
// returned document.
//
// This wires every phase-5 surface together end-to-end: server
// (BuildMetadata + NewMetadataHandler + NewHandler with a partial
// Decider) and client (FetchMetadata with the hard-fail mix-up
// check).
func TestE2E_PartialDecider_MetadataAdvertisesOnlyImplemented(t *testing.T) {
	d := &staticDecider{
		evalResp:     &authzen.EvaluationResponse{Decision: true},
		evalsResp:    &authzen.EvaluationsResponse{},
		searchSubErr: authzen.ErrNotImplemented,
		searchResErr: authzen.ErrNotImplemented,
		searchActErr: authzen.ErrNotImplemented,
	}

	// Build a mux that serves the metadata at the well-known path
	// AND the AuthZEN endpoints at their spec paths. PDP URL is the
	// httptest server's URL once it starts.
	mux := http.NewServeMux()
	mux.Handle(authzen.EvaluationEndpoint, server.NewHandler(d))
	mux.Handle(authzen.EvaluationsEndpoint, server.NewHandler(d))
	mux.Handle(authzen.SearchSubjectEndpoint, server.NewHandler(d))
	mux.Handle(authzen.SearchResourceEndpoint, server.NewHandler(d))
	mux.Handle(authzen.SearchActionEndpoint, server.NewHandler(d))
	// metadata handler installed after we know the server URL
	srv := httptest.NewUnstartedServer(mux)
	srv.Start()
	t.Cleanup(srv.Close)
	mux.Handle(authzen.MetadataPath, server.NewMetadataHandler(server.BuildMetadata(srv.URL, d)))

	// 1) PEP fetches metadata; sees ONLY the two implemented
	//    endpoints.
	c, _ := client.NewClient(srv.URL)
	m, err := c.FetchMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchMetadata: %v", err)
	}
	if m.AccessEvaluationEndpoint == "" {
		t.Error("AccessEvaluationEndpoint empty — partial Decider should still advertise required endpoint")
	}
	if m.AccessEvaluationsEndpoint == "" {
		t.Error("AccessEvaluationsEndpoint empty — Decider implements Evaluations")
	}
	if m.SearchSubjectEndpoint != "" {
		t.Errorf("SearchSubjectEndpoint = %q, want empty (Decider doesn't implement)", m.SearchSubjectEndpoint)
	}
	if m.SearchResourceEndpoint != "" {
		t.Errorf("SearchResourceEndpoint = %q, want empty", m.SearchResourceEndpoint)
	}
	if m.SearchActionEndpoint != "" {
		t.Errorf("SearchActionEndpoint = %q, want empty", m.SearchActionEndpoint)
	}
	if m.PolicyDecisionPoint != srv.URL {
		t.Errorf("PolicyDecisionPoint = %q, want %q", m.PolicyDecisionPoint, srv.URL)
	}

	// 2) The implemented endpoint works.
	resp, err := c.Evaluate(context.Background(), validEvalReq())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !resp.Decision {
		t.Error("Decision = false, want true")
	}

	// 3) The unimplemented endpoints return 501 — the handler
	//    fallback for PEPs that bypass metadata discovery.
	_, err = c.SearchAction(context.Background(), &authzen.ActionSearchRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	if err == nil {
		t.Fatal("nil error from SearchAction on partial Decider; want 501")
	}
	var se *client.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is not *StatusError: %v", err)
	}
	if se.StatusCode != http.StatusNotImplemented {
		t.Errorf("SearchAction StatusCode = %d, want 501", se.StatusCode)
	}
}

func TestE2E_FetchMetadata_RejectsMixUpAttack(t *testing.T) {
	// A separate server stands up returning a metadata document
	// claiming to be a DIFFERENT PDP. A client targeting our test
	// server must refuse the document — that's the spec §9.1.1
	// mix-up defense.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"policy_decision_point":"https://attacker.example.com","access_evaluation_endpoint":"/x"}`))
	}))
	t.Cleanup(srv.Close)
	c, _ := client.NewClient(srv.URL)
	_, err := c.FetchMetadata(context.Background())
	if err == nil {
		t.Fatal("nil error on mix-up; want *MixUpError")
	}
	var me *client.MixUpError
	if !errors.As(err, &me) {
		t.Fatalf("error is not *MixUpError: %v", err)
	}
}
