// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/server"
)

func TestBuildMetadata_FullDecider_AdvertisesEveryEndpoint(t *testing.T) {
	// A Decider that implements every endpoint (no ErrNotImplemented
	// fall-throughs) should produce a metadata document with all
	// five endpoint URLs populated.
	d := &staticDecider{
		evalResp:   &authzen.EvaluationResponse{Decision: true},
		evalsResp:  &authzen.EvaluationsResponse{},
		searchSubR: &authzen.SubjectSearchResponse{},
		searchResR: &authzen.ResourceSearchResponse{},
		searchActR: &authzen.ActionSearchResponse{},
	}
	m := server.BuildMetadata("https://pdp.example.com", d)
	if m.PolicyDecisionPoint != "https://pdp.example.com" {
		t.Errorf("PolicyDecisionPoint = %q, want %q", m.PolicyDecisionPoint, "https://pdp.example.com")
	}
	if m.AccessEvaluationEndpoint != "https://pdp.example.com"+authzen.EvaluationEndpoint {
		t.Errorf("AccessEvaluationEndpoint = %q", m.AccessEvaluationEndpoint)
	}
	if m.AccessEvaluationsEndpoint == "" {
		t.Error("AccessEvaluationsEndpoint empty, want populated")
	}
	if m.SearchSubjectEndpoint == "" {
		t.Error("SearchSubjectEndpoint empty, want populated")
	}
	if m.SearchResourceEndpoint == "" {
		t.Error("SearchResourceEndpoint empty, want populated")
	}
	if m.SearchActionEndpoint == "" {
		t.Error("SearchActionEndpoint empty, want populated")
	}
}

func TestBuildMetadata_PartialDecider_AdvertisesOnlyImplemented(t *testing.T) {
	// The load-bearing test: a partial Decider (Evaluate +
	// Evaluations only, NotImplementedDecider for the rest) should
	// produce a metadata document advertising only the two
	// implemented endpoints. The PEP that honors the document never
	// hits the search endpoints — primary signal per spec §9.1.1.
	d := &staticDecider{
		evalResp:  &authzen.EvaluationResponse{Decision: true},
		evalsResp: &authzen.EvaluationsResponse{},
		// search* fields remain zero — NotImplementedDecider returns
		// ErrNotImplemented from each search method.
		searchSubErr: authzen.ErrNotImplemented,
		searchResErr: authzen.ErrNotImplemented,
		searchActErr: authzen.ErrNotImplemented,
	}
	m := server.BuildMetadata("https://pdp.example.com", d)
	if m.AccessEvaluationEndpoint == "" {
		t.Error("AccessEvaluationEndpoint empty, want populated")
	}
	if m.AccessEvaluationsEndpoint == "" {
		t.Error("AccessEvaluationsEndpoint empty, want populated (Decider implements it)")
	}
	if m.SearchSubjectEndpoint != "" {
		t.Errorf("SearchSubjectEndpoint = %q, want empty (not implemented)", m.SearchSubjectEndpoint)
	}
	if m.SearchResourceEndpoint != "" {
		t.Errorf("SearchResourceEndpoint = %q, want empty", m.SearchResourceEndpoint)
	}
	if m.SearchActionEndpoint != "" {
		t.Errorf("SearchActionEndpoint = %q, want empty", m.SearchActionEndpoint)
	}
}

func TestBuildMetadata_EvaluateOnlyDecider(t *testing.T) {
	// A PDP that ships ONLY single-decision Evaluate — the minimal
	// conforming PDP. Metadata advertises just access_evaluation_endpoint;
	// every other endpoint URL is absent.
	d := &staticDecider{
		evalResp:     &authzen.EvaluationResponse{Decision: true},
		evalsErr:     authzen.ErrNotImplemented,
		searchSubErr: authzen.ErrNotImplemented,
		searchResErr: authzen.ErrNotImplemented,
		searchActErr: authzen.ErrNotImplemented,
	}
	m := server.BuildMetadata("https://pdp.example.com", d)
	if m.AccessEvaluationEndpoint == "" {
		t.Error("AccessEvaluationEndpoint empty, want populated")
	}
	if m.AccessEvaluationsEndpoint != "" {
		t.Errorf("AccessEvaluationsEndpoint = %q, want empty", m.AccessEvaluationsEndpoint)
	}
	if m.SearchSubjectEndpoint != "" || m.SearchResourceEndpoint != "" || m.SearchActionEndpoint != "" {
		t.Error("search endpoints leaked into metadata for an Evaluate-only Decider")
	}
}

func TestBuildMetadata_RequiredFieldAlwaysPopulated(t *testing.T) {
	// Even a fully-non-implemented Decider produces a document with
	// AccessEvaluationEndpoint set — the spec REQUIRES that field, and
	// hiding it would just produce a non-conformant metadata document.
	// The broken PDP is exposed at the handler layer (501s) rather
	// than papered over.
	d := &staticDecider{
		evalErr:      authzen.ErrNotImplemented,
		evalsErr:     authzen.ErrNotImplemented,
		searchSubErr: authzen.ErrNotImplemented,
		searchResErr: authzen.ErrNotImplemented,
		searchActErr: authzen.ErrNotImplemented,
	}
	m := server.BuildMetadata("https://pdp.example.com", d)
	if m.AccessEvaluationEndpoint == "" {
		t.Error("AccessEvaluationEndpoint must always be set even if Decider doesn't implement Evaluate")
	}
}

func TestBuildMetadata_TrimsTrailingSlash(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	d.evalsErr = authzen.ErrNotImplemented
	d.searchSubErr = authzen.ErrNotImplemented
	d.searchResErr = authzen.ErrNotImplemented
	d.searchActErr = authzen.ErrNotImplemented
	m := server.BuildMetadata("https://pdp.example.com/", d)
	// Endpoint URL must NOT double the slash.
	if strings.Contains(m.AccessEvaluationEndpoint, "//access") {
		t.Errorf("AccessEvaluationEndpoint = %q has doubled slash", m.AccessEvaluationEndpoint)
	}
}

func TestBuildMetadata_WithCapability(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	d.evalsErr = authzen.ErrNotImplemented
	d.searchSubErr = authzen.ErrNotImplemented
	d.searchResErr = authzen.ErrNotImplemented
	d.searchActErr = authzen.ErrNotImplemented
	m := server.BuildMetadata("https://pdp.example.com", d,
		server.WithCapability("urn:ietf:params:authzen:example.cap-1"),
		server.WithCapability("urn:ietf:params:authzen:example.cap-2"),
	)
	if len(m.Capabilities) != 2 {
		t.Fatalf("Capabilities = %v, want 2 entries", m.Capabilities)
	}
	if m.Capabilities[0] != "urn:ietf:params:authzen:example.cap-1" {
		t.Errorf("Capabilities[0] = %q", m.Capabilities[0])
	}
}

func TestBuildMetadata_WithSignedMetadata(t *testing.T) {
	d := &staticDecider{evalResp: &authzen.EvaluationResponse{Decision: true}}
	d.evalsErr = authzen.ErrNotImplemented
	d.searchSubErr = authzen.ErrNotImplemented
	d.searchResErr = authzen.ErrNotImplemented
	d.searchActErr = authzen.ErrNotImplemented
	jws := json.RawMessage(`"eyJhbGciOiJIUzI1NiJ9.placeholder.signature"`)
	m := server.BuildMetadata("https://pdp.example.com", d, server.WithSignedMetadata(jws))
	if string(m.SignedMetadata) != string(jws) {
		t.Errorf("SignedMetadata = %s, want %s", string(m.SignedMetadata), string(jws))
	}
}

func TestMetadataHandler_GETReturnsJSON(t *testing.T) {
	m := &authzen.Metadata{
		PolicyDecisionPoint:      "https://pdp.example.com",
		AccessEvaluationEndpoint: "https://pdp.example.com/access/v1/evaluation",
	}
	srv := httptest.NewServer(server.NewMetadataHandler(m))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + authzen.MetadataPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	var got authzen.Metadata
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.PolicyDecisionPoint != m.PolicyDecisionPoint {
		t.Errorf("PolicyDecisionPoint round-trip lost the value: got %q, want %q", got.PolicyDecisionPoint, m.PolicyDecisionPoint)
	}
}

func TestMetadataHandler_PostReturns405(t *testing.T) {
	m := &authzen.Metadata{PolicyDecisionPoint: "https://pdp.example.com"}
	srv := httptest.NewServer(server.NewMetadataHandler(m))
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+authzen.MetadataPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("StatusCode = %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow header = %q, want GET", allow)
	}
}
