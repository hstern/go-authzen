// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hstern/go-authzen"
)

// MetadataOption customizes the [authzen.Metadata] document produced
// by [BuildMetadata]. Use the predefined options to add capability
// URNs or to override an endpoint URL.
type MetadataOption func(*authzen.Metadata)

// WithCapability appends a capability URN to the metadata document's
// Capabilities list (spec §9.1.2). URNs come from the IANA
// "AuthZEN Policy Decision Point Capabilities" registry under
// urn:ietf:params:authzen:* — the library does not validate the URN
// against the registry (the registry is open and currently empty).
func WithCapability(urn string) MetadataOption {
	return func(m *authzen.Metadata) {
		m.Capabilities = append(m.Capabilities, urn)
	}
}

// WithSignedMetadata sets the [authzen.Metadata] SignedMetadata
// field to the supplied JWS-encoded bytes. The library does not
// produce or verify a JWS in v0.1; consumers that want signed
// metadata produce the JWS with their own JOSE library and pass
// the bytes here. The bytes are emitted verbatim on the wire.
func WithSignedMetadata(jws json.RawMessage) MetadataOption {
	return func(m *authzen.Metadata) {
		m.SignedMetadata = jws
	}
}

// BuildMetadata returns the [authzen.Metadata] document that
// describes the PDP fronted by d, mounted at pdpURL. The function
// introspects d by calling each optional-endpoint method with a
// zero-value request and checking the returned error against
// [authzen.ErrNotImplemented] — the endpoint URL appears in the
// document only when the corresponding method does NOT return that
// sentinel.
//
// AccessEvaluationEndpoint is always populated (spec §9.1 requires
// it) regardless of whether d.Evaluate returns ErrNotImplemented;
// a PDP that doesn't implement Evaluate is not a working PDP and
// the metadata document accurately reflects the configured URL.
// Treat that case as a consumer bug to be surfaced at the handler
// layer (501 on any call) rather than hidden by omitting the URL.
//
// pdpURL is the PDP's HTTPS base URL. BuildMetadata trims a
// trailing slash so subsequent path concatenation produces the
// canonical /access/v1/... shape. PolicyDecisionPoint in the
// returned document is set to pdpURL verbatim; a PEP that fetches
// the document will compare PolicyDecisionPoint against the URL it
// fetched from, so the caller must keep these consistent.
//
// The introspection is a one-shot at handler-build time. The
// zero-value probe is invasive (the Decider sees calls it didn't
// originate from a PEP); Deciders that log per-call should expect
// one probe call per optional method when BuildMetadata runs.
func BuildMetadata(pdpURL string, d Decider, opts ...MetadataOption) *authzen.Metadata {
	base := strings.TrimRight(pdpURL, "/")
	m := &authzen.Metadata{
		PolicyDecisionPoint:      pdpURL,
		AccessEvaluationEndpoint: base + authzen.EvaluationEndpoint,
	}

	ctx := context.Background()
	if implements(func() error {
		_, err := d.Evaluations(ctx, &authzen.EvaluationsRequest{})
		return err
	}) {
		m.AccessEvaluationsEndpoint = base + authzen.EvaluationsEndpoint
	}
	if implements(func() error {
		_, err := d.SearchSubject(ctx, &authzen.SubjectSearchRequest{})
		return err
	}) {
		m.SearchSubjectEndpoint = base + authzen.SearchSubjectEndpoint
	}
	if implements(func() error {
		_, err := d.SearchResource(ctx, &authzen.ResourceSearchRequest{})
		return err
	}) {
		m.SearchResourceEndpoint = base + authzen.SearchResourceEndpoint
	}
	if implements(func() error {
		_, err := d.SearchAction(ctx, &authzen.ActionSearchRequest{})
		return err
	}) {
		m.SearchActionEndpoint = base + authzen.SearchActionEndpoint
	}

	for _, opt := range opts {
		opt(m)
	}
	return m
}

// implements returns true when probe does NOT return
// authzen.ErrNotImplemented (any other return value — nil, an
// unrelated error, even a panic recovered upstream — counts as
// "the method is implemented and ran"). A method that ran and
// errored is by definition not the unimplemented stub.
func implements(probe func() error) bool {
	return !errors.Is(probe(), authzen.ErrNotImplemented)
}

// NewMetadataHandler returns an [http.Handler] that serves the
// metadata document at any path; consumers mount it at
// [authzen.MetadataPath] (`/.well-known/authzen-configuration`).
//
// The handler responds to GET only — POST and other methods return
// 405 Method Not Allowed. The response is JSON with
// Content-Type: application/json (spec §9.1).
//
// The Metadata document is captured by value at construction; a
// future update is a new handler.
func NewMetadataHandler(m *authzen.Metadata) http.Handler {
	body, _ := json.Marshal(m) // *authzen.Metadata always marshals (only json-tagged primitives + slices/RawMessage)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}
