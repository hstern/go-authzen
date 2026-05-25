// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen

import "encoding/json"

// Metadata is the PDP configuration document a Policy Decision Point
// publishes at [MetadataPath] (spec §9.1). PEPs discover which
// endpoints the PDP supports by fetching the document and reading
// the per-endpoint URL fields — the absence of a field is the
// canonical "PDP does not implement this endpoint" signal (spec
// §9.1.1).
//
// PolicyDecisionPoint and AccessEvaluationEndpoint are REQUIRED;
// all other URL fields are OPTIONAL and present only when the
// corresponding endpoint is implemented.
//
// PolicyDecisionPoint MUST equal the URL at which the metadata
// document was fetched — a PEP that sees a mismatch MUST reject
// the document (spec §9.1.1 — mix-up attack defense). The client's
// [github.com/hstern/go-authzen/client.Client.FetchMetadata]
// enforces this by default.
//
// signed_metadata (spec §9.1, RFC 7515 JWS) is exposed as
// [json.RawMessage] so the v0.1 library can round-trip the field
// byte-stably without taking a JOSE dependency. v0.2 will add
// produce-and-verify support; until then, consumers that want
// signed metadata plug their own JOSE verifier on the bytes.
type Metadata struct {
	// PolicyDecisionPoint is the PDP's HTTPS base URL with no query
	// or fragment (spec §9.1.1). REQUIRED.
	PolicyDecisionPoint string `json:"policy_decision_point"`

	// AccessEvaluationEndpoint is the URL of the single-decision
	// Evaluate endpoint (spec §6.1). REQUIRED — every conformant
	// PDP must implement at least this endpoint.
	AccessEvaluationEndpoint string `json:"access_evaluation_endpoint,omitempty"`

	// AccessEvaluationsEndpoint is the URL of the batch endpoint
	// (spec §6.2). OPTIONAL — absence means the PDP does not
	// implement batch evaluation.
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint,omitempty"`

	// SearchSubjectEndpoint is the URL of the Subject Search
	// endpoint (spec §6.3.1). OPTIONAL.
	SearchSubjectEndpoint string `json:"search_subject_endpoint,omitempty"`

	// SearchResourceEndpoint is the URL of the Resource Search
	// endpoint (spec §6.3.2). OPTIONAL.
	SearchResourceEndpoint string `json:"search_resource_endpoint,omitempty"`

	// SearchActionEndpoint is the URL of the Action Search
	// endpoint (spec §6.3.3). OPTIONAL.
	SearchActionEndpoint string `json:"search_action_endpoint,omitempty"`

	// Capabilities is the optional list of capability URNs the PDP
	// advertises (spec §9.1.2 / §12.3). Each URN comes from the
	// IANA "AuthZEN Policy Decision Point Capabilities" registry
	// under the urn:ietf:params:authzen:* namespace.
	//
	// The library exposes the field but does NOT enumerate any
	// "known" capability values — the registry is open with no
	// meaningful entries at the time of this writing, and the
	// library will only enumerate values once the registry has
	// content the consumer code can usefully switch on.
	Capabilities []string `json:"capabilities,omitempty"`

	// SignedMetadata is the optional JWS-encoded signed form of
	// this metadata document (spec §9.1, RFC 7515). When present,
	// the JWS takes precedence over the plain fields above.
	//
	// v0.1 of this library treats SignedMetadata as opaque bytes —
	// it does NOT produce a JWS on the server side and does NOT
	// verify a JWS on the client side. A forward-compatible PEP
	// that wants verification plugs its own JOSE verifier on the
	// raw bytes. Produce/verify support lands in v0.2 along with
	// the JOSE dependency.
	SignedMetadata json.RawMessage `json:"signed_metadata,omitempty"`
}
