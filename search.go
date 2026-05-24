// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen

import "encoding/json"

// SubjectSearchRequest asks the PDP "which subjects of this type can
// perform this action on this resource?" Per spec §6.3.1, the Subject
// carries only Type (its ID is omitted or ignored — the field exists
// in [Subject] for the single-evaluation case and stays empty here),
// and Action and Resource are fully specified.
type SubjectSearchRequest struct {
	Subject  Subject         `json:"subject"`
	Action   Action          `json:"action"`
	Resource Resource        `json:"resource"`
	Context  json.RawMessage `json:"context,omitempty"`
	Page     *PageRequest    `json:"page,omitempty"`
}

// SubjectSearchResponse is the response to a Subject Search (spec
// §6.3.1). Results contains the matching subjects in full (Type, ID,
// Properties). Page is present when results are paginated — see
// [PageResponse] for the empty-string NextToken sentinel that signals
// end-of-results.
type SubjectSearchResponse struct {
	Page    *PageResponse   `json:"page,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
	Results []Subject       `json:"results"`
}

// ResourceSearchRequest asks the PDP "which resources of this type can
// this subject perform this action on?" Per spec §6.3.2 the Resource
// carries only Type (its ID is omitted or ignored), Subject is fully
// specified (Type + ID), and Action carries Name.
type ResourceSearchRequest struct {
	Subject  Subject         `json:"subject"`
	Action   Action          `json:"action"`
	Resource Resource        `json:"resource"`
	Context  json.RawMessage `json:"context,omitempty"`
	Page     *PageRequest    `json:"page,omitempty"`
}

// ResourceSearchResponse is the response to a Resource Search (spec
// §6.3.2). Results contains the matching resources in full.
type ResourceSearchResponse struct {
	Page    *PageResponse   `json:"page,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
	Results []Resource      `json:"results"`
}

// ActionSearchRequest asks the PDP "which actions can this subject
// perform on this resource?" Per spec §6.3.3 the request body has
// NO `action` field — the implementer pin DESIGN.md §wire-fidelity
// calls out. This Go type deliberately mirrors that: only Subject,
// Resource, Context, and Page. There is no Action field.
//
// SubjectSearchRequest and ResourceSearchRequest each keep their
// pivot type (Subject and Resource respectively) with ID omitted;
// ActionSearchRequest is the asymmetric one, omitting the whole
// action object. Encoding a value of this type emits no `"action"`
// key in the JSON; consumers that need to know "which action search
// is this" inspect the endpoint URL (per spec §6).
type ActionSearchRequest struct {
	Subject  Subject         `json:"subject"`
	Resource Resource        `json:"resource"`
	Context  json.RawMessage `json:"context,omitempty"`
	Page     *PageRequest    `json:"page,omitempty"`
}

// ActionSearchResponse is the response to an Action Search (spec
// §6.3.3). Results contains the matching actions in full (Name +
// Properties).
type ActionSearchResponse struct {
	Page    *PageResponse   `json:"page,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
	Results []Action        `json:"results"`
}
