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

// Validate reports whether r is a well-formed Subject Search request
// per spec §6.3.1: Subject.Type is REQUIRED (Subject.ID is omitted
// or ignored); Action.Name is REQUIRED; Resource.Type AND Resource.ID
// are both REQUIRED (a Subject Search asks "of all subjects of this
// type, which can do this action on this specific resource?").
//
// Returns a [*ValidationError] for the first problem found, or nil
// if r is valid.
func (r *SubjectSearchRequest) Validate() error {
	if r == nil {
		return &ValidationError{Reason: "nil SubjectSearchRequest"}
	}
	if r.Subject.Type == "" {
		return &ValidationError{Field: "subject.type", Reason: "required"}
	}
	if r.Action.Name == "" {
		return &ValidationError{Field: "action.name", Reason: "required"}
	}
	if r.Resource.Type == "" {
		return &ValidationError{Field: "resource.type", Reason: "required"}
	}
	if r.Resource.ID == "" {
		return &ValidationError{Field: "resource.id", Reason: "required"}
	}
	return nil
}

// Validate reports whether r is a well-formed Resource Search request
// per spec §6.3.2: Subject.Type AND Subject.ID are REQUIRED (the
// search is anchored to a specific subject); Action.Name is REQUIRED;
// Resource.Type is REQUIRED (Resource.ID is omitted or ignored — the
// search asks "of all resources of this type, which can this subject
// do this action on?").
//
// Returns a [*ValidationError] for the first problem found, or nil
// if r is valid.
func (r *ResourceSearchRequest) Validate() error {
	if r == nil {
		return &ValidationError{Reason: "nil ResourceSearchRequest"}
	}
	if r.Subject.Type == "" {
		return &ValidationError{Field: "subject.type", Reason: "required"}
	}
	if r.Subject.ID == "" {
		return &ValidationError{Field: "subject.id", Reason: "required"}
	}
	if r.Action.Name == "" {
		return &ValidationError{Field: "action.name", Reason: "required"}
	}
	if r.Resource.Type == "" {
		return &ValidationError{Field: "resource.type", Reason: "required"}
	}
	return nil
}

// Validate reports whether r is a well-formed Action Search request
// per spec §6.3.3: Subject.Type AND Subject.ID are REQUIRED;
// Resource.Type AND Resource.ID are REQUIRED. The request body
// contains no action field at all — the spec defines that on the
// endpoint side, and the type omits the Action field accordingly
// (see ActionSearchRequest's godoc).
//
// Returns a [*ValidationError] for the first problem found, or nil
// if r is valid.
func (r *ActionSearchRequest) Validate() error {
	if r == nil {
		return &ValidationError{Reason: "nil ActionSearchRequest"}
	}
	if r.Subject.Type == "" {
		return &ValidationError{Field: "subject.type", Reason: "required"}
	}
	if r.Subject.ID == "" {
		return &ValidationError{Field: "subject.id", Reason: "required"}
	}
	if r.Resource.Type == "" {
		return &ValidationError{Field: "resource.type", Reason: "required"}
	}
	if r.Resource.ID == "" {
		return &ValidationError{Field: "resource.id", Reason: "required"}
	}
	return nil
}
