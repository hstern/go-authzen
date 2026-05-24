// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen

import "encoding/json"

// EvaluationRequest is the body of a single Access Evaluation request
// (spec §6.1.1). Subject, Action, and Resource are REQUIRED — the
// library's marshal-time validation rejects a request that omits any
// of them with a [*ValidationError]. Context carries an optional
// open extension payload.
type EvaluationRequest struct {
	Subject  Subject         `json:"subject"`
	Action   Action          `json:"action"`
	Resource Resource        `json:"resource"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// EvaluationResponse is the body of an Access Evaluation response
// (spec §6.1.2). Decision is REQUIRED — the spec encodes both permit
// and deny as HTTP 200 with the decision boolean: deny is decision
// false, NOT a 4xx status.
//
// Context carries an optional open extension payload — PDPs may
// return advisory information (obligations, advice, reason) by
// populating it with a typed extension (see [DecodeJSON]).
type EvaluationResponse struct {
	Decision bool            `json:"decision"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// EvaluationsRequest is the body of a batch Access Evaluations request
// (spec §6.2.1). The top-level Subject, Action, Resource, and Context
// are inherited DEFAULTS for any [EvaluationsItem] in Evaluations that
// omits the corresponding field — a PEP can express "evaluate these
// five actions for the same subject and resource" by setting the
// top-level Subject and Resource and leaving each item to vary its
// Action.
//
// At least one of the top-level defaults or each item's per-field
// override must supply a value for Subject, Action, and Resource;
// the library's marshal-time validation rejects a request where an
// item is missing a required field even after default-merging.
//
// Options carries the batch's optional execution semantic; nil means
// the default ([EvaluationsSemanticExecuteAll]).
type EvaluationsRequest struct {
	Subject     *Subject            `json:"subject,omitempty"`
	Action      *Action             `json:"action,omitempty"`
	Resource    *Resource           `json:"resource,omitempty"`
	Context     json.RawMessage     `json:"context,omitempty"`
	Evaluations []EvaluationsItem   `json:"evaluations"`
	Options     *EvaluationsOptions `json:"options,omitempty"`
}

// EvaluationsItem is one item in the Evaluations array of an
// [EvaluationsRequest]. Each field is OPTIONAL at the item level
// because it may be inherited from the request's top-level defaults
// (spec §6.2.1); whichever level provides a value, the effective
// item must end up with Subject, Action, and Resource.
type EvaluationsItem struct {
	Subject  *Subject        `json:"subject,omitempty"`
	Action   *Action         `json:"action,omitempty"`
	Resource *Resource       `json:"resource,omitempty"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// EvaluationsResponse is the body of a batch Access Evaluations
// response (spec §6.2.2). Evaluations contains exactly one decision
// per item in the request, in the same order as the request items.
//
// Per spec the top-level response carries no decision field of its
// own — Decision per-item lives in each [EvaluationResponse]. A
// short-circuit semantic (DenyOnFirstDeny or PermitOnFirstPermit)
// may stop the PDP early, in which case the array is shorter than
// the request's Evaluations.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// EvaluationsOptions carries the batch execution-semantic option
// (spec §6.2.1, the `options.evaluations_semantic` field).
type EvaluationsOptions struct {
	EvaluationsSemantic EvaluationsSemantic `json:"evaluations_semantic,omitempty"`
}

// EvaluationsSemantic chooses how a PDP processes the Evaluations
// array of a batch request (spec §6.2.1, the "evaluations_semantic"
// field). The spec defines three values; any other value is a wire-
// shape error.
type EvaluationsSemantic string

// Defined values of [EvaluationsSemantic]. The default when the
// option is omitted is [EvaluationsSemanticExecuteAll].
const (
	// EvaluationsSemanticExecuteAll evaluates every item in the
	// Evaluations array (the default).
	EvaluationsSemanticExecuteAll EvaluationsSemantic = "execute_all"

	// EvaluationsSemanticDenyOnFirstDeny stops as soon as any item
	// evaluates to false; the response array is truncated at that
	// item.
	EvaluationsSemanticDenyOnFirstDeny EvaluationsSemantic = "deny_on_first_deny"

	// EvaluationsSemanticPermitOnFirstPermit stops as soon as any
	// item evaluates to true; the response array is truncated at
	// that item.
	EvaluationsSemanticPermitOnFirstPermit EvaluationsSemantic = "permit_on_first_permit"
)
