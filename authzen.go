// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

// Package authzen implements the OpenID AuthZEN Authorization API 1.0
// wire protocol — the PEP↔PDP communication between a Policy
// Enforcement Point and a Policy Decision Point for fine-grained
// authorization decisions.
//
// This package and its subpackages (client, server, interop) together
// form a library-vendor-neutral Go implementation of the spec at
// https://openid.net/specs/authorization-api-1_0.html.
//
// Pre-v0.1.0: the surface is being built out in phased PRs. See
// CHANGELOG.md for what has landed, DESIGN.md for the rationale, and
// AGENTS.md for the contributor conventions.
package authzen

import (
	"errors"
	"fmt"
)

// SpecVersion is the OpenID AuthZEN Authorization API version this
// build implements. The spec reached Final on 2026-01-11; the library
// tracks 1.0 until AuthZEN itself ships a major.
const SpecVersion = "1.0"

// Default endpoint paths. Per AuthZEN 1.0 §6 these are the
// spec-suggested defaults — a conformant PDP advertises its actual
// endpoint URLs via the metadata document at [MetadataPath], and a
// PEP MUST honor those over the defaults. The constants exist so the
// client and server packages can wire the defaults without hardcoding
// strings.
const (
	// EvaluationEndpoint is the default path for the single-decision
	// endpoint (spec §6.1).
	EvaluationEndpoint = "/access/v1/evaluation"

	// EvaluationsEndpoint is the default path for the batch-decision
	// endpoint (spec §6.2).
	EvaluationsEndpoint = "/access/v1/evaluations"

	// SearchSubjectEndpoint is the default path for the
	// "which subjects of this type can do this action on this resource"
	// search (spec §6.3.1).
	SearchSubjectEndpoint = "/access/v1/search/subject"

	// SearchResourceEndpoint is the default path for the
	// "which resources of this type can this subject do this action on"
	// search (spec §6.3.2).
	SearchResourceEndpoint = "/access/v1/search/resource"

	// SearchActionEndpoint is the default path for the
	// "which actions can this subject do on this resource" search
	// (spec §6.3.3). Note that the request body for Action Search omits
	// the action field entirely — see [ActionSearchRequest].
	SearchActionEndpoint = "/access/v1/search/action"
)

// MetadataPath is the well-known path at which a PDP publishes its
// configuration document (spec §9.1). The full URL is the PDP base
// URL plus this path.
const MetadataPath = "/.well-known/authzen-configuration"

// HTTPHeaderRequestID is the HTTP header carrying a PEP-generated
// per-request identifier (spec §2.4). PEPs SHOULD send it on outbound
// requests; PDPs SHOULD echo it back on responses. The library's
// server middleware does the echo automatically.
const HTTPHeaderRequestID = "X-Request-ID"

// ErrNotImplemented is the sentinel a [Decider] method returns when the
// PDP does not implement that endpoint. The HTTP layer maps it to
// status 501 Not Implemented (spec §5.1 + §9.1.1 — see the discussion in
// DESIGN.md §7).
//
// Match it with [errors.Is]; do not compare directly. PDPs that
// implement only a subset of the [Decider] interface should embed
// [NotImplementedDecider] and override the methods they support; the
// embedded zero-value returns ErrNotImplemented for the rest.
var ErrNotImplemented = errors.New("authzen: endpoint not implemented")

// ValidationError is returned when a request or response fails the
// library's marshal-time wire-shape validation (spec-mandated required
// field missing, type/format mismatch, etc.). Per DESIGN.md §5 the
// library is strict on outbound serialization and lenient on inbound
// deserialization, so consumers will see ValidationError exclusively
// from the encode path.
//
// Field is the dotted JSON path of the offending field (e.g. "subject"
// or "evaluations[2].action.name"). Reason is a short, lower-cased,
// no-trailing-period reason — suitable for prefixing with the field
// path. Cause is an optional wrapped error from the underlying decoder
// or sub-validator; [errors.Unwrap] returns it.
type ValidationError struct {
	Field  string
	Reason string
	Cause  error
}

// Error returns the formatted "field: reason" message. Both Field and
// Reason are required by convention — callers should always set both.
// If a Cause is wrapped its message is appended.
func (e *ValidationError) Error() string {
	switch {
	case e.Field != "" && e.Reason != "" && e.Cause != nil:
		return fmt.Sprintf("authzen: %s: %s: %v", e.Field, e.Reason, e.Cause)
	case e.Field != "" && e.Reason != "":
		return fmt.Sprintf("authzen: %s: %s", e.Field, e.Reason)
	case e.Reason != "":
		return "authzen: " + e.Reason
	default:
		return "authzen: validation error"
	}
}

// Unwrap returns the wrapped Cause so [errors.Is] and [errors.As] walk
// through ValidationError to a deeper sentinel or typed error.
func (e *ValidationError) Unwrap() error { return e.Cause }
