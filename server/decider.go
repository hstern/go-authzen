// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

// Package server implements the PDP side of the OpenID AuthZEN
// Authorization API 1.0 wire — an [http.Handler] over a
// consumer-supplied [Decider] that decides authorization questions.
//
// Implement [Decider] for whichever endpoints your PDP supports;
// embed [NotImplementedDecider] for the rest. Mount the result with
// [NewHandler] under your existing mux:
//
//	type myPDP struct{ server.NotImplementedDecider }
//	func (p *myPDP) Evaluate(...) (...) { ... }
//	mux.Handle("/access/v1/", server.NewHandler(&myPDP{}))
//
// The contract DESIGN.md §wire-fidelity calls out: a policy-deny
// outcome — returning &authzen.EvaluationResponse{Decision: false},
// nil — emits HTTP 200 with {"decision": false} on the wire, NEVER a
// 4xx. The handler's status-code mapping treats nil-error + non-nil
// response as success regardless of the Decision value.
package server

import (
	"context"

	"github.com/hstern/go-authzen/v1"
)

// Decider is the contract a PDP implements: one method per AuthZEN
// endpoint (spec §6). The library's [NewHandler] adapts a Decider
// to an [http.Handler], translating method calls into HTTP requests
// and back.
//
// A PDP that does not implement an endpoint should embed
// [NotImplementedDecider] and override only the methods it
// supports. Methods that remain at the embedded zero-value return
// [authzen.ErrNotImplemented]; the handler maps that to HTTP 501,
// and the metadata builder (AUTHZEN-22, future phase 5) introspects
// the Decider and advertises only the implemented endpoints to PEPs
// that honor the metadata document.
//
// Decider methods receive a [context.Context] that the handler
// derives from the inbound HTTP request; honoring its cancellation
// is the PDP's responsibility.
type Decider interface {
	// Evaluate decides a single authorization question (spec §6.1).
	// Returning {Decision: false} on a 200 is a legal policy deny;
	// do NOT return a non-nil error for a deny.
	Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)

	// Evaluations decides a batch of authorization questions (spec
	// §6.2). The response Evaluations array is in the same order
	// as the request items; per-item deny lives as
	// {Decision: false} entries, not as errors.
	Evaluations(ctx context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error)

	// SearchSubject answers "which subjects of this type can do
	// this action on this resource?" (spec §6.3.1).
	SearchSubject(ctx context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error)

	// SearchResource answers "which resources of this type can
	// this subject do this action on?" (spec §6.3.2).
	SearchResource(ctx context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error)

	// SearchAction answers "which actions can this subject do on
	// this resource?" (spec §6.3.3). The request body carries no
	// action field — see [authzen.ActionSearchRequest].
	SearchAction(ctx context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error)
}

// NotImplementedDecider is a zero-value [Decider] whose every method
// returns [authzen.ErrNotImplemented]. PDPs that implement only a
// subset of the endpoints embed it and override what they support —
// the same embed-and-override pattern [http.ServeMux] extension uses.
//
// Example for a PDP that ships only single-evaluation:
//
//	type myPDP struct{ server.NotImplementedDecider }
//	func (p *myPDP) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
//	    // ...
//	}
//
// The handler maps the sentinel to HTTP 501 (spec's §10.1.2 error
// model is HTTP-status-only). For a conforming PEP that honors the
// metadata document (AUTHZEN-22), the 501 path is the fallback —
// the primary "I don't do this" signal is omitting the endpoint
// URL from /.well-known/authzen-configuration in the first place.
type NotImplementedDecider struct{}

// Evaluate returns [authzen.ErrNotImplemented]. Override this method
// by embedding [NotImplementedDecider] in your own Decider type.
func (NotImplementedDecider) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return nil, authzen.ErrNotImplemented
}

// Evaluations returns [authzen.ErrNotImplemented]. Override this
// method by embedding [NotImplementedDecider] in your own Decider.
func (NotImplementedDecider) Evaluations(context.Context, *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	return nil, authzen.ErrNotImplemented
}

// SearchSubject returns [authzen.ErrNotImplemented]. Override this
// method by embedding [NotImplementedDecider] in your own Decider.
func (NotImplementedDecider) SearchSubject(context.Context, *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	return nil, authzen.ErrNotImplemented
}

// SearchResource returns [authzen.ErrNotImplemented]. Override this
// method by embedding [NotImplementedDecider] in your own Decider.
func (NotImplementedDecider) SearchResource(context.Context, *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	return nil, authzen.ErrNotImplemented
}

// SearchAction returns [authzen.ErrNotImplemented]. Override this
// method by embedding [NotImplementedDecider] in your own Decider.
func (NotImplementedDecider) SearchAction(context.Context, *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	return nil, authzen.ErrNotImplemented
}

// Compile-time assertion: NotImplementedDecider satisfies Decider.
var _ Decider = NotImplementedDecider{}
