// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"

	"github.com/hstern/go-authzen/v1"
	"github.com/hstern/go-authzen/v1/server"
)

// NewDecider returns a [server.Decider] that answers Evaluate and
// Evaluations from the Todo scenario's role rules ([Decide]) and
// returns [authzen.ErrNotImplemented] from the three Search methods.
// The Todo scenario does not exercise the Search endpoints in v0.1,
// so a partial implementation is the right shape: the future metadata
// builder (AUTHZEN-22 work) will advertise only the implemented
// endpoints to PEPs that honor the metadata document.
//
// The returned Decider is safe for concurrent use; it carries no
// state of its own and forwards directly to package-level fixtures.
func NewDecider() server.Decider {
	return scenarioDecider{}
}

// scenarioDecider is the in-memory Decider that wraps [Decide]. It
// embeds [server.NotImplementedDecider] so SearchSubject,
// SearchResource, and SearchAction return [authzen.ErrNotImplemented]
// via the embed-and-override pattern documented in [server.Decider].
type scenarioDecider struct {
	server.NotImplementedDecider
}

// Evaluate answers a single Todo-scenario authorization question by
// dispatching to [Decide]. A policy deny returns
// &authzen.EvaluationResponse{Decision: false}, nil — never a non-nil
// error — matching the wire contract (spec §5.1; DESIGN.md
// §wire-fidelity).
func (scenarioDecider) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if req == nil {
		return nil, &authzen.ValidationError{Reason: "nil EvaluationRequest"}
	}
	decision := Decide(
		req.Subject.ID,
		req.Action.Name,
		req.Resource.Type,
		req.Resource.ID,
		req.Resource.Properties,
	)
	return &authzen.EvaluationResponse{Decision: decision}, nil
}

// Evaluations answers a batch of Todo-scenario authorization questions.
// Top-level Subject / Action / Resource act as defaults inherited by
// any item that omits the corresponding field (spec §6.2.1); this
// mirrors the merging the library's request validation performs and
// the way the upstream PEP composes batch requests.
//
// Only the [authzen.EvaluationsSemanticExecuteAll] semantic is
// honored — the Todo scenario does not exercise short-circuit
// semantics, and the spec's default when the option is omitted is
// execute_all. Other semantics are accepted and treated as
// execute_all rather than rejected; the wire shape is otherwise
// preserved.
func (scenarioDecider) Evaluations(_ context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	if req == nil {
		return nil, &authzen.ValidationError{Reason: "nil EvaluationsRequest"}
	}
	out := &authzen.EvaluationsResponse{
		Evaluations: make([]authzen.EvaluationResponse, 0, len(req.Evaluations)),
	}
	for _, item := range req.Evaluations {
		subject := item.Subject
		if subject == nil {
			subject = req.Subject
		}
		action := item.Action
		if action == nil {
			action = req.Action
		}
		resource := item.Resource
		if resource == nil {
			resource = req.Resource
		}
		var (
			subjectID    string
			actionName   string
			resourceType string
			resourceID   string
			props        = []byte(nil)
		)
		if subject != nil {
			subjectID = subject.ID
		}
		if action != nil {
			actionName = action.Name
		}
		if resource != nil {
			resourceType = resource.Type
			resourceID = resource.ID
			props = resource.Properties
		}
		decision := Decide(subjectID, actionName, resourceType, resourceID, props)
		out.Evaluations = append(out.Evaluations, authzen.EvaluationResponse{Decision: decision})
	}
	return out, nil
}
