// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/server"
)

//go:embed policies.cedar
var policiesSource []byte

//go:embed entities.json
var entitiesSource []byte

// Cedar entity types used by this example.
const (
	cedarTypeUser   types.EntityType = "User"
	cedarTypeTodo   types.EntityType = "Todo"
	cedarTypeAction types.EntityType = "Action"
)

// cedarResourceType maps the AuthZEN resource type string the PEP
// sends (lowercase, by Todo-scenario convention) to the Cedar entity
// type the policy and entities use (PascalCase, by Cedar convention).
// An unknown type falls through unmodified — Cedar will look it up
// in the entity store and return "deny" if no policy matches.
var cedarResourceType = map[string]types.EntityType{
	"user": cedarTypeUser,
	"todo": cedarTypeTodo,
}

func cedarType(authzenType string) types.EntityType {
	if t, ok := cedarResourceType[authzenType]; ok {
		return t
	}
	return types.EntityType(authzenType)
}

// cedarDecider implements server.Decider on top of a Cedar policy
// engine. It embeds NotImplementedDecider so the Search* methods
// inherit the spec's HTTP 501 mapping; this example does not advertise
// or serve any Search endpoint.
type cedarDecider struct {
	server.NotImplementedDecider
	policies *cedar.PolicySet
	entities cedar.EntityMap
}

// newCedarDecider parses the embedded Cedar policies and entities once
// at construction. A failure here is a programming error — both files
// ship with the binary and are caught at build time.
func newCedarDecider() (*cedarDecider, error) {
	ps, err := cedar.NewPolicySetFromBytes("policies.cedar", policiesSource)
	if err != nil {
		return nil, fmt.Errorf("parse policies: %w", err)
	}
	var ents cedar.EntityMap
	if err := json.Unmarshal(entitiesSource, &ents); err != nil {
		return nil, fmt.Errorf("parse entities: %w", err)
	}
	return &cedarDecider{policies: ps, entities: ents}, nil
}

// Evaluate translates a single AuthZEN evaluation into a Cedar
// authorization check. The AuthZEN spec's wire mapping (§5.1) goes:
//
//	subject.type, subject.id   →  Principal entity UID
//	action.name                →  Action entity UID
//	resource.type, resource.id →  Resource entity UID
//	resource.properties.ownerID →  resource.ownerID Cedar attribute
//
// A policy-deny outcome (Cedar's Decision == Deny) returns an
// EvaluationResponse with Decision: false and a nil error per spec
// §10.1.2 — never a transport-error-style error return.
func (d *cedarDecider) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	cedarReq := types.Request{
		Principal: cedar.NewEntityUID(cedarTypeUser, types.String(req.Subject.ID)),
		Action:    cedar.NewEntityUID(cedarTypeAction, types.String(req.Action.Name)),
		Resource:  cedar.NewEntityUID(cedarType(req.Resource.Type), types.String(req.Resource.ID)),
	}
	ents, err := d.entitiesForRequest(req)
	if err != nil {
		return nil, fmt.Errorf("build cedar entities: %w", err)
	}
	decision, _ := cedar.Authorize(d.policies, ents, cedarReq)
	return &authzen.EvaluationResponse{Decision: bool(decision)}, nil
}

// Evaluations delegates each item to Evaluate. Top-level Subject,
// Action, and Resource are inherited defaults for items that omit
// the corresponding field, per spec §6.2.1.
func (d *cedarDecider) Evaluations(ctx context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	results := make([]authzen.EvaluationResponse, 0, len(req.Evaluations))
	for _, item := range req.Evaluations {
		merged := &authzen.EvaluationRequest{
			Subject:  pickSubject(item.Subject, req.Subject),
			Action:   pickAction(item.Action, req.Action),
			Resource: pickResource(item.Resource, req.Resource),
			Context:  firstNonEmpty(item.Context, req.Context),
		}
		resp, err := d.Evaluate(ctx, merged)
		if err != nil {
			return nil, err
		}
		results = append(results, *resp)
	}
	return &authzen.EvaluationsResponse{Evaluations: results}, nil
}

// pickSubject returns *item if it carries a non-zero value, else
// *fallback, else the zero value. Per spec §6.2.1 the per-item field
// overrides the request-level default, which overrides nothing.
func pickSubject(item, fallback *authzen.Subject) authzen.Subject {
	if item != nil && (item.Type != "" || item.ID != "" || len(item.Properties) > 0) {
		return *item
	}
	if fallback != nil {
		return *fallback
	}
	return authzen.Subject{}
}

func pickAction(item, fallback *authzen.Action) authzen.Action {
	if item != nil && (item.Name != "" || len(item.Properties) > 0) {
		return *item
	}
	if fallback != nil {
		return *fallback
	}
	return authzen.Action{}
}

func pickResource(item, fallback *authzen.Resource) authzen.Resource {
	if item != nil && (item.Type != "" || item.ID != "" || len(item.Properties) > 0) {
		return *item
	}
	if fallback != nil {
		return *fallback
	}
	return authzen.Resource{}
}

// entitiesForRequest returns a per-request copy of the static entity
// store with the request's resource overlaid. The overlay carries any
// ownerID supplied in resource.properties as a Cedar EntityRef
// attribute, so the owner-only editor rule fires for resources the
// PEP introduces dynamically — not just the four fixture todos.
func (d *cedarDecider) entitiesForRequest(req *authzen.EvaluationRequest) (cedar.EntityMap, error) {
	resourceUID := cedar.NewEntityUID(cedarType(req.Resource.Type), types.String(req.Resource.ID))
	overlay, err := buildResourceEntity(resourceUID, req.Resource.Properties)
	if err != nil {
		return nil, err
	}
	if overlay == nil {
		return d.entities, nil
	}
	out := make(cedar.EntityMap, len(d.entities)+1)
	maps.Copy(out, d.entities)
	out[resourceUID] = *overlay
	return out, nil
}

// buildResourceEntity constructs a Cedar entity for the request's
// resource if the wire properties carry an ownerID. Returns nil when
// there is nothing to overlay — the static entity store handles the
// request without help.
func buildResourceEntity(uid types.EntityUID, raw json.RawMessage) (*types.Entity, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var props struct {
		OwnerID string `json:"ownerID"`
	}
	if err := json.Unmarshal(raw, &props); err != nil {
		return nil, fmt.Errorf("decode resource properties: %w", err)
	}
	if props.OwnerID == "" {
		return nil, nil
	}
	owner := cedar.NewEntityUID(cedarTypeUser, types.String(props.OwnerID))
	return &types.Entity{
		UID:        uid,
		Attributes: types.NewRecord(types.RecordMap{"ownerID": owner}),
	}, nil
}

func firstNonEmpty(a, b json.RawMessage) json.RawMessage {
	if len(a) > 0 {
		return a
	}
	return b
}
