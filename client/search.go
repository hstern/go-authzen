// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"

	"github.com/hstern/go-authzen/v1"
)

// SearchSubject calls the PDP's Subject Search endpoint (spec §6.3.1)
// — "which subjects of this type can perform this action on this
// resource?" The request is validated via
// [authzen.SubjectSearchRequest.Validate] before any network call.
//
// Pagination is the caller's responsibility — set req.Page on the
// follow-up call with the previous response's
// [authzen.PageResponse.NextToken]. An empty NextToken in the
// response signals end-of-results (spec §6.1.4).
func (c *Client) SearchSubject(ctx context.Context, req *authzen.SubjectSearchRequest) (*authzen.SubjectSearchResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp authzen.SubjectSearchResponse
	if err := c.postJSON(ctx, authzen.SearchSubjectEndpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SearchResource calls the PDP's Resource Search endpoint (spec
// §6.3.2) — "which resources of this type can this subject perform
// this action on?" The request is validated via
// [authzen.ResourceSearchRequest.Validate] before any network call.
//
// Same pagination contract as [Client.SearchSubject].
func (c *Client) SearchResource(ctx context.Context, req *authzen.ResourceSearchRequest) (*authzen.ResourceSearchResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp authzen.ResourceSearchResponse
	if err := c.postJSON(ctx, authzen.SearchResourceEndpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SearchAction calls the PDP's Action Search endpoint (spec §6.3.3) —
// "which actions can this subject perform on this resource?" The
// request body omits the action field entirely; the
// [authzen.ActionSearchRequest] type has no Action field for that
// reason, and any incoming JSON with an "action" key on this
// endpoint is silently ignored on decode.
//
// The request is validated via [authzen.ActionSearchRequest.Validate]
// before any network call. Pagination is the caller's responsibility,
// same contract as [Client.SearchSubject].
func (c *Client) SearchAction(ctx context.Context, req *authzen.ActionSearchRequest) (*authzen.ActionSearchResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp authzen.ActionSearchResponse
	if err := c.postJSON(ctx, authzen.SearchActionEndpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
