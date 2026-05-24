// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hstern/go-authzen/v1"
)

// Evaluate calls the PDP's Access Evaluation endpoint (spec §6.1).
// The request is validated via [authzen.EvaluationRequest.Validate]
// before any network call so a half-built struct fails fast at the
// caller, not on the wire.
//
// A policy-deny outcome — {"decision": false} — is HTTP 200 per spec
// §5.1 and DESIGN.md §wire-fidelity. Evaluate returns
// &EvaluationResponse{Decision: false}, nil in that case. The error
// return is reserved for transport failures (network, 4xx auth,
// 5xx server, malformed body, validation). Callers MUST NOT treat
// Decision: false as an error.
func (c *Client) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp authzen.EvaluationResponse
	if err := c.postJSON(ctx, authzen.EvaluationEndpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Evaluations calls the PDP's Access Evaluations (batch) endpoint
// (spec §6.2). Top-level Subject / Action / Resource on the request
// act as defaults inherited by any item that omits the corresponding
// field; [authzen.EvaluationsRequest.Validate] walks every item with
// default-merging applied and rejects the request if any effective
// item is incomplete.
//
// The response Evaluations array is in the same order as the request
// items, possibly truncated when a short-circuit semantic
// ([authzen.EvaluationsSemanticDenyOnFirstDeny] or
// [authzen.EvaluationsSemanticPermitOnFirstPermit]) is set. Per-item
// deny still encodes as {"decision": false} on a 200 — no per-item
// errors are surfaced through this method's error return.
func (c *Client) Evaluations(ctx context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	var resp authzen.EvaluationsResponse
	if err := c.postJSON(ctx, authzen.EvaluationsEndpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// postJSON marshals in to JSON, POSTs it to the AuthZEN endpoint at
// the given path under the Client's baseURL, and decodes the
// response body into out. Non-2xx responses return a
// [*StatusError] carrying the status code and raw response body.
//
// This method is the single point through which every per-endpoint
// call in the client package sends a request, so cross-cutting
// concerns (header policy, body-size limits, decode policy) all
// land here.
func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("authzen client: marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL(path), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("authzen client: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpResp, err := c.doer.Do(httpReq)
	if err != nil {
		return fmt.Errorf("authzen client: do: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("authzen client: read response body: %w", err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return &StatusError{StatusCode: httpResp.StatusCode, Body: respBody}
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("authzen client: decode response (HTTP %d): %w", httpResp.StatusCode, err)
	}
	return nil
}

// endpointURL joins the Client's baseURL with an AuthZEN endpoint
// path. The baseURL's existing path is preserved as a prefix so a
// PDP mounted under a subpath like https://gw.example.com/authzen
// works without configuration gymnastics.
func (c *Client) endpointURL(p string) string {
	u := *c.baseURL
	prefix := strings.TrimRight(c.baseURL.Path, "/")
	u.Path = prefix + p
	return u.String()
}

// StatusError is returned when the PDP responds with a non-2xx
// status. The AuthZEN error model (spec §10.1.2) is HTTP-status-
// only with an optional plain-text body — there is no JSON error
// envelope to decode, so the wire body is exposed raw.
//
// Use [errors.As] to inspect the status code from a returned error:
//
//	var se *client.StatusError
//	if errors.As(err, &se) {
//	    // se.StatusCode, se.Body
//	}
type StatusError struct {
	// StatusCode is the HTTP status the PDP returned (e.g. 400,
	// 401, 403, 500, 501 per spec §10.1.2).
	StatusCode int

	// Body is the raw response body bytes — the spec describes it
	// as plain text but does not mandate format. May be empty.
	Body []byte
}

// Error returns a stable string of the form
// "authzen: PDP returned HTTP <code>" with the trimmed body appended
// when present.
func (e *StatusError) Error() string {
	body := strings.TrimSpace(string(e.Body))
	if body == "" {
		return fmt.Sprintf("authzen client: PDP returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("authzen client: PDP returned HTTP %d: %s", e.StatusCode, body)
}

// Ensure StatusError is never matched against a plain error sentinel
// by accident — it has no Unwrap, so errors.Is walks past it cleanly
// to whatever the caller wraps it in.
var _ error = (*StatusError)(nil)
