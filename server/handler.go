// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hstern/go-authzen"
)

// NewHandler returns an [http.Handler] that adapts d to the AuthZEN
// HTTP wire (spec §6). The handler routes the five spec-defined
// endpoint paths to the corresponding [Decider] methods; requests
// to other paths return 404.
//
// Status code mapping:
//
//   - nil error + non-nil response → 200 OK with JSON body. This
//     INCLUDES the policy-deny case: returning
//     &authzen.EvaluationResponse{Decision: false}, nil emits
//     HTTP 200 with {"decision": false} on the wire, NEVER 4xx
//     (DESIGN.md §wire-fidelity).
//   - [*authzen.ValidationError] from request decode or Decider →
//     400 Bad Request.
//   - errors.Is(err, [authzen.ErrNotImplemented]) → 501 Not
//     Implemented. PDPs that ship only some endpoints embed
//     [NotImplementedDecider] and return this sentinel from the
//     rest; the metadata builder (AUTHZEN-22) likewise advertises
//     only the implemented endpoints.
//   - Any other error → 500 Internal Server Error.
//
// Error responses are plain text (spec §10.1.2 — no JSON error
// envelope). The plain-text body is the Go error message; consumers
// MUST NOT depend on its format.
//
// The returned handler is safe for concurrent use.
func NewHandler(d Decider, opts ...HandlerOption) http.Handler {
	h := &handler{decider: d}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+authzen.EvaluationEndpoint, h.handleEvaluate)
	mux.HandleFunc("POST "+authzen.EvaluationsEndpoint, h.handleEvaluations)
	mux.HandleFunc("POST "+authzen.SearchSubjectEndpoint, h.handleSearchSubject)
	mux.HandleFunc("POST "+authzen.SearchResourceEndpoint, h.handleSearchResource)
	mux.HandleFunc("POST "+authzen.SearchActionEndpoint, h.handleSearchAction)
	h.mux = mux
	h.chain = mux
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandlerOption configures the [http.Handler] returned by
// [NewHandler]. Middleware-style options wrap the handler's request
// chain (logging, metrics, X-Request-ID echo) — they may compose by
// wrapping each other in option-order. The middleware options
// themselves land in subsequent steps; the type is exported here so
// [NewHandler]'s signature stays stable.
type HandlerOption func(*handler)

type handler struct {
	decider Decider
	mux     *http.ServeMux
	// chain is the request-dispatch chain — mux at the bottom,
	// possibly wrapped by middleware HandlerOptions. ServeHTTP
	// dispatches to it.
	chain http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.chain.ServeHTTP(w, r)
}

func (h *handler) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req authzen.EvaluationRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := h.decider.Evaluate(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) handleEvaluations(w http.ResponseWriter, r *http.Request) {
	var req authzen.EvaluationsRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := h.decider.Evaluations(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) handleSearchSubject(w http.ResponseWriter, r *http.Request) {
	var req authzen.SubjectSearchRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := h.decider.SearchSubject(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) handleSearchResource(w http.ResponseWriter, r *http.Request) {
	var req authzen.ResourceSearchRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := h.decider.SearchResource(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) handleSearchAction(w http.ResponseWriter, r *http.Request) {
	var req authzen.ActionSearchRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := h.decider.SearchAction(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeRequest decodes the JSON request body into v. A decode
// failure surfaces as [*authzen.ValidationError] with Field "body"
// and Reason "invalid JSON" so the writeError mapping turns it into
// the spec-mandated 400 (spec §10.1.2).
func decodeRequest(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return &authzen.ValidationError{
			Field:  "body",
			Reason: "invalid JSON",
			Cause:  err,
		}
	}
	return nil
}

// writeJSON serializes body as JSON, sets Content-Type, and writes
// the status code. Encode errors after WriteHeader cannot be
// surfaced over the wire (the response is already committed); they
// would land in a server log via the optional logging hook
// (AUTHZEN-20). For now they are silently dropped.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError maps err to the appropriate HTTP status code per the
// table in [NewHandler]'s godoc and writes a plain-text body. The
// body format is intentionally unspecified; consumers MUST NOT
// pattern-match on it (per spec §10.1.2 the wire's only typed
// error signal is the status code).
func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var ve *authzen.ValidationError
	switch {
	case errors.As(err, &ve):
		status = http.StatusBadRequest
	case errors.Is(err, authzen.ErrNotImplemented):
		status = http.StatusNotImplemented
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, err.Error())
}
