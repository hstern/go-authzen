// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/server"
)

// allowAllDecider permits every Evaluate call and inherits the
// [server.NotImplementedDecider] defaults for everything else. Used
// by several examples in this file.
type allowAllDecider struct {
	server.NotImplementedDecider
}

func (allowAllDecider) Evaluate(_ context.Context, _ *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{Decision: true}, nil
}

// ExampleNewHandler shows the smallest useful PDP server: a Decider
// that permits every request, wrapped by [server.NewHandler], mounted
// on a test server, and called over HTTP. Real PDPs implement policy
// in the Decider; the wire shape stays the same.
//
// The body uses [http.NewServeMux] so the example mirrors composing
// the handler under an existing application's routing tree. Mounting
// the handler at the root works too.
func ExampleNewHandler() {
	mux := http.NewServeMux()
	mux.Handle("/", server.NewHandler(allowAllDecider{}))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(
		srv.URL+authzen.EvaluationEndpoint,
		"application/json",
		strings.NewReader(`{"subject":{"type":"user","id":"alice"},`+
			`"action":{"name":"read"},`+
			`"resource":{"type":"document","id":"doc-42"}}`),
	)
	if err != nil {
		fmt.Println("post:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.StatusCode, strings.TrimSpace(string(body)))
	// Output: 200 {"decision":true}
}

// evaluateOnlyDecider implements just Evaluate; the other four methods
// inherit [server.NotImplementedDecider]. Used by ExampleBuildMetadata
// to demonstrate that BuildMetadata advertises only the implemented
// endpoint.
type evaluateOnlyDecider struct {
	server.NotImplementedDecider
}

func (evaluateOnlyDecider) Evaluate(_ context.Context, _ *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{Decision: true}, nil
}

// ExampleBuildMetadata shows the metadata document a partial Decider
// produces. evaluateOnlyDecider implements Evaluate; Evaluations and
// the three Search methods inherit the [server.NotImplementedDecider]
// defaults. [server.BuildMetadata] introspects the Decider with a
// zero-value probe per method and emits only the implemented endpoints
// — matching spec §9.1.1's "absent URL = unimplemented endpoint"
// capability model.
func ExampleBuildMetadata() {
	m := server.BuildMetadata("https://pdp.example.com", evaluateOnlyDecider{})

	advertised := []string{}
	if m.AccessEvaluationEndpoint != "" {
		advertised = append(advertised, "evaluation")
	}
	if m.AccessEvaluationsEndpoint != "" {
		advertised = append(advertised, "evaluations")
	}
	if m.SearchSubjectEndpoint != "" {
		advertised = append(advertised, "search/subject")
	}
	if m.SearchResourceEndpoint != "" {
		advertised = append(advertised, "search/resource")
	}
	if m.SearchActionEndpoint != "" {
		advertised = append(advertised, "search/action")
	}
	slices.Sort(advertised)
	fmt.Println("pdp:", m.PolicyDecisionPoint)
	fmt.Println("endpoints:", strings.Join(advertised, ","))
	// Output:
	// pdp: https://pdp.example.com
	// endpoints: evaluation
}

// ExampleDecider shows the embed-and-override pattern for implementing
// only the endpoints a PDP supports. roleDecider implements Evaluate;
// Evaluations and the three Search methods inherit
// [server.NotImplementedDecider] and return
// [authzen.ErrNotImplemented], which [server.NewHandler] maps to
// HTTP 501.
//
// This is the recommended shape: implement what you support, embed
// for the rest, advertise the implemented set via
// [server.BuildMetadata].
func ExampleDecider() {
	d := roleDecider{}

	// Direct method call — no HTTP — to keep the example focused on
	// the Decider contract.
	resp, _ := d.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "admin"},
		Action:   authzen.Action{Name: "delete"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	fmt.Println("admin delete:", resp.Decision)

	resp, _ = d.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "guest"},
		Action:   authzen.Action{Name: "delete"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	fmt.Println("guest delete:", resp.Decision)
	// Output:
	// admin delete: true
	// guest delete: false
}

// roleDecider is a tiny PDP: "admin" may do anything; everyone else is
// denied. It embeds [server.NotImplementedDecider] so the three Search
// methods and Evaluations inherit the [authzen.ErrNotImplemented]
// sentinel that the handler maps to HTTP 501.
type roleDecider struct {
	server.NotImplementedDecider
}

func (roleDecider) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{Decision: req.Subject.ID == "admin"}, nil
}

// ExampleNotImplementedDecider shows the bare zero value: every
// method returns [authzen.ErrNotImplemented], which
// [server.NewHandler] maps to HTTP 501. PDPs embed
// NotImplementedDecider in their own Decider type and override only
// the endpoints they implement; the inherited methods stay at this
// sentinel.
func ExampleNotImplementedDecider() {
	var d server.NotImplementedDecider

	_, err := d.Evaluate(context.Background(), &authzen.EvaluationRequest{})
	fmt.Println("Evaluate err:", err)

	_, err = d.SearchSubject(context.Background(), &authzen.SubjectSearchRequest{})
	fmt.Println("SearchSubject err:", err)
	// Output:
	// Evaluate err: authzen: endpoint not implemented
	// SearchSubject err: authzen: endpoint not implemented
}

// Compile-time checks that the example helper Deciders satisfy
// [server.Decider]. Keeps the examples honest if the interface ever
// grows a method.
var (
	_ server.Decider = allowAllDecider{}
	_ server.Decider = evaluateOnlyDecider{}
	_ server.Decider = roleDecider{}
)
