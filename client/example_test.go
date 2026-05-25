// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/client"
)

// ExampleClient_Evaluate demonstrates the single-decision call path: a
// PEP builds an [authzen.EvaluationRequest], hands it to a Client
// pointed at the PDP, and inspects the returned Decision. The stand-in
// PDP here is an [httptest.Server] so the example is self-contained; in
// a real PEP, the base URL is the PDP's HTTPS address.
//
// A policy deny — Decision: false — arrives as HTTP 200 per spec §5.1.
// Evaluate returns it as a successful response with a nil error;
// consumers MUST NOT treat Decision: false as a transport failure.
func ExampleClient_Evaluate() {
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Stand-in PDP: always permits. A real PDP runs the actual
		// policy and returns either {"decision": true} or
		// {"decision": false} — both at HTTP 200.
		_, _ = io.WriteString(w, `{"decision": true}`)
	}))
	defer pdp.Close()

	c, err := client.NewClient(pdp.URL)
	if err != nil {
		fmt.Println("new client:", err)
		return
	}

	resp, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   authzen.Action{Name: "can_read_todos"},
		Resource: authzen.Resource{Type: "todo", ID: "todo-1"},
	})
	if err != nil {
		fmt.Println("evaluate:", err)
		return
	}
	fmt.Println("decision:", resp.Decision)
	// Output: decision: true
}
