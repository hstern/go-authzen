// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hstern/go-authzen"
)

func TestSpecVersion(t *testing.T) {
	if authzen.SpecVersion != "1.0" {
		t.Fatalf("SpecVersion = %q, want %q", authzen.SpecVersion, "1.0")
	}
}

func TestEndpointPaths(t *testing.T) {
	// Spec §6 endpoint paths. These are the defaults; PDPs may override
	// via the metadata document. The values are pinned to the spec so a
	// rename here is a visible breaking change.
	cases := map[string]string{
		authzen.EvaluationEndpoint:     "/access/v1/evaluation",
		authzen.EvaluationsEndpoint:    "/access/v1/evaluations",
		authzen.SearchSubjectEndpoint:  "/access/v1/search/subject",
		authzen.SearchResourceEndpoint: "/access/v1/search/resource",
		authzen.SearchActionEndpoint:   "/access/v1/search/action",
		authzen.MetadataPath:           "/.well-known/authzen-configuration",
		authzen.HTTPHeaderRequestID:    "X-Request-ID",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("endpoint constant = %q, want %q", got, want)
		}
	}
}

func TestErrNotImplementedSentinel(t *testing.T) {
	// errors.Is must identify ErrNotImplemented through wrapping. The
	// server's 501 mapping (AUTHZEN-19) and the metadata builder's
	// per-method introspection (AUTHZEN-22) both rely on this.
	wrapped := errors.New("wrap: " + authzen.ErrNotImplemented.Error())
	if errors.Is(wrapped, authzen.ErrNotImplemented) {
		t.Fatalf("plain string-wrapped error must NOT match sentinel — use %%w to wrap")
	}
	wrapped2 := &wrapperError{authzen.ErrNotImplemented}
	if !errors.Is(wrapped2, authzen.ErrNotImplemented) {
		t.Fatalf("%%w-wrapped error must match the sentinel via errors.Is")
	}
}

type wrapperError struct{ inner error }

func (e *wrapperError) Error() string { return "wrap: " + e.inner.Error() }
func (e *wrapperError) Unwrap() error { return e.inner }

func TestValidationError_Error(t *testing.T) {
	cases := []struct {
		name string
		err  *authzen.ValidationError
		want string // substring expected in the error text
	}{
		{
			"field+reason",
			&authzen.ValidationError{Field: "subject.type", Reason: "required"},
			"subject.type: required",
		},
		{
			"field+reason+cause",
			&authzen.ValidationError{Field: "context", Reason: "invalid JSON", Cause: errors.New("unexpected end of input")},
			"unexpected end of input",
		},
		{
			"reason only",
			&authzen.ValidationError{Reason: "something off"},
			"something off",
		},
		{
			"empty",
			&authzen.ValidationError{},
			"validation error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.err.Error()
			if !strings.Contains(got, tc.want) {
				t.Errorf("Error() = %q, want substring %q", got, tc.want)
			}
			if !strings.HasPrefix(got, "authzen: ") {
				t.Errorf("Error() = %q, want \"authzen: \" prefix", got)
			}
		})
	}
}

func TestValidationError_Unwrap(t *testing.T) {
	sentinel := errors.New("oops")
	ve := &authzen.ValidationError{Field: "x", Reason: "bad", Cause: sentinel}
	if !errors.Is(ve, sentinel) {
		t.Fatalf("errors.Is must walk through ValidationError.Cause")
	}
	plain := &authzen.ValidationError{Field: "x", Reason: "bad"}
	if errors.Unwrap(plain) != nil {
		t.Fatalf("plain ValidationError must Unwrap to nil")
	}
}
