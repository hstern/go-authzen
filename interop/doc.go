// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

// Package interop exposes the OpenID AuthZEN Todo interoperability
// scenario as Go-native fixtures.
//
// The Todo scenario is the live conformance harness the OpenID AuthZEN
// WG maintains at https://todo.authzen-interop.net — sources at
// https://github.com/openid/authzen/tree/main/interop. A conformant
// Policy Decision Point returns the documented decisions for the
// scripted interactions; a conformant Policy Enforcement Point
// correctly translates application actions into AuthZEN requests and
// honors the responses.
//
// This package exposes the moving parts of that scenario — the five
// test users, the actions and resource types in play, the fixture
// todo set, the role-based authorization rules — and a curated table
// of (subject, action, resource) → decision Cases. Tests in this
// repository iterate the Cases to exercise the library in both PEP
// and PDP roles.
//
// The package is import-safe by itself: it carries no network code
// and pulls in only the standard library. Tests that reach the
// public scenario endpoint over the network carry the `interop`
// build tag and are skipped by default. Build them with
// `go test -tags interop ./interop/...`.
//
// # Refresh procedure
//
// The scenario evolves with the spec and the WG's conformance work.
// When upstream changes — a renamed action, an altered rule, a new
// fixture user — re-fetch the relevant files from the openid/authzen
// repository (particularly authzen-todo-backend/src/auth.ts for the
// action shapes and authzen-todo-backend/src/directory.ts for the
// user list) and regenerate the values in this package. See
// README.md in this directory for the step-by-step procedure.
package interop
