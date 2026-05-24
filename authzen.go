// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

// Package authzen implements the OpenID AuthZEN Authorization API 1.0
// wire protocol — the PEP↔PDP communication between a Policy
// Enforcement Point and a Policy Decision Point for fine-grained
// authorization decisions.
//
// This package and its subpackages (client, server, interop) together
// form a library-vendor-neutral Go implementation of the spec at
// https://openid.net/specs/authorization-api-1_0.html.
//
// Pre-v0.1.0: the surface is being built out in phased PRs. See
// CHANGELOG.md for what has landed, DESIGN.md for the rationale, and
// AGENTS.md for the contributor conventions.
package authzen

// SpecVersion is the OpenID AuthZEN Authorization API version this
// build implements. The spec reached Final on 2026-01-11; the library
// tracks 1.0 until AuthZEN itself ships a major.
const SpecVersion = "1.0"
