# Changelog

All notable changes to `go-authzen` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

The library SemVer is independent of the AuthZEN spec version it
implements. See [`DESIGN.md`](DESIGN.md) §8 for the versioning policy.

## [Unreleased]

## [0.1.0] - 2026-05-25

First tagged release. Implements OpenID AuthZEN Authorization API 1.0
(Final, 2026-01-11) — the PEP↔PDP wire protocol for fine-grained
authorization decisions.

### Added

- **Wire types** for every spec-defined message: `Subject`, `Resource`,
  `Action`, `EvaluationRequest` / `EvaluationResponse`,
  `EvaluationsRequest` / `EvaluationsResponse` (batch), and the three
  search variants `SubjectSearchRequest` / `Response`,
  `ResourceSearchRequest` / `Response`, and `ActionSearchRequest` /
  `Response`. Open-extension fields (`Properties`, `Context`) are
  `json.RawMessage` so they round-trip byte-stably; `DecodeJSON` and
  `EncodeJSON` bridge them to typed Go values.
- **`client/` package**: `Client.Evaluate`, `Evaluations`,
  `SearchSubject`, `SearchResource`, `SearchAction`, and
  `FetchMetadata`. Pluggable `HTTPDoer` for composition with retry,
  auth, and tracing middleware. Policy-deny rides on HTTP 200 with
  `{"decision": false}` per spec §10.1.2 — never a transport error.
- **`server/` package**: `NewHandler` over a five-method `Decider`
  interface. `NotImplementedDecider` zero-value supports the
  embed-and-override pattern for partial implementations;
  unimplemented endpoints map to HTTP 501. `HandlerOption` hooks for
  structured logging, metrics, and `X-Request-ID` echo (spec §2.4).
- **Metadata document** (`/.well-known/authzen-configuration`, spec
  §9): `server.BuildMetadata` introspects a `Decider` and advertises
  only implemented endpoints. `client.FetchMetadata` enforces spec
  §9.1.1 mix-up protection (hard-fail by default,
  `WithRelaxedMetadataValidation` escape hatch), honors
  `Cache-Control: max-age`, and falls back to a one-hour TTL
  (`WithMetadataTTL`). `signed_metadata` is round-tripped as opaque
  JWS bytes — verification deferred to `v0.2.0`.
- **`interop/` package**: Go-native fixtures for the OpenID AuthZEN
  Todo conformance scenario — `Users`, `Todos`, the role-based
  `Decide` rule, a curated `Cases` table, and an in-memory `Decider`.
  `//go:build interop`-tagged tests drive the library in both PEP and
  PDP roles against Topaz at `topaz-todo-proxy.authzen-interop.net`.
- **CI fan-out**: `build`, `static`, `test`, `lint`, `interop` jobs.
  Branch protection on `main` enforces all five.
- **Documentation**: `README.md` with PEP + PDP quickstart, a
  typed-extensions example, and a Metadata-document section.
  `DESIGN.md` capturing the eight design decisions. `AGENTS.md` for
  contributor conventions. godoc on every exported symbol naming the
  spec section it implements, with `Example` tests for the
  load-bearing surfaces (`Client.Evaluate`, `NewHandler`,
  `BuildMetadata`, `Decider`, `NotImplementedDecider`).

### Compatibility

- Go 1.26+.
- Zero non-test runtime dependencies; standard library only.

### Deferred to a future release

- `signed_metadata` produce / verify, with the JOSE dependency it
  pulls in (`v0.2.0`).
- An example PDP demonstrating the server surface end-to-end
  (post-`v0.1.0`).
- gRPC / ConnectRPC bindings (possible later as sibling packages).
- The MCP Tool Authorization profile (future sibling package).

Tracks AuthZEN Authorization API 1.0 (Final, 2026-01-11).
