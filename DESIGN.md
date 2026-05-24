# Design

This document captures the rationale behind `go-authzen`'s API
shape and behavior — the decisions that shape the library, and why
they came out the way they did. If you're trying to understand
*why* something is the way it is, this is the right document. If
you're trying to learn *how to use* the library, see the godoc and
the README.

## Why `go-authzen` exists

OpenID AuthZEN is a JSON-on-the-wire protocol; in principle, every
team that needs it can write its own request/response types and
HTTP plumbing in an afternoon. In practice, every team writes the
same types in slightly different ways and gets the same set of
edge cases subtly wrong: forgetting that Action Search omits the
`action` key entirely, treating a policy-deny as a 4xx, mis-parsing
the empty-string pagination sentinel, missing the mix-up-attack
check on the metadata document.

A canonical Go library closes that surface. The OpenID AuthZEN WG
maintains reference implementations in Node.js and Python; the Go
prior art is coupled to specific PDP backends (Topaz being the
most prominent). `go-authzen` is the standalone, backend-neutral
Go alternative.

The library is positioned as a foundation for anyone implementing
either side of the AuthZEN wire in Go — application authors building
a PEP, PDP vendors exposing an AuthZEN front-end, gateway authors
wrapping a downstream PDP. It is not itself a PDP.

## The eight design decisions

Eight questions shape the API surface. Each one is settled here
with its rationale.

### 1. Module path & versioning

The library follows the
[`go-jose`](https://github.com/go-jose/go-jose) convention for
major-version handling: no versioned subdirectories. v0.x and v1.x
ship from `main` with `module <host>/go-authzen` (no suffix, per Go
SemVer's v0/v1 rule); when the library bumps to v2, `main` advances
with `module <host>/go-authzen/v2`, and the v1 codebase is
preserved on a `v1` branch carrying its own `go.mod`. Same shape
as `go-jose` itself.

The library name is `go-authzen` regardless of where it lives.
This follows the `go-jose` / `go-yaml` / `go-redis` "the Go library
for X" convention.

### 2. Standalone repo

`go-authzen` is a standalone repository rather than a subpackage of
any larger project. Four reasons:

1. **Adoption credibility.** External Go projects will not (and
   should not) depend on a library buried inside a larger product.
2. **Lifecycle independence.** The AuthZEN spec evolves on the
   OpenID WG's clock; tying release cadence to an unrelated
   project would force consumers to pin unrelated versions to get
   a spec patch.
3. **Clean dependency direction.** Consumers depend on
   `go-authzen`, not the reverse. A standalone repo enforces that
   direction structurally.
4. **WG-list eligibility.** The OpenID AuthZEN implementations
   list expects a standalone repo URL.

### 3. Transport pluggability

The library ships a `net/http`-based client and an `http.Handler`
constructor by default — zero dependencies beyond stdlib.

For consumers who need to customize transport (auth headers, retry
logic, OpenTelemetry instrumentation, connection pooling), the
client accepts an `HTTPDoer` interface:

```go
type HTTPDoer interface {
    Do(*http.Request) (*http.Response, error)
}
```

This is the same shape `golang.org/x/oauth2` uses for its
underlying client — proven, idiomatic, no invention. Wrap an
`HTTPDoer` to add behavior; the library doesn't care what's under
the wrapper.

The library deliberately does **not** ship a transport abstraction
in the gRPC sense (codec registry, name-resolver interface,
balancer plug-in). AuthZEN is plain HTTP+JSON. Reinventing the
gRPC transport stack here would be bait.

Server side ships `http.Handler` constructors only; consumers
compose with their existing mux and middleware stack
(`net/http`, `chi`, `gorilla/mux`, etc.).

### 4. JSON dialect

The library uses `encoding/json` from the standard library, not
`jsoniter` or `go-json` or any other faster decoder.

The framing types (`EvaluationRequest`, `EvaluationResponse`,
etc.) are small and rarely on a hot path; the marginal speedup of
a faster JSON library doesn't justify a runtime dependency.

The open fields — `Subject.Properties`, `Resource.Properties`,
`Action.Properties`, `Context` — can be arbitrary JSON of
arbitrary size. They are typed as `json.RawMessage`, which lets a
performance-conscious consumer plug a faster decoder *for just
those fields* without forcing the whole library to take a
non-stdlib JSON dependency.

When `encoding/json/v2` lands in stdlib (Go 1.27+ horizon), the
library will move with it.

### 5. Validation posture

The library is **lenient on unmarshal, strict at the marshal
boundary**, with an opt-in strict-validation hook.

- **At unmarshal**, the library decodes whatever the wire gave it
  and exposes the result. The AuthZEN spec MANDATES that receivers
  ignore unknown fields, so the library does. Consumers who want
  stricter input validation call `Validate(*EvaluationRequest) error`
  explicitly.
- **At marshal**, the library fails fast with a typed
  `*ValidationError` if a top-level message is missing a required
  field (e.g. `EvaluationRequest.Subject` is nil). This catches
  the common "half-built struct" bug at the latest practical
  moment — when the consumer is about to send the value over the
  wire.
- **Structural invariants** that the type system can express are
  encoded as distinct types. `SubjectSearchRequest` is a different
  type from `EvaluationRequest`; you can't accidentally send the
  former where the latter is expected.

There are no `NewEvaluationRequest(...)` factory constructors as
the only way to build a message. Idiomatic Go prefers exported
struct literals; consumers can write
`&authzen.EvaluationRequest{Subject: ..., Action: ..., Resource: ...}`
without going through a factory.

### 6. Extensibility through `json.RawMessage`

The open fields (`Subject.Properties`, `Resource.Properties`,
`Action.Properties`, `Context`) are typed as `json.RawMessage`,
not `map[string]any`:

```go
type Subject struct {
    Type       string          `json:"type"`
    ID         string          `json:"id,omitempty"`
    Properties json.RawMessage `json:"properties,omitempty"`
}
```

Three reasons:

1. **Byte-stable round-trip.** The AuthZEN interop scenario pins
   exact JSON bytes for these fields. `map[string]any` reorders
   keys on every marshal cycle (Go's map iteration order is
   randomized); `json.RawMessage` preserves the wire bytes
   verbatim.
2. **Zero deserialization cost for fields the consumer doesn't
   read.** A PDP that doesn't care about a specific `properties`
   extension shouldn't pay to unmarshal it.
3. **No `any` in the public surface.** Consumers decode into
   their own typed struct when they want to read, which means
   linters, IDE completion, and refactoring all work on the
   consumer's extension definition.

The library exposes `DecodeJSON` and `EncodeJSON` helpers for the
typed-extension pattern:

```go
type DeviceContext struct {
    DeviceID string `json:"device_id"`
}

var dc DeviceContext
if err := authzen.DecodeJSON(req.Context, &dc); err != nil {
    // ...
}
```

The helpers treat nil/empty `RawMessage` as "no extension
present", which saves consumers from boilerplate nil checks at
every decode site.

### 7. PDP composition — `Decider` interface

PDP authors implement a single `Decider` interface with one method
per AuthZEN endpoint:

```go
type Decider interface {
    Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error)
    Evaluations(ctx context.Context, req *EvaluationsRequest) (*EvaluationsResponse, error)
    SearchSubject(ctx context.Context, req *SubjectSearchRequest) (*SubjectSearchResponse, error)
    SearchResource(ctx context.Context, req *ResourceSearchRequest) (*ResourceSearchResponse, error)
    SearchAction(ctx context.Context, req *ActionSearchRequest) (*ActionSearchResponse, error)
}
```

A `NotImplementedDecider` zero-value type implements all five
methods by returning `ErrNotImplemented`. PDPs that implement only
a subset of the endpoints embed it and override what they support:

```go
type MyPDP struct {
    authzen.NotImplementedDecider // covers SearchSubject, SearchResource, SearchAction
}

func (p *MyPDP) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    // ...
}

func (p *MyPDP) Evaluations(ctx context.Context, req *authzen.EvaluationsRequest) (*authzen.EvaluationsResponse, error) {
    // ...
}
```

Why a single interface rather than one interface per endpoint:

- **One implementation point.** An IDE's "implement interface"
  command fills the whole surface in one shot. PDP authors don't
  pattern-match against "which interface again?"
- **Partial implementations are common** — most PDPs ship
  `Evaluate` and `Evaluations`; the three search variants are
  rarer. The embed-and-override pattern via
  `NotImplementedDecider` mirrors how `http.ServeMux` extension
  works.
- **Future-proofing.** Adding a method to an interface is a
  breaking change in Go. If a future AuthZEN spec ever adds an
  endpoint, `NotImplementedDecider` lets consumers absorb the
  addition without immediate code changes.

#### `ErrNotImplemented` and HTTP 501

AuthZEN 1.0 §10.1.2 defines errors as HTTP status codes only — no
JSON error envelope. The mandated codes are 400, 401, 403, 500.
The spec is silent on the "endpoint not supported" condition
specifically, because §9.1.1 makes endpoint *advertisement* the
canonical capability signal:

> Note: the absence of any of these parameters is sufficient for
> the PEP to determine that the PDP is not capable and therefore
> will not return a result for the associated API.

So the **primary** mechanism for "I don't do search" is omitting
the endpoint URL from the metadata document. The library's
metadata builder introspects the `Decider` and only publishes
endpoints whose method doesn't return `ErrNotImplemented`. A
conforming PEP never reaches the handler for an unsupported
endpoint.

For PEPs that bypass metadata discovery or are non-conforming, the
HTTP layer **maps `ErrNotImplemented` to HTTP 501 Not
Implemented** with a plain-text body. 501 fits the spec's
HTTP-only error model and is unambiguous against 400/401/403/500.
404 conflates "you mistyped the URL" with "the PDP doesn't do
search"; 405 is about HTTP methods, not endpoint capabilities.

The `Decider` interface stays Go-idiomatic — methods return
`error`, sentinel `ErrNotImplemented` is matched with
`errors.Is`. The HTTP layer handles the wire translation.

#### Policy-deny is HTTP 200

A policy-deny outcome — `Decision: false` — is **HTTP 200, not a
4xx**. Per spec §5.1, the only non-200 status codes are for
authentication failures (401), authorization-against-the-PDP-itself
failures (403), malformed payloads (400), and server / not-implemented
errors (500, 501). A `Decider.Evaluate` returning
`&EvaluationResponse{Decision: false}, nil` emits HTTP 200 with
the JSON-encoded response. The handler does NOT translate that to
4xx.

This is the single most common contract mistake in AuthZEN
implementations across all language stacks. Test fixtures should
include explicit deny-via-200 cases on both client and server
sides.

### 8. Spec-version pinning & library SemVer

The AuthZEN spec version this build implements is exposed as a
build-time constant:

```go
const SpecVersion = "1.0"
```

`SpecVersion` is embedded in the
`/.well-known/authzen-configuration` metadata response and
surfaced in the library's `Version()` helper for diagnostics.

Library SemVer is **independent** of the spec version:

- **`v0.x`** for the pre-stability phase. First tag is `v0.1.0`.
  The library stays on `v0.x` until the interop scenario passes in
  both PEP and PDP roles AND at least one external consumer has
  integrated and stayed integrated across a release cycle.
- **`v1.0.0`** is the library's API-stability commitment. No
  breaking changes to types or signatures without a Go
  major-version bump (per Go SemVer's versioned-import-paths
  rule).
- **AuthZEN spec MINOR / patch** ships as additive Go-minor
  releases — same as how `golang.org/x/oauth2` absorbs RFC errata
  without bumping its Go module path.
- **AuthZEN spec MAJOR** ships as a Go-major bump if the spec
  change is wire-breaking, or as additive types in v1.x / v2.x if
  wire-additive. Decided at the time, documented in
  `CHANGELOG.md`.
- **Library major bump (v2+)** advances `main` and rewrites
  `go.mod` to `module <host>/go-authzen/v2`; the v1 codebase moves
  to a `v1` branch (the `go-jose` pattern from §1).

## The metadata document

The `/.well-known/authzen-configuration` document is how a PDP
advertises its endpoints and capabilities to PEPs. The library's
metadata machinery makes five smaller decisions that the spec
leaves to the implementation.

### 1. `signed_metadata` is deferred to v0.2

Spec §9.1.1 lets a PDP sign the metadata document as a JWS (per
RFC 7515); the signed form takes precedence when present.
Implementing it pulls in a JOSE dependency — which would be the
library's **only** non-stdlib runtime dependency — and forces a
key-distribution conversation the spec leaves open (where does the
PEP get the verification key? JWKS endpoint? Out-of-band trust?).

`v0.1` ships plain metadata only and emits/accepts
`signed_metadata` as an opaque pass-through `json.RawMessage` so
forward-compatible consumers can plug their own JOSE verifier.
The JOSE dependency lands in v0.2 along with the actual signing
and verification machinery.

This deferral is the load-bearing reason the v0.1 library has
zero non-stdlib runtime dependencies.

### 2. Mix-up validation hard-fails by default

Spec §9.1.1 mandates that `policy_decision_point` MUST equal the
URL the metadata document was fetched from. The library performs
this check client-side in `FetchMetadata`.

The default mode is **hard-fail**: reject the response with a
typed `*MixUpError` if the URLs don't match. The consequences of
mix-up are an authorization bypass; defaulting to warn-and-proceed
would defeat the spec's protection.

For tests or genuine redirect topologies, an explicit opt-out is
available: `client.WithRelaxedMetadataValidation()`. The name is
deliberately ugly so it's hard to use accidentally.

### 3. Capability URNs

The `capabilities` field is an array of IANA-registered URNs from
the AuthZEN Policy Decision Point Capabilities registry (spec
§12.3, URN namespace `urn:ietf:params:authzen:*`). The registry is
open and currently has no meaningful entries.

The library exposes `Capabilities []string` and lets consumers
append; it does **not** enumerate "known" capabilities until the
registry has any. Consumers should not write `switch` statements
on URN values that haven't been standardized.

### 4. Metadata caching

The spec is silent on cache lifetimes for the metadata document.
The library respects HTTP `Cache-Control` directives. When the
response has no caching directive, the default fallback is **one
hour**, configurable via `client.WithMetadataTTL(d)`.

One hour is short enough that a PDP rolling out a new endpoint
sees PEP uptake within a workday; long enough that the metadata
fetch isn't on every request's hot path.

### 5. JWKS / key distribution

This question only matters if `signed_metadata` ships in v0.1
(see decision 1). It is deferred along with `signed_metadata` to
v0.2.

## Wire-fidelity invariants

These are the quirks of the AuthZEN wire that the library handles
correctly, and that hand-rolled implementations get wrong. They're
called out here so consumers know to expect them.

- **Policy-deny is HTTP 200.** Already covered above; mentioned
  here for the catalog. `decision: false` is not an error.
- **Action Search omits the `action` key entirely.** Per spec
  §6.3, the request body for Action Search has no `action` field —
  not "action with empty fields", not "action.name omitted". The
  whole key is absent. `ActionSearchRequest` in this library has
  no `Action` field (`SubjectSearchRequest` and
  `ResourceSearchRequest` do carry their pivot type, with `id`
  omitted — the asymmetry is real).
- **Pagination uses empty-string sentinels.** Response
  `page.next_token == ""` signals "no more pages" — not null, not
  absent. The library round-trips the empty string verbatim.
- **Receivers MUST ignore unknown fields.** The library does this
  on unmarshal (decision 5).
- **Metadata `policy_decision_point` MUST equal fetch URL.** The
  library hard-fails by default (decision 5.2).
- **Default endpoint paths are spec-suggested, not mandated.** A
  PDP advertises its actual endpoint URLs via the metadata
  document; the library defaults to `/access/v1/evaluation` etc.
  but honors metadata-document overrides on the client side.

## Out of scope for v0.1

Things this library deliberately does not do:

- **A policy engine.** The library provides the *interface* for a
  PDP (the `Decider`); consumers wire whatever backend they want
  (Rego, Cedar, in-memory tables, a downstream service, a custom
  policy engine). This is the same separation the AuthZEN spec
  itself draws.
- **Authentication of AuthZEN endpoints.** The spec is silent on
  how PEPs and PDPs authenticate to each other. Consumers compose
  their own auth via `HTTPDoer` middleware on the client side and
  `HandlerOption` middleware on the server side.
- **`signed_metadata` end-to-end.** Deferred to v0.2 with the JOSE
  dependency (decision 5.1).
- **ConnectRPC or gRPC bindings.** The spec's HTTPS+JSON binding
  is what this library implements. Other bindings are possible as
  sibling adapter packages later if there's demand.
- **The MCP Tool Authorization profile.** The OpenID AuthZEN WG
  publishes a profile for Model Context Protocol tool
  authorization (in `profiles/authzen-mcp-profile-1_0.md` in the
  spec repo). A future sibling package may implement it; v0.1
  ships only the core 1.0 wire.
- **An example PDP.** Possible as a separate `examples/`
  directory after v0.1.0.

## References

- [OpenID AuthZEN Authorization API 1.0 (Final)](https://openid.net/specs/authorization-api-1_0.html)
- [Spec source on GitHub](https://github.com/openid/authzen)
- [Interop scenario (live Todo PDP)](https://todo.authzen-interop.net)
- [OpenID AuthZEN Working Group](https://openid.net/wg/authzen/)
