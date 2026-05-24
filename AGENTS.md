# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Aider, Copilot
Workspace, etc.) working on `go-authzen`. Human contributors will get
more out of `CONTRIBUTING.md` once it exists; this file captures the
things that are easy for an agent to get wrong if it doesn't know them
up front.

## What this project is

`go-authzen` is a Go implementation of the
[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
— the PEP↔PDP wire protocol for fine-grained authorization. The
library is **library-vendor-neutral**: it implements the spec, nothing
more. It provides:

- HTTP client for calling AuthZEN PDPs (PEP role).
- `http.Handler` constructors over a `Decider` interface (PDP role).
- Full type surface for every spec-defined message.
- `/.well-known/authzen-configuration` metadata document support.

It does NOT provide a policy engine, an opinion about authentication
between PEP and PDP, or a vendor-specific adapter. Those belong in
downstream consumers.

Spec version: **1.0 Final**, published 2026-01-11. Tracked in source
as `const SpecVersion = "1.0"`.

## Repository scope rules

These rules are absolute. They are not preferences; they're correctness
constraints for what lands in the repo.

1. **The library is the subject.** Code, comments, docs, commit
   messages, and CI artifacts describe what the library does for an
   anonymous Go developer who found it via a search engine. They do not
   describe what the maintainer is using it for, where it is being
   developed, who is tracking which task, or how it relates to anything
   outside this repository.
2. **No private infrastructure references.** No internal hostnames,
   internal Git hosts, internal issue trackers, internal documentation
   sites, or any URL pointing at non-public infrastructure. If you find
   yourself wanting to cite `*.someprivate.tld`, the answer is: don't.
3. **No private-tracker identifiers.** Ticket short-codes, project
   IDs, page UUIDs, board names from any private tracker — none of it
   in source, README, CHANGELOG, or commit messages. When public issue
   tracking exists (GitHub Issues), reference its public URL only.
4. **No interim hosting paths.** `go.mod` declares the eventual
   publication module path. The interim location of the repo during
   private development MUST NOT appear in `go.mod`, README, comments,
   or CI configuration.
5. **No references to sibling private libraries.** "Matches the
   pattern in [internal-library-X]" is fine framing in a private
   conversation but MUST NOT land in the repo. Public libraries
   (`go-jose`, `go-yaml`, `golang.org/x/oauth2`) may be cited by name.

If you are unsure whether something is safe to write, default to
omitting it and ask. The cost of asking is low; the cost of leaking
context that can't be deleted from git history is high.

## Go conventions for this codebase

### Dependencies

**Zero non-test runtime dependencies.** Standard library only. This is
load-bearing for adoption: a standards-implementing library that pulls
in `jsoniter` / `go-json` / a logger / a metrics SDK forces those
choices on every consumer. The library exposes interfaces; consumers
plug their own implementations.

Exceptions, with explicit rationale documented at the import site:

- Test-only dependencies (e.g. `github.com/stretchr/testify` if
  needed) are fine; keep them under `_test.go` files.
- A JOSE library will be added when `signed_metadata` end-to-end
  support lands (post-v0.1). That decision is documented in
  `.claude/design-decisions.md`.

### Style

- `gofmt`, `go vet`, `staticcheck`, `golangci-lint` all run in CI and
  must pass.
- Receivers: short, lowercase, consistent within a type.
- Errors: lowercase sentence, no trailing punctuation, wrap with
  `%w` when adding context.
- Exported symbols have godoc comments. Short, link-rich.
- Examples live in `_test.go` as `Example*` functions and render in
  godoc.

### Validation posture

Lenient on unmarshal (the spec MANDATES ignoring unknown fields),
strict at the marshal boundary. The library validates required fields
when a message is being sent over the wire, not when it's being
received. Consumers who want stricter input validation call the
explicit `Validate(*EvaluationRequest) error` helper.

Do not add `NewEvaluationRequest(...)` constructor functions as the
only way to build a message. Exported struct literals are the
idiomatic Go construction pattern.

### JSON / wire fidelity

- Open fields (`Subject.Properties`, `Resource.Properties`,
  `Action.Properties`, `Context`) are `json.RawMessage`, NOT
  `map[string]any`. Reason: byte-stable round-trip; Go's map iteration
  order is randomized and AuthZEN interop pins exact JSON bytes.
- Empty-string pagination tokens (`next_token: ""`) are round-tripped
  verbatim — that's the spec's "no more pages" sentinel, not null,
  not absent.
- A policy-deny outcome (`decision: false`) is **HTTP 200, not a 4xx**.
  Clients must NOT treat `decision: false` as an error; servers must
  NOT emit a 4xx for it.
- Action Search requests omit the `action` key entirely. The
  `ActionSearchRequest` Go type does NOT carry an `Action` field.

### Interfaces vs structs

- One `Decider` interface, five methods, one per endpoint. PDPs
  embed `NotImplementedDecider` (a zero-value type whose methods all
  return `ErrNotImplemented`) and override the methods they support.
  This is the "embed and override" pattern that mirrors
  `http.ServeMux` extension.
- Transport is pluggable via an `HTTPDoer` interface (shape:
  `Do(*http.Request) (*http.Response, error)`) — same contract
  `golang.org/x/oauth2` uses. Server side ships `http.Handler` only;
  no framework adapters in the core library.

## Testing

- Table-driven tests for wire round-trips. Each spec-defined message
  has a round-trip test against hand-crafted JSON from the spec's
  example figures (Figures 14–37 in the spec HTML).
- `httptest.NewServer` for handler tests; `httptest.NewRecorder` is
  fine for unit tests that don't need a full server.
- The library passes the **OpenID AuthZEN Todo interop scenario** in
  both PEP and PDP roles. The Phase 6 acceptance test (see
  `.claude/build-plan.md`) implements this against the public scenario
  hosted at `todo.authzen-interop.net`.
- `go test -race -shuffle=on ./...` is the CI test invocation.
- No network calls in unit tests by default. The interop-scenario
  test that hits the public PDP is gated behind a build tag or env
  var so it doesn't flake CI when the public endpoint is unreachable.

## Commit messages

- Imperative present tense ("add metadata document support", not
  "added").
- Reference public artifacts only — public RFC numbers, spec section
  numbers, public PRs / issues, public commit SHAs. Do not reference
  private trackers (see rule 3 above).
- One logical change per commit. The phased build plan in
  `.claude/build-plan.md` is structured so each phase fits in one PR
  (or a small series).

## CI

GitHub Actions, two workflows:

- `.github/workflows/ci.yml` — build a common CI image with all
  check tools at pinned versions, then fan out parallel jobs
  (`static`, `test`, `lint`, `interop`). One CI run surfaces every
  failure at once, not just the first.
- `.github/workflows/vuln.yml` — separate, non-blocking, runs on
  `main` + daily cron. `govulncheck` opens deduped GitHub issues per
  affecting vulnerability and auto-closes them when resolved.

Required checks on every `pull_request`:

- `static`: `gofmt -l`, `go vet ./...`, `go mod tidy -diff`
- `test`: `go test -race -shuffle=on ./...`
- `lint`: `golangci-lint run ./...`
- `interop`: the AuthZEN Todo scenario in PDP role
  (`httptest.NewServer`-backed, deterministic). PEP-role smoke test
  against the public endpoint is best-effort.

## Where to find more detail

`.claude/` contains the deeper design notes — same content, more
exposition:

- `.claude/CLAUDE.md` — entry point for Claude-specific agents,
  pointer to the rest.
- `.claude/design-decisions.md` — the eight design questions and
  their settled answers (module path, transport, JSON dialect,
  validation, extensibility, PDP composition, spec-version pinning).
- `.claude/spec-reference.md` — AuthZEN 1.0 wire quick-reference:
  endpoints, request/response shapes, error semantics, headers,
  metadata document.
- `.claude/interop.md` — the OpenID AuthZEN Todo interop scenario,
  how the library participates in it, the WG implementations-list
  visibility step.
- `.claude/build-plan.md` — the eight phased PRs from repo bootstrap
  to `v0.1.0` and publication.

If you're starting fresh on a task, read `.claude/CLAUDE.md` first and
follow its pointers. Most questions an agent will have are answered
there.

## When to ask vs when to proceed

- Bug fix, refactor, doc tweak, test addition for an existing feature:
  proceed. Reference the spec section that motivates the change in the
  commit message.
- New exported API surface, new dependency, change to an interface
  signature, anything that affects backwards compatibility: ask first.
  These are forever-decisions once the library is published.
- Anything that might cross the scope rules above (1–5): ask. The
  cost of a quick check is far less than the cost of force-pushing
  history after a leak.
