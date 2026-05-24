# go-authzen

A Go implementation of the
[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
— the wire protocol between a Policy Enforcement Point (PEP) and a
Policy Decision Point (PDP) for fine-grained authorization decisions.

`go-authzen` provides:

- A typed HTTP client for calling AuthZEN PDPs (PEP role).
- `http.Handler` constructors over a `Decider` interface (PDP role).
- The full type surface for every spec-defined message — evaluation,
  batch evaluations, and the three search variants.
- `/.well-known/authzen-configuration` metadata document support
  with mix-up validation on the client side and capability-based
  endpoint advertisement on the server side.

The library is **library-vendor-neutral**: it implements the spec,
nothing more. It does not include a policy engine, an opinion about
how PEPs and PDPs authenticate to each other, or a vendor-specific
adapter. Those belong in downstream consumers.

## Status

**Pre-release.** Active development toward `v0.1.0`. The wire types,
client, server, and metadata machinery are all implemented in phased
PRs; once the interop scenario passes in both PEP and PDP roles, the
first tag ships.

The library tracks **AuthZEN 1.0 Final** (published 2026-01-11). The
spec version is exposed as `authzen.SpecVersion`.

Until `v1.0.0`, expect minor API churn. Breaking changes will be
documented in `CHANGELOG.md` with migration notes. The wire types
themselves are pinned to the spec and will not change without a spec
change.

## Why this library

The Go ecosystem had no widely-used AuthZEN library before this one.
The OpenID AuthZEN WG's reference implementations are in Node.js and
Python; existing Go prior art is coupled to specific PDP backends.
`go-authzen` closes that gap with a standalone, backend-neutral,
zero-non-stdlib-dependency library that any Go service can use as
either a PEP or PDP.

The longer rationale — the eight design decisions that shape the API,
how the metadata document is wired, what's deferred and why — lives
in [`DESIGN.md`](DESIGN.md).

## Compatibility

- **Go**: 1.26+
- **Dependencies**: zero non-test runtime dependencies. Standard
  library only.
- **Spec**: AuthZEN Authorization API 1.0 (Final).

## Contributing

Contributions welcome. See [`AGENTS.md`](AGENTS.md) for the guidance
this project gives to AI coding assistants — humans will find the
same conventions useful.

The short version: standard Go style (`gofmt`, `go vet`,
`staticcheck`, `golangci-lint` all run in CI), zero non-test runtime
dependencies, table-driven tests, and a strong preference for wire
fidelity over ergonomic shortcuts. New exported API surface and new
dependencies go through review.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
