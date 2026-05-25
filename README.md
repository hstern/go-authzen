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
- `/.well-known/authzen-configuration` metadata document support with
  mix-up validation on the client side and capability-based endpoint
  advertisement on the server side.

The library is **library-vendor-neutral**: it implements the spec,
nothing more. It does not include a policy engine, an opinion about
how PEPs and PDPs authenticate to each other, or a vendor-specific
adapter. Those belong in downstream consumers.

## Status

`v0.1.0` is the first tagged release. The library tracks
**AuthZEN 1.0 Final** (published 2026-01-11), exposed as
`authzen.SpecVersion`. The full wire surface (single evaluation,
batch evaluations, the three search variants), the metadata document,
and an interop fixture set covering both PEP and PDP roles ship in
this release. See [`CHANGELOG.md`](CHANGELOG.md) for what landed.

The path to `v1.0.0` is open external integration and continued
interop confidence; see the **Stability** section for what changes
between minor versions and what does not.

## Quickstart

### PEP role — call a PDP

```go
package main

import (
	"context"
	"log"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/client"
)

func main() {
	c, err := client.NewClient("https://pdp.example.com")
	if err != nil {
		log.Fatal(err)
	}
	resp, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice@example.com"},
		Action:   authzen.Action{Name: "read"},
		Resource: authzen.Resource{Type: "document", ID: "doc-42"},
	})
	if err != nil {
		log.Fatal(err) // transport / 4xx / 5xx — NOT policy-deny
	}
	log.Printf("decision: %v", resp.Decision) // false = legal policy deny
}
```

A `false` decision is a successful HTTP 200 response, never an error.
Reserve the error return for transport failures, authn rejections, and
malformed responses — exactly as the spec requires (§10.1.2).

### PDP role — serve a `Decider`

```go
package main

import (
	"context"
	"net/http"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/server"
)

type myPDP struct{ server.NotImplementedDecider }

func (p *myPDP) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Toy policy: alice can read anything; everyone else is denied.
	allow := req.Subject.ID == "alice@example.com" && req.Action.Name == "read"
	return &authzen.EvaluationResponse{Decision: allow}, nil
}

func main() {
	h := server.NewHandler(&myPDP{})
	http.ListenAndServe(":8080", h)
}
```

Embed `server.NotImplementedDecider` and override only the endpoints
your PDP serves. The handler maps unimplemented methods to HTTP 501,
and `server.BuildMetadata` introspects the `Decider` so the
`/.well-known/authzen-configuration` document advertises only the
endpoints you actually implement.

### Typed extensions on `Properties` and `Context`

The open extension fields — `Subject.Properties`, `Resource.Properties`,
`Action.Properties`, and the request / response `Context` — are
`json.RawMessage` so they round-trip byte-stably regardless of key
order. Use `authzen.DecodeJSON` and `authzen.EncodeJSON` to bridge
them to typed Go values:

```go
type DocumentMeta struct {
	OwnerID    string   `json:"ownerID"`
	Classifier []string `json:"classifier"`
}

// Building a request — typed → RawMessage.
props, _ := authzen.EncodeJSON(DocumentMeta{
	OwnerID:    "alice@example.com",
	Classifier: []string{"internal"},
})
req := &authzen.EvaluationRequest{
	Subject:  authzen.Subject{Type: "user", ID: "bob@example.com"},
	Action:   authzen.Action{Name: "read"},
	Resource: authzen.Resource{Type: "document", ID: "doc-42", Properties: props},
}

// Reading a response — RawMessage → typed.
var advice struct {
	Reason string `json:"reason"`
}
if err := authzen.DecodeJSON(resp.Context, &advice); err != nil {
	// ...
}
```

`DecodeJSON` treats an absent or empty `RawMessage` as "no extension
present" (no error, `v` left untouched), so you do not need to guard
against nil yourself.

## Metadata document

The library implements `/.well-known/authzen-configuration` (spec §9)
on both sides of the wire:

- **Server**: `server.BuildMetadata(pdpURL, decider, opts...)`
  introspects the `Decider` by probing each method with a sentinel
  request and publishes only the endpoints the PDP actually
  implements. Serve the result with `server.NewMetadataHandler` at
  `authzen.MetadataPath`.
- **Mix-up protection (client default)**: `Client.FetchMetadata` fails
  hard with a typed `*client.MixUpError` when the response's
  `policy_decision_point` does not match the base URL the client was
  configured with — the spec §9.1.1 defense against a swapped
  metadata document, an authorization-bypass-class vulnerability.
  Opt out with `client.WithRelaxedMetadataValidation()` only when the
  configured URL is known to differ from the published one (a TLS
  terminator or load balancer in front of the PDP, say).
- **Capabilities as opaque strings**: `Metadata.Capabilities` is
  `[]string`. The library never branches on specific URN values; the
  IANA `urn:ietf:params:authzen:*` registry has no entries yet, and
  clients should treat any URN they don't recognize as
  forward-compatible data rather than an error.
- **Caching**: `Client.FetchMetadata` honors the response's
  `Cache-Control: max-age=N`; absent that, it falls back to a
  configurable default (one hour). Override with
  `client.WithMetadataTTL(d)`. The cache lives on the `Client`, not
  globally — different clients can hold different documents.
- **Signed metadata** (`signed_metadata`, a JWS per RFC 7515) is
  round-tripped as opaque bytes in `v0.x` so existing data survives
  upgrades without churn. Verification and production move into
  `v0.2.0` along with a JOSE dependency; see the **Stability**
  section.

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

## Stability

Until `v1.0.0`, expect minor API churn at the Go-surface level —
constructor signatures, option ordering, exported helper names. The
**wire types** are pinned to the AuthZEN 1.0 spec and will not change
without a spec change; a PEP or PDP built against an earlier `v0.x`
will continue to interoperate over the wire across upgrades, even
when source-level renames force a small code edit.

Breaking changes are documented in [`CHANGELOG.md`](CHANGELOG.md) with
migration notes. Per the
[`go-jose` precedent](https://pkg.go.dev/github.com/go-jose/go-jose/v4),
major bumps after `v1.0.0` will live on `vN` branches with `vN`
embedded in the module path — no versioned subdirectories.

The `signed_metadata` field on the metadata document is round-tripped
as opaque JWS in `v0.x`; verification and signing land in `v0.2.0`
along with a JOSE dependency. See `DESIGN.md` §metadata for the
rationale.

## Compatibility

- **Go**: 1.26+
- **Runtime dependencies**: none. Standard library only.
- **Test dependencies**: none. Standard `testing` package with
  table-driven patterns.
- **Spec**: AuthZEN Authorization API 1.0 (Final, 2026-01-11).

## Contributing

Contributions welcome. See [`AGENTS.md`](AGENTS.md) for the
contributor conventions — they're written as guidance for AI coding
assistants, but humans will find the same conventions useful.

The short version: standard Go style (`gofmt`, `go vet`,
`staticcheck`, `golangci-lint` all run in CI), zero non-test runtime
dependencies, table-driven tests, and a strong preference for wire
fidelity over ergonomic shortcuts. New exported API surface and new
dependencies go through review.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
