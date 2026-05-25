# todo-pdp — example AuthZEN Policy Decision Point

A minimal Policy Decision Point that speaks the OpenID AuthZEN
Authorization API 1.0 wire protocol over a [Cedar](https://www.cedarpolicy.com/)
policy engine. Implements the OpenID AuthZEN WG's [Todo
conformance scenario](https://github.com/openid/authzen/tree/main/interop)
end-to-end: the same five users, the same five actions, the same
role-based rules every other conformant PDP encodes in its own
policy language.

The point of the example is to show a Go developer what a working
AuthZEN PDP looks like, end-to-end:

- how a `server.Decider` is implemented over a real policy engine,
- how `server.BuildMetadata` introspects the Decider and publishes
  only the endpoints the PDP actually supports,
- how the spec's load-bearing invariants (policy-deny is HTTP 200,
  `Properties` round-trip byte-stably, the metadata document carries
  the `policy_decision_point` URL for mix-up protection) play out on
  the wire when a Cedar backend is wired in.

It is **not production code**. There is no transport-level
authentication, no TLS, and no input rate limiting. Do not expose
it on the open internet.

## Quick start

```sh
go run .
```

In a second terminal:

```sh
# 1. The metadata document — published endpoints + policy_decision_point.
curl -s http://localhost:8080/.well-known/authzen-configuration | jq

# 2. Admin permit: Rick reading Beth's profile → HTTP 200 {"decision": true}.
curl -s -X POST http://localhost:8080/access/v1/evaluation \
  -H 'Content-Type: application/json' \
  -d '{
    "subject":  { "type": "user", "id": "rick@the-citadel.com" },
    "action":   { "name": "can_read_user" },
    "resource": { "type": "user", "id": "beth@the-smiths.com" }
  }'

# 3. Role-based deny: Jerry (viewer) trying to create a todo → HTTP 200 {"decision": false}.
curl -s -X POST http://localhost:8080/access/v1/evaluation \
  -H 'Content-Type: application/json' \
  -d '{
    "subject":  { "type": "user", "id": "jerry@the-smiths.com" },
    "action":   { "name": "can_create_todo" },
    "resource": { "type": "todo", "id": "todo-1" }
  }'

# 4. Owner-based deny: Morty (editor) trying to delete Summer's todo.
#    The PEP carries Summer's user ID in resource.properties.ownerID,
#    and the editor rule fires only when ownerID == principal.
curl -s -X POST http://localhost:8080/access/v1/evaluation \
  -H 'Content-Type: application/json' \
  -d '{
    "subject":  { "type": "user", "id": "morty@the-citadel.com" },
    "action":   { "name": "can_delete_todo" },
    "resource": { "type": "todo", "id": "todo-2",
                  "properties": { "ownerID": "summer@the-smiths.com" } }
  }'
```

Every one of those returns **HTTP 200**. A `decision: false` value is
the spec's representation of a legal policy deny (§5.1) — not an
error. Clients that treat a deny as a transport failure are
non-conformant.

## The role rules

| Role           | can_read_user | can_read_todos | can_create_todo | can_update_todo | can_delete_todo |
|----------------|:--:|:--:|:--:|:--:|:--:|
| admin          | ✅ | ✅ | ✅ | ✅ | ✅ |
| editor         | ✅ | ✅ | ✅ | owner only | owner only |
| viewer         | ✅ | ✅ | ❌ | ❌ | ❌ |

The five users (per the upstream scenario's `directory.ts`):

| User                          | Role(s)              |
|-------------------------------|----------------------|
| `rick@the-citadel.com`        | admin, evil_genius (unused) |
| `morty@the-citadel.com`       | editor               |
| `summer@the-smiths.com`       | editor               |
| `beth@the-smiths.com`         | viewer               |
| `jerry@the-smiths.com`        | viewer               |

The rules live in [`policies.cedar`](policies.cedar). The user / role
graph and the fixture todos live in [`entities.json`](entities.json).
Adjust either file and restart — the engine re-parses on startup.

## How the adapter works

`decider.go` is the AuthZEN ↔ Cedar bridge. Its job is small:

| AuthZEN wire field             | Cedar concept           |
|--------------------------------|-------------------------|
| `subject.type`, `subject.id`   | `Principal` `EntityUID` |
| `action.name`                  | `Action` `EntityUID`    |
| `resource.type`, `resource.id` | `Resource` `EntityUID`  |
| `resource.properties.ownerID`  | `resource.ownerID` attribute (`EntityRef`) |

Resource types are normalised — the AuthZEN PEP sends lowercase
(`"user"`, `"todo"`), Cedar's convention is PascalCase (`User`,
`Todo`) — and the resource's `ownerID` from `properties` is overlaid
onto the entity store at request time, so the engine's `when {
resource.ownerID == principal }` clause fires for resources the PEP
introduces dynamically and not only for the four fixture todos in
`entities.json`.

The Search* methods inherit `server.NotImplementedDecider`'s
`ErrNotImplemented` return — the example doesn't advertise or serve
the Search endpoints. The metadata document `BuildMetadata`
publishes reflects that: only `access_evaluation_endpoint` and
`access_evaluations_endpoint` appear in the JSON. A conformant
client that honors the metadata document doesn't try to call what
isn't advertised; one that does anyway gets a `501 Not Implemented`.

## Why Cedar

Three production-shaped Go-friendly PDP backends are realistic for a
v0.1 example: Cedar, Open Policy Agent (Rego), and Cerbos.

Cedar wins for an example because the policy file is one declarative
document a reader can skim, the entity model maps onto AuthZEN's
subject / action / resource one-to-one, and `cedar-go` is pure Go
with no embedded server or auxiliary process. Swapping it for
another engine is a `Decider` re-implementation — the `server`
package and the wire layer don't care which engine made the
decision.

## Conformance

`decider_test.go` drives every case from
`github.com/hstern/go-authzen/interop`'s `Cases()` table through the
Cedar-backed Decider and asserts the decision matches the documented
expectation. The same table is exercised by the library's own
in-memory Decider (the reference rule in `interop.Decide`) and by
the `//go:build interop`-tagged tests against Topaz on the network.
All three layers agree on every case in this release; a
disagreement would name exactly which layer is wrong.

Run it:

```sh
go test ./...
```

## What is intentionally NOT in this example

- **Authentication** of the PEP → PDP call. The spec is silent;
  consumers compose their own (mTLS, OAuth 2.0 bearer token, …) on
  top of `client.HTTPDoer` and `server.HandlerOption` middleware.
- **TLS**. Run behind a reverse proxy that handles termination.
- **Persistent state**. The entity store is loaded once from
  `entities.json` at startup; changes require a restart. A
  production PDP would refresh from a directory service or
  re-evaluate on the fly.
- **Search endpoints**. AuthZEN's three search variants are
  available on the library — see `server.Decider` — but this
  example does not implement them.
- **Signed metadata**. The library round-trips `signed_metadata` as
  opaque JWS bytes; verification ships in a future release.
