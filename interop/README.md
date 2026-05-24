# interop — OpenID AuthZEN Todo scenario fixtures

This package exposes the OpenID AuthZEN Todo interoperability scenario
as Go-native fixtures. The scenario is the live conformance harness the
WG maintains at <https://todo.authzen-interop.net>; sources at
<https://github.com/openid/authzen/tree/main/interop>.

Tests in this repository iterate the fixtures in two roles:

- **PEP role** — the library's client makes requests against the live
  public PDP at `interop.PublicPDPBaseURL` and asserts the decisions
  match the table.
- **PDP role** — `httptest.NewServer(server.NewHandler(d))` is stood
  up with an in-memory `Decider` that wraps `interop.Decide`; the
  library's client drives it with the same scenario inputs and the
  same decisions are asserted.

Network-dependent tests carry the `interop` build tag and are skipped
by default. Build them with:

```sh
go test -tags interop ./interop/...
```

The non-network sanity tests run on every CI fan-out and assert the
fixtures' internal consistency: user IDs unique, todo owners resolve to
known users, the `Cases` table is consistent with the `Decide` rule,
and every (user × action) pair is covered.

## What is in the fixtures

| Constant / function                  | Source                                                           |
| ------------------------------------ | ---------------------------------------------------------------- |
| `PublicPDPBaseURL`                   | the live scenario PDP endpoint                                   |
| `SubjectType` = `"user"`             | `authzen-todo-backend/src/auth.ts` builds `{type:"user", id:sub}`|
| `ResourceTypeUser`, `ResourceTypeTodo`| same                                                            |
| `ActionRead{User,Todos}`, `Action{Create,Update,Delete}Todo` | same             |
| `Users()`                            | `authzen-todo-backend/src/directory.ts`                          |
| `Todos()`                            | fixture set local to this package; mirrors what the live PDP serves|
| `Decide(...)`                        | the role-based rules participating PDPs apply (admin/editor/viewer)|
| `Cases()`                            | curated `(subject, action, resource) → decision` table          |

## Refresh procedure

The scenario evolves with the spec and the WG's interop runs. When
upstream changes, refresh the fixtures here in order:

1. **Fetch the upstream PEP.** From
   <https://github.com/openid/authzen/tree/main/interop/authzen-todo-backend/src>
   read at least:
   - `auth.ts` — the action / resource shape each PEP call sends.
   - `directory.ts` — the user list with subject IDs and roles.
   - any policy / rules files referenced from the README (the
     scenario today follows the "Topaz Citadel" admin/editor/viewer
     rules — different participating PDPs encode the same rules in
     their native policy languages).
2. **Diff against `scenario.go`.** If action names changed, update the
   `Action…` constants and any callers in `policy.go`. If users came
   or went, update the `users` slice. The order in the slice is the
   order `Users()` returns; preserve determinism.
3. **Update `policy.go` if rules changed.** Decide is the only place
   the rules live. Keep the role-based shape (`admin → permit-all`,
   `editor → own-resource`, `viewer → read-only`); reach for new role
   tiers only when upstream introduces them.
4. **Run the sanity tests.**
   ```sh
   go test ./interop/...
   ```
   `TestCasesAreConsistentWithDecide` fails if Cases drifts from
   Decide. `TestCasesCoverEveryRoleActionCombination` fails if the
   `Cases` generator misses a (user × action) pair.
5. **Run the network tests against the live PDP.**
   ```sh
   go test -tags interop ./interop/...
   ```
   If the live PDP disagrees with `Decide` on any case, the live PDP
   wins: update `Decide` and the rules documentation to match, then
   re-run the sanity tests until both layers agree again.
6. **Note the refresh in `CHANGELOG.md`** under the next version's
   unreleased entry.

## What is intentionally NOT in this package

- A full live HTTP client or live HTTP server. The PEP-role and PDP-role
  tests live next to the fixtures (with the `interop` build tag), not
  here, so callers that import `interop` for the fixtures alone don't
  drag in `net/http` linkage they didn't ask for.
- The Todo application's UI surface. The library tests the AuthZEN wire
  protocol against the scenario's authorization decisions, not the
  Todo app's user-facing behavior.
- `signed_metadata` verification. Per the library's deferred-to-v0.2
  posture the metadata document round-trips `signed_metadata` as an
  opaque JWS; the scenario does not require verification today.
