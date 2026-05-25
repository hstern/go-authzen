#!/bin/sh
# Interop scenario tests against the live OpenID AuthZEN Todo PDP. Owned by the `interop` CI job.
#
# The `interop` build tag gates network-dependent tests in interop/ — see interop/README.md.
# Without the tag, only the package's sanity tests (fixture consistency, decide-vs-cases
# agreement) run, and those already run as part of the `test` job. Under the tag, the
# PEP-role tests reach <https://todo.authzen-interop.net> and assert the live PDP agrees
# with the decision table.
#
# -race + -shuffle=on match the `test` job's invariants: races in the client's HTTP path
# are CI-blocking, and order-dependent fixtures must surface here rather than as flaky
# local repros. -count=1 defeats Go's test cache; with network in the mix, a cache hit
# would silently skip the actual call.
set -eu

echo "==> go test -tags interop -race -shuffle=on -count=1 ./interop/..."
go test -tags interop -race -shuffle=on -count=1 ./interop/...
echo "OK: interop tests passed."
