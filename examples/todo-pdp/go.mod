module github.com/hstern/go-authzen/examples/todo-pdp

go 1.26

// Track the library at the same tree level during local development;
// callers cloning this directory outside the repo should remove the
// replace directive and pin a tagged release of go-authzen instead.
replace github.com/hstern/go-authzen => ../..

require (
	github.com/cedar-policy/cedar-go v1.6.2
	github.com/hstern/go-authzen v0.1.0
)

require golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect
