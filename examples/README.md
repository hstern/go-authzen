# Examples

Self-contained programs that exercise the `go-authzen` library.
Each example lives in its own subdirectory with its own `go.mod` so
its dependencies never leak into the library's graph.

| Example | Shows |
|---|---|
| [`todo-pdp/`](todo-pdp/) | A working PDP for the OpenID AuthZEN Todo conformance scenario, backed by a Cedar policy engine. Implements `server.Decider`, publishes the metadata document, and passes every case in `interop.Cases()`. |

To run an example, `cd` into its directory and `go run .`. Each
example carries its own README with a curl walkthrough of the wire
shapes it speaks.
