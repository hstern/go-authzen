# go-authzen — Go library for the OpenID AuthZEN 1.0 wire protocol. Pure-Go,
# zero-non-stdlib-runtime-dep library; no shipping runtime image. This Dockerfile
# exists ONLY to build the common `ci` image the CI fan-out runs off — built once
# per PR, pushed to the Forgejo container registry, then pulled + `docker run`
# by each check job (static, test, lint, interop).
# syntax=docker/dockerfile:1

# 1) Common Go base. Sources present, GOWORK off.
#    go.sum is added to the COPY line once the library has its first dependency
#    (currently zero non-test runtime deps per the design doc).
FROM golang:1.26.3-alpine AS gobase
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ENV GOWORK=off GOFLAGS=-trimpath

# 2) THE COMMON CI IMAGE — built ONCE, then every check job runs off it. Carries:
#      - gcc/musl-dev — the race detector needs cgo
#      - git — golangci-lint reads .git in some checks; future interop-scenario
#        tests may want it for fetching upstream fixtures
#      - golangci-lint — PINNED PREBUILT BINARY (static, musl-safe). NOT
#        `go install`, which would compile hundreds of modules and bloat the
#        image by gigabytes.
#      - staticcheck — pinned via go install
#      - govulncheck — go install (small, no meaningful version pinning)
#    gofmt and go vet come with the Go toolchain — no install needed.
#    TARGETARCH is set by BuildKit (default amd64).
FROM gobase AS ci
ARG TARGETARCH=amd64
ARG GOLANGCI_VERSION=2.12.1
ARG STATICCHECK_VERSION=2025.1.1
ARG GOVULNCHECK_VERSION=v1.1.4
RUN apk add --no-cache gcc musl-dev curl ca-certificates git \
 && curl -fsSL "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_VERSION}/golangci-lint-${GOLANGCI_VERSION}-linux-${TARGETARCH}.tar.gz" \
    | tar -xz --strip-components=1 -C /usr/local/bin "golangci-lint-${GOLANGCI_VERSION}-linux-${TARGETARCH}/golangci-lint" \
 && go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" \
 && go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
ENV PATH="/go/bin:${PATH}" CGO_ENABLED=1
