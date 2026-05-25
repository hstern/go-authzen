// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

// Command todo-pdp is a tiny example Policy Decision Point that
// implements the OpenID AuthZEN Authorization API 1.0 wire protocol
// over a Cedar policy engine. It mounts an http.Handler at the
// AuthZEN paths and serves the metadata document at
// /.well-known/authzen-configuration.
//
// The example exists to show consumers what a working AuthZEN PDP
// looks like end-to-end: how a Decider is wired, how the metadata
// document is published, and how the wire payloads round-trip.
// It is not production code — there is no transport-level
// authentication, no TLS, and no input rate limiting. Do not expose
// it on the open internet.
//
//	go run . -addr :8080
//
// See README.md in this directory for the curl walkthrough.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hstern/go-authzen"
	"github.com/hstern/go-authzen/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "todo-pdp:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", ":8080", "listen address (host:port)")
	pdpURL := flag.String("pdp-url", "", "public URL of this PDP (defaults to http://<addr>); the metadata document's policy_decision_point field")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	decider, err := newCedarDecider()
	if err != nil {
		return fmt.Errorf("build decider: %w", err)
	}

	publicURL := *pdpURL
	if publicURL == "" {
		publicURL = "http://" + httpHost(*addr)
	}
	metadata := server.BuildMetadata(publicURL, decider)

	logHook := func(e server.LogEvent) {
		logger.Info("evaluated", "method", e.Method, "path", e.Path, "status", e.Status, "duration", e.Duration)
	}

	mux := http.NewServeMux()
	mux.Handle(authzen.MetadataPath, server.NewMetadataHandler(metadata))
	mux.Handle("/access/v1/", server.NewHandler(decider, server.WithLogger(logHook), server.WithRequestIDEcho()))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *addr, "policy_decision_point", publicURL)
		serverErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

// httpHost turns the flag value (which may be ":8080" or
// "0.0.0.0:8080") into something a URL can use. An empty / wildcard
// host becomes "localhost" so the published policy_decision_point
// value is reachable in development.
func httpHost(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "localhost" + strings.TrimPrefix(addr, "0.0.0.0")
	}
	return addr
}
