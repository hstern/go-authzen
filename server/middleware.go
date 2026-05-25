// Copyright 2026 The go-authzen Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"time"

	"github.com/hstern/go-authzen"
)

// LogEvent carries the data a logging hook receives once per
// request, after the response is committed. Consumers wire this
// into their existing log layer (slog, logrus, zap, etc.) via
// [WithLogger].
//
// Status is the HTTP status code the handler wrote. Duration is
// wall-clock time from request entry to response completion. Path
// is the request path as the server saw it (no normalization,
// matches what the route table dispatched on).
type LogEvent struct {
	Method   string
	Path     string
	Status   int
	Duration time.Duration
}

// MetricsEvent carries the data a metrics hook receives once per
// request. Counter-style hooks should treat each call as one
// request observed and increment with the labels in MetricsEvent.
type MetricsEvent struct {
	Path     string
	Status   int
	Duration time.Duration
}

// WithLogger installs a structured-logging hook called once per
// request, after the response is committed. The hook receives a
// [LogEvent] with method, path, status, and duration; consumers
// wire it into their existing log layer.
//
// The hook is called from the request goroutine — it MUST NOT
// block (any meaningful blocking work should be queued onto a
// channel and processed elsewhere) and MUST NOT panic. Passing
// nil installs no hook.
//
// If WithLogger is given multiple times, only the last one wins
// (no fan-out). Consumers that need fan-out implement it inside
// the supplied function.
func WithLogger(fn func(LogEvent)) HandlerOption {
	if fn == nil {
		return func(*handler) {}
	}
	return func(h *handler) {
		h.chain = withResponseObserver(h.chain, func(method, path string, status int, dur time.Duration) {
			fn(LogEvent{Method: method, Path: path, Status: status, Duration: dur})
		})
	}
}

// WithMetrics installs a metrics hook called once per request,
// after the response is committed. The hook receives a
// [MetricsEvent] with path, status, and duration; the canonical
// shape pairs with prometheus.CounterVec.WithLabelValues or
// equivalent.
//
// Same blocking / panic / single-hook rules as [WithLogger].
func WithMetrics(fn func(MetricsEvent)) HandlerOption {
	if fn == nil {
		return func(*handler) {}
	}
	return func(h *handler) {
		h.chain = withResponseObserver(h.chain, func(_ /* method */, path string, status int, dur time.Duration) {
			fn(MetricsEvent{Path: path, Status: status, Duration: dur})
		})
	}
}

// WithRequestIDEcho installs the spec §2.4 X-Request-ID echo
// middleware: if the incoming request carries an X-Request-ID
// header, the same value is set on the response. Absent header
// in: absent header out — no library-generated IDs.
//
// PEPs SHOULD send X-Request-ID per the spec to correlate logs
// and traces across the PEP/PDP boundary; this middleware
// guarantees the PDP holds up its half of that contract.
func WithRequestIDEcho() HandlerOption {
	return func(h *handler) {
		next := h.chain
		h.chain = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id := r.Header.Get(authzen.HTTPHeaderRequestID); id != "" {
				w.Header().Set(authzen.HTTPHeaderRequestID, id)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// withResponseObserver wraps next with a [http.Handler] that
// records the status code and duration, then invokes obs once
// the inner handler returns.
//
// Internal helper shared by [WithLogger] and [WithMetrics] — both
// observe the same response envelope; only the event-struct shape
// differs. Defined as a package-private function rather than a
// method on handler because the wrap composes around an arbitrary
// inner Handler, not specifically the handler's mux.
func withResponseObserver(next http.Handler, obs func(method, path string, status int, dur time.Duration)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		obs(r.Method, r.URL.Path, rec.status, time.Since(start))
	})
}

// statusRecorder wraps an [http.ResponseWriter] to capture the
// status code that was written. Defaults to 200 because that is
// the implicit code for any handler that writes a body without
// calling WriteHeader (the net/http standard semantic).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
