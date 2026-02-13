// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"internal/godebug"
	"net/textproto"
	"strings"
)

// W3C Trace Context propagation support.
// This implements https://www.w3.org/TR/trace-context/

var httpw3ctrace = godebug.New("httpw3ctrace")

// traceMode represents the W3C trace context propagation mode.
type traceMode int

const (
	traceModeIgnore      traceMode = iota // "ignore" - no parsing, no injection
	traceModePassthrough                  // "passthrough" - opaque forward, no parsing
	traceModeContinue                     // "continue" - full W3C participation
	traceModeRestart                      // "restart" - discard inbound, create fresh
)

// tracePolicy returns the effective trace mode by reading the current
// GODEBUG httpw3ctrace value. The value is read on every call so that
// runtime changes via os.Setenv are honoured, consistent with other
// net/http GODEBUG settings.
func tracePolicy() traceMode {
	switch httpw3ctrace.Value() {
	case "ignore":
		return traceModeIgnore
	case "continue":
		return traceModeContinue
	case "restart":
		return traceModeRestart
	default: // "", "passthrough", or unknown
		return traceModePassthrough
	}
}

// traceWillInject reports whether injectClientTraceContext would write
// headers for the given request. Used to avoid unnecessary header
// cloning on the HTTP/2 path.
//
// The early-return logic here (ignore mode, existing Traceparent) must
// stay in sync with injectClientTraceContext.
func traceWillInject(req *Request) bool {
	mode := tracePolicy()
	if mode == traceModeIgnore {
		return false
	}
	if req.Header.has("Traceparent") {
		return false
	}
	if mode == traceModePassthrough {
		// Passthrough only emits when context carries raw headers.
		tc, ok := getTraceContext(req.Context())
		return ok && tc.raw != ""
	}
	// Continue and restart always inject.
	return true
}

// cloneAndInjectTraceContext shallow-copies req with cloned headers,
// removes any orphaned Tracestate, and injects W3C trace context.
// Used by the HTTP/2 paths in transport.go to avoid mutating the
// caller's original request.
func cloneAndInjectTraceContext(req *Request) *Request {
	clone := *req
	clone.Header = req.Header.Clone()
	clone.Header.Del("Tracestate")
	injectClientTraceContext(&clone, clone.Header)
	return &clone
}

// traceContext holds W3C trace context information.
type traceContext struct {
	traceID    [16]byte // 128-bit trace-id
	spanID     [8]byte  // 64-bit parent-id from incoming traceparent
	traceFlags byte     // trace-flags byte
	tracestate string   // raw validated tracestate, or ""
	raw        string   // original traceparent for passthrough mode
}

var traceContextKey = &contextKey{"w3c-trace-context"}

func getTraceContext(ctx context.Context) (traceContext, bool) {
	tc, ok := ctx.Value(traceContextKey).(traceContext)
	return tc, ok
}

func setTraceContext(ctx context.Context, tc traceContext) context.Context {
	return context.WithValue(ctx, traceContextKey, tc)
}

// parseTraceparent parses and validates a traceparent header.
// Returns the parsed trace context and true if valid, or zero value and false if invalid.
//
// Format: version-traceid-parentid-traceflags
// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//
// Per W3C spec:
// - version: 2-char hex, 0xFF is invalid
// - traceid: 32-char hex (128 bits), must be non-zero
// - parentid: 16-char hex (64 bits), must be non-zero
// - traceflags: 2-char hex (8 bits)
// - Future versions (> 00) are parsed using version 00 format, extra fields ignored
func parseTraceparent(h string) (traceContext, bool) {
	// Trim optional HTTP whitespace (OWS) before validation so that
	// values like "00-...-01 " are not falsely rejected.
	h = textproto.TrimString(h)
	if len(h) < 55 { // minimum: VV-TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT-PPPPPPPPPPPPPPPP-FF
		return traceContext{}, false
	}

	// The v00 traceparent format is fixed-width (55 chars):
	//   VV-TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT-PPPPPPPPPPPPPPPP-FF
	//   0  3                                36               53
	// Use direct indexing to avoid the []string allocation from SplitN.

	// Verify dash positions.
	if h[2] != '-' || h[35] != '-' || h[52] != '-' {
		return traceContext{}, false
	}

	// Version (bytes 0-1)
	if !isValidHexID(h[0:2], 2) {
		return traceContext{}, false
	}
	if h[0:2] == "ff" {
		return traceContext{}, false
	}

	// Version 00 must be exactly 55 chars; future versions may have
	// extra dash-separated fields (len > 55 with h[55] == '-').
	if h[0:2] == "00" {
		if len(h) != 55 {
			return traceContext{}, false
		}
	} else if len(h) > 55 && h[55] != '-' {
		return traceContext{}, false
	}

	// Trace-id (bytes 3-34, 32 hex chars, non-zero)
	if !isValidHexID(h[3:35], 32) {
		return traceContext{}, false
	}
	var traceID [16]byte
	_, _ = hex.Decode(traceID[:], []byte(h[3:35]))
	if isZeroID(traceID[:]) {
		return traceContext{}, false
	}

	// Parent-id (bytes 36-51, 16 hex chars, non-zero)
	if !isValidHexID(h[36:52], 16) {
		return traceContext{}, false
	}
	var spanID [8]byte
	_, _ = hex.Decode(spanID[:], []byte(h[36:52]))
	if isZeroID(spanID[:]) {
		return traceContext{}, false
	}

	// Trace-flags (bytes 53-54, exactly 2 hex chars for all versions)
	if !isValidHexID(h[53:55], 2) {
		return traceContext{}, false
	}
	var traceFlags [1]byte
	_, _ = hex.Decode(traceFlags[:], []byte(h[53:55]))

	return traceContext{
		traceID:    traceID,
		spanID:     spanID,
		traceFlags: traceFlags[0],
		raw:        h,
	}, true
}

// formatTraceparent formats a traceContext into a valid traceparent header string.
// Always produces version 00 format.
func formatTraceparent(tc traceContext) string {
	return "00-" + traceIDToHex(tc.traceID) + "-" + spanIDToHex(tc.spanID) + "-" + hex.EncodeToString([]byte{tc.traceFlags})
}

// validateTracestate validates a tracestate header.
// Returns the sanitized string and true if valid, or empty string and false if invalid.
// Per W3C spec the maximum size is 512 bytes.
// TODO: strict key/value parsing per W3C spec.
func validateTracestate(h string) (string, bool) {
	// Trim optional HTTP whitespace before enforcing the 512-byte
	// limit so that trailing OWS does not cause false rejection.
	h = textproto.TrimString(h)
	if len(h) > 512 {
		return "", false
	}
	return h, true
}

// randReadFunc is the function used to generate random bytes.
// It defaults to crypto/rand.Read. Tests may override it to
// simulate RNG failures.
var randReadFunc = rand.Read

// newTraceID generates a random 128-bit trace-id.
// Returns an error if the RNG source is unavailable so callers can
// degrade gracefully instead of crashing the process.
func newTraceID() ([16]byte, error) {
	var id [16]byte
	for {
		_, err := randReadFunc(id[:])
		if err != nil {
			return id, err
		}
		if !isZeroID(id[:]) {
			return id, nil
		}
	}
}

// newSpanID generates a random 64-bit span-id.
// Returns an error if the RNG source is unavailable so callers can
// degrade gracefully instead of crashing the process.
func newSpanID() ([8]byte, error) {
	var id [8]byte
	for {
		_, err := randReadFunc(id[:])
		if err != nil {
			return id, err
		}
		if !isZeroID(id[:]) {
			return id, nil
		}
	}
}

// traceIDToHex encodes a trace-id as lowercase hex.
func traceIDToHex(id [16]byte) string {
	return hex.EncodeToString(id[:])
}

// spanIDToHex encodes a span-id as lowercase hex.
func spanIDToHex(id [8]byte) string {
	return hex.EncodeToString(id[:])
}

// isValidHexID validates a hex string: correct length, lowercase hex chars only.
func isValidHexID(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isZeroID checks if an ID is all zeros.
func isZeroID(id []byte) bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// applyServerTraceContext extracts W3C trace context from incoming request headers
// and enriches the request context according to the configured mode.
func applyServerTraceContext(ctx context.Context, headers Header) context.Context {
	mode := tracePolicy()
	if mode == traceModeIgnore {
		return ctx
	}

	// Use the full header slices so that duplicate Traceparent lines
	// are treated as ambiguous (invalid) and multi-line Tracestate
	// entries are combined per the HTTP field combination rule.
	tpVals := headers.Values("Traceparent")
	tsVals := headers.Values("Tracestate")

	// W3C spec: multiple Traceparent fields are ambiguous;
	// treat as if the field were not provided.
	var traceparent string
	if len(tpVals) == 1 {
		traceparent = tpVals[0]
	}

	var tracestate string
	if len(tsVals) == 1 {
		tracestate = tsVals[0]
	} else if len(tsVals) > 1 {
		// HTTP allows combining multiple header lines with commas.
		tracestate = strings.Join(tsVals, ",")
	}

	// W3C spec: tracestate without traceparent is discarded
	if traceparent == "" && tracestate != "" {
		tracestate = ""
	}

	switch mode {
	case traceModePassthrough:
		return applyServerTraceContextPassthrough(ctx, traceparent, tracestate)
	case traceModeContinue:
		return applyServerTraceContextContinue(ctx, traceparent, tracestate)
	default: // traceModeRestart
		return createNewTraceContext(ctx)
	}
}

// applyServerTraceContextPassthrough implements passthrough mode:
// Store raw headers without parsing or validation.
func applyServerTraceContextPassthrough(ctx context.Context, traceparent, tracestate string) context.Context {
	if traceparent == "" {
		return ctx
	}
	return setTraceContext(ctx, traceContext{
		raw:        traceparent,
		tracestate: tracestate,
	})
}

// applyServerTraceContextContinue implements continue mode:
// Parse and validate traceparent, join existing trace or create new one.
func applyServerTraceContextContinue(ctx context.Context, traceparent, tracestate string) context.Context {
	if traceparent == "" {
		return createNewTraceContext(ctx)
	}

	tc, ok := parseTraceparent(traceparent)
	if !ok {
		// Invalid inbound traceparent: start a fresh trace context.
		// Incoming tracestate is intentionally dropped in this path.
		return createNewTraceContext(ctx)
	}

	if tracestate != "" {
		if validated, ok := validateTracestate(tracestate); ok {
			tracestate = validated
		} else {
			tracestate = ""
		}
	}

	tc.tracestate = tracestate
	return setTraceContext(ctx, tc)
}

// createNewTraceContext creates a new trace context with random IDs.
// If ID generation fails, the context is returned unmodified so
// tracing degrades gracefully instead of crashing the process.
func createNewTraceContext(ctx context.Context) context.Context {
	traceID, err := newTraceID()
	if err != nil {
		return ctx
	}
	spanID, err := newSpanID()
	if err != nil {
		return ctx
	}
	tc := traceContext{
		traceID:    traceID,
		spanID:     spanID,
		traceFlags: 0x01, // sampled by default
	}

	return setTraceContext(ctx, tc)
}

// injectClientTraceContext injects W3C trace context headers on outbound requests
// according to the configured mode. Called as the final step before dispatch.
// Headers are written to extra (the per-send extra header map) rather than
// req.Header, so caller-set headers are never mutated.
// If a Traceparent header is already present on req.Header (valid or not),
// this is a no-op: the caller owns the header and auto-injection does not
// override or validate it. This avoids mutating the original request during
// RoundTrip, which would violate the RoundTripper contract on the HTTP/1 path.
//
// The early-return logic here (ignore mode, existing Traceparent) must
// stay in sync with traceWillInject.
func injectClientTraceContext(req *Request, extra Header) {
	mode := tracePolicy()
	if mode == traceModeIgnore {
		return
	}

	// If the caller or middleware already set a Traceparent header
	// (even to an empty value), treat it as intentional and leave it
	// (and any Tracestate) as-is. Use has() rather than Get() != ""
	// so that an explicitly empty Traceparent is still respected.
	if req.Header.has("Traceparent") {
		return
	}

	switch mode {
	case traceModePassthrough:
		injectClientTraceContextPassthrough(req, extra)
	case traceModeContinue, traceModeRestart:
		injectClientTraceContextWithSpan(req, extra)
	}
}

// injectClientTraceContextPassthrough implements passthrough mode:
// Re-emit raw headers unchanged if present in context.
func injectClientTraceContextPassthrough(req *Request, extra Header) {
	tc, ok := getTraceContext(req.Context())
	if !ok || tc.raw == "" {
		return
	}
	extra.Set("Traceparent", tc.raw)
	if tc.tracestate != "" {
		extra.Set("Tracestate", tc.tracestate)
	} else {
		extra.Del("Tracestate")
	}
}

// injectClientTraceContextWithSpan is the shared implementation for continue
// and restart modes: use trace context from the request context if present
// (with a new span-id), or create a new trace context.
func injectClientTraceContextWithSpan(req *Request, extra Header) {
	tc, ok := getTraceContext(req.Context())
	if !ok || isZeroID(tc.traceID[:]) {
		// No context, or context came from passthrough mode (which
		// stores only raw and leaves traceID zeroed). Generate fresh
		// IDs so we never emit an all-zero trace-id on the wire.
		traceID, err := newTraceID()
		if err != nil {
			return
		}
		tc = traceContext{
			traceID:    traceID,
			traceFlags: 0x01, // sampled
		}
	}

	spanID, err := newSpanID()
	if err != nil {
		return
	}
	tc.spanID = spanID

	extra.Set("Traceparent", formatTraceparent(tc))
	if tc.tracestate != "" {
		extra.Set("Tracestate", tc.tracestate)
	} else {
		// Remove any stale Tracestate that may be present in extra
		// (e.g. from cloned headers on the HTTP/2 path) so it does
		// not travel alongside a freshly generated trace-id.
		extra.Del("Tracestate")
	}
}
