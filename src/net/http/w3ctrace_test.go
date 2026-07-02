// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// mustTraceID is a test helper that calls newTraceID and fails on error.
func mustTraceID(t testing.TB) [16]byte {
	t.Helper()
	id, err := newTraceID()
	if err != nil {
		t.Fatalf("newTraceID: %v", err)
	}
	return id
}

// mustSpanID is a test helper that calls newSpanID and fails on error.
func mustSpanID(t testing.TB) [8]byte {
	t.Helper()
	id, err := newSpanID()
	if err != nil {
		t.Fatalf("newSpanID: %v", err)
	}
	return id
}

// newTestRequest returns a minimal GET request suitable for trace injection tests.
func newTestRequest(t testing.TB) *Request {
	t.Helper()
	return &Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Header: make(Header),
	}
}

func TestTracePolicy(t *testing.T) {
	// Just verify the function is callable and returns a valid mode
	mode := tracePolicy()
	if mode < traceModeIgnore || mode > traceModeRestart {
		t.Errorf("tracePolicy() returned invalid mode: %d", mode)
	}
}

func TestParseTraceparent(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantRaw string // expected raw value; if empty, defaults to input
	}{
		{
			name:  "valid v00",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			want:  true,
		},
		{
			name:  "valid v00 not sampled",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
			want:  true,
		},
		{
			name:  "future version with extra fields",
			input: "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
			want:  true, // Future versions may have extra fields
		},
		{
			name:  "future version with unseparated extension data",
			input: "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01extra",
			want:  false, // extension data must be dash-separated
		},
		{
			name:  "v00 with extra fields",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
			want:  false, // v00 must have exactly 4 fields
		},
		{
			name:  "v00 with overlong trace-flags",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0100",
			want:  false, // v00 trace-flags must be exactly 2 hex chars
		},
		{
			name:  "invalid version ff",
			input: "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			want:  false,
		},
		{
			name:  "all-zero trace-id",
			input: "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
			want:  false,
		},
		{
			name:  "all-zero span-id",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
			want:  false,
		},
		{
			name:  "uppercase hex",
			input: "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01",
			want:  false, // Must be lowercase
		},
		{
			name:  "wrong trace-id length",
			input: "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
			want:  false,
		},
		{
			name:  "wrong span-id length",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b-01",
			want:  false,
		},
		{
			name:  "invalid hex chars in trace-id",
			input: "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01",
			want:  false,
		},
		{
			name:  "truncated",
			input: "00-4bf92f3577b34da6a3ce929d0e0e4736",
			want:  false,
		},
		{
			name:  "empty",
			input: "",
			want:  false,
		},
		{
			name:  "missing version",
			input: "4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			want:  false,
		},
		{
			name:  "future version with long extra fields",
			input: "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-" + strings.Repeat("a", 256),
			want:  true, // Future versions may carry arbitrary extra fields
		},
		{
			name:    "valid with trailing OWS",
			input:   "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01  ",
			want:    true,
			wantRaw: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		},
		{
			name:    "valid with leading OWS",
			input:   "  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			want:    true,
			wantRaw: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, ok := parseTraceparent(tt.input)
			if ok != tt.want {
				t.Errorf("parseTraceparent(%q) ok = %v, want %v", tt.input, ok, tt.want)
			}
			if ok {
				// Verify trace-id and span-id are non-zero
				if isZeroID(tc.traceID[:]) {
					t.Error("parsed trace-id is zero")
				}
				if isZeroID(tc.spanID[:]) {
					t.Error("parsed span-id is zero")
				}
				// Verify raw is preserved (trimmed)
				wantRaw := tt.wantRaw
				if wantRaw == "" {
					wantRaw = tt.input
				}
				if tc.raw != wantRaw {
					t.Errorf("raw = %q, want %q", tc.raw, wantRaw)
				}
			}
		})
	}
}

func TestFormatTraceparent(t *testing.T) {
	// Test round-trip
	original := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc, ok := parseTraceparent(original)
	if !ok {
		t.Fatalf("parseTraceparent failed for valid input")
	}

	formatted := formatTraceparent(tc)

	// The formatted version should be valid
	tc2, ok := parseTraceparent(formatted)
	if !ok {
		t.Errorf("formatted traceparent is invalid: %q", formatted)
	}

	// trace-id and span-id should match
	if tc.traceID != tc2.traceID {
		t.Errorf("trace-id mismatch: %v != %v", tc.traceID, tc2.traceID)
	}
	if tc.spanID != tc2.spanID {
		t.Errorf("span-id mismatch: %v != %v", tc.spanID, tc2.spanID)
	}
	if tc.traceFlags != tc2.traceFlags {
		t.Errorf("trace-flags mismatch: %v != %v", tc.traceFlags, tc2.traceFlags)
	}

	// Formatted version should match original for v00
	if formatted != original {
		t.Errorf("formatted = %q, want %q", formatted, original)
	}
}

func TestValidateTracestate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty",
			input: "",
			want:  true,
		},
		{
			name:  "valid simple",
			input: "vendor1=value1",
			want:  true,
		},
		{
			name:  "valid multiple",
			input: "vendor1=value1,vendor2=value2",
			want:  true,
		},
		{
			name:  "at size limit",
			input: strings.Repeat("a", 512),
			want:  true,
		},
		{
			name:  "over size limit",
			input: strings.Repeat("a", 513),
			want:  false,
		},
		{
			name:  "at limit with trailing OWS",
			input: strings.Repeat("a", 512) + "  ",
			want:  true, // trailing whitespace trimmed before limit check
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  true, // Trimmed to empty, which is valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := validateTracestate(tt.input)
			if ok != tt.want {
				t.Errorf("validateTracestate(%q) ok = %v, want %v", tt.input, ok, tt.want)
			}
		})
	}
}

func TestNewTraceID(t *testing.T) {
	ids := make(map[[16]byte]bool)
	for i := 0; i < 100; i++ {
		id := mustTraceID(t)
		if isZeroID(id[:]) {
			t.Error("newTraceID() returned zero ID")
		}
		if ids[id] {
			t.Error("newTraceID() returned duplicate ID")
		}
		ids[id] = true
	}
}

func TestNewSpanID(t *testing.T) {
	ids := make(map[[8]byte]bool)
	for i := 0; i < 100; i++ {
		id := mustSpanID(t)
		if isZeroID(id[:]) {
			t.Error("newSpanID() returned zero ID")
		}
		if ids[id] {
			t.Error("newSpanID() returned duplicate ID")
		}
		ids[id] = true
	}
}

func TestIsValidHexID(t *testing.T) {
	tests := []struct {
		input  string
		length int
		want   bool
	}{
		{"0123456789abcdef", 16, true},
		{"0123456789ABCDEF", 16, false},  // Uppercase not allowed
		{"0123456789abcdef", 32, false},  // Wrong length
		{"0123456789abcde", 16, false},   // Too short
		{"0123456789abcdefg", 16, false}, // Invalid char
		{"", 0, true},
		{"00", 2, true},
		{"0g", 2, false},
	}

	for _, tt := range tests {
		got := isValidHexID(tt.input, tt.length)
		if got != tt.want {
			t.Errorf("isValidHexID(%q, %d) = %v, want %v", tt.input, tt.length, got, tt.want)
		}
	}
}

func TestIsZeroID(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"all zeros", []byte{0, 0, 0, 0}, true},
		{"one non-zero", []byte{0, 0, 0, 1}, false},
		{"all non-zero", []byte{1, 2, 3, 4}, false},
		{"empty", []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isZeroID(tt.input)
			if got != tt.want {
				t.Errorf("isZeroID(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTraceIDToHex(t *testing.T) {
	id := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	want := "4bf92f3577b34da6a3ce929d0e0e4736"
	got := traceIDToHex(id)
	if got != want {
		t.Errorf("traceIDToHex() = %q, want %q", got, want)
	}
}

func TestSpanIDToHex(t *testing.T) {
	id := [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7}
	want := "00f067aa0ba902b7"
	got := spanIDToHex(id)
	if got != want {
		t.Errorf("spanIDToHex() = %q, want %q", got, want)
	}
}

func TestTraceContextGetSet(t *testing.T) {
	ctx := context.Background()

	// Initially should not be present
	_, ok := getTraceContext(ctx)
	if ok {
		t.Error("expected no trace context initially")
	}

	// Set a trace context
	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
		tracestate: "vendor=value",
		raw:        "00-...",
	}

	ctx = setTraceContext(ctx, tc)

	// Retrieve it
	tc2, ok := getTraceContext(ctx)
	if !ok {
		t.Fatal("expected trace context to be present")
	}

	if tc.traceID != tc2.traceID {
		t.Error("trace-id mismatch")
	}
	if tc.spanID != tc2.spanID {
		t.Error("span-id mismatch")
	}
	if tc.traceFlags != tc2.traceFlags {
		t.Error("trace-flags mismatch")
	}
	if tc.tracestate != tc2.tracestate {
		t.Error("tracestate mismatch")
	}
	if tc.raw != tc2.raw {
		t.Error("raw mismatch")
	}
}

func FuzzParseTraceparent(f *testing.F) {
	// Seed with valid and invalid examples
	f.Add("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	f.Add("")
	f.Add("ff-00000000000000000000000000000000-0000000000000000-00")
	f.Add("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01")
	f.Add("00")
	f.Add("00-")
	f.Add("00-4bf92f3577b34da6a3ce929d0e0e4736")

	f.Fuzz(func(t *testing.T, s string) {
		tc, ok := parseTraceparent(s)
		if ok {
			// If parsing succeeded, verify invariants
			if isZeroID(tc.traceID[:]) {
				t.Error("valid parse produced zero trace-id")
			}
			if isZeroID(tc.spanID[:]) {
				t.Error("valid parse produced zero span-id")
			}

			// Round-trip must produce valid output
			out := formatTraceparent(tc)
			tc2, ok2 := parseTraceparent(out)
			if !ok2 {
				t.Errorf("round-trip failed: formatted %q is invalid", out)
			}

			// trace-id and span-id must survive round-trip
			if tc.traceID != tc2.traceID {
				t.Error("trace-id lost in round-trip")
			}
			if tc.spanID != tc2.spanID {
				t.Error("span-id lost in round-trip")
			}
			if tc.traceFlags != tc2.traceFlags {
				t.Error("trace-flags lost in round-trip")
			}
		}
	})
}

func BenchmarkParseTraceparent(b *testing.B) {
	input := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseTraceparent(input)
	}
}

func BenchmarkFormatTraceparent(b *testing.B) {
	tc := traceContext{
		traceID:    mustTraceID(b),
		spanID:     mustSpanID(b),
		traceFlags: 0x01,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatTraceparent(tc)
	}
}

func BenchmarkNewTraceID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := newTraceID(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewSpanID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := newSpanID(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTracePolicy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tracePolicy()
	}
}

func TestServerTraceContext_Continue_WithValidHeader(t *testing.T) {
	ctx := context.Background()

	result := applyServerTraceContextContinue(ctx,
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"vendor1=value1")

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be present")
	}

	// Should preserve the trace-id from incoming header
	expectedTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	if tc.traceID != expectedTraceID {
		t.Errorf("trace-id mismatch: got %v, want %v", tc.traceID, expectedTraceID)
	}

	// Should preserve the span-id (parent-id) from incoming header
	expectedSpanID := [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7}
	if tc.spanID != expectedSpanID {
		t.Errorf("span-id mismatch: got %v, want %v", tc.spanID, expectedSpanID)
	}

	// Should preserve trace-flags
	if tc.traceFlags != 0x01 {
		t.Errorf("trace-flags mismatch: got %02x, want 01", tc.traceFlags)
	}

	// Should preserve tracestate
	if tc.tracestate != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q, want %q", tc.tracestate, "vendor1=value1")
	}

	// Span-id came from a valid inbound header, so it must be marked inbound
	// (outbound injection preserves it when no local span is registered).
	if !tc.inbound {
		t.Error("inbound flag should be true for a valid inbound traceparent")
	}
}

func TestServerTraceContext_Continue_WithoutHeader(t *testing.T) {
	result := applyServerTraceContextContinue(context.Background(), "", "")

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be created")
	}
	if isZeroID(tc.traceID[:]) {
		t.Error("trace-id should not be zero")
	}
	if isZeroID(tc.spanID[:]) {
		t.Error("span-id should not be zero")
	}
	if tc.traceFlags != 0x01 {
		t.Errorf("trace-flags should be 0x01 (sampled), got %02x", tc.traceFlags)
	}
	// A freshly created context (no inbound header) is not inbound: its span-id
	// is locally minted, so outbound injection is free to replace it.
	if tc.inbound {
		t.Error("inbound flag should be false when no inbound traceparent was present")
	}
}

func TestServerTraceContext_Continue_InvalidHeader(t *testing.T) {
	result := applyServerTraceContextContinue(context.Background(), "invalid-traceparent", "vendor1=value1")

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be created")
	}
	if isZeroID(tc.traceID[:]) {
		t.Error("trace-id should not be zero")
	}
	if isZeroID(tc.spanID[:]) {
		t.Error("span-id should not be zero")
	}
	if tc.tracestate != "" {
		t.Errorf("tracestate should be discarded, got %q", tc.tracestate)
	}
	// Invalid inbound header falls back to a fresh context: not inbound.
	if tc.inbound {
		t.Error("inbound flag should be false when the inbound traceparent was invalid")
	}
}

func TestServerTraceContext_Continue_TracestateWithoutTraceparent(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	headers := make(Header)
	headers.Set("Tracestate", "vendor1=value1")

	result := applyServerTraceContext(context.Background(), headers)

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be created in continue mode")
	}
	if tc.tracestate != "" {
		t.Errorf("tracestate should be discarded per W3C spec, got %q", tc.tracestate)
	}
}

func TestServerTraceContext_Continue_InvalidTracestate(t *testing.T) {
	ctx := context.Background()

	result := applyServerTraceContextContinue(ctx,
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		strings.Repeat("a", 600))

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be present")
	}

	// Invalid tracestate should be discarded
	if tc.tracestate != "" {
		t.Errorf("invalid tracestate should be discarded, got %q", tc.tracestate)
	}
}

func TestServerTraceContext_Passthrough_WithHeader(t *testing.T) {
	ctx := context.Background()
	originalTraceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	result := applyServerTraceContextPassthrough(ctx, originalTraceparent, "vendor1=value1")

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be present")
	}

	// In passthrough mode, raw should be preserved
	if tc.raw != originalTraceparent {
		t.Errorf("raw traceparent mismatch: got %q, want %q", tc.raw, originalTraceparent)
	}

	// Tracestate should be preserved
	if tc.tracestate != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q, want %q", tc.tracestate, "vendor1=value1")
	}

	// IDs should be zero (not parsed)
	if !isZeroID(tc.traceID[:]) {
		t.Error("trace-id should be zero in passthrough mode")
	}
	if !isZeroID(tc.spanID[:]) {
		t.Error("span-id should be zero in passthrough mode")
	}
}

func TestServerTraceContext_Passthrough_WithoutHeader(t *testing.T) {
	ctx := context.Background()

	result := applyServerTraceContextPassthrough(ctx, "", "")

	// Should not create context if no headers present
	_, ok := getTraceContext(result)
	if ok {
		t.Error("passthrough mode should not create context when no headers present")
	}
}

func TestServerTraceContext_Restart(t *testing.T) {
	ctx := context.Background()

	result := createNewTraceContext(ctx)

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be created")
	}

	// Should have generated NEW IDs (not from incoming header)
	expectedTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	if tc.traceID == expectedTraceID {
		t.Error("restart mode should generate new trace-id, not use incoming")
	}

	// Should be non-zero
	if isZeroID(tc.traceID[:]) {
		t.Error("trace-id should not be zero")
	}
	if isZeroID(tc.spanID[:]) {
		t.Error("span-id should not be zero")
	}

	// Incoming tracestate should be discarded in restart mode
	if tc.tracestate != "" {
		t.Errorf("tracestate should be discarded in restart mode, got %q", tc.tracestate)
	}
}

func TestServerTraceContext_DuplicateTraceparent(t *testing.T) {
	// Multiple Traceparent header lines are ambiguous and must be
	// treated as if the field were absent.
	headers := make(Header)
	headers.Add("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	headers.Add("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00")

	result := applyServerTraceContext(context.Background(), headers)

	mode := tracePolicy()
	switch mode {
	case traceModeContinue:
		// Continue mode creates a new context when traceparent is absent/invalid.
		tc, ok := getTraceContext(result)
		if !ok {
			t.Fatal("expected trace context to be created")
		}
		// The trace-id must NOT come from either duplicate header.
		dup1 := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
			0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
		dup2 := [16]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
		if tc.traceID == dup1 || tc.traceID == dup2 {
			t.Error("duplicate traceparent should be treated as absent, not used")
		}
	case traceModePassthrough:
		// Passthrough with empty traceparent should produce no context.
		_, ok := getTraceContext(result)
		if ok {
			t.Error("duplicate traceparent should produce no context in passthrough")
		}
	}
}

func TestServerTraceContext_MultiLineTracestate(t *testing.T) {
	// Multiple Tracestate header lines must be combined with commas.
	headers := make(Header)
	headers.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	headers.Add("Tracestate", "vendor1=value1")
	headers.Add("Tracestate", "vendor2=value2")

	result := applyServerTraceContext(context.Background(), headers)

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context to be present")
	}

	// In passthrough mode, the combined tracestate is stored as-is.
	// In continue mode, it is validated then stored.
	if !strings.Contains(tc.tracestate, "vendor1=value1") {
		t.Errorf("tracestate missing vendor1: got %q", tc.tracestate)
	}
	if !strings.Contains(tc.tracestate, "vendor2=value2") {
		t.Errorf("tracestate missing vendor2: got %q", tc.tracestate)
	}
}

func BenchmarkApplyServerTraceContext_Continue_WithHeader(b *testing.B) {
	ctx := context.Background()
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tracestate := "vendor1=value1,vendor2=value2"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		applyServerTraceContextContinue(ctx, traceparent, tracestate)
	}
}

func BenchmarkApplyServerTraceContext_Continue_WithoutHeader(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		applyServerTraceContextContinue(ctx, "", "")
	}
}

func BenchmarkApplyServerTraceContext_Continue_InvalidHeader(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		applyServerTraceContextContinue(ctx, "invalid-traceparent", "vendor1=value1")
	}
}

func BenchmarkApplyServerTraceContext_Passthrough(b *testing.B) {
	ctx := context.Background()
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tracestate := "vendor1=value1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		applyServerTraceContextPassthrough(ctx, traceparent, tracestate)
	}
}

func BenchmarkApplyServerTraceContext_Restart(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		createNewTraceContext(ctx)
	}
}

// End-to-end server benchmark
func BenchmarkServeHTTP_Baseline(b *testing.B) {
	// Baseline: simple handler, no trace headers
	handler := HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusOK)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(Header),
			Body:   NoBody,
		}
		w := &responseWriterBenchmark{}
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkServeHTTP_WithTraceparent(b *testing.B) {
	// With valid traceparent header (continue mode will parse)
	handler := HandlerFunc(func(w ResponseWriter, r *Request) {
		// Access the trace context (simulating middleware that uses it)
		_, _ = getTraceContext(r.Context())
		w.WriteHeader(StatusOK)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(Header),
			Body:   NoBody,
		}
		req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		w := &responseWriterBenchmark{}
		handler.ServeHTTP(w, req)
	}
}

type responseWriterBenchmark struct {
	h Header
}

func (w *responseWriterBenchmark) Header() Header {
	if w.h == nil {
		w.h = make(Header)
	}
	return w.h
}

func (*responseWriterBenchmark) Write(b []byte) (int, error) { return len(b), nil }
func (*responseWriterBenchmark) WriteHeader(int)             {}

func TestClientTraceContext_Continue_ExistingValidHeader(t *testing.T) {
	// When valid traceparent already present, should be no-op
	req := newTestRequest(t)
	originalTraceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	req.Header.Set("Traceparent", originalTraceparent)

	extra := make(Header)
	injectClientTraceContext(req, extra)

	// Should not have written anything to extra (no-op)
	if extra.Get("Traceparent") != "" {
		t.Errorf("existing valid traceparent should cause no-op, but extra got %q",
			extra.Get("Traceparent"))
	}
}

func TestClientTraceContext_ExistingInvalidHeader_NoOp(t *testing.T) {
	// When any traceparent is present (even invalid), injectClientTraceContext
	// should be a no-op: the caller owns the header and auto-injection does
	// not override, validate, or delete it.
	req := newTestRequest(t)
	req.Header.Set("Traceparent", "invalid-traceparent")
	req.Header.Set("Tracestate", "stale=value")

	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContext(req, extra)

	// Should not have written anything to extra (no-op).
	if extra.Get("Traceparent") != "" {
		t.Errorf("existing invalid traceparent should cause no-op, but extra got %q",
			extra.Get("Traceparent"))
	}

	// req.Header must not be mutated.
	if req.Header.Get("Traceparent") != "invalid-traceparent" {
		t.Errorf("req.Header Traceparent was mutated: got %q", req.Header.Get("Traceparent"))
	}
	if req.Header.Get("Tracestate") != "stale=value" {
		t.Errorf("req.Header Tracestate was mutated: got %q", req.Header.Get("Tracestate"))
	}
}

func TestClientTraceContext_Continue_FromContext(t *testing.T) {
	// A context parsed from a valid inbound traceparent (inbound=true) with no
	// registered span must PRESERVE the inbound parent-id on the outbound
	// request, rather than minting a random ("phantom") span-id. This keeps a
	// service that does not report a span linked to the real upstream span.
	req := newTestRequest(t)

	originalTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	originalSpanID := [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7}

	tc := traceContext{
		traceID:    originalTraceID,
		spanID:     originalSpanID,
		traceFlags: 0x01,
		tracestate: "vendor1=value1",
		inbound:    true,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	// Should have traceparent in extra
	traceparent := extra.Get("Traceparent")
	if traceparent == "" {
		t.Fatal("expected traceparent to be set")
	}

	// Parse it
	injectedTC, ok := parseTraceparent(traceparent)
	if !ok {
		t.Fatalf("injected traceparent is invalid: %q", traceparent)
	}

	// Should preserve trace-id
	if injectedTC.traceID != originalTraceID {
		t.Error("trace-id was not preserved")
	}

	// Should PRESERVE the inbound span-id (no phantom mint) since no
	// observability library registered a span via WithTraceInfo.
	if injectedTC.spanID != originalSpanID {
		t.Errorf("inbound span-id should be preserved, got %x want %x",
			injectedTC.spanID, originalSpanID)
	}

	// Should preserve tracestate
	if extra.Get("Tracestate") != "vendor1=value1" {
		t.Errorf("tracestate not preserved: got %q", extra.Get("Tracestate"))
	}

	// req.Header must not have been mutated
	if req.Header.Get("Traceparent") != "" {
		t.Error("req.Header was mutated; trace headers should only go to extra")
	}
}

func TestClientTraceContext_Continue_NoContext(t *testing.T) {
	// Should create new trace context when none present
	req := newTestRequest(t)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	// Should have traceparent in extra
	traceparent := extra.Get("Traceparent")
	if traceparent == "" {
		t.Fatal("expected traceparent to be created")
	}

	// Should be valid
	tc, ok := parseTraceparent(traceparent)
	if !ok {
		t.Fatalf("created traceparent is invalid: %q", traceparent)
	}

	// Should have non-zero IDs
	if isZeroID(tc.traceID[:]) {
		t.Error("created trace-id is zero")
	}
	if isZeroID(tc.spanID[:]) {
		t.Error("created span-id is zero")
	}

	// Should be sampled
	if tc.traceFlags != 0x01 {
		t.Errorf("trace-flags should be 0x01, got %02x", tc.traceFlags)
	}
}

func TestClientTraceContext_Continue_TraceInfoUpdatesSpanID(t *testing.T) {
	// When an observability library registers a span via WithTraceInfo, its
	// span-id becomes the outbound parent-id even for an inbound context —
	// the library's real span replaces the preserved upstream parent-id.
	req := newTestRequest(t)

	originalTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	originalSpanID := [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7}
	tc := traceContext{traceID: originalTraceID, spanID: originalSpanID, traceFlags: 0x01, inbound: true}
	ctx := WithTraceInfo(setTraceContext(context.Background(), tc), TraceInfo{SpanID: 0x1122334455667788, Sampled: true})
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	injectedTC, ok := parseTraceparent(extra.Get("Traceparent"))
	if !ok {
		t.Fatalf("injected traceparent is invalid: %q", extra.Get("Traceparent"))
	}
	if injectedTC.traceID != originalTraceID {
		t.Error("trace-id was not preserved")
	}
	wantSpanID := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if injectedTC.spanID != wantSpanID {
		t.Errorf("span-id should be the TraceInfo span-id, got %x want %x", injectedTC.spanID, wantSpanID)
	}
}

func TestClientTraceContext_Continue_TraceInfoUnsampledClearsFlag(t *testing.T) {
	// TraceInfo.Sampled reflects the local recording decision and overrides
	// the upstream sampled flag on the outbound traceparent.
	req := newTestRequest(t)
	tc := traceContext{
		traceID:    [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36},
		spanID:     [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7},
		traceFlags: 0x01, // upstream sampled
		inbound:    true,
	}
	ctx := WithTraceInfo(setTraceContext(context.Background(), tc), TraceInfo{SpanID: 0x1122334455667788, Sampled: false})
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)
	injectedTC, _ := parseTraceparent(extra.Get("Traceparent"))
	if injectedTC.traceFlags&0x01 != 0 {
		t.Errorf("sampled flag should be cleared by local decision, got flags %02x", injectedTC.traceFlags)
	}
}

func TestClientTraceContext_Continue_VendorEntryMergedNewestFirst(t *testing.T) {
	// A TraceInfo vendor entry is prepended to the inbound tracestate
	// (newest-first) so the library's span identity is carried in tracestate.
	req := newTestRequest(t)
	tc := traceContext{
		traceID:    [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36},
		spanID:     [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7},
		traceFlags: 0x01,
		tracestate: "vendor1=value1",
		inbound:    true,
	}
	ctx := WithTraceInfo(setTraceContext(context.Background(), tc), TraceInfo{
		SpanID:          0x1122334455667788,
		Sampled:         true,
		TraceStateEntry: "dd=s:1122334455667788",
	})
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	want := "dd=s:1122334455667788,vendor1=value1"
	if got := extra.Get("Tracestate"); got != want {
		t.Errorf("tracestate merge: got %q want %q", got, want)
	}
}

func TestClientTraceContext_Continue_VendorEntryDedupesSameKey(t *testing.T) {
	// If the inbound tracestate already carries the library's vendor key, the
	// stale member is dropped so the fresh value wins with no duplicate key.
	req := newTestRequest(t)
	tc := traceContext{
		traceID:    [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36},
		spanID:     [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7},
		traceFlags: 0x01,
		tracestate: "dd=s:old,foo=bar",
		inbound:    true,
	}
	ctx := WithTraceInfo(setTraceContext(context.Background(), tc), TraceInfo{
		SpanID:          0x1122334455667788,
		Sampled:         true,
		TraceStateEntry: "dd=s:new",
	})
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	want := "dd=s:new,foo=bar"
	if got := extra.Get("Tracestate"); got != want {
		t.Errorf("tracestate dedup: got %q want %q", got, want)
	}
}

func TestClientTraceContext_Restart_InjectsVendorEntryDropsPrior(t *testing.T) {
	// Restart shape: the server-side createNewTraceContext already dropped the
	// prior tracestate, so injection with a TraceInfo vendor entry emits only
	// the library's own entry (Gap 4: restart vendor-key injection).
	req := newTestRequest(t)
	ctx := createNewTraceContext(context.Background()) // fresh: no tracestate, inbound=false
	ctx = WithTraceInfo(ctx, TraceInfo{
		SpanID:          0x1122334455667788,
		Sampled:         true,
		TraceStateEntry: "dd=s:1122334455667788",
	})
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	if got := extra.Get("Tracestate"); got != "dd=s:1122334455667788" {
		t.Errorf("restart tracestate: got %q want only the vendor entry", got)
	}
	injectedTC, ok := parseTraceparent(extra.Get("Traceparent"))
	if !ok {
		t.Fatalf("injected traceparent invalid: %q", extra.Get("Traceparent"))
	}
	if wantSpanID := ([8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}); injectedTC.spanID != wantSpanID {
		t.Errorf("restart span-id: got %x want %x", injectedTC.spanID, wantSpanID)
	}
}

func TestMergeTracestate(t *testing.T) {
	long := strings.Repeat("k", 300)
	tests := []struct {
		name  string
		entry string
		prior string
		want  string
	}{
		{"empty entry returns prior", "", "foo=bar", "foo=bar"},
		{"empty prior returns entry", "dd=s:1", "", "dd=s:1"},
		{"prepend newest first", "dd=s:1", "foo=bar", "dd=s:1,foo=bar"},
		{"dedup same key", "dd=s:new", "dd=s:old,foo=bar", "dd=s:new,foo=bar"},
		{"trim whitespace members", "dd=s:1", "foo=bar, baz=qux", "dd=s:1,foo=bar,baz=qux"},
		// entry + two ~300-byte members exceeds 512; oldest is dropped, entry kept.
		{"truncate oldest to fit", "dd=s:1", "a=" + long + ",b=" + long, "dd=s:1,a=" + long},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeTracestate(tt.entry, tt.prior); got != tt.want {
				t.Errorf("mergeTracestate(%q, %q) = %q, want %q", tt.entry, tt.prior, got, tt.want)
			}
			if got := mergeTracestate(tt.entry, tt.prior); len(got) > 512 {
				t.Errorf("mergeTracestate result exceeds 512 bytes: %d", len(got))
			}
		})
	}
}

func TestClientTraceContext_Passthrough_WithContext(t *testing.T) {
	// Should re-emit raw headers from context
	req := newTestRequest(t)

	rawTraceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc := traceContext{
		raw:        rawTraceparent,
		tracestate: "vendor1=value1",
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextPassthrough(req, extra)

	// Should have exact raw traceparent in extra
	if extra.Get("Traceparent") != rawTraceparent {
		t.Errorf("traceparent mismatch: got %q, want %q",
			extra.Get("Traceparent"), rawTraceparent)
	}

	// Should have tracestate in extra
	if extra.Get("Tracestate") != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q", extra.Get("Tracestate"))
	}
}

func TestClientTraceContext_Passthrough_NoContext(t *testing.T) {
	// Should not inject headers when no context
	req := newTestRequest(t)

	extra := make(Header)
	injectClientTraceContextPassthrough(req, extra)

	// Should not have traceparent
	if extra.Get("Traceparent") != "" {
		t.Error("passthrough mode should not create headers when no context")
	}
}

func TestClientTraceContext_Passthrough_ExistingHeader_NoValidation(t *testing.T) {
	// In passthrough mode, an existing Traceparent on req.Header should
	// cause a no-op without any parsing or validation.
	req := newTestRequest(t)
	// A non-parseable traceparent that passthrough should leave untouched.
	req.Header.Set("Traceparent", "not-a-valid-traceparent-at-all")

	extra := make(Header)
	injectClientTraceContext(req, extra)

	// Should not have injected anything.
	if extra.Get("Traceparent") != "" {
		t.Errorf("passthrough should no-op with existing header, but extra got %q",
			extra.Get("Traceparent"))
	}
	// Original header must be intact (not deleted or mutated).
	if req.Header.Get("Traceparent") != "not-a-valid-traceparent-at-all" {
		t.Errorf("req.Header was mutated: got %q", req.Header.Get("Traceparent"))
	}
}

func TestClientTraceContext_StaleTracestateCleared(t *testing.T) {
	// When injecting a new Traceparent into extra (e.g. cloned headers on
	// the HTTP/2 path), any pre-existing Tracestate in extra must be removed
	// if the trace context carries no tracestate.
	req := newTestRequest(t)

	// Simulate context with no tracestate.
	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	// Simulate the HTTP/2 path: extra starts as a clone of req.Header and
	// may carry a stale Tracestate from a previous hop.
	extra := make(Header)
	extra.Set("Tracestate", "stale=value")

	injectClientTraceContextWithSpan(req, extra)

	// Traceparent must be present.
	if extra.Get("Traceparent") == "" {
		t.Fatal("expected Traceparent in extra")
	}
	// Stale Tracestate must have been removed.
	if extra.Get("Tracestate") != "" {
		t.Errorf("stale Tracestate was not cleared: got %q", extra.Get("Tracestate"))
	}
}

func TestClientTraceContext_PassthroughContextInContinueMode(t *testing.T) {
	// When mode switches at runtime from passthrough to continue,
	// the context carries only raw (traceID is zero). The injection
	// must generate fresh IDs instead of emitting an all-zero trace-id.
	req := newTestRequest(t)

	// Simulate a passthrough-mode context: raw is set, traceID is zero.
	tc := traceContext{
		raw:        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		tracestate: "vendor1=value1",
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	traceparent := extra.Get("Traceparent")
	if traceparent == "" {
		t.Fatal("expected Traceparent in extra")
	}
	parsed, ok := parseTraceparent(traceparent)
	if !ok {
		t.Fatalf("emitted traceparent is invalid: %q", traceparent)
	}
	if isZeroID(parsed.traceID[:]) {
		t.Error("emitted traceparent has all-zero trace-id")
	}
	if isZeroID(parsed.spanID[:]) {
		t.Error("emitted traceparent has all-zero span-id")
	}
}

func TestClientTraceContext_PassthroughStaleTracestateCleared(t *testing.T) {
	// Same as above but for the passthrough injection path.
	req := newTestRequest(t)

	tc := traceContext{
		raw: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		// No tracestate.
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	extra.Set("Tracestate", "stale=value")

	injectClientTraceContextPassthrough(req, extra)

	if extra.Get("Traceparent") == "" {
		t.Fatal("expected Traceparent in extra")
	}
	if extra.Get("Tracestate") != "" {
		t.Errorf("stale Tracestate was not cleared: got %q", extra.Get("Tracestate"))
	}
}

func TestClientTraceContext_OrphanedTracestateCleared(t *testing.T) {
	// When req.Header has Tracestate but no Traceparent (spec-invalid),
	// and injection generates a fresh Traceparent, the stale Tracestate
	// must not appear on the wire alongside it. The HTTP/1 transport
	// path clones req.Header to remove it before calling injection;
	// this test simulates that clone-then-inject sequence.
	req := newTestRequest(t)
	// Orphaned Tracestate on the request (no Traceparent).
	req.Header.Set("Tracestate", "stale=orphan")

	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	// Simulate the HTTP/1 clone path: remove Tracestate from a cloned
	// header before injection, as the transport does.
	cloned := req.Header.Clone()
	cloned.Del("Tracestate")

	extra := make(Header)
	clonedReq := *req
	clonedReq.Header = cloned
	// Use injectClientTraceContextWithSpan directly (continue/restart
	// mode), which is the path where orphaned Tracestate matters.
	injectClientTraceContextWithSpan(&clonedReq, extra)

	if extra.Get("Traceparent") == "" {
		t.Fatal("expected Traceparent in extra")
	}
	// The cloned header should not carry the stale Tracestate.
	if clonedReq.Header.Get("Tracestate") != "" {
		t.Errorf("stale Tracestate was not removed from cloned header: got %q",
			clonedReq.Header.Get("Tracestate"))
	}
	// The original request must not be mutated.
	if req.Header.Get("Tracestate") != "stale=orphan" {
		t.Errorf("original req.Header was mutated: got %q", req.Header.Get("Tracestate"))
	}
}

func TestTraceWillInject(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=passthrough")
	// traceWillInject should return false when injection is a no-op,
	// so the HTTP/2 path can skip header cloning.
	tests := []struct {
		name       string
		header     string // Traceparent on req.Header ("" = absent)
		ctxRaw     string // raw traceparent in context ("" = no context)
		wantInject bool
	}{
		{
			name:       "no header, context with raw (passthrough injects)",
			ctxRaw:     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			wantInject: true,
		},
		{
			name:       "no header, no context (passthrough skips)",
			wantInject: false,
		},
		{
			name:       "existing header (all modes skip)",
			header:     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			wantInject: false,
		},
		{
			name:       "existing invalid header (all modes skip)",
			header:     "garbage",
			wantInject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newTestRequest(t)
			if tt.header != "" {
				req.Header.Set("Traceparent", tt.header)
			}
			ctx := context.Background()
			if tt.ctxRaw != "" {
				ctx = setTraceContext(ctx, traceContext{raw: tt.ctxRaw})
			}
			req = req.WithContext(ctx)

			if got := traceWillInject(req); got != tt.wantInject {
				t.Errorf("traceWillInject() = %v, want %v", got, tt.wantInject)
			}
		})
	}
}

// --- Mode-specific tests via GODEBUG ---
// These tests exercise the dispatcher functions (applyServerTraceContext,
// injectClientTraceContext, traceWillInject) in all four modes by setting
// GODEBUG at runtime.

func TestTracePolicyModes(t *testing.T) {
	tests := []struct {
		godebug string
		want    traceMode
	}{
		{"", traceModePassthrough},
		{"httpw3ctrace=passthrough", traceModePassthrough},
		{"httpw3ctrace=ignore", traceModeIgnore},
		{"httpw3ctrace=continue", traceModeContinue},
		{"httpw3ctrace=restart", traceModeRestart},
		{"httpw3ctrace=bogus", traceModePassthrough},
	}
	for _, tt := range tests {
		t.Run(tt.godebug, func(t *testing.T) {
			t.Setenv("GODEBUG", tt.godebug)
			if got := tracePolicy(); got != tt.want {
				t.Errorf("tracePolicy() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestApplyServerTraceContext_IgnoreMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=ignore")

	ctx := context.Background()
	headers := make(Header)
	headers.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	result := applyServerTraceContext(ctx, headers)

	_, ok := getTraceContext(result)
	if ok {
		t.Error("expected no trace context in ignore mode")
	}
}

func TestApplyServerTraceContext_ContinueMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	ctx := context.Background()
	headers := make(Header)
	headers.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	headers.Set("Tracestate", "vendor1=value1")

	result := applyServerTraceContext(ctx, headers)

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context in continue mode")
	}
	expectedTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	if tc.traceID != expectedTraceID {
		t.Errorf("trace-id mismatch in continue mode")
	}
	if tc.tracestate != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q", tc.tracestate)
	}
}

func TestApplyServerTraceContext_ContinueMode_InvalidTraceparentCreatesNew(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	headers := make(Header)
	headers.Set("Traceparent", "invalid-traceparent")
	headers.Set("Tracestate", "vendor1=value1")

	result := applyServerTraceContext(context.Background(), headers)
	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context in continue mode")
	}
	if isZeroID(tc.traceID[:]) {
		t.Error("trace-id should not be zero")
	}
	if isZeroID(tc.spanID[:]) {
		t.Error("span-id should not be zero")
	}
	if tc.tracestate != "" {
		t.Errorf("tracestate should be discarded with invalid traceparent, got %q", tc.tracestate)
	}
}

func TestApplyServerTraceContext_ContinueMode_InvalidVersionCreatesNew(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	headers := make(Header)
	// Non-hex version means version parsing fails.
	headers.Set("Traceparent", "zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	headers.Set("Tracestate", "vendor1=value1")

	result := applyServerTraceContext(context.Background(), headers)
	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context in continue mode")
	}
	if isZeroID(tc.traceID[:]) {
		t.Error("trace-id should not be zero")
	}
	if isZeroID(tc.spanID[:]) {
		t.Error("span-id should not be zero")
	}
	if tc.tracestate != "" {
		t.Errorf("tracestate should be discarded with invalid version, got %q", tc.tracestate)
	}
}

func TestApplyServerTraceContext_ContinueMode_FutureVersionIsAccepted(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	const incoming = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03-extra"

	headers := make(Header)
	headers.Set("Traceparent", incoming)
	headers.Set("Tracestate", "vendor1=value1")

	result := applyServerTraceContext(context.Background(), headers)
	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context in continue mode")
	}

	expectedTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	if tc.traceID != expectedTraceID {
		t.Errorf("trace-id mismatch for future version")
	}
	expectedParentID := [8]byte{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7}
	if tc.spanID != expectedParentID {
		t.Errorf("parent-id mismatch for future version")
	}
	if tc.traceFlags != 0x03 {
		t.Errorf("trace-flags mismatch: got %02x, want 03", tc.traceFlags)
	}
	if tc.tracestate != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q", tc.tracestate)
	}
}

func TestApplyServerTraceContext_RestartMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=restart")

	ctx := context.Background()
	headers := make(Header)
	headers.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	result := applyServerTraceContext(ctx, headers)

	tc, ok := getTraceContext(result)
	if !ok {
		t.Fatal("expected trace context in restart mode")
	}
	// Restart mode discards incoming trace-id and generates new.
	incomingTraceID := [16]byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
		0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	if tc.traceID == incomingTraceID {
		t.Error("restart mode should not use incoming trace-id")
	}
	if isZeroID(tc.traceID[:]) {
		t.Error("trace-id should not be zero")
	}
}

func TestInjectClientTraceContext_IgnoreMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=ignore")

	req := newTestRequest(t)
	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContext(req, extra)

	if extra.Get("Traceparent") != "" {
		t.Error("expected no traceparent in ignore mode")
	}
}

func TestInjectClientTraceContext_ContinueMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	req := newTestRequest(t)
	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
		tracestate: "vendor1=value1",
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContext(req, extra)

	traceparent := extra.Get("Traceparent")
	if traceparent == "" {
		t.Fatal("expected traceparent in continue mode")
	}
	parsed, ok := parseTraceparent(traceparent)
	if !ok {
		t.Fatalf("invalid traceparent: %q", traceparent)
	}
	if parsed.traceID != tc.traceID {
		t.Error("trace-id was not preserved")
	}
	if extra.Get("Tracestate") != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q", extra.Get("Tracestate"))
	}
}

func TestInjectClientTraceContext_RestartMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=restart")

	req := newTestRequest(t)
	tc := traceContext{
		traceID:    mustTraceID(t),
		spanID:     mustSpanID(t),
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContext(req, extra)

	if extra.Get("Traceparent") == "" {
		t.Fatal("expected traceparent in restart mode")
	}
}

func TestTraceWillInject_IgnoreMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=ignore")

	req := newTestRequest(t)
	if traceWillInject(req) {
		t.Error("traceWillInject should return false in ignore mode")
	}
}

func TestTraceWillInject_ContinueMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	// Continue mode always injects when no header present.
	req := newTestRequest(t)
	if !traceWillInject(req) {
		t.Error("traceWillInject should return true in continue mode with no header")
	}

	// With existing header, should return false.
	req2 := newTestRequest(t)
	req2.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if traceWillInject(req2) {
		t.Error("traceWillInject should return false with existing header")
	}
}

func TestTraceWillInject_RestartMode(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=restart")

	req := newTestRequest(t)
	if !traceWillInject(req) {
		t.Error("traceWillInject should return true in restart mode with no header")
	}
}

func TestParseTraceparent_FewDashes(t *testing.T) {
	// A string ≥55 chars but with no dashes at the expected positions
	// (h[2], h[35], h[52]) is rejected by the dash-position check.
	_, ok := parseTraceparent(strings.Repeat("a", 55))
	if ok {
		t.Error("expected false for no-dash string")
	}
}

func TestParseTraceparent_InvalidVersionHex(t *testing.T) {
	// Version field is not valid lowercase hex → !isValidHexID(h[0:2], 2).
	_, ok := parseTraceparent("XX-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if ok {
		t.Error("expected false for uppercase version")
	}
}

func TestParseTraceparent_InvalidSpanIDHex(t *testing.T) {
	// Span-id field has uppercase hex → !isValidHexID(h[36:52], 16).
	_, ok := parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00F067AA0BA902B7-01")
	if ok {
		t.Error("expected false for uppercase span-id")
	}
}

func TestInjectClientTraceContext_PassthroughMode(t *testing.T) {
	// Exercise the passthrough dispatch branch inside injectClientTraceContext.
	t.Setenv("GODEBUG", "httpw3ctrace=passthrough")

	req := newTestRequest(t)
	tc := traceContext{
		raw:        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		tracestate: "vendor1=value1",
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContext(req, extra)

	if extra.Get("Traceparent") != tc.raw {
		t.Errorf("traceparent mismatch: got %q, want %q", extra.Get("Traceparent"), tc.raw)
	}
	if extra.Get("Tracestate") != "vendor1=value1" {
		t.Errorf("tracestate mismatch: got %q", extra.Get("Tracestate"))
	}
}

// failingRandRead is a test helper that replaces randReadFunc with one that
// always returns errRandFail. It restores the original on test cleanup.
func failingRandRead(t *testing.T) {
	t.Helper()
	orig := randReadFunc
	randReadFunc = func(b []byte) (int, error) {
		return 0, errRandFail
	}
	t.Cleanup(func() { randReadFunc = orig })
}

var errRandFail = errors.New("simulated rand failure")

func TestNewTraceID_RandError(t *testing.T) {
	failingRandRead(t)
	_, err := newTraceID()
	if err != errRandFail {
		t.Errorf("newTraceID error = %v, want errRandFail", err)
	}
}

func TestNewSpanID_RandError(t *testing.T) {
	failingRandRead(t)
	_, err := newSpanID()
	if err != errRandFail {
		t.Errorf("newSpanID error = %v, want errRandFail", err)
	}
}

func TestCreateNewTraceContext_TraceIDError(t *testing.T) {
	failingRandRead(t)
	ctx := context.Background()
	result := createNewTraceContext(ctx)
	// On error, context should be returned unmodified.
	if _, ok := getTraceContext(result); ok {
		t.Error("expected no trace context when newTraceID fails")
	}
}

func TestCreateNewTraceContext_SpanIDError(t *testing.T) {
	// First call to randReadFunc (newTraceID) succeeds; second (newSpanID) fails.
	orig := randReadFunc
	calls := 0
	randReadFunc = func(b []byte) (int, error) {
		calls++
		if calls <= 1 {
			return orig(b)
		}
		return 0, errRandFail
	}
	t.Cleanup(func() { randReadFunc = orig })

	ctx := context.Background()
	result := createNewTraceContext(ctx)
	if _, ok := getTraceContext(result); ok {
		t.Error("expected no trace context when newSpanID fails")
	}
}

func TestInjectClientTraceContextWithSpan_TraceIDError(t *testing.T) {
	// No context → generates fresh IDs. newTraceID fails.
	failingRandRead(t)

	req := newTestRequest(t)
	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	if extra.Get("Traceparent") != "" {
		t.Error("expected no traceparent when newTraceID fails")
	}
}

func TestInjectClientTraceContextWithSpan_SpanIDError_NoContext(t *testing.T) {
	// No context → newTraceID succeeds, newSpanID fails.
	orig := randReadFunc
	calls := 0
	randReadFunc = func(b []byte) (int, error) {
		calls++
		if calls <= 1 {
			return orig(b)
		}
		return 0, errRandFail
	}
	t.Cleanup(func() { randReadFunc = orig })

	req := newTestRequest(t)
	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	if extra.Get("Traceparent") != "" {
		t.Error("expected no traceparent when newSpanID fails (no context)")
	}
}

func TestInjectClientTraceContextWithSpan_SpanIDError_WithContext(t *testing.T) {
	// With valid context → newSpanID fails in the else branch.
	failingRandRead(t)

	req := newTestRequest(t)
	tc := traceContext{
		traceID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		spanID:     [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)
	req = req.WithContext(ctx)

	extra := make(Header)
	injectClientTraceContextWithSpan(req, extra)

	if extra.Get("Traceparent") != "" {
		t.Error("expected no traceparent when newSpanID fails (with context)")
	}
}

func BenchmarkInjectClientTraceContext_Continue_FromContext(b *testing.B) {
	tc := traceContext{
		traceID:    mustTraceID(b),
		spanID:     mustSpanID(b),
		traceFlags: 0x01,
		tracestate: "vendor1=value1",
	}
	ctx := setTraceContext(context.Background(), tc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(Header),
		}
		req = req.WithContext(ctx)
		extra := make(Header)
		injectClientTraceContextWithSpan(req, extra)
	}
}

func BenchmarkInjectClientTraceContext_Continue_NoContext(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(Header),
		}
		req = req.WithContext(ctx)
		extra := make(Header)
		injectClientTraceContextWithSpan(req, extra)
	}
}

func BenchmarkInjectClientTraceContext_Continue_ExistingHeader(b *testing.B) {
	// Benchmark the no-op path when valid header already present.
	// Request and extra are created outside the loop because the
	// function does not mutate them on the early-return path.
	req := &Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Header: make(Header),
	}
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	extra := make(Header)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		injectClientTraceContext(req, extra)
	}
}

func BenchmarkInjectClientTraceContext_Passthrough(b *testing.B) {
	tc := traceContext{
		raw:        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		tracestate: "vendor1=value1",
	}
	ctx := setTraceContext(context.Background(), tc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(Header),
		}
		req = req.WithContext(ctx)
		extra := make(Header)
		injectClientTraceContextPassthrough(req, extra)
	}
}

func BenchmarkInjectClientTraceContext_Restart(b *testing.B) {
	tc := traceContext{
		traceID:    mustTraceID(b),
		spanID:     mustSpanID(b),
		traceFlags: 0x01,
	}
	ctx := setTraceContext(context.Background(), tc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(Header),
		}
		req = req.WithContext(ctx)
		extra := make(Header)
		injectClientTraceContextWithSpan(req, extra)
	}
}
