// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http_test

// Tests for W3C Trace Context propagation over HTTP/2 connections.
// These tests verify that the http2Handler.ServeHTTP bridge applies the server
// trace hook so that inbound HTTP/2 trace context reaches the handler's Context.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestW3CTraceContext_HTTP2ServerHook verifies that applyServerTraceContext is
// called for HTTP/2 requests, i.e. that the hook relocated from h2_bundle.go to
// http2Handler.ServeHTTP in http2.go is active.
//
// The observable signal: in "continue" mode, if the server hook stored the
// inbound trace-id in the request context, the client hook will propagate that
// same trace-id on any outbound request that carries the handler's context.
// A missing server hook would cause the client to mint a fresh (different) trace-id.
func TestW3CTraceContext_HTTP2ServerHook(t *testing.T) {
	t.Setenv("GODEBUG", "httpw3ctrace=continue")

	const inboundTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"

	// capturedTP receives the Traceparent header from the outbound request.
	capturedTP := make(chan string, 1)

	// capture is a plain HTTP/1 server that records the Traceparent it receives.
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTP <- r.Header.Get("Traceparent")
	}))
	t.Cleanup(capture.Close)

	// h2srv is an HTTP/2 server. Its handler makes an outbound request to the
	// capture server using the inbound request's Context, which should carry the
	// extracted trace context set by the server hook.
	h2srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, capture.URL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp.Body.Close()
	}))
	h2srv.EnableHTTP2 = true
	h2srv.StartTLS()
	t.Cleanup(h2srv.Close)

	// Send a request with a known Traceparent to the HTTP/2 server.
	req, err := http.NewRequest(http.MethodGet, h2srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Traceparent", inboundTraceparent)

	resp, err := h2srv.Client().Do(req)
	if err != nil {
		t.Fatalf("HTTP/2 request failed: %v", err)
	}
	resp.Body.Close()

	// Wait for the outbound Traceparent to arrive at the capture server.
	var outboundTP string
	select {
	case outboundTP = <-capturedTP:
	case <-time.After(5 * time.Second):
		t.Fatal("capture server did not receive a request within 5 seconds")
	}

	// In "continue" mode, the outbound Traceparent must carry the same trace-id
	// as the inbound one. A missing server hook would cause a freshly generated
	// (different) trace-id to appear here.
	if outboundTP == "" {
		t.Error("HTTP/2 handler made outbound request with no Traceparent header; server hook may be missing")
		return
	}
	parts := strings.Split(outboundTP, "-")
	if len(parts) < 4 {
		t.Errorf("outbound Traceparent %q has unexpected format", outboundTP)
		return
	}
	if got := parts[1]; got != inboundTraceID {
		t.Errorf("outbound trace-id = %q, want %q; server hook may not have propagated inbound trace context to HTTP/2 handler", got, inboundTraceID)
	}
}
