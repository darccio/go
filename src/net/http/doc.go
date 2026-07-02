// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package http provides HTTP client and server implementations.

[Get], [Head], [Post], and [PostForm] make HTTP (or HTTPS) requests:

	resp, err := http.Get("http://example.com/")
	...
	resp, err := http.Post("http://example.com/upload", "image/jpeg", &buf)
	...
	resp, err := http.PostForm("http://example.com/form",
		url.Values{"key": {"Value"}, "id": {"123"}})

The caller must close the response body when finished with it:

	resp, err := http.Get("http://example.com/")
	if err != nil {
		// handle error
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	// ...

# Clients and Transports

For control over HTTP client headers, redirect policy, and other
settings, create a [Client]:

	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
	}

	resp, err := client.Get("http://example.com")
	// ...

	req, err := http.NewRequest("GET", "http://example.com", nil)
	// ...
	req.Header.Add("If-None-Match", `W/"wyzzy"`)
	resp, err := client.Do(req)
	// ...

For control over proxies, TLS configuration, keep-alives,
compression, and other settings, create a [Transport]:

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://example.com")

Clients and Transports are safe for concurrent use by multiple
goroutines and for efficiency should only be created once and re-used.

# Servers

ListenAndServe starts an HTTP server with a given address and handler.
The handler is usually nil, which means to use [DefaultServeMux].
[Handle] and [HandleFunc] add handlers to [DefaultServeMux]:

	http.Handle("/foo", fooHandler)

	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))

More control over the server's behavior is available by creating a
custom Server:

	s := &http.Server{
		Addr:           ":8080",
		Handler:        myHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())

# HTTP/2

The http package has transparent support for the HTTP/2 protocol.

[Server] and [DefaultTransport] automatically enable HTTP/2 support
when using HTTPS. [Transport] does not enable HTTP/2 by default.

To enable or disable support for HTTP/1, HTTP/2, and/or unencrypted HTTP/2,
see the [Server.Protocols] and [Transport.Protocols] configuration fields.

To configure advanced HTTP/2 features, see the [Server.HTTP2] and
[Transport.HTTP2] configuration fields.

Alternatively, the following GODEBUG settings are currently supported:

	GODEBUG=http2client=0  # disable HTTP/2 client support
	GODEBUG=http2server=0  # disable HTTP/2 server support
	GODEBUG=http2debug=1   # enable verbose HTTP/2 debug logs
	GODEBUG=http2debug=2   # ... even more verbose, with frame dumps

The "omithttp2" build tag may be used to disable the HTTP/2 implementation
contained in the http package.

# W3C Trace Context Propagation

The net/http package supports automatic W3C Trace Context propagation
(https://www.w3.org/TR/trace-context/) through the httpw3ctrace GODEBUG setting.
When enabled, the package automatically extracts trace context from incoming
requests and injects it into outbound requests.

The following modes are supported:

	GODEBUG=httpw3ctrace=ignore      # explicitly disable propagation
	GODEBUG=httpw3ctrace=continue    # full W3C participation (parse, validate, propagate)
	GODEBUG=httpw3ctrace=passthrough # opaque forward (no parsing)
	GODEBUG=httpw3ctrace=restart     # discard inbound, create fresh context

By default (when GODEBUG is unset), the default mode is "passthrough". For ensuring zero overhead,
set GODEBUG=httpw3ctrace=ignore.

On the server side, trace context is extracted from incoming Traceparent and
Tracestate headers and stored in the request's Context. On the client side,
trace context is injected into outbound requests as the final step before dispatch.

The implementation preserves user-set and middleware-set headers: if a valid
Traceparent header is already present on an outbound request, it will not be
overridden. This ensures that applications performing manual or library-driven
propagation (e.g., OpenTelemetry) remain fully in control.

For more details on modes and behavior, see the GODEBUG documentation.
*/
package http
