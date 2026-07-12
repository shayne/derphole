# HTTP Proxy Support for DERP Connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make derphole, derptun, and derpssh establish their shared DERP connection through standard HTTP proxy environment variables while preserving optional direct-path promotion.

**Architecture:** Add proxy selection and HTTP `CONNECT` tunneling in a focused `pkg/derpbind/proxy.go` unit, then let the existing fixed-URL DERP client choose either that tunnel or its unchanged IPv4/IPv6 direct dialer. Expose only redacted proxy metadata from `derpbind`; the shared session layer emits verbose diagnostics and continues to own relay/direct path policy.

**Tech Stack:** Go 1.26.1, `net/http`, `crypto/tls`, Tailscale `derphttp`, existing `pkg/telemetry`, local DERP and CONNECT-proxy test fixtures, GitButler.

## Global Constraints

- Honor `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and their lowercase forms with standard Go matching and precedence semantics.
- Proxy presence must not set `ForceRelay`, disable UDP discovery, or suppress direct promotion.
- Once a proxy applies to a DERP URL, proxy failure must not fall back to direct DERP TCP; `NO_PROXY` is the direct-access override.
- Support only `http://` and `https://` proxy endpoints in this iteration.
- Support Basic proxy authentication only when both username and password are present in proxy URL userinfo.
- Never expose proxy userinfo, passwords, authorization values, or unbounded response bodies in errors, debug output, or telemetry.
- Keep token formats, CLI flags, peer protocol, QUIC framing, DERP selection, and packaging unchanged.
- Do not make `pkg/derpbind` depend on `pkg/session` or `pkg/telemetry`.
- Preserve unrelated GitButler branches and working-tree changes; every commit must select only the files named by its task.

## File Map

- Create `pkg/derpbind/proxy.go`: proxy selection, redacted metadata, HTTP/HTTPS proxy dialing, CONNECT negotiation, setup deadlines, and safe errors.
- Create `pkg/derpbind/proxy_test.go`: table-driven proxy semantics, HTTP/HTTPS CONNECT fixtures, authentication, cancellation, redaction, and direct-fallback prevention.
- Modify `pkg/derpbind/client.go`: give the fixed-URL dialer the parsed DERP URL, select proxy versus existing direct racing, record `ProxyInfo`, and expose it from `Client`.
- Modify `pkg/derpbind/derpbind_test.go`: exchange a real DERP packet through a CONNECT proxy whose advertised DERP target is not directly reachable.
- Modify `pkg/session/external.go`: add the shared `emitDERPProxyDebug` helper.
- Modify `pkg/session/external_attach.go`, `pkg/session/external_share.go`, `pkg/session/external_v2.go`, `pkg/session/external_v2_offer.go`, and `pkg/session/derptun.go`: call the shared debug helper at DERP-client construction boundaries without changing path policy.
- Create `pkg/session/proxy_test.go`: exercise derphole's public relay path and the derptun app-mux path through a proxy, including the path used by derpssh.
- Modify `docs/derp/client-runtime.md`: document constrained egress, supported proxy forms, security boundaries, and relay/direct behavior.

---

### Task 1: Standard proxy selection and redacted metadata

**Files:**
- Create: `pkg/derpbind/proxy.go`
- Create: `pkg/derpbind/proxy_test.go`

**Interfaces:**
- Consumes: a parsed DERP `*url.URL`.
- Produces: `func derpProxyForURL(*url.URL) (*url.URL, error)`, `type ProxyInfo struct`, `func (ProxyInfo) DebugString() string`, and safe endpoint-formatting helpers used by later tasks.

**Implementation correction:** Rebuild `httpproxy.FromEnvironment()` for every
DERP dial so reconnects observe the current environment. Its `ProxyFunc`
silently drops malformed proxy parse errors, so first evaluate a copy whose
scheme-applicable proxy value is a known-valid sentinel. That preserves the
standard uppercase/lowercase precedence, scheme selection, `NO_PROXY`,
loopback, and CGI rules. Only when the sentinel says a proxy applies, parse the
selected real value using Go's complete-URL-or-bare-host syntax and return a
sanitized error on failure. Keep the environment matrix in fresh subprocesses
so each case also exercises the production boundary without process-global
state leaking between cases.

- [ ] **Step 1: Write failing selection and redaction tests**

Create table-driven tests that set one environment configuration at a time and call the production resolver. Do not call `t.Parallel` because proxy variables are process-global.

```go
func TestDERPProxyForURLUsesStandardEnvironment(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		httpProxy  string
		httpsProxy string
		noProxy    string
		httpLower  string
		httpsLower string
		noLower    string
		want       string
	}{
		{name: "no proxy", target: "https://derp.example/derp", want: ""},
		{name: "https proxy", target: "https://derp.example/derp", httpsProxy: "http://proxy.example:3128", want: "http://proxy.example:3128"},
		{name: "http proxy ignored for https", target: "https://derp.example/derp", httpProxy: "http://fallback.example:8080", want: ""},
		{name: "https precedence", target: "https://derp.example/derp", httpProxy: "http://fallback.example:8080", httpsProxy: "http://preferred.example:3128", want: "http://preferred.example:3128"},
		{name: "lowercase https", target: "https://derp.example/derp", httpsLower: "http://lower.example:3128", want: "http://lower.example:3128"},
		{name: "lowercase no proxy", target: "https://derp.example/derp", httpsLower: "http://lower.example:3128", noLower: "derp.example", want: ""},
		{name: "no proxy exact host", target: "https://derp.example/derp", httpsProxy: "http://proxy.example:3128", noProxy: "derp.example", want: ""},
		{name: "no proxy domain", target: "https://derp.example/derp", httpsProxy: "http://proxy.example:3128", noProxy: ".example", want: ""},
		{name: "no proxy ip", target: "https://192.0.2.10/derp", httpsProxy: "http://proxy.example:3128", noProxy: "192.0.2.10", want: ""},
		{name: "no proxy cidr", target: "https://192.0.2.10/derp", httpsProxy: "http://proxy.example:3128", noProxy: "192.0.2.0/24", want: ""},
		{name: "no proxy port match", target: "https://derp.example:8443/derp", httpsProxy: "http://proxy.example:3128", noProxy: "derp.example:8443", want: ""},
		{name: "no proxy port mismatch", target: "https://derp.example:443/derp", httpsProxy: "http://proxy.example:3128", noProxy: "derp.example:8443", want: "http://proxy.example:3128"},
		{name: "http target", target: "http://derp.example:3340/derp", httpProxy: "http://proxy.example:3128", want: "http://proxy.example:3128"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", tt.httpProxy)
			t.Setenv("HTTPS_PROXY", tt.httpsProxy)
			t.Setenv("NO_PROXY", tt.noProxy)
			t.Setenv("http_proxy", tt.httpLower)
			t.Setenv("https_proxy", tt.httpsLower)
			t.Setenv("no_proxy", tt.noLower)
			target, err := url.Parse(tt.target)
			if err != nil { t.Fatal(err) }
			got, err := derpProxyForURL(target)
			if err != nil { t.Fatalf("derpProxyForURL() error = %v", err) }
			gotString := ""
			if got != nil { gotString = got.String() }
			if gotString != tt.want { t.Fatalf("proxy = %q, want %q", gotString, tt.want) }
		})
	}
}

func TestProxyInfoDebugStringRedactsCredentials(t *testing.T) {
	info := newProxyInfo(
		&url.URL{Scheme: "http", Host: "proxy.example:3128", User: url.UserPassword("alice", "secret")},
		"derp1.tailscale.com:443",
	)
	got := info.DebugString()
	if got != "derp-proxy=http://proxy.example:3128 target=derp1.tailscale.com:443" {
		t.Fatalf("DebugString() = %q", got)
	}
	if strings.Contains(got, "alice") || strings.Contains(got, "secret") {
		t.Fatalf("DebugString() leaked credentials: %q", got)
	}
}

func TestValidateDERPProxyURL(t *testing.T) {
	for _, raw := range []string{"socks5://proxy.example:1080", "http:///missing-host"} {
		t.Run(raw, func(t *testing.T) {
			proxyURL, err := url.Parse(raw)
			if err != nil { t.Fatal(err) }
			if err := validateDERPProxyURL(proxyURL); err == nil { t.Fatalf("validateDERPProxyURL(%q) error = nil", raw) }
		})
	}
}
```

- [ ] **Step 2: Run the focused tests and confirm the expected compile failure**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestDERPProxyForURLUsesStandardEnvironment|TestProxyInfoDebugStringRedactsCredentials|TestValidateDERPProxyURL' -count=1
```

Expected: FAIL because `derpProxyForURL`, `ProxyInfo`, `newProxyInfo`, and
`validateDERPProxyURL` do not exist.

- [ ] **Step 3: Implement proxy selection and metadata**

Add the following boundary. Rebuild the `httpproxy` configuration for each
dial, probe applicability with a valid sentinel, and parse the selected real
value only after standard bypass and CGI behavior have been evaluated.

```go
type ProxyInfo struct {
	Scheme    string
	ProxyAddr string
	TargetAddr string
}

func (i ProxyInfo) DebugString() string {
	if i.Scheme == "" || i.ProxyAddr == "" || i.TargetAddr == "" { return "" }
	return "derp-proxy=" + i.Scheme + "://" + i.ProxyAddr + " target=" + i.TargetAddr
}

func newProxyInfo(proxyURL *url.URL, target string) ProxyInfo {
	return ProxyInfo{Scheme: proxyURL.Scheme, ProxyAddr: canonicalProxyAddr(proxyURL), TargetAddr: target}
}

func canonicalProxyAddr(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		if proxyURL.Scheme == "https" { port = "443" } else { port = "80" }
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

var derpProxyFromEnvironment = uncachedDERPProxyFromEnvironment

func uncachedDERPProxyFromEnvironment(target *url.URL) (*url.URL, error) {
	config := httpproxy.FromEnvironment()
	probe := *config
	var proxyValue string
	switch target.Scheme {
	case "http":
		proxyValue = config.HTTPProxy
		probe.HTTPProxy = "http://proxy.invalid"
	case "https":
		proxyValue = config.HTTPSProxy
		probe.HTTPSProxy = "http://proxy.invalid"
	default:
		return nil, nil
	}
	if proxyValue == "" {
		return nil, nil
	}

	proxyURL, err := probe.ProxyFunc()(target)
	if err != nil || proxyURL == nil {
		return proxyURL, err
	}
	return parseDERPProxy(proxyValue)
}

func parseDERPProxy(proxyValue string) (*url.URL, error) {
	proxyURL, err := url.Parse(proxyValue)
	if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
		if withScheme, withSchemeErr := url.Parse("http://" + proxyValue); withSchemeErr == nil {
			return withScheme, nil
		}
	}
	if err != nil {
		return nil, errors.New("invalid DERP proxy configuration")
	}
	return proxyURL, nil
}

func derpProxyForURL(target *url.URL) (*url.URL, error) {
	if target == nil { return nil, errors.New("nil DERP URL") }
	proxyURL, err := derpProxyFromEnvironment(target)
	if err != nil { return nil, fmt.Errorf("resolve DERP proxy: %w", err) }
	if proxyURL == nil { return nil, nil }
	if err := validateDERPProxyURL(proxyURL); err != nil { return nil, err }
	return proxyURL, nil
}

func validateDERPProxyURL(proxyURL *url.URL) error {
	if proxyURL == nil { return errors.New("nil DERP proxy URL") }
	switch proxyURL.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported DERP proxy scheme %q", proxyURL.Scheme)
	}
	if proxyURL.Hostname() == "" { return errors.New("DERP proxy URL has no hostname") }
	return nil
}
```

The helper deliberately uses only `Hostname()` and `Port()` and never formats
`URL.User`.

- [ ] **Step 4: Run selection tests and the package suite**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestDERPProxyForURLUsesStandardEnvironment|TestProxyInfoDebugStringRedactsCredentials|TestValidateDERPProxyURL' -count=1
mise exec -- go test ./pkg/derpbind -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit only Task 1 files with GitButler**

Run `but diff`, select the IDs printed for `pkg/derpbind/proxy.go` and `pkg/derpbind/proxy_test.go`, and create `codex/http-proxy-derp` with message `net: resolve standard DERP proxy environment`. Do not select any other dirty file.

---

### Task 2: HTTP and HTTPS CONNECT tunnel establishment

**Files:**
- Modify: `pkg/derpbind/proxy.go`
- Modify: `pkg/derpbind/proxy_test.go`

**Interfaces:**
- Consumes: `derpProxyForURL`, `ProxyInfo`, the existing `derpDialContext`, a DERP target authority, `logger.Logf`, and `*netmon.Monitor`.
- Produces: `func dialDERPThroughProxy(context.Context, *url.URL, string, logger.Logf, *netmon.Monitor) (net.Conn, ProxyInfo, error)`.

- [ ] **Step 1: Add failing HTTP CONNECT, Basic auth, and no-fallback tests**

Build a local proxy fixture that records the request and either returns a configured status or hijacks the connection. The success test must assert the exact authority and Basic header.

```go
func TestDialDERPThroughHTTPProxy(t *testing.T) {
	proxy := newTestConnectProxy(t, testConnectProxyOptions{Status: http.StatusOK})
	proxyURL, _ := url.Parse(proxy.URL())
	proxyURL.User = url.UserPassword("alice", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, info, err := dialDERPThroughProxy(ctx, proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err != nil { t.Fatalf("dialDERPThroughProxy() error = %v", err) }
	defer conn.Close()
	req := proxy.Request()
	if req.Method != http.MethodConnect || req.Host != "derp.example:443" {
		t.Fatalf("CONNECT request = %s %s", req.Method, req.Host)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if got := req.Header.Get("Proxy-Authorization"); got != wantAuth { t.Fatalf("auth = %q, want %q", got, wantAuth) }
	if got := info.DebugString(); strings.Contains(got, "alice") || strings.Contains(got, "secret") { t.Fatalf("ProxyInfo leaked: %q", got) }
}

func TestSelectedProxyFailureDoesNotDialDERPDirectly(t *testing.T) {
	oldDial := derpDialContext
	defer func() { derpDialContext = oldDial }()
	var dials []string
	derpDialContext = func(ctx context.Context, _ logger.Logf, _ *netmon.Monitor, network, addr string) (net.Conn, error) {
		dials = append(dials, addr)
		return nil, errors.New("blocked")
	}
	proxyURL, _ := url.Parse("http://proxy.example:3128")
	_, _, err := dialDERPThroughProxy(context.Background(), proxyURL, "derp.example:443", t.Logf, netmon.NewStatic())
	if err == nil { t.Fatal("error = nil") }
	if diff := cmp.Diff([]string{"proxy.example:3128"}, dials); diff != "" { t.Fatalf("dials mismatch (-want +got):\n%s", diff) }
}
```

Add table cases for missing password, `407`, `403`, a response body larger than the cap, password and Basic-token redaction, malformed response, and cancellation while waiting for the CONNECT response.

- [ ] **Step 2: Run the CONNECT tests and verify they fail**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestDialDERPThrough|TestSelectedProxyFailure' -count=1
```

Expected: FAIL because `dialDERPThroughProxy` and the test fixture do not exist.

- [ ] **Step 3: Implement bounded, cancellable CONNECT negotiation**

Use the existing five-second DERP setup timeout and direct dial seam. Preserve any bytes already buffered after `http.ReadResponse`.

```go
const maxProxyErrorBody = 4 << 10

func dialDERPThroughProxy(ctx context.Context, proxyURL *url.URL, target string, logf logger.Logf, netMon *netmon.Monitor) (_ net.Conn, _ ProxyInfo, retErr error) {
	ctx, cancel := derpDialContextWithTimeout(ctx)
	defer cancel()
	proxyAddr := canonicalProxyAddr(proxyURL)
	raw, err := derpDialContext(ctx, logf, netMon, "tcp", proxyAddr)
	if err != nil { return nil, ProxyInfo{}, fmt.Errorf("dial DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, err) }
	conn := raw
	defer func() { if retErr != nil { _ = conn.Close() } }()
	if deadline, ok := ctx.Deadline(); ok { _ = conn.SetDeadline(deadline) }
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(raw, proxyTLSConfig(proxyURL.Hostname()))
		if err := tlsConn.HandshakeContext(ctx); err != nil { return nil, ProxyInfo{}, fmt.Errorf("TLS to DERP proxy https://%s: %w", proxyAddr, err) }
		conn = tlsConn
	}
	req, err := newProxyConnectRequest(proxyURL, target)
	if err != nil { return nil, ProxyInfo{}, err }
	if err := req.Write(conn); err != nil { return nil, ProxyInfo{}, fmt.Errorf("write CONNECT to DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, err) }
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil { return nil, ProxyInfo{}, fmt.Errorf("read CONNECT from DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, err) }
	if res.StatusCode != http.StatusOK {
		return nil, ProxyInfo{}, proxyConnectRejectionError(ctx, res.Body, proxyURL, target, proxyAddr, res.StatusCode)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil { return nil, ProxyInfo{}, fmt.Errorf("clear DERP proxy setup deadline: %w", err) }
	return &bufferedProxyConn{Conn: conn, reader: br}, newProxyInfo(proxyURL, target), nil
}

type bufferedProxyConn struct { net.Conn; reader *bufio.Reader }
func (c *bufferedProxyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
```

`newProxyConnectRequest` must reject userinfo without an explicit password, set Basic auth only for an explicit username/password pair, and construct a standard CONNECT request with `Host: target`. `safeProxyResponseSummary` must read at most 4096 bytes, normalize control characters, and replace raw and normalized forms of the username and password plus the encoded Basic value before returning text. `proxyConnectStatusError` must render only scheme, canonical proxy address, target, status, and the safe summary.

Use these exact helper contracts:

```go
var proxyTLSConfig = func(host string) *tls.Config { return &tls.Config{ServerName: host} }

func newProxyConnectRequest(proxyURL *url.URL, target string) (*http.Request, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if proxyURL.User == nil { return req, nil }
	username := proxyURL.User.Username()
	password, ok := proxyURL.User.Password()
	if username == "" || !ok { return nil, errors.New("DERP proxy credentials require username and password") }
	raw := username + ":" + password
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(raw)))
	return req, nil
}

func safeProxyResponseSummary(body io.Reader, proxyURL *url.URL, limit int64) (string, error) {
	if body == nil || limit < 1 { return "", nil }
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	truncated := int64(len(b)) > limit
	if truncated { b = b[:limit] }
	summary := normalizeProxyResponseSummary(string(b))
	summary = redactProxyResponseSummary(summary, proxyURL)
	summary = strings.TrimSpace(summary)
	if truncated { summary += "..." }
	return summary, err
}

func proxyConnectRejectionError(ctx context.Context, body io.ReadCloser, proxyURL *url.URL, target, proxyAddr string, statusCode int) error {
	summary, bodyErr := safeProxyResponseSummary(body, proxyURL, maxProxyErrorBody)
	_ = body.Close()
	ctxErr := ctx.Err()
	var timeoutErr net.Error
	if ctxErr == nil && errors.As(bodyErr, &timeoutErr) && timeoutErr.Timeout() {
		ctxErr = context.DeadlineExceeded
	}
	if ctxErr != nil {
		return fmt.Errorf("read CONNECT rejection body from DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, ctxErr)
	}
	return proxyConnectStatusError(proxyURL, target, statusCode, summary)
}

func normalizeProxyResponseSummary(summary string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' { return ' ' }
		if unicode.IsControl(r) { return -1 }
		return r
	}, summary)
}

func redactProxyResponseSummary(summary string, proxyURL *url.URL) string {
	if proxyURL.User == nil { return summary }
	username := proxyURL.User.Username()
	password, hasPassword := proxyURL.User.Password()
	candidates := []string{username, password}
	if username != "" && hasPassword {
		candidates = append(candidates, base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
	secrets := make([]string, 0, len(candidates)*2)
	seen := make(map[string]struct{}, len(candidates)*2)
	for _, candidate := range candidates {
		for _, secret := range []string{candidate, normalizeProxyResponseSummary(candidate)} {
			if secret == "" { continue }
			if _, ok := seen[secret]; ok { continue }
			seen[secret] = struct{}{}
			secrets = append(secrets, secret)
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	replacements := make([]string, 0, len(secrets)*2)
	for _, secret := range secrets { replacements = append(replacements, secret, "[redacted]") }
	return strings.NewReplacer(replacements...).Replace(summary)
}

func proxyConnectStatusError(proxyURL *url.URL, target string, statusCode int, summary string) error {
	status := fmt.Sprintf("%d", statusCode)
	if text := http.StatusText(statusCode); text != "" { status += " " + text }
	detail := ""
	if summary != "" { detail = ": " + summary }
	if statusCode == http.StatusProxyAuthRequired {
		return fmt.Errorf("DERP proxy %s://%s rejected authentication for CONNECT to %s: %s%s", proxyURL.Scheme, canonicalProxyAddr(proxyURL), target, status, detail)
	}
	return fmt.Errorf("DERP proxy %s://%s rejected CONNECT to %s: %s%s", proxyURL.Scheme, canonicalProxyAddr(proxyURL), target, status, detail)
}
```

- [ ] **Step 4: Add and pass the HTTPS-proxy test**

Make `proxyTLSConfig` a package-level function whose production value returns `&tls.Config{ServerName: host}`. In the test, build a root pool from the `httptest.NewTLSServer` certificate, keep hostname verification enabled, and assert that the CONNECT request arrives through TLS.

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestDialDERPThrough|TestSelectedProxyFailure' -count=1
mise exec -- go test -race ./pkg/derpbind -run 'TestDialDERPThrough|TestSelectedProxyFailure' -count=1
```

Expected: PASS with no race report.

- [ ] **Step 5: Commit only Task 2 files with GitButler**

Run `but diff`, select only the Task 2 hunks in `pkg/derpbind/proxy.go` and `pkg/derpbind/proxy_test.go`, and commit them to `codex/http-proxy-derp` with message `net: tunnel DERP through HTTP proxies`.

---

### Task 3: Integrate proxy dialing with the DERP client

**Files:**
- Modify: `pkg/derpbind/client.go`
- Modify: `pkg/derpbind/derpbind_test.go`
- Modify: `pkg/derpbind/proxy_test.go`

**Interfaces:**
- Consumes: `derpProxyForURL` and `dialDERPThroughProxy` from Tasks 1-2.
- Produces: `func (c *Client) ProxyInfo() (ProxyInfo, bool)` and a fixed-URL dialer that selects proxy or the existing direct race on every connection attempt.

- [ ] **Step 1: Write a failing real-DERP-through-proxy integration test**

Extend the CONNECT fixture so a successful request dials a configured local target and runs bidirectional `io.Copy`. Advertise an unreachable node address and a fake hostname; map the fake hostname to the local DERP server only inside the proxy.

```go
func TestClientsExchangePacketAndReconnectThroughHTTPProxy(t *testing.T) {
	srv := newTestDERPServer(t)
	derpTarget := strings.TrimPrefix(srv.DERPURL, "http://")
	derpTarget = strings.TrimSuffix(derpTarget, "/derp")
	proxy := newForwardingConnectProxy(t, derpTarget)
	t.Setenv("HTTP_PROXY", proxy.URL())
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")
	node := *srv.Map.Regions[1].Nodes[0]
	node.HostName = "derp.proxy-test.invalid"
	node.IPv4 = "192.0.2.1"
	serverURL := "http://derp.proxy-test.invalid/derp"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := NewClient(ctx, &node, serverURL)
	if err != nil { t.Fatalf("NewClient(a) error = %v", err) }
	defer a.Close()
	b, err := NewClient(ctx, &node, serverURL)
	if err != nil { t.Fatalf("NewClient(b) error = %v", err) }
	defer b.Close()
	payload := []byte("proxied DERP packet")
	if err := a.Send(ctx, b.PublicKey(), payload); err != nil { t.Fatalf("Send() error = %v", err) }
	got, err := b.Receive(ctx)
	if err != nil { t.Fatalf("Receive() error = %v", err) }
	if !bytes.Equal(got.Payload, payload) { t.Fatalf("payload = %q, want %q", got.Payload, payload) }
	if proxy.ConnectCount() != 2 { t.Fatalf("CONNECT count = %d, want 2", proxy.ConnectCount()) }
	if info, ok := a.ProxyInfo(); !ok || info.TargetAddr != "derp.proxy-test.invalid:80" { t.Fatalf("ProxyInfo = %#v, %v", info, ok) }
	connectsBeforeReconnect := proxy.ConnectCount()
	srv.http.CloseClientConnections()
	time.Sleep(50 * time.Millisecond)
	second := []byte("proxied after reconnect")
	if err := a.Send(ctx, b.PublicKey(), second); err != nil { t.Fatalf("Send() after disconnect error = %v", err) }
	got, err = b.Receive(ctx)
	if err != nil { t.Fatalf("Receive() after disconnect error = %v", err) }
	if !bytes.Equal(got.Payload, second) { t.Fatalf("reconnected payload = %q, want %q", got.Payload, second) }
	if proxy.ConnectCount() <= connectsBeforeReconnect { t.Fatalf("CONNECT count did not increase across reconnect: before=%d after=%d", connectsBeforeReconnect, proxy.ConnectCount()) }
}
```

The existing `pkg/derpbind` client tests continue to exercise the direct
fixed-URL path with no applicable proxy. Together with Task 1's `NO_PROXY`
table, the full package run is the direct-path regression proof; do not add a
second copy of the IPv4/IPv6 racing tests.

- [ ] **Step 2: Run the integration tests and verify failure**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestClientsExchangePacketAndReconnectThroughHTTPProxy' -count=1
```

Expected: FAIL because the client does not consult the proxy and `ProxyInfo` is missing.

- [ ] **Step 3: Wire proxy selection into `newClientWithPrivateKey`**

Parse the server URL once, create a concurrency-safe recorder shared with the dialer, and retain the existing direct path verbatim when no proxy applies.

```go
type proxyInfoRecorder struct { mu sync.RWMutex; info ProxyInfo }
func (r *proxyInfoRecorder) Store(info ProxyInfo) { r.mu.Lock(); r.info = info; r.mu.Unlock() }
func (r *proxyInfoRecorder) Load() (ProxyInfo, bool) {
	r.mu.RLock(); defer r.mu.RUnlock()
	return r.info, r.info.Scheme != ""
}

func (c *Client) ProxyInfo() (ProxyInfo, bool) {
	if c == nil || c.proxyInfo == nil { return ProxyInfo{}, false }
	return c.proxyInfo.Load()
}
```

Add `proxyInfo *proxyInfoRecorder` to `Client` and set it to the recorder in
the successful `Client` initializer. This keeps the accessor valid across
reconnects without exposing the recorder outside `pkg/derpbind`.

Change the dialer construction to accept the parsed DERP URL and recorder:

```go
proxyURL, err := url.Parse(serverURL)
if err != nil { return nil, fmt.Errorf("parse DERP URL: %w", err) }
proxyInfo := &proxyInfoRecorder{}
dc.SetURLDialer(newDERPNodeDialer(node, proxyURL, proxyInfo, logf, netMon))
```

Inside the returned dial function:

```go
selectedProxy, err := derpProxyForURL(serverURL)
if err != nil { return nil, err }
if selectedProxy != nil {
	target, err := canonicalDERPTarget(serverURL)
	if err != nil { return nil, err }
	conn, info, err := dialDERPThroughProxy(ctx, selectedProxy, target, logf, netMon)
	if err != nil { return nil, err }
	proxyInfo.Store(info)
	return conn, nil
}
return dialDERPDirect(ctx, node, logf, netMon, addr)
```

Extract the current `SplitHostPort`, target construction, explicit-disable handling, and `raceDERPDial` call into `dialDERPDirect` without changing behavior.

- [ ] **Step 4: Run DERP package verification**

Run:

```sh
mise exec -- go test ./pkg/derpbind -count=1
mise exec -- go test -race ./pkg/derpbind -count=1
```

Expected: PASS, including a real packet exchange through two CONNECT tunnels.

- [ ] **Step 5: Commit only Task 3 files with GitButler**

Run `but diff`, select only Task 3 changes in `pkg/derpbind/client.go`, `pkg/derpbind/derpbind_test.go`, and `pkg/derpbind/proxy_test.go`, and commit with message `net: route DERP clients through selected proxies`.

---

### Task 4: Emit shared session diagnostics and prove product paths

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_attach.go`
- Modify: `pkg/session/external_share.go`
- Modify: `pkg/session/external_v2.go`
- Modify: `pkg/session/external_v2_offer.go`
- Modify: `pkg/session/derptun.go`
- Create: `pkg/session/proxy_test.go`
- Modify: `pkg/session/external_v2_test.go`
- Test: `pkg/derpssh/session/share_connect_test.go` (verification only unless an existing wrapper assertion needs extension)

**Interfaces:**
- Consumes: `(*derpbind.Client).ProxyInfo()` and `ProxyInfo.DebugString()`.
- Produces: `func emitDERPProxyDebug(*telemetry.Emitter, *derpbind.Client)` and verbose events at every production DERP-client creation boundary.

- [ ] **Step 1: Write failing telemetry and proxied-session tests**

Create `pkg/session/proxy_test.go` with a CONNECT forwarder and two acceptance tests. The public relay test validates `emitDERPProxyDebug` through real clients, so no test-only production constructor is needed.

```go
func TestPublicRelayRoundTripThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	fixture.ConfigureEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var listenerOut, listenerDebug, senderDebug bytes.Buffer
	tokens := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{Emitter: telemetry.New(&listenerDebug, telemetry.LevelVerbose), TokenSink: tokens, StdioOut: &listenerOut, ForceRelay: true, UsePublicDERP: true})
		listenErr <- err
	}()
	tok := <-tokens
	err := Send(ctx, SendConfig{Token: tok, Emitter: telemetry.New(&senderDebug, telemetry.LevelVerbose), StdioIn: strings.NewReader("through proxy"), ForceRelay: true, UsePublicDERP: true})
	if err != nil { t.Fatalf("Send() error = %v", err) }
	if err := <-listenErr; err != nil { t.Fatalf("Listen() error = %v", err) }
	if listenerOut.String() != "through proxy" { t.Fatalf("output = %q", listenerOut.String()) }
	if !strings.Contains(listenerDebug.String(), "derp-proxy=http://") || !strings.Contains(senderDebug.String(), "derp-proxy=http://") { t.Fatalf("missing proxy debug: listener=%q sender=%q", listenerDebug.String(), senderDebug.String()) }
}

func TestDerptunAppStreamRoundTripThroughHTTPProxy(t *testing.T) {
	fixture := newSessionProxyFixture(t)
	fixture.ConfigureEnvironment(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	accepted := make(chan struct{})
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunAppServe(ctx, DerptunAppServeConfig{
			ServerToken: serverToken,
			ForceRelay:  true,
			OnMux: func(ctx context.Context, mux *derptun.Mux) error {
				conn, err := mux.Accept(ctx)
				if err != nil { return err }
				close(accepted)
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil { return err }
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil { return err }
				_, err = io.WriteString(conn, "echo: "+line)
				if err != nil { return err }
				<-ctx.Done()
				return ctx.Err()
			},
		})
	}()
	conn, cleanup, err := DerptunAppDialStream(ctx, DerptunAppDialConfig{ClientToken: clientToken, ForceRelay: true})
	if err != nil { t.Fatalf("DerptunAppDialStream() error = %v", err) }
	defer cleanup()
	defer conn.Close()
	select {
	case <-accepted:
	case <-ctx.Done(): t.Fatalf("app stream not accepted: %v", ctx.Err())
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil { t.Fatal(err) }
	if _, err := io.WriteString(conn, "derpssh transport\n"); err != nil { t.Fatal(err) }
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil { t.Fatal(err) }
	if line != "echo: derpssh transport\n" { t.Fatalf("line = %q", line) }
	if fixture.ConnectCount() < 2 { t.Fatalf("CONNECT count = %d, want at least 2", fixture.ConnectCount()) }
	cancel()
	if err := <-serveErr; err != nil && !errors.Is(err, context.Canceled) { t.Fatalf("serve error = %v", err) }
}
```

This is the transport entrypoint used by derpssh, so it is the required derpssh-path acceptance test without involving terminal UI state.

In `TestExternalV2OfferReceivePromotesToDirectWhenBothSidesReady`, replace the existing `newSessionTestDERPServer` environment setup with:

```go
fixture := newSessionProxyFixture(t)
fixture.ConfigureEnvironment(t)
```

Keep its existing `DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT=0` setup and both `connected-direct` assertions unchanged. This turns the existing test into proof that a proxied DERP control/relay connection does not disable direct promotion.

- [ ] **Step 2: Run the new session tests and verify they fail**

Run:

```sh
mise exec -- go test ./pkg/session -run 'TestPublicRelayRoundTripThroughHTTPProxy|TestDerptunAppStreamRoundTripThroughHTTPProxy|TestExternalV2OfferReceivePromotesToDirectWhenBothSidesReady' -count=1
```

Expected: FAIL because proxy debug emission and the session proxy fixture are not implemented.

- [ ] **Step 3: Implement shared debug emission**

Add this helper in `pkg/session/external.go`:

```go
func emitDERPProxyDebug(emitter *telemetry.Emitter, client *derpbind.Client) {
	if emitter == nil || client == nil { return }
	info, ok := client.ProxyInfo()
	if !ok { return }
	if msg := info.DebugString(); msg != "" { emitter.Debug(msg) }
}
```

Wire it immediately after successful DERP creation:

- Change `issuePublicQUICSession(ctx, capabilities)` to `issuePublicQUICSession(ctx, capabilities, emitter)` and pass each config's emitter from listen, offer, share, and attach call sites.
- In `externalV2SendRuntime.openDERP`, call `emitDERPProxyDebug(rt.cfg.Emitter, client)`.
- Change `openDerptunServeDERP` and `openDerptunDialDERP` to accept an emitter, then pass the existing config emitter from derptun serve/open/connect/app constructors.
- Call the helper once at each factory boundary, not in reconnect loops.
- Do not read proxy state to set or modify `ForceRelay`.

- [ ] **Step 4: Implement and pass product-path acceptance tests**

Implement the session fixture with the existing local DERP server and a
CONNECT handler that maps the fake authority to the real listener:

```go
type sessionProxyFixture struct {
	mapURL   string
	proxyURL string
	connects atomic.Int64
}

func newSessionProxyFixture(t *testing.T) *sessionProxyFixture {
	t.Helper()
	srv := newSessionTestDERPServer(t)
	derpURL, err := url.Parse(srv.DERPURL)
	if err != nil { t.Fatal(err) }
	fixture := &sessionProxyFixture{mapURL: srv.MapURL}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "derp.proxy-test.invalid:80" {
			http.Error(w, "unexpected CONNECT target", http.StatusBadGateway)
			return
		}
		upstream, err := net.Dial("tcp", derpURL.Host)
		if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
		hijacker, ok := w.(http.Hijacker)
		if !ok { upstream.Close(); http.Error(w, "hijacking unsupported", http.StatusInternalServerError); return }
		client, rw, err := hijacker.Hijack()
		if err != nil { upstream.Close(); return }
		fixture.connects.Add(1)
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil { client.Close(); upstream.Close(); return }
		go func() { defer client.Close(); defer upstream.Close(); _, _ = io.Copy(upstream, rw) }()
		go func() { defer client.Close(); defer upstream.Close(); _, _ = io.Copy(client, upstream) }()
	}))
	t.Cleanup(proxy.Close)
	fixture.proxyURL = proxy.URL
	return fixture
}

func (f *sessionProxyFixture) ConfigureEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", f.mapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "http://derp.proxy-test.invalid/derp")
	t.Setenv("HTTP_PROXY", f.proxyURL)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("no_proxy", "")
}

func (f *sessionProxyFixture) ConnectCount() int64 { return f.connects.Load() }
```

Run:

```sh
mise exec -- go test ./pkg/session -run 'TestPublicRelayRoundTripThroughHTTPProxy|TestDerptunAppStreamRoundTripThroughHTTPProxy|TestExternalV2OfferReceivePromotesToDirectWhenBothSidesReady' -count=1
mise exec -- go test ./pkg/session ./pkg/derpssh/session -count=1
```

Expected: PASS. The relay tests must observe CONNECT on both peers; the direct-promotion test must still report `connected-direct`.

- [ ] **Step 5: Commit only Task 4 files with GitButler**

Run `but diff`, select only the session implementation and test files listed in Task 4, and commit with message `session: report proxied DERP connections`.

---

### Task 5: Document constrained egress and run release-grade verification

**Files:**
- Modify: `docs/derp/client-runtime.md`
- Modify if generated checks require it: `cmd/derphole/depaware.txt`
- Modify if generated checks require it: `cmd/derptun/depaware.txt`
- Modify if generated checks require it: `cmd/derpssh/depaware.txt`

**Interfaces:**
- Consumes: the implemented proxy behavior and error contracts.
- Produces: user-facing operating instructions and a fully verified implementation branch.

- [ ] **Step 1: Add the constrained-egress documentation**

Append a section with this operational shape:

````markdown
## Constrained Egress Through an HTTP Proxy

derphole, derptun, and derpssh honor the standard `HTTP_PROXY`, `HTTPS_PROXY`,
and `NO_PROXY` environment variables for their outbound DERP connection:

```sh
export HTTPS_PROXY=http://proxy.example:3128
export NO_PROXY=localhost,127.0.0.1
derphole send
```

The proxy must allow a long-lived HTTP `CONNECT` tunnel to the selected DERP
host and port, normally TCP 443. HTTP and HTTPS proxy endpoints are supported;
Basic credentials may be included in the proxy URL. Direct UDP discovery still
runs unless `--force-relay` is supplied, so a session can promote away from DERP
when the network permits it. The CONNECT proxy can observe the DERP destination,
timing, and byte volume, but DERP TLS and encrypted peer payloads remain inside
the tunnel.
````

Also document that proxy failure is authoritative, `NO_PROXY` is the direct-access escape hatch, unsupported authentication or CONNECT policy returns an explicit error, and credentials in environment variables have normal process-environment exposure.

- [ ] **Step 2: Run formatting and focused verification**

Run:

```sh
gofmt -w pkg/derpbind/proxy.go pkg/derpbind/proxy_test.go pkg/derpbind/client.go pkg/derpbind/derpbind_test.go pkg/session/external.go pkg/session/external_attach.go pkg/session/external_share.go pkg/session/external_v2.go pkg/session/external_v2_offer.go pkg/session/external_v2_test.go pkg/session/derptun.go pkg/session/proxy_test.go
mise exec -- go test -race ./pkg/derpbind ./pkg/session ./pkg/derpssh/session -count=1
```

Expected: PASS with no race report.

- [ ] **Step 3: Run the complete repository gates**

Run:

```sh
mise run test
mise run check
```

Expected: PASS. If `mise run check` reports dependency snapshots are stale, regenerate them using the repository's existing depaware task, inspect the diff, and rerun `mise run check`. Do not hand-edit generated snapshots.

- [ ] **Step 4: Review the final diff against the acceptance criteria**

Run `but diff` and confirm:

- proxy selection occurs only in `pkg/derpbind`,
- direct dialing remains the no-proxy path,
- there is no assignment from proxy state to `ForceRelay`,
- errors and debug output contain no proxy userinfo,
- the real DERP integration test and both product-path tests use CONNECT,
- docs describe `NO_PROXY`, long-lived CONNECT, metadata visibility, and direct promotion, and
- no generated `dist/` content or unrelated TUI changes are present.

- [ ] **Step 5: Commit documentation and any generated dependency snapshots**

Run `but diff`, select only `docs/derp/client-runtime.md` and any dependency snapshots legitimately regenerated by Step 3, and commit them to `codex/http-proxy-derp` with message `docs: explain DERP proxy egress`.

- [ ] **Step 6: Create the pre-finish recovery point and report branch state**

Run:

```sh
but oplog snapshot -m "before HTTP proxy DERP finish"
but pull --check
but status
```

Expected: the implementation branch contains only the planned commits, the target is current, and no other active branch is modified. Do not push or land on `main` unless the user explicitly asks.
