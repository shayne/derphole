# DERP Proxy IP Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DERP connections recover when a selected HTTP proxy silently fails hostname CONNECT but accepts a literal IP CONNECT, without changing TLS identity or bypassing the proxy.

**Architecture:** Keep `dialDERPThroughProxy` responsible for one CONNECT exchange and give its response-read failures a typed, wrapped cause. Add a coordinator in `pkg/derpbind/client.go` that tries the hostname first, collects at most two node-provided or locally resolved IP authorities only after a retryable pre-response failure, and retries through the same proxy while leaving the original DERP URL untouched.

**Tech Stack:** Go 1.26 via `mise`, `net/http`, `net/netip`, Tailscale `derphttp`, local `httptest` CONNECT fixtures, GitButler.

## Global Constraints

- `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` remain the only proxy-selection surface.
- A selected proxy remains authoritative; never dial the DERP destination directly after proxy selection.
- Keep the hostname CONNECT as the first and unchanged normal path.
- Retry only typed CONNECT response-read EOF, unexpected EOF, or attempt-local timeout while the caller context remains active.
- Never retry an explicit HTTP status, malformed HTTP, proxy dial/TLS/write failure, caller cancellation, or a post-CONNECT failure.
- Preserve the original DERP URL for TLS SNI, certificate verification, and the DERP HTTP upgrade.
- Try no more than two unique literal IP authorities, once each, within the existing caller deadline.
- Prefer node-provided IPs; locally resolve only address families whose node field is empty, and respect non-empty disable markers such as `none`.
- Do not change custom route or token wire formats.
- Keep proxy credentials and untrusted response bytes out of diagnostics.

---

### Task 1: Preserve and classify CONNECT response-read failures

**Files:**
- Modify: `pkg/derpbind/proxy.go:139-185`
- Modify: `pkg/derpbind/proxy_test.go:490-530`
- Modify: `pkg/derpbind/proxy_test.go:611-700`

**Interfaces:**
- Produces: `type proxyConnectResponseError struct { cause error }`
- Produces: `func retryableProxyConnectResponseError(context.Context, error) bool`
- Consumes: existing `dialDERPThroughProxy`

- [ ] **Step 1: Extend the proxy fixture so it can close without a response.**

Add an authority set to `testConnectProxyOptions`:

```go
CloseWithoutResponse map[string]bool
```

At the start of `serveHTTP`, after recording the cloned request and CONNECT
count, hijack and close immediately when `CloseWithoutResponse[r.Host]` is
true. This must produce a real `io.EOF` in the client rather than a synthetic
test error.

- [ ] **Step 2: Write failing diagnostics tests.**

Add `TestDialDERPThroughProxyPreservesResponseReadCause` with subtests:

```go
tests := []struct {
    name       string
    options    testConnectProxyOptions
    wantCause  error
    wantDetail string
}{
    {
        name: "empty response",
        options: testConnectProxyOptions{
            CloseWithoutResponse: map[string]bool{"derp.example:443": true},
        },
        wantCause: io.ErrUnexpectedEOF,
    },
    {
        name:       "truncated response",
        options:    testConnectProxyOptions{RawResponse: "HTTP/1.1 200"},
        wantCause:  io.ErrUnexpectedEOF,
    },
    {
        name:       "malformed response",
        options:    testConnectProxyOptions{RawResponse: "not-http\r\n\r\n"},
        wantDetail: "malformed HTTP response",
    },
}
```

For EOF cases, assert `errors.Is(err, wantCause)`. For every case, assert a
`*proxyConnectResponseError` exists with `errors.As`. For malformed HTTP,
assert the underlying parsing text is retained but
`retryableProxyConnectResponseError(context.Background(), err)` is false.

Add a classifier table that proves EOF, unexpected EOF, and an attempt-local
`context.DeadlineExceeded` are retryable while malformed errors and a canceled
caller context are not.

- [ ] **Step 3: Run the diagnostics tests and verify RED.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestDialDERPThroughProxyPreservesResponseReadCause|TestRetryableProxyConnectResponseError' -count=1
```

Expected: FAIL because the existing implementation discards the read cause
and the typed classifier does not exist.

- [ ] **Step 4: Implement the typed response error and classifier.**

Add to `proxy.go`:

```go
type proxyConnectResponseError struct {
    cause error
}

func (e *proxyConnectResponseError) Error() string { return e.cause.Error() }
func (e *proxyConnectResponseError) Unwrap() error { return e.cause }

func retryableProxyConnectResponseError(ctx context.Context, err error) bool {
    if ctx.Err() != nil {
        return false
    }
    var responseErr *proxyConnectResponseError
    if !errors.As(err, &responseErr) {
        return false
    }
    if errors.Is(responseErr, io.EOF) ||
        errors.Is(responseErr, io.ErrUnexpectedEOF) ||
        errors.Is(responseErr, context.DeadlineExceeded) {
        return true
    }
    var timeoutErr net.Error
    return errors.As(responseErr, &timeoutErr) && timeoutErr.Timeout()
}
```

Replace both CONNECT response-read returns with a `%w` wrapper around
`proxyConnectResponseError`. When the attempt context expired, wrap
`ctx.Err()`; otherwise wrap the original `http.ReadResponse` error. Keep the
safe proxy scheme/address prefix and do not include response bytes.

- [ ] **Step 5: Run the diagnostics tests and verify GREEN.**

Run the Step 3 command again.

Expected: PASS. Empty and truncated responses preserve their
`io.ErrUnexpectedEOF` causes, malformed HTTP remains non-retryable, and
caller cancellation disables retry.

---

### Task 2: Collect bounded proxy IP fallback authorities

**Files:**
- Modify: `pkg/derpbind/client.go:70-85`
- Modify: `pkg/derpbind/client.go:158-215`
- Modify: `pkg/derpbind/derpbind_test.go:330-390`

**Interfaces:**
- Produces: `var derpLookupNetIP = net.DefaultResolver.LookupNetIP`
- Produces: `func proxyDERPIPTargets(context.Context, *tailcfg.DERPNode, *url.URL) ([]string, error)`
- Consumes: `canonicalDERPTarget`

- [ ] **Step 1: Write failing candidate-selection tests.**

Add `TestProxyDERPIPTargets` with table cases that inject `derpLookupNetIP` and
assert exact authorities:

```go
tests := []struct {
    name       string
    node       *tailcfg.DERPNode
    rawURL     string
    resolved   []netip.Addr
    want       []string
    wantLookups int
}{
    {
        name: "node IPs avoid DNS",
        node: &tailcfg.DERPNode{IPv4: "192.0.2.10", IPv6: "2001:db8::10"},
        rawURL: "https://derp.example:8443/derp",
        want: []string{"192.0.2.10:8443", "[2001:db8::10]:8443"},
    },
    {
        name: "empty custom node resolves locally",
        node: &tailcfg.DERPNode{},
        rawURL: "https://derp.example/derp",
        resolved: []netip.Addr{
            netip.MustParseAddr("192.0.2.20"),
            netip.MustParseAddr("2001:db8::20"),
        },
        want: []string{"192.0.2.20:443", "[2001:db8::20]:443"},
        wantLookups: 1,
    },
    {
        name: "disable marker suppresses IPv4",
        node: &tailcfg.DERPNode{IPv4: "none"},
        rawURL: "https://derp.example/derp",
        resolved: []netip.Addr{
            netip.MustParseAddr("192.0.2.30"),
            netip.MustParseAddr("2001:db8::30"),
        },
        want: []string{"[2001:db8::30]:443"},
        wantLookups: 1,
    },
    {
        name: "literal URL has no fallback",
        node: &tailcfg.DERPNode{},
        rawURL: "https://192.0.2.40/derp",
        want: nil,
    },
}
```

Add cases for duplicate/mapped addresses, invalid multicast/unspecified
addresses, both families disabled, resolver failure, and more than two
addresses. Restore the injected resolver with `t.Cleanup` and do not mark
these global-seam tests parallel.

- [ ] **Step 2: Run candidate tests and verify RED.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run '^TestProxyDERPIPTargets$' -count=1
```

Expected: FAIL because `proxyDERPIPTargets` and `derpLookupNetIP` do not exist.

- [ ] **Step 3: Implement candidate collection.**

Add `net/netip` to `client.go`, define the resolver seam, and implement a
maximum of two targets. Treat an empty node family as resolver-eligible, a
valid matching-family value as authoritative, and any other non-empty value
as disabled. Normalize IPv4-mapped addresses with `Unmap`, accept global
unicast or loopback addresses, reject zones, preserve local resolver order,
deduplicate by `netip.Addr`, and join every IP with the DERP URL port.

Use this signature exactly:

```go
var derpLookupNetIP = net.DefaultResolver.LookupNetIP

func proxyDERPIPTargets(
    ctx context.Context,
    node *tailcfg.DERPNode,
    derpURL *url.URL,
) ([]string, error)
```

Return no targets and no lookup for a literal-IP DERP URL. Wrap resolver
failures with `fmt.Errorf("resolve DERP hostname for proxy IP fallback %s: %w",
host, err)`.

- [ ] **Step 4: Run candidate tests and verify GREEN.**

Run the Step 2 command again.

Expected: PASS with exact ordering, family-disable behavior, deduplication,
and the two-candidate bound.

---

### Task 3: Coordinate hostname-first CONNECT with IP fallback

**Files:**
- Modify: `pkg/derpbind/client.go:158-185`
- Modify: `pkg/derpbind/proxy_test.go:611-760`
- Modify: `pkg/derpbind/derpbind_test.go:520-620`

**Interfaces:**
- Produces: `func dialDERPNodeThroughProxy(context.Context, *url.URL, *tailcfg.DERPNode, *url.URL, logger.Logf, *netmon.Monitor) (net.Conn, ProxyInfo, error)`
- Consumes: `dialDERPThroughProxy`, `retryableProxyConnectResponseError`, `proxyDERPIPTargets`

- [ ] **Step 1: Write a failing successful-fallback test.**

Configure the test proxy to close `derp.example:443` without a response and
return `200 OK` for `192.0.2.50:443`. Stub the local resolver to return
`192.0.2.50`, select that proxy through `derpProxyFromEnvironment`, invoke the
real `newDERPNodeDialer`, then assert:

```go
if got, want := first.Host, "derp.example:443"; got != want { ... }
if got, want := second.Host, "192.0.2.50:443"; got != want { ... }
if proxy.ConnectCount() != 2 { ... }
if info, ok := recorder.Load(); !ok || info.TargetAddr != "192.0.2.50:443" { ... }
```

The returned tunnel may be closed immediately; no direct DERP socket is
needed for this coordinator test.

- [ ] **Step 2: Write failing no-fallback and bounded-fallback tests.**

Add table-driven tests proving:

- a successful hostname CONNECT makes one proxy connection and zero resolver
  calls;
- 403, 407, and 502 make one proxy connection and zero resolver calls;
- malformed HTTP makes one proxy connection and zero resolver calls;
- caller cancellation during a blocked hostname response makes one proxy
  connection and zero resolver calls;
- a private attempt timeout falls back while the parent context remains live;
- two IP candidates are each tried once after the hostname and the final error
  contains all three authorities;
- a resolver failure joins the preserved hostname EOF with the resolver cause.

For the attempt-timeout case, temporarily set `derpDialTimeout` to 25ms,
block only the hostname authority, keep a one-second parent context, and let
the IP authority return 200.

- [ ] **Step 3: Write failing real DERP and TLS hostname tests.**

Create `TestClientsExchangePacketThroughHTTPProxyIPFallback` from the existing
proxy exchange fixture. Keep the real local DERP server, set the advertised
hostname to `derp.proxy-test.invalid`, retain its `127.0.0.1` node IPv4, and
make the forwarding proxy silently close the hostname authority while
forwarding the literal IPv4 authority with the same dynamic listener port.

Connect two `Client` instances, exchange an exact packet, and assert:

- each client first attempted the hostname authority;
- each client then attempted the literal IPv4 authority;
- both `ProxyInfo.TargetAddr` values equal the literal IP authority;
- the proxy observed four initial CONNECTs;
- no direct-dial seam was called.

Add `TestDERPProxyIPFallbackPreservesTLSHostname`. Start
`httptest.NewTLSServer`, trust its certificate in a test root pool, and build
the original URL with:

```go
derpURL, err := url.Parse(fmt.Sprintf(
    "https://example.com:%s/derp",
    portString(t, tlsServer.Listener.Addr()),
))
```

The standard test certificate covers `example.com`. Make the proxy close the
hostname authority and forward the IP authority to the TLS server. Obtain the
tunnel from `newDERPNodeDialer`, then perform:

```go
tlsConn := tls.Client(conn, &tls.Config{
    RootCAs:    roots,
    ServerName: derpURL.Hostname(),
})
if err := tlsConn.HandshakeContext(ctx); err != nil {
    t.Fatalf("TLS over proxy IP fallback: %v", err)
}
if got := tlsConn.ConnectionState().ServerName; got != "example.com" {
    t.Fatalf("TLS ServerName = %q, want example.com", got)
}
```

- [ ] **Step 4: Run coordinator and integration tests and verify RED.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestNewDERPNodeDialer.*Proxy|TestDialDERPNodeThroughProxy|TestClientsExchangePacketThroughHTTPProxyIPFallback|TestDERPProxyIPFallbackPreservesTLSHostname' -count=1
```

Expected: FAIL because the selected-proxy path performs exactly one hostname
CONNECT and returns its failure.

- [ ] **Step 5: Implement the proxy-target coordinator.**

Add:

```go
func dialDERPNodeThroughProxy(
    ctx context.Context,
    proxyURL *url.URL,
    node *tailcfg.DERPNode,
    derpURL *url.URL,
    logf logger.Logf,
    netMon *netmon.Monitor,
) (net.Conn, ProxyInfo, error)
```

The function must:

1. call `canonicalDERPTarget` and attempt it once;
2. return success immediately;
3. require `retryableProxyConnectResponseError(ctx, err)` before resolving;
4. collect bounded IP targets;
5. try them sequentially through the same `proxyURL`;
6. return immediately on success or any non-retryable IP error;
7. continue to the next IP only after another retryable response-read error;
8. stop on `ctx.Err()`;
9. return `errors.Join` of the hostname, resolver, and IP attempt errors.

Wrap each attempt with
`fmt.Errorf("CONNECT %s through DERP proxy: %w", authority, err)` so joined
errors identify the target without exposing proxy credentials. Replace the
single `dialDERPThroughProxy` call in `newDERPNodeDialer` with this coordinator
and continue storing only the successful `ProxyInfo`.

- [ ] **Step 6: Run coordinator and package tests and verify GREEN.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestNewDERPNodeDialer.*Proxy|TestDialDERPNodeThroughProxy|TestProxyDERPIPTargets|TestDialDERPThroughProxy' -count=1
mise exec -- go test ./pkg/derpbind -count=1
```

Expected: PASS. Existing successful proxy tests remain one attempt and the new
fallback tests show hostname then unique IP authorities only.

---

### Task 4: Document behavior and run focused integration verification

**Files:**
- Modify: `docs/derp/custom-server.md:35-55`
- Modify: `docs/derp/client-runtime.md`

**Interfaces:**
- Consumes: completed hostname-first proxy coordinator and its integration tests
- Produces: operator documentation and repeated focused verification

- [ ] **Step 1: Re-run the real DERP and TLS hostname tests.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run 'TestClientsExchangePacketThroughHTTPProxyIPFallback|TestDERPProxyIPFallbackPreservesTLSHostname' -count=1
```

Expected: PASS with real packet exchange and TLS hostname verification.

- [ ] **Step 2: Update operator documentation.**

In `docs/derp/custom-server.md`, retain the requirement for a long-lived
CONNECT tunnel and add:

```markdown
The client tries CONNECT with the DERP hostname first. If the proxy closes or
times out before returning any HTTP response, the client may resolve the DERP
hostname locally and retry a literal IP authority through the same proxy. TLS
still authenticates the original DERP hostname. Explicit proxy responses are
final and never trigger this fallback.
```

Add the same mechanism-level explanation to the proxy section of
`docs/derp/client-runtime.md`. Do not promise recovery when both proxy DNS and
local DNS fail.

- [ ] **Step 3: Run focused and race verification.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -count=20
mise exec -- go test -race ./pkg/derpbind -count=1
```

Expected: PASS with no races in resolver seams, proxy fixture state, or
connection cleanup.

---

### Task 5: Full verification, review, and local checkpoint

**Files:**
- Review all files changed by Tasks 1-4

**Interfaces:**
- Consumes: complete implementation and documentation
- Produces: a clean, verified local GitButler checkpoint

- [ ] **Step 1: Format and inspect the exact diff.**

Run:

```sh
mise exec -- gofmt -w pkg/derpbind/proxy.go pkg/derpbind/proxy_test.go pkg/derpbind/client.go pkg/derpbind/derpbind_test.go
git diff --check
but diff
```

Expected: no formatting or whitespace errors; only the spec, plan, shared
DERP proxy code/tests, and proxy documentation are changed.

- [ ] **Step 2: Run full repository tests.**

Run:

```sh
mise run test
```

Expected: PASS.

- [ ] **Step 3: Run the repository check gate.**

Run:

```sh
mise run check
```

Expected: all hooks, build, tests, topology checks, and policy checks pass.

- [ ] **Step 4: Review requirements against evidence.**

Confirm from tests and diff that:

- the normal hostname path performs no lookup;
- only typed pre-response EOF/timeouts trigger fallback;
- explicit responses and caller cancellation remain final;
- the proxy remains authoritative for every attempt;
- TLS keeps the original hostname;
- custom token/route formats are untouched;
- diagnostics preserve causes and redact credentials.

- [ ] **Step 5: Create a local GitButler checkpoint without pushing.**

Use `but diff` to obtain the exact whole-file change IDs. Copy every ID for
this session's implementation, test, plan, spec amendment, and documentation
files into one `--changes` argument, then run `but commit` on
`codex/derp-proxy-ip-fallback` with subject
`net: retry DERP proxy via resolved IP`.

Expected: the branch contains the design/plan checkpoint plus one coherent
implementation commit, the workspace is clean, and no remote branch or
`origin/main` ref is changed.
