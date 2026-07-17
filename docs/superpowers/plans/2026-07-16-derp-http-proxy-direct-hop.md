# Direct DERP HTTP Proxy Hop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent an already-selected DERP HTTP(S) proxy from being routed recursively through `ALL_PROXY`, while retaining `ALL_PROXY` support for otherwise-direct DERP connections.

**Architecture:** Split DERP destination dialing from selected HTTP proxy-hop dialing. Keep `derpDialContext` backed by Tailscale's `netns.NewDialer` for direct DERP paths, and add a small plain-`net.Dialer` seam used only by `dialDERPThroughProxy` to reach the selected proxy endpoint. Prove the boundary in a fresh subprocess because `golang.org/x/net/proxy` caches proxy environment state.

**Tech Stack:** Go 1.26 via `mise`, `net.Dialer`, Tailscale `netns`, subprocess tests, local HTTP CONNECT and failing SOCKS fixtures, GitButler.

## Global Constraints

- `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` continue to select or bypass the HTTP proxy for the original DERP URL.
- `ALL_PROXY` continues to apply when DERP is otherwise dialed directly.
- Once an HTTP(S) proxy is selected, dial that proxy endpoint directly; do not infer a SOCKS-to-HTTP chain from environment variables.
- Do not mutate proxy environment variables in production code.
- Preserve proxy TLS, authentication, CONNECT formatting, IP fallback, redaction, timeouts, and diagnostics.
- Do not add CLI flags or product-specific implementations; the fix belongs in shared `pkg/derpbind` code.
- Do not modify or commit work from other active GitButler branches.

---

### Task 1: Prove a selected HTTP proxy bypasses `ALL_PROXY`

**Files:**
- Modify: `pkg/derpbind/proxy_test.go`

**Interfaces:**
- Consumes: `dialDERPThroughProxy`
- Consumes: existing `newTestConnectProxy`
- Extends: `proxyTestEnvironment`

- [ ] **Step 1: Add a subprocess regression around the real environment behavior.**

Add `TestDialDERPThroughProxyBypassesAllProxy`. In the parent process, start a
working local HTTP CONNECT proxy and a fake local SOCKS listener that records
and immediately closes any accepted connection. Start the current test binary
with a helper marker, the HTTP proxy URL, `ALL_PROXY=socks5://<fake-listener>`,
and empty `NO_PROXY`/`no_proxy` values.

In the child process, parse the HTTP proxy URL and call the real proxy path:

```go
ctx, cancel := context.WithTimeout(context.Background(), time.Second)
defer cancel()
conn, _, err := dialDERPThroughProxy(
	ctx,
	proxyURL,
	"derp.example:443",
	t.Logf,
	netmon.NewStatic(),
)
if err != nil {
	t.Fatal(err)
}
_ = conn.Close()
```

The parent asserts that the HTTP proxy receives exactly one CONNECT request and
that the fake SOCKS listener is never contacted. Keep the listener's accept
goroutine bounded by closing the listener during cleanup.

- [ ] **Step 2: Isolate all proxy environment variables used by subprocess tests.**

Extend `proxyTestEnvironment` so it removes the new helper variables plus
`ALL_PROXY` and `all_proxy` before constructing each child environment. This
keeps the regression independent from the developer machine and prevents the
existing proxy-selection tests from inheriting a SOCKS setting.

- [ ] **Step 3: Run the regression and verify RED.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run '^TestDialDERPThroughProxyBypassesAllProxy$' -count=1
```

Expected: FAIL. The child reaches the fake SOCKS listener and reports a
`socks connect` failure instead of reaching the HTTP CONNECT proxy.

---

### Task 2: Give selected HTTP proxies a dedicated direct dialer

**Files:**
- Modify: `pkg/derpbind/client.go`
- Modify: `pkg/derpbind/proxy.go`
- Modify: `pkg/derpbind/proxy_test.go`
- Modify: `pkg/derpbind/derpbind_test.go`

**Interfaces:**
- Produces: `var derpProxyDialContext`
- Consumes: `derpProxyDialContext` from `dialDERPThroughProxy`
- Preserves: `derpDialContext` for direct DERP destinations

- [ ] **Step 1: Add the direct proxy-hop dial seam.**

Next to `derpDialContext` in `client.go`, add a function with the same signature
so tests can inject it without changing the proxy call shape:

```go
var derpProxyDialContext = func(
	ctx context.Context,
	_ logger.Logf,
	_ *netmon.Monitor,
	network, addr string,
) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}
```

This function intentionally does not inspect any proxy environment variable.

- [ ] **Step 2: Use the seam only for the selected proxy endpoint.**

In `dialDERPThroughProxy`, replace the proxy-address call to
`derpDialContext` with `derpProxyDialContext`. Do not change any subsequent TLS,
CONNECT, response, deadline, or error-handling code.

- [ ] **Step 3: Move proxy-hop test instrumentation to the new seam.**

Update `TestSelectedProxyFailureDoesNotDialDERPDirectly` to stub
`derpProxyDialContext`. Add `stubDERPProxyDial` beside `stubDERPDial` and use it
in `TestClientsExchangePacketThroughHTTPProxyIPFallback` so the integration
test still proves every transport socket first goes to the selected proxy.
Keep direct-dial tests on `stubDERPDial`.

- [ ] **Step 4: Run the regression and verify GREEN.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -run '^TestDialDERPThroughProxyBypassesAllProxy$' -count=1
```

Expected: PASS. The HTTP proxy sees one CONNECT and the SOCKS listener sees no
connection.

- [ ] **Step 5: Run focused package verification.**

Run:

```sh
mise exec -- go test ./pkg/derpbind -count=1
mise exec -- go test -race ./pkg/derpbind -count=1
```

Expected: PASS with existing proxy TLS, authentication, failure, reconnect, and
IP-fallback behavior unchanged.

---

### Task 3: Document and verify the environment boundary

**Files:**
- Modify: `docs/derp/client-runtime.md`

- [ ] **Step 1: Document the direct selected-proxy hop.**

In the constrained-egress section, state that `NO_PROXY` applies to the
original DERP URL, while a selected HTTP(S) proxy endpoint is dialed directly
and is not routed through `ALL_PROXY`. Remove the example's implication that a
loopback `NO_PROXY` entry is required merely to reach a local selected proxy.
State that intentional SOCKS-to-HTTP chaining must be implemented by one
operator-provided endpoint.

- [ ] **Step 2: Run full repository verification.**

Run:

```sh
mise run test
mise run check
```

Expected: PASS.

- [ ] **Step 3: Review and commit only this session's changes.**

Run `but pull --check`, inspect `but diff`, and verify the patch contains only
the design/plan, shared dialer, regression tests, adjusted existing tests, and
runtime documentation. Use GitButler to amend the plan into the existing
design commit when practical, then create one clean scoped implementation
commit such as:

```text
net: dial selected DERP HTTP proxies directly
```

Do not push or land on `main` unless explicitly requested.
