# DERP Testing and Validation

## What Should Be Tested

A DERP system is not just "can I open TCP 443". At minimum, useful validation covers:

- map distribution,
- STUN reachability,
- DERP transport establishment,
- server admission control,
- preferred/home DERP propagation,
- continued health across map refreshes,
- websocket compatibility if used,
- client behavior under blocked UDP or fallback conditions.

## Headscale Embedded DERP Integration Coverage

Headscale has integration tests that exercise the embedded server end to end.

### Embedded DERP Connectivity Scenario

The main scenario starts Headscale with:

- embedded DERP enabled,
- STUN exposed,
- HTTPS on port 443,
- verification enabled,
- periodic DERP map refresh enabled.

```go
// Source: headscale/integration/embedded_derp_test.go:117-132
err = scenario.CreateHeadscaleEnv(
    []tsic.Option{
        tsic.WithWebsocketDERP(websocket),
    },
    hsic.WithTestName(testName),
    hsic.WithExtraPorts([]string{"3478/udp"}),
    hsic.WithPort(443),
    hsic.WithConfigEnv(map[string]string{
        "HEADSCALE_DERP_AUTO_UPDATE_ENABLED":   "true",
        "HEADSCALE_DERP_UPDATE_FREQUENCY":      "10s",
        "HEADSCALE_LISTEN_ADDR":                "0.0.0.0:443",
        "HEADSCALE_DERP_SERVER_VERIFY_CLIENTS": "true",
    }),
)
```

The test then checks:

- clients do not report DERP relay failure,
- clients can ping over DERP,
- connectivity remains healthy after the map updater runs multiple times.

```go
// Source: headscale/integration/embedded_derp_test.go:181-205
// Let the DERP updater run a couple of times to ensure it does not
// break the DERPMap.
time.Sleep(30 * time.Second)

success = pingDerpAllHelper(t, allClients, allHostnames)
...
for _, client := range allClients {
    assert.EventuallyWithT(t, func(ct *assert.CollectT) {
        status, err := client.Status()
        ...
        assert.NotContains(ct, health, "could not connect to any relay server", ...)
    }, 30*time.Second, 2*time.Second)
}
```

This is good coverage of one of the most failure-prone control-plane behaviors: live DERP map refresh.

### Websocket DERP Scenario

Headscale also verifies websocket DERP mode:

```go
// Source: headscale/integration/embedded_derp_test.go:70-95
func TestDERPServerWebsocketScenario(t *testing.T) {
    ...
    derpServerScenario(t, spec, "derp-ws", true, func(scenario *Scenario) {
        ...
        for _, client := range allClients {
            if !didClientUseWebsocketForDERP(t, client) {
                t.Fail()
            }
        }
    })
}
```

That is important because websocket support is a separate code path in the HTTP wrapper even though the inner DERP runtime is shared.

## Verify Endpoint Coverage

Headscale also tests the external `derper -> /verify` pattern.

### External DERP + Headscale Verification

The test sets up a standalone DERP server with `verify-client-url` pointed at Headscale:

```go
// Source: headscale/integration/derp_verify_endpoint_test.go:48-50
derper, err := scenario.CreateDERPServer("head",
    dsic.WithCACert(caHeadscale),
    dsic.WithVerifyClientURL(fmt.Sprintf("https://%s/verify", net.JoinHostPort(hostname, strconv.Itoa(headscalePort)))),
)
```

It then validates that:

- a fake key is rejected,
- real client node keys are accepted.

```go
// Source: headscale/integration/derp_verify_endpoint_test.go:93-100
fakeKey := key.NewNode()
DERPVerify(t, fakeKey, derpRegion, false)

for _, client := range allClients {
    nodeKey, err := client.GetNodePrivateKey()
    require.NoError(t, err)
    DERPVerify(t, *nodeKey, derpRegion, true)
}
```

### Minimal DERP Verification Helper

The helper itself is a compact example of what a DERP sanity check looks like:

```go
// Source: headscale/integration/derp_verify_endpoint_test.go:103-133
func DERPVerify(t *testing.T, nodeKey key.NodePrivate, region tailcfg.DERPRegion, expectSuccess bool) {
    c := derphttp.NewRegionClient(nodeKey, t.Logf, netmon.NewStatic(), func() *tailcfg.DERPRegion {
        return &region
    })
    defer c.Close()

    err := c.Connect(t.Context())
    ...
    if m, err := c.Recv(); err != nil {
        result = fmt.Errorf("client first Recv: %w", err)
    } else if v, ok := m.(derp.ServerInfoMessage); !ok {
        result = fmt.Errorf("client first Recv was unexpected type %T", v)
    }
    ...
}
```

That helper is a useful blueprint for manual or automated smoke tests:

- connect,
- expect successful handshake,
- expect `ServerInfoMessage`,
- treat anything else as a failure.

## Manual Validation Checklist

### 1. Confirm the DERP Map

On a client:

- `tailscale debug derp-map`
- confirm the expected region IDs, region codes, hostnames, STUN ports, and IPs

On Headscale:

- inspect current generated config and source maps
- confirm the embedded region is injected if expected

### 2. Confirm STUN Reachability

Useful tools:

- `tailscale/cmd/stunc/stunc.go`
- `tailscale/cmd/stunstamp/stunstamp.go`

What to validate:

- UDP/3478 reachable from client networks,
- response contains the expected reflexive address,
- latency is sensible for the intended region.

### 3. Confirm DERP Reachability

Useful client checks:

- `tailscale debug derp`
- `tailscale netcheck`

Useful server checks:

- `HEAD /derp/probe`
- `GET /derp/latency-check`
- `/debug/varz` where available

### 4. Confirm Home DERP Propagation

After a client connects:

- inspect its status for the preferred/home DERP,
- confirm peers can route to it through the expected region,
- if using Headscale, confirm `PreferredDERP` changes become peer patches rather than only full node refreshes.

### 5. Confirm Fallback Behavior

If possible, test at least one environment where:

- UDP is blocked,
- HTTPS still works,
- DERP becomes the effective path,
- netcheck reports the right fallback behavior.

This is essential because many DERP bugs only show up in degraded-path environments.

## Source-Level Validation Ideas

If extending DERP or integrating with it, tests should ideally cover:

- handshake success and rejection cases,
- duplicate key handling,
- packet routing local vs meshed,
- queue overflow/drop behavior,
- watcher subscription correctness,
- map update propagation,
- region weighting and home-DERP stickiness,
- Headscale verify endpoint semantics,
- websocket and fast-start transport modes.

## Good Regression Targets

The highest-value regressions to defend against are:

- home DERP flapping caused by map updates or noisy latency samples,
- silent breakage of `/verify` admission behavior,
- broken websocket fallback,
- broken STUN listener configuration,
- map merge bugs that accidentally delete or shadow regions,
- embedded DERP region generation mismatching the advertised public endpoint.

## Testing Conclusions

1. DERP requires both transport tests and policy/control-plane tests.
2. Headscale's existing integration tests cover the two most important operator-facing behaviors: embedded connectivity and verify endpoint interoperability.
3. The simplest useful smoke test is: create a `derphttp.NewRegionClient`, connect, and assert the first received message is `derp.ServerInfoMessage`.
