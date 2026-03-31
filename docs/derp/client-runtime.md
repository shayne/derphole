# DERP Client Runtime

## Overview

The client runtime is spread across three layers:

- `derphttp.Client` manages transport establishment and reconnects.
- `derp.Client` speaks DERP frames once connected.
- `netcheck` and `magicsock` decide when, where, and why DERP should be used.

This split is important because "DERP client behavior" is not just a socket dial. It includes measurement, ranking, stickiness, fallback, and route learning.

## Transport Establishment

The transport implementation is in `tailscale/derp/derphttp/derphttp_client.go`.

### Connection Modes

`derphttp.Client` can be created either:

- for a fixed URL (`NewClient`),
- for a region chosen from a `DERPMap` (`NewRegionClient`),
- for TLS probing only (`NewNetcheckClient`).

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:120-177
func NewRegionClient(...)
func NewNetcheckClient(...)
func NewClient(...)
```

### Dial Sequence

The `connect` method handles:

- region resolution,
- TCP dialing,
- TLS handshake,
- optional fast-start,
- HTTP upgrade,
- DERP client creation,
- preferred/home signaling,
- optional watcher subscription.

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:331-585
func (c *Client) connect(ctx context.Context, caller string) (client *derp.Client, connGen int, err error) {
    ...
    switch {
    case canWebsockets && useWebsockets():
        ...
    case c.url != nil:
        tcpConn, err = c.dialURL(ctx)
    default:
        tcpConn, node, err = c.dialRegion(ctx, reg)
        idealNodeInRegion = err == nil && reg.Nodes[0] == node
    }
    ...
    if c.useHTTPS() {
        tlsConn := c.tlsClient(tcpConn, node)
        ...
        if cs.Version >= tls.VersionTLS13 {
            serverPub, serverProtoVersion = parseMetaCert(cs.PeerCertificates)
        }
    }
    ...
    req.Header.Set("Upgrade", "DERP")
    req.Header.Set("Connection", "Upgrade")
    ...
    derpClient, err = derp.NewClient(...)
    ...
    if c.preferred {
        if err := derpClient.NotePreferred(true); err != nil { ... }
    }
    if c.WatchConnectionChanges {
        if err := derpClient.WatchConnectionChanges(); err != nil { ... }
    }
    ...
}
```

## Region and Node Selection

When using a DERP map, clients dial a region by trying nodes in priority order and skipping `STUNOnly` nodes for DERP transport.

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:624-648
func (c *Client) dialRegion(ctx context.Context, reg *tailcfg.DERPRegion) (net.Conn, *tailcfg.DERPNode, error) {
    if len(reg.Nodes) == 0 { ... }
    for _, n := range reg.Nodes {
        if n.STUNOnly {
            continue
        }
        c, err := c.dialNode(ctx, n)
        if err == nil {
            return c, n, nil
        }
    }
    return nil, nil, firstErr
}
```

### Happy Eyeballs Style Racing

`dialNode` races IPv4 and IPv6 and can prefer IPv6 with a slight delay before IPv4:

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:722-827
func (c *Client) dialNode(ctx context.Context, n *tailcfg.DERPNode) (net.Conn, error) {
    ...
    if proto == "tcp4" && c.preferIPv6() {
        t, tChannel := c.clock.NewTimer(200 * time.Millisecond)
        ...
    }
    ...
    if shouldDialProto(n.IPv4, netip.Addr.Is4) { ... }
    if shouldDialProto(n.IPv6, netip.Addr.Is6) { ... }
}
```

The node model therefore supports:

- hard-coded IPs,
- DNS fallback,
- dual-stack racing,
- explicit family disablement (`"none"`),
- proxies when environment hooks say so.

## Reconnect Model

`derphttp.Client` is designed to reconnect lazily:

- failed `Send`/`Recv` report errors,
- later calls re-establish a fresh DERP transport automatically,
- `connGen` increments per reconnect,
- `RecvDetail()` surfaces the generation to callers.

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:1089-1111
func (c *Client) RecvDetail() (m derp.ReceivedMessage, connGen int, err error) {
    client, connGen, err := c.connect(c.newContext(), "derphttp.Client.Recv")
    ...
    m, err = client.Recv()
    ...
    if err != nil {
        c.closeForReconnect(client)
        ...
    }
    return m, connGen, err
}
```

This is why higher-level code can treat DERP as a semi-stable service rather than as a single-use socket.

## Netcheck: Measuring the Network

Netcheck is the measurement engine that feeds home DERP selection.

### Report Model

```go
// Source: tailscale/net/netcheck/netcheck.go:88-126
type Report struct {
    UDP bool
    IPv6 bool
    IPv4 bool
    ICMPv4 bool
    PreferredDERP int
    RegionLatency map[int]time.Duration
    RegionV4Latency map[int]time.Duration
    RegionV6Latency map[int]time.Duration
    GlobalV4 netip.AddrPort
    GlobalV6 netip.AddrPort
    CaptivePortal opt.Bool
}
```

This is not just a DERP measurement structure. It is a combined NAT, reachability, and relay-viability report.

### Probe Planning

Netcheck generates probe plans from the DERP map, recent latency history, and the current preferred DERP:

```go
// Source: tailscale/net/netcheck/netcheck.go:422-535
func makeProbePlan(dm *tailcfg.DERPMap, ifState *netmon.State, last *Report, preferredDERP int) (plan probePlan) {
    ...
    // ensure that the home region is always probed
    ...
    if regIsHome {
        tries = 4
        planContainsHome = true
    }
    ...
}
```

Key behaviors:

- incremental reports re-probe only the most relevant regions,
- the current home region is forcibly included to avoid flapping,
- dual-stack probing adapts based on previous success,
- the fastest prior regions get extra retries.

### HTTP-Only and HTTPS Fallback

If UDP is blocked, netcheck falls back to HTTPS-based latency measurement:

```go
// Source: tailscale/net/netcheck/netcheck.go:960-1015
if !rs.anyUDP() && ctx.Err() == nil && !onlySTUN {
    ...
    c.logf("netcheck: UDP is blocked, trying HTTPS")
    ...
    if d, ip, err := c.measureHTTPSLatency(ctx, reg); err != nil { ... }
}
```

And in JS/wasm or similarly constrained environments it uses `/derp/probe`:

```go
// Source: tailscale/net/netcheck/netcheck.go:1034-1101
func (c *Client) runHTTPOnlyChecks(ctx context.Context, last *Report, rs *reportState, dm *tailcfg.DERPMap) error {
    ...
    req, _ := http.NewRequestWithContext(ctx, "HEAD", "https://"+node.HostName+"/derp/probe", nil)
    ...
}
```

## Preferred/Home DERP Selection

Netcheck includes explicit anti-flap constants:

```go
// Source: tailscale/net/netcheck/netcheck.go:1330-1353
const (
    preferredDERPAbsoluteDiff = 10 * time.Millisecond
    PreferredDERPFrameTime = 8 * time.Second
    PreferredDERPKeepAliveTimeout = 2 * derp.KeepAlive
)
```

And the actual selection logic combines:

- best recent latency over a 5-minute window,
- optional `HomeParams.RegionScore` scaling,
- whether the old region is still accessible,
- whether DERP frames were heard from recently,
- absolute and relative improvement thresholds.

```go
// Source: tailscale/net/netcheck/netcheck.go:1355-1455
func (c *Client) addReportHistoryAndSetPreferredDERP(rs *reportState, r *Report, dm tailcfg.DERPMapView) {
    ...
    for regionID, d := range bestRecent {
        if score := scores.Get(regionID); score > 0 {
            bestRecent[regionID] = time.Duration(float64(d) * score)
        }
    }
    ...
    changingPreferred := prevDERP != 0 && r.PreferredDERP != prevDERP
    ...
    oldRegionIsAccessible := oldRegionCurLatency != 0 || heardFromOldRegionRecently
    if changingPreferred && oldRegionIsAccessible {
        if oldRegionCurLatency-bestAny < preferredDERPAbsoluteDiff {
            keepOld = true
        }
        if bestAny > oldRegionCurLatency/3*2 {
            keepOld = true
        }
    }
}
```

This is one of the most important runtime behaviors in DERP: the system is intentionally conservative about home-region changes.

## Magicsock: Turning Reports into Live Behavior

`magicsock` takes the netcheck report and uses it to update `tailcfg.NetInfo` and select a live home DERP:

```go
// Source: tailscale/wgengine/magicsock/magicsock.go:1008-1062
func (c *Conn) updateNetInfo(ctx context.Context) (*netcheck.Report, error) {
    ...
    report, err := c.netChecker.GetReport(ctx, dm, &netcheck.GetReportOpts{
        GetLastDERPActivity: c.health.GetDERPRegionReceivedTime,
        OnlyTCP443:          c.onlyTCP443.Load(),
    })
    ...
    ni.PreferredDERP = c.maybeSetNearestDERP(report)
    ...
}
```

Important consequence: recent incoming DERP frame activity feeds back into future home-DERP decisions through `GetLastDERPActivity`.

### No-Control-Plane Suppression

Magicsock will not casually change home DERP if the node is disconnected from control and already has one:

```go
// Source: tailscale/wgengine/magicsock/derp.go:152-206
func (c *Conn) maybeSetNearestDERP(report *netcheck.Report) (preferredDERP int) {
    ...
    if !connectedToControl {
        if myDerp != 0 {
            return myDerp
        }
    }
    preferredDERP = report.PreferredDERP
    if preferredDERP == 0 {
        preferredDERP = c.pickDERPFallback()
    }
    ...
    if !c.setNearestDERP(preferredDERP) {
        preferredDERP = 0
    }
    return
}
```

That is a subtle but critical correctness rule: changing home DERP without control-plane connectivity can strand peer reachability because peers cannot learn the new home.

## Fallback Home DERP

If the report cannot identify a preferred region, the client picks a deterministic fallback:

```go
// Source: tailscale/wgengine/magicsock/derp.go:106-146
func (c *Conn) pickDERPFallback() int {
    ...
    if c.myDerp != 0 {
        return c.myDerp
    }
    ...
    return ids[rands.IntN(uint64(uintptr(unsafe.Pointer(c))), len(ids))]
}
```

This is a fallback of last resort, used when measurement is impossible or incomplete, not a substitute for normal latency-driven selection.

## Reverse-Path Learning

Clients can learn a peer's likely DERP region by observing recent inbound DERP traffic:

```go
// Source: tailscale/wgengine/magicsock/derp.go:70-88
func (c *Conn) fallbackDERPRegionForPeer(peer key.NodePublic) (regionID int) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if dr, ok := c.derpRoute[peer]; ok {
        return dr.regionID
    }
    return 0
}
```

This is especially useful for:

- slow or delayed control planes,
- peers that have not yet advertised stable UDP endpoints,
- one-way or server-like nodes that only learn peers reactively.

## Per-Region Connections

`magicsock` keeps active DERP connections per region and notes which one is the current home:

```go
// Source: tailscale/wgengine/magicsock/derp.go:228-273
func (c *Conn) setNearestDERP(derpNum int) (wantDERP bool) {
    ...
    c.myDerp = derpNum
    ...
    for i, ad := range c.activeDerp {
        go ad.c.NotePreferred(i == c.myDerp)
    }
    c.goDerpConnect(derpNum)
    return true
}
```

This means:

- one active home connection is special,
- other region connections may still exist,
- all active connections get updated when the home flag changes.

## Client-Side Conclusions

1. DERP connection choice is measurement-driven, not static.
2. The client uses multiple fallback layers: STUN, HTTPS probe, last-known activity, deterministic fallback region.
3. Home DERP changes are intentionally sticky.
4. The live runtime depends on both control-plane metadata and observed traffic.
5. `derphttp.Client` is only one layer of the behavior; `netcheck` and `magicsock` provide the actual policy.
