# DERP Operations and Diagnostics

## When You Should and Should Not Run DERP

Tailscale's own `derper` documentation is unusually explicit: most users should not run custom DERP.

```text
Source: tailscale/cmd/derper/README.md:5-15
In general, you should not need to or want to run this code.
In the happy path, Tailscale establishes direct connections between peers.
If you find yourself wanting DERP for more bandwidth, the real problem is usually the
network configuration of your Tailscale node(s).
```

DERP is operationally justified when:

- you need self-hosted relay control,
- clients are in environments where public DERP reachability is undesirable,
- you need a relay path that is local to your own infrastructure,
- you are operating Headscale and want an embedded or custom-controlled fallback path.

## Ports and Network Exposure

The expected public surface is:

- TCP 443 for DERP-over-TLS.
- TCP 80 for ACME and `/generate_204` captive portal checks in `derper`.
- UDP 3478 for STUN.

```text
Source: tailscale/cmd/derper/README.md:67-68
The firewall on the derper should permit TCP ports 80 and 443 and UDP port 3478.
```

Headscale's embedded DERP exposes STUN and the DERP HTTP endpoints, but not the full `derper` surface.

## TLS and HTTP Constraints

DERP is not an ordinary HTTP workload.

```text
Source: tailscale/cmd/derper/README.md:37-43
The DERP protocol does a protocol switch inside TLS from HTTP to a custom
bidirectional binary protocol. It is thus incompatible with many HTTP proxies.
Do not put derper behind another HTTP proxy.

The tailscaled client does its own selection of the fastest/nearest DERP
server based on latency measurements. Do not put derper behind a global load
balancer.
```

Operationally this means:

- avoid generic reverse proxies in front of `derper`,
- avoid global LBs that hide per-node identity or distort latency,
- preserve direct reachability to each node listed in the DERP map,
- prefer stable public IP addresses with explicit `IPv4`/`IPv6` entries in the map.

## Addressing Best Practices

Tailscale's docs recommend explicit public addressing:

```text
Source: tailscale/cmd/derper/README.md:45-50
DERP servers should ideally have both a static IPv4 and static IPv6 address.
Both of those should be listed in the DERP map so the client doesn't need to
rely on its DNS which might be broken and dependent on DERP to get back up.

A DERP server should not share an IP address with any other DERP server.
```

This recommendation aligns directly with the `DERPNode` schema, which provides explicit `IPv4`, `IPv6`, `DERPPort`, and `CanPort80` fields.

## Meshing Strategy

Multiple nodes in one region are possible, but they are not free operationally.

Reference code guidance:

```text
Source: tailscale/derp/README.md:39-53
Regions generally have multiple nodes per region "meshed" together for redundancy.
Each node in the region is required to be meshed with every other node in the region.
Packets are forwarded only one hop within the region.
There is no routing between regions.
```

And operator guidance:

```text
Source: tailscale/cmd/derper/README.md:51-57
Avoid having multiple DERP nodes in a region. If you must, they all need to be
meshed with each other and monitored.
Having two one-node "regions" in the same datacenter is usually easier and more reliable than meshing.
```

Practical reading:

- one node per region is simplest,
- multiple nodes per region require private, low-latency inter-node connectivity,
- meshing is for HA, not for capacity magic,
- every extra node adds watcher and forwarding complexity.

## `derper` Runtime Surface

The main binary exposes flags for:

- STUN,
- DERP enable/disable,
- mesh key and mesh peers,
- verification,
- TCP write timeout,
- cert mode and ACME settings,
- listener rate limiting.

```go
// Source: tailscale/cmd/derper/derper.go:56-99
var (
    addr = flag.String("a", ":443", ...)
    httpPort = flag.Int("http-port", 80, ...)
    stunPort = flag.Int("stun-port", 3478, ...)
    runSTUN = flag.Bool("stun", true, ...)
    runDERP = flag.Bool("derp", true, ...)
    meshPSKFile = flag.String("mesh-psk-file", ...)
    meshWith = flag.String("mesh-with", ...)
    verifyClients = flag.Bool("verify-clients", false, ...)
    verifyClientURL = flag.String("verify-client-url", "", ...)
    verifyFailOpen = flag.Bool("verify-client-url-fail-open", true, ...)
    tcpWriteTimeout = flag.Duration("tcp-write-timeout", derpserver.DefaultTCPWiteTimeout, ...)
)
```

And wires the server like this:

```go
// Source: tailscale/cmd/derper/derper.go:180-280
if *runSTUN {
    ss := stunserver.New(ctx)
    go ss.ListenAndServe(...)
}
...
s := derpserver.New(cfg.PrivateKey, log.Printf)
s.SetVerifyClient(*verifyClients)
s.SetTailscaledSocketPath(*socket)
s.SetVerifyClientURL(*verifyClientURL)
s.SetVerifyClientURLFailOpen(*verifyFailOpen)
s.SetTCPWriteTimeout(*tcpWriteTimeout)
...
mux.Handle("/derp", derpHandler)
mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)
mux.HandleFunc("/bootstrap-dns", ...)
mux.Handle("/generate_204", http.HandlerFunc(derpserver.ServeNoContent))
```

## Mesh Wiring in `derper`

Meshing is built on top of ordinary DERP clients authenticated with the mesh key:

```go
// Source: tailscale/cmd/derper/mesh.go:21-78
func startMesh(s *derpserver.Server) error { ... }

func startMeshWithHost(s *derpserver.Server, hostTuple string) error {
    ...
    c, err := derphttp.NewClient(s.PrivateKey(), "https://"+host+"/derp", logf, netMon)
    ...
    c.MeshKey = s.MeshKey()
    c.WatchConnectionChanges = true
    ...
    add := func(m derp.PeerPresentMessage) { s.AddPacketForwarder(m.Key, c) }
    remove := func(m derp.PeerGoneMessage) { s.RemovePacketForwarder(m.Peer, c) }
    go c.RunWatchConnectionLoop(...)
}
```

Operational implication: a region mesh is just a set of mutually connected privileged DERP clients watching and forwarding for one another.

## Observability

The DERP docs and binary expose several useful diagnostics:

```text
Source: tailscale/cmd/derper/README.md:90-104
* The debug handler is accessible at URL path /debug/
* Go pprof can be accessed via the debug handler at /debug/pprof/
* Prometheus compatible metrics can be gathered from the debug handler at /debug/varz.
* cmd/stunc provides a basic tool for diagnosing issues with STUN.
* cmd/derpprobe provides a service for monitoring DERP cluster health.
* tailscale debug derp and tailscale netcheck provide additional client driven diagnostic information.
```

### Useful Tools

- `tailscale/cmd/derpprobe/derpprobe.go`
- `tailscale/cmd/stunc/stunc.go`
- `tailscale/cmd/stunstamp/stunstamp.go`
- `tailscale/cmd/tailscale/cli/netcheck.go`

These cover:

- STUN reachability,
- DERP latency,
- cluster health,
- client-visible DERP routing state.

## Captive Portal Checks

Tailscale `derper` exposes `/generate_204` to support captive portal detection:

```go
// Source: tailscale/derp/derpserver/handler.go:84-108
func ServeNoContent(w http.ResponseWriter, r *http.Request) {
    if challenge := r.Header.Get(NoContentChallengeHeader); challenge != "" {
        ...
        w.Header().Set(NoContentResponseHeader, "response "+challenge)
    }
    w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, no-transform, max-age=0")
    w.WriteHeader(http.StatusNoContent)
}
```

Headscale embedded DERP does not expose this endpoint, which means it should not be treated as a drop-in replacement for the entire public `derper` HTTP surface.

## Failure Modes to Watch

The most common problematic classes, as implied by the code and docs, are:

- TLS or HTTP proxy interference with the upgrade.
- DNS breakage when the map does not include explicit public IPs.
- UDP blocked, forcing relay and HTTPS fallback measurements.
- Region mesh misconfiguration causing missing or stale forwarders.
- Duplicate clients or cloned node keys causing ambiguous delivery.
- Admission-controller outages, especially when fail-open is disabled.
- Firewalls suppressing TCP resets or rate-limiting the wrong traffic class.

## Practical Troubleshooting Sequence

1. Confirm the DERP map the client sees with `tailscale debug derp-map`.
2. Run `tailscale netcheck` and inspect preferred DERP and UDP availability.
3. Probe `/derp/probe` or `tailscale debug derp` to confirm relay reachability.
4. Check `/debug/varz` and `/debug/pprof/` on `derper` if available.
5. Validate STUN on UDP/3478.
6. If using verification, test the verify path independently.
7. If using a region mesh, confirm watcher subscriptions and forwarders exist on every node.

## Operational Conclusions

1. DERP is easy to misunderstand because it begins as HTTPS but behaves like a custom long-lived binary service.
2. Custom DERP operations require both network and application-layer troubleshooting skills.
3. Explicit addressing, minimal proxying, and careful mesh design matter more than generic "just put it behind infra" instincts.
