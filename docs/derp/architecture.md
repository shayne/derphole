# DERP Architecture

## Executive Summary

DERP is a distributed relay subsystem that sits between the control plane and the encrypted data plane:

- The control plane distributes a DERP map and peer home-region metadata.
- Clients measure latency, choose a home DERP region, and maintain that connection.
- DERP servers relay encrypted packets using node public keys as addresses.
- STUN and disco traffic are used to escape DERP when direct UDP becomes possible.
- Region meshes provide redundancy inside a region, not global routing.

The practical result is a fallback network that keeps nodes reachable even behind hard NATs, blocked UDP, broken DNS, captive portals, or pathologically asymmetric networks.

## Major Components

### 1. DERP Map and Control Plane

The control plane publishes the set of regions and nodes that clients should know about.

```go
// Source: tailscale/tailcfg/derpmap.go:13-31
type DERPMap struct {
    HomeParams *DERPHomeParams `json:",omitempty"`
    Regions map[int]*DERPRegion
    OmitDefaultRegions bool `json:"omitDefaultRegions,omitempty"`
}
```

The DERP map is not just a list of endpoints. It also carries:

- Region ordering information.
- Optional weighting for home-region selection (`HomeParams.RegionScore`).
- STUN information.
- Whether a region should be measured or eligible as a home.
- Node ordering inside a region.

### 2. Client Runtime

The client side is split across several packages:

- `tailscale/net/netcheck/netcheck.go` measures reachability and latency.
- `tailscale/wgengine/magicsock/magicsock.go` turns those measurements into runtime path choices.
- `tailscale/derp/derphttp/derphttp_client.go` establishes DERP-over-HTTP/TLS connections.
- `tailscale/derp/derp_client.go` speaks the DERP binary protocol once the transport exists.

The client keeps one long-lived home connection and may create additional region connections on demand.

### 3. DERP Server

The server side is centered on `tailscale/derp/derpserver/derpserver.go`.

Responsibilities include:

- Transport upgrade and handshake completion.
- Admission control and optional verification.
- Maintaining the active client set keyed by node public key.
- Relaying packets to local or meshed peers.
- Tracking duplicate connections and watcher subscriptions.
- Emitting keepalives, pongs, peer-present, and peer-gone notifications.

### 4. Region Mesh

Multiple DERP nodes can exist within one region. Those nodes subscribe to each other's peer presence and forward packets within the region.

```text
Source: tailscale/derp/README.md:39-47
Regions generally have multiple nodes per region "meshed" together for redundancy.
Packets are forwarded only one hop within the region.
There is no routing between regions.
The assumption is that the mesh TCP connections are over a VPC that's very fast.
```

The region mesh is a redundancy and balancing tool, not a WAN overlay between arbitrary regions.

### 5. STUN Sidecar

DERP deployments usually also expose STUN on UDP/3478 so clients can learn reflexive addresses and attempt direct NAT traversal.

Tailscale `derper` and Headscale embedded DERP both explicitly wire this in:

- `tailscale/cmd/derper/derper.go:180-183`
- `headscale/hscontrol/app.go:553-560`
- `headscale/hscontrol/derp/server/derp_server.go:356-425`

## End-to-End Flow

### Control-Plane Distribution

1. The control plane assembles or fetches a DERP map.
2. The client receives the map in a map response.
3. The client runs netcheck against the map and chooses a home DERP region.
4. The client reports its preferred/home DERP back via hostinfo/netinfo.

### Steady State

1. The client holds a DERP connection to its home region.
2. Peers learn each other's home DERP through the control plane.
3. If a direct path is unavailable, the sender writes to the peer's home DERP region.
4. If the destination is on another node in the same region mesh, the receiving DERP forwards internally.
5. If direct NAT traversal succeeds, traffic exits DERP and uses UDP directly.

### Failure and Recovery

When the home node inside a region fails:

- The client re-dials another node in the same region.
- The mesh preserves reachability to peers during rebalancing.
- The control plane does not need to reassign every peer immediately.

When the region itself becomes worse but still alive:

- netcheck and magicsock apply stickiness rules to avoid flapping.
- A region move happens only when the new choice is materially better or the old one appears degraded enough.

## Core Design Invariants

### Key-Based Routing

DERP servers route by node public key rather than IP address.

```go
// Source: tailscale/derp/derp.go:4-12
// Package derp implements the Designated Encrypted Relay for Packets (DERP)
// protocol.
//
// DERP routes packets to clients using curve25519 keys as addresses.
//
// DERP is used by Tailscale nodes to proxy encrypted WireGuard
// packets through the Tailscale cloud servers when a direct path
// cannot be found or opened.
```

This is why the server can relay encrypted traffic without understanding packet payloads or owning a conventional routed overlay.

### Region Locality

The implementation explicitly optimizes for keeping traffic within a region:

- `DERPRegion.Nodes` is ordered in per-client priority order.
- Clients ideally use only the first node in a region.
- Mesh forwarding exists to survive local failure or skew.
- There is no server-side cross-region forwarding fabric.

### Direct Path Preference

DERP exists to make connectivity reliable, but it is intentionally not the preferred path for bulk steady-state traffic:

- disco messages use DERP as a side channel during NAT traversal.
- encrypted WireGuard fallback rides DERP only when direct paths fail.
- netcheck and magicsock continuously work to maintain or recover direct connectivity.

### Strict Capability Separation

Regular clients can:

- connect,
- mark whether the connection is preferred,
- send packets,
- receive packets,
- respond to pings.

Privileged mesh/trusted clients can additionally:

- watch peer presence,
- forward packets on behalf of other peers,
- close peer connections for rebalancing or maintenance.

That separation is enforced by the mesh key checks in the server.

## Tailscale Reference Design vs Headscale Integration

Tailscale provides the reference DERP implementation and client behavior. Headscale largely reuses that implementation and focuses on:

- configuration,
- map assembly,
- embedded server lifecycle,
- local verify endpoint behavior,
- control-plane propagation of DERP map changes.

Headscale does not reimplement the DERP wire protocol. Its embedded server wraps Tailscale's `derpserver.Server`.

## Why DERP Looks Like HTTP But Isn't HTTP

The transport is "HTTP enough" to traverse common network infrastructure:

- Clients start with an HTTP `Upgrade: DERP` request.
- TLS is used by default.
- Websocket transport is also supported in some environments.

But after upgrade, the actual traffic is a custom framed binary protocol. This is why generic HTTP load-balancers or reverse proxies are a poor fit for production DERP.

## Architecture Risks and Tradeoffs

### Benefits

- Connectivity survives aggressive NAT and firewall conditions.
- Servers do not need packet decryption keys.
- Region meshes provide local HA without a global relay fabric.
- The system can blend latency measurements, recent activity, and policy weighting when choosing a home.

### Costs

- DERP is more latent and more expensive than direct paths.
- Custom DERP deployments lose some Tailscale control-plane optimizations.
- Region meshes add operational complexity if you run more than one node in a region.
- Proxying, load-balancing, and captive-portal behaviors need to be handled with care.

The remaining documents break each of these concerns down from protocol level to operations.
