# DERP Map and Control Plane

## Why the DERP Map Exists

DERP only works because clients agree on a shared description of:

- which DERP regions exist,
- which nodes belong to each region,
- which nodes offer STUN,
- which regions are eligible to become a home DERP,
- how to weight or de-prioritize regions.

That description is the `DERPMap`.

## Core Schema

The schema lives in `tailscale/tailcfg/derpmap.go`.

```go
// Source: tailscale/tailcfg/derpmap.go:13-31
type DERPMap struct {
    HomeParams *DERPHomeParams `json:",omitempty"`
    Regions map[int]*DERPRegion
    OmitDefaultRegions bool `json:"omitDefaultRegions,omitempty"`
}
```

### HomeParams

`HomeParams` lets the control plane influence home-region selection without redefining the whole map:

```go
// Source: tailscale/tailcfg/derpmap.go:44-61
type DERPHomeParams struct {
    RegionScore map[int]float64 `json:",omitempty"`
}
```

`RegionScore` scales measured latency:

- `< 1.0` makes a region more attractive.
- `> 1.0` penalizes a region.
- omitted means neutral.

This is an important design point: the control plane can bias selection policy without lying about raw network measurements.

### Regions

```go
// Source: tailscale/tailcfg/derpmap.go:63-138
type DERPRegion struct {
    RegionID int
    RegionCode string
    RegionName string
    Latitude float64 `json:",omitempty"`
    Longitude float64 `json:",omitempty"`
    Avoid bool `json:",omitempty"`
    NoMeasureNoHome bool `json:",omitempty"`
    Nodes []*DERPNode
}
```

Important semantics:

- `RegionID` is the canonical integer identity and is shared in peer metadata.
- `RegionCode` / `RegionName` are UI and operator-facing identifiers.
- `Avoid` is deprecated and should not be used for new designs.
- `NoMeasureNoHome` means the region can still be used for talking to peers there, but should not be latency-measured or selected as home.
- `Nodes` are ordered in priority order for the current client.

### Nodes

```go
// Source: tailscale/tailcfg/derpmap.go:140-210
type DERPNode struct {
    Name string
    RegionID int
    HostName string
    CertName string `json:",omitempty"`
    IPv4 string `json:",omitempty"`
    IPv6 string `json:",omitempty"`
    STUNPort int `json:",omitempty"`
    STUNOnly bool `json:",omitempty"`
    DERPPort int `json:",omitempty"`
    InsecureForTests bool `json:",omitempty"`
    STUNTestIP string `json:",omitempty"`
    CanPort80 bool `json:",omitempty"`
}
```

This schema explicitly models several operational realities:

- DNS may be broken, so explicit IPv4/IPv6 addresses are first-class.
- STUN and DERP may share or not share the same host/port identity.
- Port 80 availability matters for captive-portal checks.
- Test environments may need insecure cert or STUN overrides.

## Control-Plane Responsibilities

The control plane is responsible for more than just handing out endpoints.

It must:

- provide a coherent region graph,
- provide stable region IDs across clients,
- distribute map changes,
- collect and redistribute each peer's preferred/home DERP region.

The DERP map is part of a normal map response in Headscale:

```go
// Source: headscale/hscontrol/mapper/builder.go:102-105
func (b *MapResponseBuilder) WithDERPMap() *MapResponseBuilder {
    b.resp.DERPMap = b.mapper.state.DERPMap().AsStruct()
    return b
}
```

## Admission Controller Schema

Tailscale also defines a schema for DERP admission control, used by `derper --verify-client-url` and by Headscale's `/verify` endpoint.

```go
// Source: tailscale/tailcfg/derpmap.go:219-229
type DERPAdmitClientRequest struct {
    NodePublic key.NodePublic
    Source     netip.Addr
}

type DERPAdmitClientResponse struct {
    Allow bool
}
```

That schema is deliberately small: it decides whether a client may enter the relay, not how the control plane should configure the client.

## How Tailscale Uses the Map

From the client perspective, the map drives:

- netcheck probe planning,
- region/node dial order,
- home DERP selection,
- STUN targeting,
- direct communication with a peer's declared home region.

The ordering inside `DERPRegion.Nodes` matters. The first entry is supposed to be the ideal target for both DERP and, usually, STUN.

```text
Source: tailscale/tailcfg/derpmap.go:125-137
Nodes are the DERP nodes running in this region, in priority order for the current client.
Client TLS connections should ideally only go to the first entry.
STUN packets should go to the first 1 or 2.
If nodes within a region route packets amongst themselves, but not to other regions.
```

## How Headscale Builds a DERP Map

Headscale can compose a final DERP map from multiple sources:

- an in-memory `cfg.DERPMap`,
- JSON maps fetched from configured URLs,
- YAML maps loaded from local files,
- the automatically generated embedded DERP region.

```go
// Source: headscale/hscontrol/derp/derp.go:100-127
func GetDERPMap(cfg types.DERPConfig) (*tailcfg.DERPMap, error) {
    var derpMaps []*tailcfg.DERPMap
    if cfg.DERPMap != nil {
        derpMaps = append(derpMaps, cfg.DERPMap)
    }
    for _, addr := range cfg.URLs { ... }
    for _, path := range cfg.Paths { ... }
    derpMap := mergeDERPMaps(derpMaps)
    shuffleDERPMap(derpMap)
    return derpMap, nil
}
```

### Merge Semantics

Headscale merges maps naively by region ID, with "last writer wins" semantics:

```go
// Source: headscale/hscontrol/derp/derp.go:76-98
func mergeDERPMaps(derpMaps []*tailcfg.DERPMap) *tailcfg.DERPMap {
    result := tailcfg.DERPMap{
        OmitDefaultRegions: false,
        Regions: map[int]*tailcfg.DERPRegion{},
    }
    for _, derpMap := range derpMaps {
        maps.Copy(result.Regions, derpMap.Regions)
    }
    for id, region := range result.Regions {
        if region == nil {
            delete(result.Regions, id)
        }
    }
    return &result
}
```

Practical implications:

- A later file or URL can override a region from an earlier source.
- Setting a region to `null` deletes it.
- The merge is region-granular, not field-granular.

## Node Ordering and Shuffling in Headscale

Headscale shuffles nodes within a region after merge:

```go
// Source: headscale/hscontrol/derp/derp.go:130-188
func shuffleDERPMap(dm *tailcfg.DERPMap) {
    ...
    for _, id := range ids {
        region := dm.Regions[id]
        if len(region.Nodes) == 0 {
            continue
        }
        dm.Regions[id] = shuffleRegionNoClone(region)
    }
}
```

The seed is deterministic per `dns.base_domain` when set, otherwise time-based. This matters because node order affects the client's ideal node and dial order.

This is a subtle but important behavioral difference from treating the map as a static literal: Headscale intentionally perturbs intra-region ordering.

## Embedded Region Injection in Headscale

If embedded DERP is enabled and auto-add is on, Headscale generates a `DERPRegion` for itself and injects it into the map.

```go
// Source: headscale/hscontrol/app.go:562-576
derpMap, err := derp.GetDERPMap(h.cfg.DERP)
...
if h.cfg.DERP.ServerEnabled && h.cfg.DERP.AutomaticallyAddEmbeddedDerpRegion {
    region, _ := h.DERPServer.GenerateRegion()
    derpMap.Regions[region.RegionID] = &region
}
...
h.state.SetDERPMap(derpMap)
```

That region is then exposed to clients through Headscale state and map responses.

## DERP State in Headscale

Headscale stores the current DERP map in process state:

```go
// Source: headscale/hscontrol/state/state.go:241-248
func (s *State) SetDERPMap(dm *tailcfg.DERPMap) {
    s.derpMap.Store(dm)
}

func (s *State) DERPMap() tailcfg.DERPMapView {
    return s.derpMap.Load().View()
}
```

It also emits a dedicated change type to tell map-response machinery to include the updated map:

```go
// Source: headscale/hscontrol/types/change/change.go:304-308
func DERPMap() Change {
    return Change{
        Reason:         "DERP map update",
        IncludeDERPMap: true,
    }
}
```

## Scheduled DERP Map Refresh in Headscale

When auto-update is enabled, Headscale periodically rebuilds the map and broadcasts the change:

```go
// Source: headscale/hscontrol/app.go:302-325
case <-derpTickerChan:
    derpMap, err := backoff.Retry(ctx, func() (*tailcfg.DERPMap, error) {
        derpMap, err := derp.GetDERPMap(h.cfg.DERP)
        ...
        if h.cfg.DERP.ServerEnabled && h.cfg.DERP.AutomaticallyAddEmbeddedDerpRegion {
            region, _ := h.DERPServer.GenerateRegion()
            derpMap.Regions[region.RegionID] = &region
        }
        return derpMap, nil
    }, ...)
    ...
    h.state.SetDERPMap(derpMap)
    h.Change(change.DERPMap())
```

This means DERP map updates are a live control-plane event, not merely startup configuration.

## Peer Home DERP Propagation

Clients report their preferred DERP through `Hostinfo.NetInfo.PreferredDERP`. Headscale observes that and turns it into peer changes.

```go
// Source: headscale/hscontrol/types/node.go:551-569
if node.Hostinfo != nil &&
    node.Hostinfo.NetInfo != nil &&
    req.Hostinfo != nil &&
    req.Hostinfo.NetInfo != nil &&
    node.Hostinfo.NetInfo.PreferredDERP != req.Hostinfo.NetInfo.PreferredDERP {
    ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
}
```

Later, lightweight endpoint/DERP-only updates can be sent without a full node rebuild:

```go
// Source: headscale/hscontrol/state/state.go:2403-2419
if endpointChanged || derpChanged {
    patch := &tailcfg.PeerChange{NodeID: id.NodeID()}
    ...
    if derpChanged {
        if hi := node.Hostinfo(); hi.Valid() {
            if ni := hi.NetInfo(); ni.Valid() {
                patch.DERPRegion = ni.PreferredDERP()
            }
        }
    }
    return change.EndpointOrDERPUpdate(id, patch), nil
}
```

This is the control-plane bridge between the client's measured home DERP and every other peer's routing decisions.

## Legacy DERP String Compatibility

Headscale still populates the legacy DERP string field in `tailcfg.Node`:

```go
// Source: headscale/hscontrol/types/node.go:1092-1139
legacyDERP := "127.3.3.40:0"
if nv.Hostinfo().Valid() && nv.Hostinfo().NetInfo().Valid() {
    legacyDERP = fmt.Sprintf("127.3.3.40:%d", nv.Hostinfo().NetInfo().PreferredDERP())
    derp = nv.Hostinfo().NetInfo().PreferredDERP()
}
...
HomeDERP:         derp,
LegacyDERPString: legacyDERP,
```

That is primarily compatibility scaffolding for older clients.

## Headscale Configuration Surface

Headscale's YAML configuration exposes both embedded DERP server settings and source-map settings:

```yaml
# Source: headscale/config-example.yaml:85-143
derp:
  server:
    enabled: false
    region_id: 999
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 198.51.100.1
    ipv6: 2001:db8::1
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: true
  update_frequency: 3h
```

This division matches the implementation model:

- `server.*` configures the local embedded server.
- `urls` and `paths` describe external map sources.
- `auto_update_*` controls refresh and redistribution.

## Reserved Region Ranges

The reference schema reserves region IDs `900-999` for end users running their own DERP nodes:

```text
Source: tailscale/tailcfg/derpmap.go:79-84
RegionIDs in range 900-999 are reserved for end users to run their
own DERP nodes.
```

That convention appears in both Headscale examples and tests.

## Important Control-Plane Conclusions

1. DERP behavior is not purely a transport concern. It depends heavily on what the control plane publishes and propagates.
2. Region/node order is semantically important.
3. Home DERP selection combines live latency, recent history, and control-plane weighting.
4. Headscale's DERP story is largely a map-assembly and distribution story wrapped around Tailscale's runtime implementation.
