# DERP in Headscale

## Headscale's Role

Headscale does not implement a separate DERP protocol. Instead, it:

- embeds Tailscale's `derpserver.Server`,
- builds and distributes DERP maps,
- exposes a `/verify` admission endpoint,
- optionally injects an embedded local DERP region into the published map,
- propagates peer DERP-region changes to clients.

That means the DERP runtime semantics are mostly inherited from Tailscale, while Headscale owns the control-plane and packaging story.

## Embedded DERP Server Construction

Headscale creates an embedded DERP server during app initialization when `derp.server.enabled` is true.

```go
// Source: headscale/hscontrol/app.go:215-246
if cfg.DERP.ServerEnabled {
    derpServerKey, err := readOrCreatePrivateKey(cfg.DERP.ServerPrivateKeyPath)
    ...
    if cfg.DERP.ServerVerifyClients {
        t := http.DefaultTransport.(*http.Transport)
        t.RegisterProtocol(
            derpServer.DerpVerifyScheme,
            derpServer.NewDERPVerifyTransport(app.handleVerifyRequest),
        )
    }
    embeddedDERPServer, err := derpServer.NewDERPServer(
        cfg.ServerURL,
        key.NodePrivate(*derpServerKey),
        &cfg.DERP,
    )
    ...
    app.DERPServer = embeddedDERPServer
}
```

Notable design choices:

- The DERP server gets its own private key, distinct from the Noise key.
- If verification is enabled, Headscale installs a custom transport scheme for local in-process verification.
- The embedded DERP server is created early, before the map is published.

## Wrapper Around Tailscale DERP Server

The embedded server is a thin wrapper around `tailscale.com/derp/derpserver.Server`:

```go
// Source: headscale/hscontrol/derp/server/derp_server.go:45-70
type DERPServer struct {
    serverURL string
    key key.NodePrivate
    cfg *types.DERPConfig
    tailscaleDERP *derpserver.Server
}

func NewDERPServer(...) (*DERPServer, error) {
    server := derpserver.New(derpKey, util.TSLogfWrapper())
    if cfg.ServerVerifyClients {
        server.SetVerifyClientURL(DerpVerifyScheme + "://verify")
        server.SetVerifyClientURLFailOpen(false)
    }
    ...
}
```

The most important Headscale-specific behavior here is that verification is routed through a local pseudo-URL scheme rather than a real HTTP loopback request.

## Region Generation

Headscale can synthesize a DERP region definition for its own embedded server based on `server_url` and DERP config.

```go
// Source: headscale/hscontrol/derp/server/derp_server.go:73-147
func (d *DERPServer) GenerateRegion() (tailcfg.DERPRegion, error) {
    ...
    localDERPregion := tailcfg.DERPRegion{
        RegionID:   d.cfg.ServerRegionID,
        RegionCode: d.cfg.ServerRegionCode,
        RegionName: d.cfg.ServerRegionName,
        Avoid:      false,
        Nodes: []*tailcfg.DERPNode{
            {
                Name:     strconv.Itoa(d.cfg.ServerRegionID),
                RegionID: d.cfg.ServerRegionID,
                HostName: host,
                DERPPort: port,
                IPv4:     d.cfg.IPv4,
                IPv6:     d.cfg.IPv6,
            },
        },
    }
    ...
    localDERPregion.Nodes[0].STUNPort = portSTUN
    return localDERPregion, nil
}
```

Important details:

- the embedded region ID/code/name come from config,
- the DERP host and port come from `server_url`,
- STUN port comes from `stun_listen_addr`,
- explicit public IPv4/IPv6 addresses can be injected into the published node definition,
- a debug flag can resolve the hostname to an IP for testing.

## Transport Handling in Headscale

Headscale supports both plain DERP-over-upgrade and websocket DERP:

```go
// Source: headscale/hscontrol/derp/server/derp_server.go:150-183
func (d *DERPServer) DERPHandler(writer http.ResponseWriter, req *http.Request) {
    upgrade := strings.ToLower(req.Header.Get("Upgrade"))
    if upgrade != "websocket" && upgrade != "derp" { ... }
    if strings.Contains(req.Header.Get("Sec-Websocket-Protocol"), "derp") {
        d.serveWebsocket(writer, req)
    } else {
        d.servePlain(writer, req)
    }
}
```

Plain upgraded mode:

```go
// Source: headscale/hscontrol/derp/server/derp_server.go:228-279
func (d *DERPServer) servePlain(writer http.ResponseWriter, req *http.Request) {
    fastStart := req.Header.Get(fastStartHeader) == "1"
    ...
    if !fastStart {
        fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
            "Upgrade: DERP\r\n"+
            "Connection: Upgrade\r\n"+
            "Derp-Version: %v\r\n"+
            "Derp-Public-Key: %s\r\n\r\n",
            derp.ProtocolVersion,
            string(pubKeyStr))
    }
    d.tailscaleDERP.Accept(req.Context(), netConn, conn, netConn.RemoteAddr().String())
}
```

Websocket mode:

```go
// Source: headscale/hscontrol/derp/server/derp_server.go:185-226
func (d *DERPServer) serveWebsocket(writer http.ResponseWriter, req *http.Request) {
    websocketConn, err := websocket.Accept(writer, req, &websocket.AcceptOptions{
        Subprotocols: []string{"derp"},
        OriginPatterns: []string{"*"},
        CompressionMode: websocket.CompressionDisabled,
    })
    ...
    wc := wsconn.NetConn(req.Context(), websocketConn, websocket.MessageBinary, req.RemoteAddr)
    brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
    d.tailscaleDERP.Accept(req.Context(), wc, brw, req.RemoteAddr)
}
```

This is a good illustration of Headscale's design: it adapts the surrounding HTTP/websocket environment, then hands an ordinary stream to the Tailscale DERP server.

## Probe and Bootstrap Endpoints

Headscale exposes:

- `/derp`
- `/derp/probe`
- `/derp/latency-check`
- `/bootstrap-dns`
- `/verify`

Router wiring:

```go
// Source: headscale/hscontrol/app.go:498-505
r.Post("/verify", h.VerifyHandler)

if h.cfg.DERP.ServerEnabled {
    r.HandleFunc("/derp", h.DERPServer.DERPHandler)
    r.HandleFunc("/derp/probe", derpServer.DERPProbeHandler)
    r.HandleFunc("/derp/latency-check", derpServer.DERPProbeHandler)
    r.HandleFunc("/bootstrap-dns", derpServer.DERPBootstrapDNSHandler(h.state.DERPMap()))
}
```

Unlike Tailscale `derper`, Headscale does not expose `/generate_204` in this route set.

## STUN in Headscale

When embedded DERP is enabled, Headscale also starts STUN:

```go
// Source: headscale/hscontrol/app.go:553-560
if h.cfg.DERP.ServerEnabled {
    if h.cfg.DERP.STUNAddr == "" {
        return errSTUNAddressNotSet
    }
    go h.DERPServer.ServeSTUN()
}
```

And the implementation is a straightforward UDP STUN responder:

```go
// Source: headscale/hscontrol/derp/server/derp_server.go:356-425
func (d *DERPServer) ServeSTUN() {
    packetConn, err := new(net.ListenConfig).ListenPacket(context.Background(), "udp", d.cfg.STUNAddr)
    ...
    serverSTUNListener(context.Background(), udpConn)
}
```

## Verification Path

Headscale's verify logic checks whether the connecting node public key belongs to any known node:

```go
// Source: headscale/hscontrol/handlers.go:83-114
func (h *Headscale) handleVerifyRequest(req *http.Request, writer io.Writer) error {
    ...
    var derpAdmitClientRequest tailcfg.DERPAdmitClientRequest
    if err := json.Unmarshal(body, &derpAdmitClientRequest); err != nil { ... }
    nodes := h.state.ListNodes()
    var nodeKeyFound bool
    for _, node := range nodes.All() {
        if node.NodeKey() == derpAdmitClientRequest.NodePublic {
            nodeKeyFound = true
            break
        }
    }
    resp := &tailcfg.DERPAdmitClientResponse{
        Allow: nodeKeyFound,
    }
    return json.NewEncoder(writer).Encode(resp)
}
```

And exposes it over HTTP:

```go
// Source: headscale/hscontrol/handlers.go:116-133
func (h *Headscale) VerifyHandler(writer http.ResponseWriter, req *http.Request) {
    if req.Method != http.MethodPost {
        httpError(writer, errMethodNotAllowed)
        return
    }
    err := h.handleVerifyRequest(req, writer)
    ...
    writer.Header().Set("Content-Type", "application/json")
}
```

This same logic can be used:

- internally by embedded DERP through the custom transport,
- externally by a standalone `derper` through `-verify-client-url=https://headscale.example.com/verify`.

## Configuration Surface

The relevant config loading path is:

```go
// Source: headscale/hscontrol/types/config.go:550-612
func derpConfig() DERPConfig {
    serverEnabled := viper.GetBool("derp.server.enabled")
    serverRegionID := viper.GetInt("derp.server.region_id")
    serverRegionCode := viper.GetString("derp.server.region_code")
    serverRegionName := viper.GetString("derp.server.region_name")
    serverVerifyClients := viper.GetBool("derp.server.verify_clients")
    stunAddr := viper.GetString("derp.server.stun_listen_addr")
    ...
    if serverEnabled && stunAddr == "" {
        log.Fatal().Msg("derp.server.stun_listen_addr must be set if derp.server.enabled is true")
    }
    ...
    if serverEnabled && !automaticallyAddEmbeddedDerpRegion && len(paths) == 0 {
        log.Fatal().Msg("Disabling derp.server.automatically_add_embedded_derp_region requires to configure the derp server in derp.paths")
    }
    ...
}
```

That validation encodes two operational invariants:

- embedded DERP requires STUN configuration,
- disabling automatic map injection requires an explicit map entry elsewhere.

## DERP Map Distribution in Headscale

Headscale rebuilds or refreshes its DERP map, injects the embedded region if requested, stores it in state, and broadcasts `IncludeDERPMap` changes to clients. See:

- `headscale/hscontrol/app.go:302-325`
- `headscale/hscontrol/app.go:562-576`
- `headscale/hscontrol/state/state.go:241-248`
- `headscale/hscontrol/types/change/change.go:304-308`

This is the core distinction between Headscale and `derper`: Headscale is the map authority for its clients.

## Peer DERP Region Propagation

Headscale stores the preferred DERP region in node hostinfo and exports it into tailcfg:

```go
// Source: headscale/hscontrol/types/node.go:668-705
func (node *Node) ApplyPeerChange(change *tailcfg.PeerChange) {
    ...
    if change.DERPRegion != 0 {
        if node.Hostinfo == nil {
            node.Hostinfo = &tailcfg.Hostinfo{
                NetInfo: &tailcfg.NetInfo{
                    PreferredDERP: change.DERPRegion,
                },
            }
        } else if node.Hostinfo.NetInfo == nil {
            node.Hostinfo.NetInfo = &tailcfg.NetInfo{
                PreferredDERP: change.DERPRegion,
            }
        } else {
            node.Hostinfo.NetInfo.PreferredDERP = change.DERPRegion
        }
    }
    ...
}
```

And then emits both `HomeDERP` and the legacy DERP string:

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

## External `derper` with Headscale

Headscale supports third-party `derper` instances by giving them the `/verify` endpoint and publishing a DERP map that points clients at those servers.

The integration test demonstrates this pattern:

```go
// Source: headscale/integration/derp_verify_endpoint_test.go:48-50
derper, err := scenario.CreateDERPServer("head",
    dsic.WithCACert(caHeadscale),
    dsic.WithVerifyClientURL(fmt.Sprintf("https://%s/verify", net.JoinHostPort(hostname, strconv.Itoa(headscalePort)))),
)
```

That is the cleanest way to understand Headscale's interoperability story: Headscale can be the control plane and verifier even when it is not the relay binary.

## Known Limitations

Headscale's own reference docs explicitly call out two important limitations:

```text
Source: headscale/docs/ref/derp.md:168-172
- The embedded DERP server can't be used for Tailscale's captive portal checks
  as it doesn't support the /generate_204 endpoint via HTTP on port tcp/80.
- There are no speed or throughput optimisations, the main purpose is to assist
  in node connectivity.
```

The first limitation is corroborated by the router wiring in `app.go`, which mounts `/derp`, `/probe`, `/latency-check`, and `/bootstrap-dns`, but not `/generate_204`.

## Practical Conclusions

1. Headscale's DERP implementation is mostly orchestration around Tailscale's runtime.
2. The embedded server is suitable for connectivity assistance, not for matching every operational feature of Tailscale's public DERP fleet.
3. Client verification is a first-class Headscale feature, both for embedded DERP and for third-party `derper`.
4. The control-plane map story is where Headscale adds the most value.
