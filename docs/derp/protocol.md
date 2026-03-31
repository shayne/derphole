# DERP Protocol

## Wire Model

DERP is a framed binary protocol carried over an upgraded TCP connection. In the common case it runs over TLS after an HTTP upgrade, but the upgraded stream is not HTTP anymore.

The frame header is fixed-width:

- 1 byte: frame type
- 4 bytes: big-endian payload length

```go
// Source: tailscale/derp/derp.go:51-54
type FrameType byte
```

```go
// Source: tailscale/derp/derp.go:248-255
// WriteFrameHeader writes a DERP frame header to bw: a one-byte frame
// type followed by a big-endian uint32 frame length.
func WriteFrameHeader(bw *bufio.Writer, t FrameType, frameLen uint32) error
```

## Handshake Sequence

The intended protocol flow is documented directly in the reference implementation:

```text
Source: tailscale/derp/derp.go:56-70
Protocol flow:

Login:
* client connects
* server sends frameServerKey
* client sends frameClientInfo
* server sends frameServerInfo

Steady state:
* server occasionally sends frameKeepAlive (or framePing)
* client responds to any framePing with a framePong
* client sends frameSendPacket
* server then sends frameRecvPacket to recipient
```

The concrete client-side handshake is:

1. Receive `FrameServerKey`.
2. Validate the DERP magic string.
3. Record the server public key.
4. Send `FrameClientInfo` containing:
   - client public key,
   - NaCl box nonce/ciphertext,
   - JSON-encoded `ClientInfo`.

```go
// Source: tailscale/derp/derp_client.go:126-140
func (c *Client) recvServerKey() error {
    var buf [40]byte
    t, flen, err := readFrame(c.br, 1<<10, buf[:])
    ...
    if flen < uint32(len(buf)) || t != FrameServerKey || string(buf[:len(Magic)]) != Magic {
        return errors.New("invalid server greeting")
    }
    c.serverKey = key.NodePublicFromRaw32(mem.B(buf[len(Magic):]))
    return nil
}
```

```go
// Source: tailscale/derp/derp_client.go:195-210
func (c *Client) sendClientKey() error {
    msg, err := json.Marshal(ClientInfo{
        Version:     ProtocolVersion,
        MeshKey:     c.meshKey,
        CanAckPings: c.canAckPings,
        IsProber:    c.isProber,
    })
    ...
    buf = c.publicKey.AppendTo(buf)
    buf = append(buf, msgbox...)
    return WriteFrame(c.bw, FrameClientInfo, buf)
}
```

On the server side, the flow is symmetrical:

```go
// Source: tailscale/derp/derpserver/derpserver.go:914-979
func (s *Server) accept(ctx context.Context, nc derp.Conn, brw *bufio.ReadWriter, remoteAddr string, connNum int64) error {
    ...
    if err := s.sendServerKey(bw); err != nil { ... }
    clientKey, clientInfo, err := s.recvClientKey(br)
    ...
    if err := s.verifyClient(ctx, clientKey, clientInfo, remoteIPPort.Addr()); err != nil { ... }
    ...
    s.registerClient(c)
    defer s.unregisterClient(c)
    err = s.sendServerInfo(c.bw, clientKey)
    ...
    return c.run(ctx)
}
```

## ClientInfo

`ClientInfo` advertises capabilities and trust level:

```go
// Source: tailscale/derp/derp_client.go:163-182
type ClientInfo struct {
    MeshKey key.DERPMesh `json:"meshKey,omitempty,omitzero"`
    Version int `json:"version,omitempty"`
    CanAckPings bool
    IsProber bool `json:",omitempty"`
}
```

Interpretation:

- `MeshKey` elevates the client into a trusted mesh/watcher role.
- `Version` identifies the protocol build.
- `CanAckPings` lets the server know pings can be answered.
- `IsProber` marks measurement clients and changes peer-present flags.

## Core Frame Types

The important frame types are declared centrally:

```go
// Source: tailscale/derp/derp.go:71-130
const (
    FrameServerKey     = FrameType(0x01)
    FrameClientInfo    = FrameType(0x02)
    FrameServerInfo    = FrameType(0x03)
    FrameSendPacket    = FrameType(0x04)
    FrameForwardPacket = FrameType(0x0a)
    FrameRecvPacket    = FrameType(0x05)
    FrameKeepAlive     = FrameType(0x06)
    FrameNotePreferred = FrameType(0x07)
    FramePeerGone      = FrameType(0x08)
    FramePeerPresent   = FrameType(0x09)
    FrameWatchConns    = FrameType(0x10)
    FrameClosePeer     = FrameType(0x11)
    FramePing          = FrameType(0x12)
    FramePong          = FrameType(0x13)
    FrameHealth        = FrameType(0x14)
    FrameRestarting    = FrameType(0x15)
)
```

### Data Frames

`FrameSendPacket`

- Sent by a regular client to deliver payload to a destination public key.
- Payload layout: destination public key + packet bytes.

`FrameForwardPacket`

- Sent only by privileged mesh peers.
- Payload layout: source public key + destination public key + packet bytes.

`FrameRecvPacket`

- Delivered by the server to the destination client.
- In protocol version 2, includes the source public key at the front.

### Presence and Mesh Frames

`FrameWatchConns`

- Privileged subscription request.
- Causes an initial peer flood plus ongoing `PeerPresent`/`PeerGone` updates.

`FramePeerPresent`

- Announces that a peer is currently connected in the region.
- Can include source IP:port and flags.

`FramePeerGone`

- Announces that a previously reachable peer is no longer available on the region path.

`FrameClosePeer`

- Privileged administrative request to close a peer's TCP connection.

### Connection Health Frames

`FrameKeepAlive`

- Unidirectional no-op to keep the connection open.

`FramePing` / `FramePong`

- Challenge/response health and RTT signaling.

`FrameHealth`

- Server-to-client health status such as duplicate-client problems.

`FrameRestarting`

- Server telling the client it is about to restart and how aggressively to reconnect.

## Message Parsing on the Client

The client receives server traffic through `Recv()` and maps each frame to a typed message:

```go
// Source: tailscale/derp/derp_client.go:535-645
switch t {
case FrameServerInfo:
    ...
case FrameKeepAlive:
    return KeepAliveMessage{}, nil
case FramePeerGone:
    ...
case FramePeerPresent:
    ...
case FrameRecvPacket:
    ...
case FramePing:
    ...
case FramePong:
    ...
case FrameHealth:
    return HealthMessage{Problem: string(b[:])}, nil
case FrameRestarting:
    ...
}
```

This is the protocol surface that `magicsock` and other consumers actually work with.

## Preferred-Node Signaling

Clients can tell the server whether a connection is currently their preferred/home DERP path:

```go
// Source: tailscale/derp/derp_client.go:306-330
func (c *Client) NotePreferred(preferred bool) (err error) {
    ...
    if err := WriteFrameHeader(c.bw, FrameNotePreferred, 1); err != nil {
        return err
    }
    var b byte = 0x00
    if preferred {
        b = 0x01
    }
    ...
}
```

This is mostly used by the server for stats and operator visibility, but it also surfaces "not ideal" vs preferred-home behavior in region meshes.

## Watchers and Privileged Actions

Watching connections and closing peers require `canMesh` privileges:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1070-1078
func (c *sclient) handleFrameWatchConns(ft derp.FrameType, fl uint32) error {
    if fl != 0 {
        return fmt.Errorf("handleFrameWatchConns wrong size")
    }
    if !c.canMesh {
        return fmt.Errorf("insufficient permissions")
    }
    c.s.addWatcher(c)
    return nil
}
```

```go
// Source: tailscale/derp/derpserver/derpserver.go:1108-1137
func (c *sclient) handleFrameClosePeer(ft derp.FrameType, fl uint32) error {
    if fl != derp.KeyLen { ... }
    if !c.canMesh {
        return fmt.Errorf("insufficient permissions")
    }
    ...
}
```

That separation is fundamental: regular clients relay only their own traffic; privileged clients help maintain the regional relay fabric.

## Transport Upgrade

The DERP transport usually begins as an HTTP request:

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:499-518
req, err := http.NewRequest("GET", c.urlString(node), nil)
...
req.Header.Set("Upgrade", "DERP")
req.Header.Set("Connection", "Upgrade")
if !idealNodeInRegion && reg != nil {
    req.Header.Set(derp.IdealNodeHeader, reg.Nodes[0].Name)
}
```

The server accepts either `Upgrade: derp` or `Upgrade: websocket`:

```go
// Source: tailscale/derp/derpserver/handler.go:30-39
up := strings.ToLower(r.Header.Get("Upgrade"))
if up != "websocket" && up != "derp" {
    http.Error(w, "DERP requires connection upgrade", http.StatusUpgradeRequired)
    return
}

fastStart := r.Header.Get(derp.FastStartHeader) == "1"
```

After hijacking the HTTP connection, the server either emits `101 Switching Protocols` or suppresses it in fast-start mode.

## Fast Start and Meta Certificates

The fast-start optimization exists to remove one round trip from connection setup:

- The server appends a special "meta cert" to the TLS certificate chain.
- The client extracts the DERP public key and protocol version from that cert.
- If successful, the client sends the HTTP request with `Derp-Fast-Start: 1`.
- The server hijacks without returning the HTTP response headers and DERP starts immediately.

Client side:

```go
// Source: tailscale/derp/derphttp/derphttp_client.go:518-527
if !serverPub.IsZero() && serverProtoVersion != 0 {
    req.Header.Set(derp.FastStartHeader, "1")
    if err := req.Write(brw); err != nil {
        return nil, 0, err
    }
}
```

Server side:

```go
// Source: tailscale/derp/derpserver/handler.go:54-63
if !fastStart {
    fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
        "Upgrade: DERP\r\n"+
        "Connection: Upgrade\r\n"+
        "Derp-Version: %v\r\n"+
        "Derp-Public-Key: %s\r\n\r\n",
        derp.ProtocolVersion,
        pubKey.UntypedHexString())
}
```

## Websocket Mode

Websocket transport exists mainly for environments where raw DERP-over-upgraded-HTTP is awkward or unavailable, such as browser-driven or network-constrained scenarios. Headscale also exposes websocket support explicitly using `coder/websocket`.

## Practical Protocol Constraints

- `MaxPacketSize` is 64 KiB.
- `KeepAlive` is 60 seconds minimum, with server-side jitter in practice.
- `ProtocolVersion` is currently 2.

```go
// Source: tailscale/derp/derp.go:25-49
const MaxPacketSize = 64 << 10
const KeepAlive = 60 * time.Second
const ProtocolVersion = 2
```

The next documents show how those protocol primitives are combined into control-plane and runtime behavior.
