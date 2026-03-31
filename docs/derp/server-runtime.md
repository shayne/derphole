# DERP Server Runtime

## Overview

The reference server implementation is in `tailscale/derp/derpserver/derpserver.go`. The server owns:

- admission and handshake,
- client registration keyed by node public key,
- duplicate-connection handling,
- local packet delivery,
- intra-region forwarding,
- presence tracking for watchers,
- output queueing and keepalive behavior,
- metrics and drop accounting.

The server is intentionally stateful and connection-oriented.

## Core Server State

The main `Server` structure makes the responsibilities visible:

```go
// Source: tailscale/derp/derpserver/derpserver.go:125-209
type Server struct {
    WriteTimeout time.Duration
    privateKey key.NodePrivate
    publicKey key.NodePublic
    meshKey key.DERPMesh
    verifyClientsLocalTailscaled bool
    verifyClientsURL string
    verifyClientsURLFailOpen bool
    netConns map[derp.Conn]chan struct{}
    clients map[key.NodePublic]*clientSet
    watchers set.Set[*sclient]
    clientsMesh map[key.NodePublic]PacketForwarder
    peerGoneWatchers map[key.NodePublic]set.HandleSet[func(key.NodePublic)]
    keyOfAddr map[netip.AddrPort]key.NodePublic
    perClientSendQueueDepth int
    tcpWriteTimeout time.Duration
}
```

Important internal maps:

- `clients`: currently connected local clients by node key.
- `clientsMesh`: region-wide knowledge of where a key can be reached, including local and remote forwarders.
- `watchers`: privileged mesh/trusted clients subscribed to peer state changes.
- `peerGoneWatchers`: callbacks to tell prior senders when a peer disappears from the region entirely.

## Accept Path

Every accepted DERP transport goes through the same path:

```go
// Source: tailscale/derp/derpserver/derpserver.go:914-979
func (s *Server) accept(ctx context.Context, nc derp.Conn, brw *bufio.ReadWriter, remoteAddr string, connNum int64) error {
    ...
    if err := s.sendServerKey(bw); err != nil { ... }
    clientKey, clientInfo, err := s.recvClientKey(br)
    ...
    if err := s.verifyClient(ctx, clientKey, clientInfo, remoteIPPort.Addr()); err != nil { ... }
    ...
    c := &sclient{ ... }
    ...
    s.registerClient(c)
    defer s.unregisterClient(c)
    err = s.sendServerInfo(c.bw, clientKey)
    ...
    return c.run(ctx)
}
```

The sequencing matters:

1. Greet and identify the DERP server.
2. Receive the client identity and capability claims.
3. Verify the client if verification is enabled.
4. Instantiate the per-connection `sclient`.
5. Register it under its node public key.
6. Send `ServerInfo`.
7. Hand off to the main read loop.

## Client Verification

The server supports two verification mechanisms, plus a bypass for trusted mesh peers:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1377-1440
func (s *Server) verifyClient(ctx context.Context, clientKey key.NodePublic, info *derp.ClientInfo, clientIP netip.Addr) error {
    if s.isMeshPeer(info) {
        return nil
    }
    if s.verifyClientsLocalTailscaled {
        _, err := s.localClient.WhoIsNodeKey(ctx, clientKey)
        ...
    }
    if s.verifyClientsURL != "" {
        ...
        req, err := http.NewRequestWithContext(ctx, "POST", s.verifyClientsURL, bytes.NewReader(jreq))
        ...
        if !jres.Allow {
            return fmt.Errorf("admission controller: %v/%v not allowed", clientKey, clientIP)
        }
    }
    return nil
}
```

Modes:

- local `tailscaled` lookup (`WhoIsNodeKey`),
- external admission controller URL,
- optional fail-open when the admission controller is unreachable,
- unconditional allow for mesh peers with the right mesh key.

## Registration and Duplicate Handling

The server tracks connections by public key and explicitly handles duplicates:

```go
// Source: tailscale/derp/derpserver/derpserver.go:663-719
func (s *Server) registerClient(c *sclient) {
    ...
    cs, ok := s.clients[c.key]
    if !ok {
        cs = &clientSet{}
        s.clients[c.key] = cs
    }
    was := cs.activeClient.Load()
    if was != nil {
        was.isDup.Store(true)
        c.isDup.Store(true)
    }
    ...
    cs.activeClient.Store(c)
    if _, ok := s.clientsMesh[c.key]; !ok {
        s.clientsMesh[c.key] = nil
    }
    ...
    s.broadcastPeerStateChangeLocked(c.key, c.remoteIPPort, c.presentFlags(), true)
}
```

And unregistering reverses that state:

```go
// Source: tailscale/derp/derpserver/derpserver.go:738-811
func (s *Server) unregisterClient(c *sclient) {
    ...
    if dup == nil {
        ...
        delete(s.clients, c.key)
        if v, ok := s.clientsMesh[c.key]; ok && v == nil {
            delete(s.clientsMesh, c.key)
            s.notePeerGoneFromRegionLocked(c.key)
        }
        s.broadcastPeerStateChangeLocked(c.key, netip.AddrPort{}, 0, false)
    } else {
        ...
        set.activeClient.Store(set.pickActiveClient())
    }
    ...
}
```

Design intent:

- keep only one active connection per public key in the normal case,
- tolerate transient duplicates during reconnects,
- disable or de-preference conflicting active/active duplicates,
- notify watchers when presence changes.

## Main Read Loop

The per-client runtime is split into a reader (`run`) and a sender (`sendLoop`).

```go
// Source: tailscale/derp/derpserver/derpserver.go:988-1050
func (c *sclient) run(ctx context.Context) error {
    var grp errgroup.Group
    sendCtx, cancelSender := context.WithCancel(ctx)
    grp.Go(func() error { return c.sendLoop(sendCtx) })
    ...
    for {
        ft, fl, err := derp.ReadFrameHeader(c.br)
        ...
        switch ft {
        case derp.FrameNotePreferred:
            err = c.handleFrameNotePreferred(ft, fl)
        case derp.FrameSendPacket:
            err = c.handleFrameSendPacket(ft, fl)
        case derp.FrameForwardPacket:
            err = c.handleFrameForwardPacket(ft, fl)
        case derp.FrameWatchConns:
            err = c.handleFrameWatchConns(ft, fl)
        case derp.FrameClosePeer:
            err = c.handleFrameClosePeer(ft, fl)
        case derp.FramePing:
            err = c.handleFramePing(ft, fl)
        default:
            err = c.handleUnknownFrame(ft, fl)
        }
        if err != nil {
            return err
        }
    }
}
```

This split keeps the write side buffered and serialized while the read side can continue processing frames and state changes.

## Packet Routing

### Regular Client Send

A regular client sends `FrameSendPacket`, which becomes one of three outcomes:

1. direct local delivery,
2. forwarding to a mesh forwarder,
3. drop with a reason and optional `PeerGone`.

```go
// Source: tailscale/derp/derpserver/derpserver.go:1184-1235
func (c *sclient) handleFrameSendPacket(ft derp.FrameType, fl uint32) error {
    dstKey, contents, err := s.recvPacket(c.br, fl)
    ...
    if set, ok := s.clients[dstKey]; ok {
        dstLen = set.Len()
        dst = set.activeClient.Load()
    }
    if dst == nil && dstLen < 1 {
        fwd = s.clientsMesh[dstKey]
    }
    ...
    if dst == nil {
        if fwd != nil {
            err := fwd.ForwardPacket(c.key, dstKey, contents)
            ...
            return nil
        }
        ...
        return nil
    }
    return c.sendPkt(dst, p)
}
```

### Mesh Forwarded Send

A trusted mesh peer may forward on behalf of another source:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1140-1182
func (c *sclient) handleFrameForwardPacket(ft derp.FrameType, fl uint32) error {
    if !c.canMesh {
        return fmt.Errorf("insufficient permissions")
    }
    srcKey, dstKey, contents, err := s.recvForwardPacket(c.br, fl)
    ...
    if dst == nil {
        ...
        return nil
    }
    return c.sendPkt(dst, pkt{
        bs: contents,
        enqueuedAt: c.s.clock.Now(),
        src: srcKey,
    })
}
```

This is the core of intra-region mesh forwarding.

## Queueing and Drop Policy

Per-client queueing is intentionally bounded and freshness-biased:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1286-1325
func (c *sclient) sendPkt(dst *sclient, p pkt) error {
    sendQueue := dst.sendQueue
    if disco.LooksLikeDiscoWrapper(p.bs) {
        sendQueue = dst.discoSendQueue
    }
    for attempt := range 3 {
        ...
        select {
        case sendQueue <- p:
            return nil
        default:
        }
        select {
        case pkt := <-sendQueue:
            s.recordDrop(pkt.bs, c.key, dstKey, dropReasonQueueHead)
            ...
        default:
        }
    }
    s.recordDrop(p.bs, c.key, dstKey, dropReasonQueueTail)
    return nil
}
```

Key properties:

- regular and disco packets have separate queues,
- queue depth is bounded,
- the server tries to make room by dropping the oldest queued packet first,
- after several failed attempts, the new packet is tail-dropped.

This is a deliberate latency-over-throughput choice.

## Send Loop

The send loop batches non-blocking work, flushes, then blocks for the next event:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1789-1862
func (c *sclient) sendLoop(ctx context.Context) error {
    ...
    jitter := rand.N(5 * time.Second)
    keepAliveTick, keepAliveTickChannel := c.s.clock.NewTicker(derp.KeepAlive + jitter)
    ...
    select {
    case msg := <-c.peerGone:
        werr = c.sendPeerGone(msg.peer, msg.reason)
    case <-c.meshUpdate:
        werr = c.sendMeshUpdates()
    case msg := <-c.sendQueue:
        werr = c.sendPacket(msg.src, msg.bs)
    case msg := <-c.discoSendQueue:
        werr = c.sendPacket(msg.src, msg.bs)
    case msg := <-c.sendPongCh:
        werr = c.sendPong(msg)
    case <-keepAliveTickChannel:
        werr = c.sendKeepAlive()
    }
}
```

Consequences:

- keepalives are jittered,
- pongs, peer-gone, mesh updates, and packets share one serialized writer,
- flushes happen between bursts rather than after every single event,
- write deadlines are enforced per connection class.

## Keepalive, Ping, and Health

The server supports both old-style keepalives and newer ping/pong activity.

Ping handling:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1081-1105
func (c *sclient) handleFramePing(ft derp.FrameType, fl uint32) error {
    ...
    select {
    case c.sendPongCh <- [8]byte(m):
    default:
        // They're pinging too fast. Ignore.
    }
    return err
}
```

Keepalive write:

```go
// Source: tailscale/derp/derpserver/derpserver.go:1891-1895
func (c *sclient) sendKeepAlive() error {
    c.setWriteDeadline()
    return derp.WriteFrameHeader(c.bw.bw(), derp.FrameKeepAlive, 0)
}
```

## Watchers and Peer Presence

Trusted peers may subscribe to peer presence, receiving a flood of current clients and then incremental updates.

Watcher registration:

```go
// Source: tailscale/derp/derpserver/derpserver.go:880-911
func (s *Server) addWatcher(c *sclient) {
    ...
    for peer, clientSet := range s.clients {
        ac := clientSet.activeClient.Load()
        if ac == nil {
            continue
        }
        c.peerStateChange = append(c.peerStateChange, peerConnState{
            peer: peer,
            present: true,
            ipPort: ac.remoteIPPort,
            flags: ac.presentFlags(),
        })
    }
    s.watchers.Add(c)
    go c.requestMeshUpdate()
}
```

Broadcast on peer state change:

```go
// Source: tailscale/derp/derpserver/derpserver.go:721-735
func (s *Server) broadcastPeerStateChangeLocked(peer key.NodePublic, ipPort netip.AddrPort, flags derp.PeerPresentFlags, present bool) {
    for w := range s.watchers {
        w.peerStateChange = append(w.peerStateChange, peerConnState{
            peer: peer,
            present: present,
            ipPort: ipPort,
            flags: flags,
        })
        go w.requestMeshUpdate()
    }
}
```

This is the mechanism that makes regional meshes possible.

## Multi-Forwarder

If multiple forwarders exist for the same destination key, the server wraps them in a `multiForwarder` and picks a preferred one consistently:

```go
// Source: tailscale/derp/derpserver/derpserver.go:2057-2198
func (s *Server) AddPacketForwarder(dst key.NodePublic, fwd PacketForwarder)
func (s *Server) RemovePacketForwarder(dst key.NodePublic, fwd PacketForwarder)
type multiForwarder struct { ... }
```

This is a rare-state mechanism used when a peer is temporarily reachable through multiple meshed nodes in the same region.

## Meta Certificate and Fast Start

The server generates a self-signed "meta cert" that encodes its public key and protocol version, letting clients skip an RTT when TLS 1.3 preserves the extra cert in the encrypted certificate payload.

The full implementation is in:

- `tailscale/derp/derpserver/derpserver.go:597-660`
- `tailscale/derp/derphttp/derphttp_client.go:1165-1177`

Operationally, this is a pure optimization. DERP still functions without it.

## HTTP Handler Surface

The main handler exposes:

- `/derp`
- `/derp/probe`
- `/derp/latency-check`
- `/generate_204` via `derper`

```go
// Source: tailscale/derp/derpserver/handler.go:15-70
func Handler(s *Server) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ...
        switch r.URL.Path {
        case "/derp/probe", "/derp/latency-check":
            ProbeHandler(w, r)
            return
        }
        ...
        s.Accept(ctx, netConn, conn, netConn.RemoteAddr().String())
    })
}
```

## Server-Side Conclusions

1. DERP server behavior is connection-stateful, not stateless request routing.
2. Routing by node public key is central to every data path.
3. Region meshes are implemented by watcher subscriptions plus forwarding, not by a separate routing plane.
4. Queueing is deliberately shallow and biased toward freshness.
5. Admission control is pluggable and can be tied either to a local `tailscaled` or an external controller.
