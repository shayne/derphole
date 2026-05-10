// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	probeTransportLegacy             = "legacy"
	probeTransportBatched            = "batched"
	probeIdealBatchSize              = 128
	probePacedBatchTarget            = 2 * time.Millisecond
	probeLargeChunkPacedBatchTarget  = 8 * time.Millisecond
	probeLargeChunkPacedBatchBytes   = 32 << 10
	probeLargeChunkPacedBatchMinMbps = 225
)

type TransportCaps struct {
	Kind             string `json:"kind"`
	RequestedKind    string `json:"requested_kind,omitempty"`
	BatchSize        int    `json:"batch_size,omitempty"`
	RequestedSockBuf int    `json:"requested_sock_buf,omitempty"`
	ReadBufferBytes  int    `json:"read_buffer_bytes,omitempty"`
	WriteBufferBytes int    `json:"write_buffer_bytes,omitempty"`
	TXOffload        bool   `json:"tx_offload,omitempty"`
	RXOffload        bool   `json:"rx_offload,omitempty"`
	RXQOverflow      bool   `json:"rxq_overflow,omitempty"`
	Connected        bool   `json:"connected,omitempty"`
}

func (c TransportCaps) Summary() string {
	if c.Kind == "" {
		return "none"
	}
	return fmt.Sprintf(
		"%s(req=%s batch=%d read_buf=%d write_buf=%d tx_offload=%t rx_offload=%t rxq_overflow=%t connected=%t)",
		c.Kind,
		c.RequestedKind,
		c.BatchSize,
		c.ReadBufferBytes,
		c.WriteBufferBytes,
		c.TXOffload,
		c.RXOffload,
		c.RXQOverflow,
		c.Connected,
	)
}

type batchReadBuffer struct {
	Bytes []byte
	N     int
	Addr  net.Addr
}

type packetBatcher interface {
	Capabilities() TransportCaps
	MaxBatch() int
	WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error)
	ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error)
}

func normalizeTransport(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", probeTransportLegacy:
		return probeTransportLegacy, nil
	case probeTransportBatched:
		return probeTransportBatched, nil
	default:
		return "", fmt.Errorf("unsupported transport %q", raw)
	}
}

func NormalizeTransportForCLI(raw string) (string, error) {
	return normalizeTransport(raw)
}

func PreviewTransportCaps(conn net.PacketConn, requested string) TransportCaps {
	return newPacketBatcher(conn, requested).Capabilities()
}

func newLegacyBatcher(conn net.PacketConn) packetBatcher {
	return newLegacyBatcherRequested(conn, probeTransportLegacy)
}

func newLegacyBatcherRequested(conn net.PacketConn, requested string) packetBatcher {
	requested, err := normalizeTransport(requested)
	if err != nil {
		requested = probeTransportLegacy
	}
	return &legacyBatcher{
		conn: conn,
		caps: tuneSocketCaps(conn, TransportCaps{
			Kind:          probeTransportLegacy,
			RequestedKind: requested,
		}),
	}
}

func newPacketBatcher(conn net.PacketConn, requested string) packetBatcher {
	requested, err := normalizeTransport(requested)
	if err != nil {
		requested = probeTransportLegacy
	}
	if requested == probeTransportBatched {
		if batcher := newPlatformBatcher(conn, requested); batcher != nil {
			return batcher
		}
	}
	return newLegacyBatcherRequested(conn, requested)
}

type legacyBatcher struct {
	conn       net.PacketConn
	caps       TransportCaps
	deadlineMu sync.Mutex
	readBy     time.Time
	writeBy    time.Time
}

func (b *legacyBatcher) Capabilities() TransportCaps { return b.caps }
func (b *legacyBatcher) MaxBatch() int               { return 1 }

func (b *legacyBatcher) WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil {
		return 0, errors.New("nil packet conn")
	}
	if err := b.setWriteDeadline(ctx); err != nil {
		return 0, err
	}

	if n, ok, err := b.writeUDPBatch(peer, packets); ok {
		return n, err
	}
	return writePacketBatch(b.conn, peer, packets)
}

func (b *legacyBatcher) writeUDPBatch(peer net.Addr, packets [][]byte) (int, bool, error) {
	udpConn, ok := b.conn.(*net.UDPConn)
	if !ok {
		return 0, false, nil
	}
	udpPeer, ok := peer.(*net.UDPAddr)
	if !ok {
		return 0, false, nil
	}
	addrPort := udpPeer.AddrPort()
	for i, packet := range packets {
		if _, err := udpConn.WriteToUDPAddrPort(packet, addrPort); err != nil {
			return i, true, err
		}
	}
	return len(packets), true, nil
}

func writePacketBatch(conn net.PacketConn, peer net.Addr, packets [][]byte) (int, error) {
	for i, packet := range packets {
		if _, err := conn.WriteTo(packet, peer); err != nil {
			return i, err
		}
	}
	return len(packets), nil
}

func (b *legacyBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil {
		return 0, errors.New("nil packet conn")
	}
	if err := b.setReadDeadline(ctx, timeout); err != nil {
		return 0, err
	}

	if udpConn, ok := b.conn.(*net.UDPConn); ok {
		n, addr, err := udpConn.ReadFromUDPAddrPort(bufs[0].Bytes)
		if err != nil {
			b.invalidateReadDeadline()
			return 0, err
		}
		bufs[0].N = n
		bufs[0].Addr = net.UDPAddrFromAddrPort(addr)
		for i := 1; i < len(bufs); i++ {
			bufs[i].N = 0
			bufs[i].Addr = nil
		}
		return 1, nil
	}

	n, addr, err := b.conn.ReadFrom(bufs[0].Bytes)
	if err != nil {
		b.invalidateReadDeadline()
		return 0, err
	}
	bufs[0].N = n
	bufs[0].Addr = cloneAddr(addr)
	for i := 1; i < len(bufs); i++ {
		bufs[i].N = 0
		bufs[i].Addr = nil
	}
	return 1, nil
}

func (b *legacyBatcher) setReadDeadline(ctx context.Context, timeout time.Duration) error {
	deadline, err := batchReadDeadline(ctx, timeout)
	if err != nil {
		return err
	}
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	if !cachedDeadlineNeedsRefresh(time.Now(), b.readBy, deadline, timeout) {
		return nil
	}
	if err := b.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	b.readBy = deadline
	return nil
}

func (b *legacyBatcher) invalidateReadDeadline() {
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	b.readBy = time.Time{}
}

func (b *legacyBatcher) setWriteDeadline(ctx context.Context) error {
	deadline, err := batchWriteDeadline(ctx)
	if err != nil {
		return err
	}
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	if !cachedDeadlineNeedsRefresh(time.Now(), b.writeBy, deadline, time.Second) {
		return nil
	}
	if err := b.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	b.writeBy = deadline
	return nil
}

type connectedUDPBatcher struct {
	conn       *net.UDPConn
	peer       net.Addr
	caps       TransportCaps
	deadlineMu sync.Mutex
	readBy     time.Time
	writeBy    time.Time
}

func newConnectedUDPBatcher(conn net.PacketConn, peer net.Addr, requested string) (packetBatcher, bool) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok || udpConn == nil || peer == nil {
		return nil, false
	}
	udpPeer, ok := peer.(*net.UDPAddr)
	if !ok || udpPeer == nil {
		return nil, false
	}
	if err := platformConnectUDP(udpConn, udpPeer); err != nil {
		probeTracef("connected udp disabled local=%s peer=%s err=%v", udpConn.LocalAddr(), udpPeer, err)
		return nil, false
	}
	probeTracef("connected udp enabled local=%s peer=%s", udpConn.LocalAddr(), udpPeer)
	requested, err := normalizeTransport(requested)
	if err != nil {
		requested = probeTransportLegacy
	}
	return &connectedUDPBatcher{
		conn: udpConn,
		peer: cloneAddr(udpPeer),
		caps: tuneSocketCaps(udpConn, TransportCaps{
			Kind:          probeTransportLegacy,
			RequestedKind: requested,
			Connected:     true,
		}),
	}, true
}

func (b *connectedUDPBatcher) Capabilities() TransportCaps { return b.caps }
func (b *connectedUDPBatcher) MaxBatch() int               { return 1 }

func (b *connectedUDPBatcher) WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil {
		return 0, errors.New("nil packet conn")
	}
	if err := b.setWriteDeadline(ctx); err != nil {
		return 0, err
	}

	for i, packet := range packets {
		if _, err := b.conn.Write(packet); err != nil {
			return i, err
		}
	}
	return len(packets), nil
}

func (b *connectedUDPBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil {
		return 0, errors.New("nil packet conn")
	}
	if err := b.setReadDeadline(ctx, timeout); err != nil {
		return 0, err
	}

	n, err := b.conn.Read(bufs[0].Bytes)
	if err != nil {
		b.invalidateReadDeadline()
		return 0, err
	}
	bufs[0].N = n
	bufs[0].Addr = b.peer
	for i := 1; i < len(bufs); i++ {
		bufs[i].N = 0
		bufs[i].Addr = nil
	}
	return 1, nil
}

func (b *connectedUDPBatcher) setReadDeadline(ctx context.Context, timeout time.Duration) error {
	deadline, err := batchReadDeadline(ctx, timeout)
	if err != nil {
		return err
	}
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	if !cachedDeadlineNeedsRefresh(time.Now(), b.readBy, deadline, timeout) {
		return nil
	}
	if err := b.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	b.readBy = deadline
	return nil
}

func (b *connectedUDPBatcher) invalidateReadDeadline() {
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	b.readBy = time.Time{}
}

func (b *connectedUDPBatcher) setWriteDeadline(ctx context.Context) error {
	deadline, err := batchWriteDeadline(ctx)
	if err != nil {
		return err
	}
	b.deadlineMu.Lock()
	defer b.deadlineMu.Unlock()
	if !cachedDeadlineNeedsRefresh(time.Now(), b.writeBy, deadline, time.Second) {
		return nil
	}
	if err := b.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	b.writeBy = deadline
	return nil
}

func readBatchWith(b packetBatcher, ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if b == nil {
		return 0, errors.New("nil batcher")
	}
	return b.ReadBatch(ctx, timeout, bufs)
}

func tuneSocketCaps(conn net.PacketConn, caps TransportCaps) TransportCaps {
	caps.RequestedSockBuf = defaultSocketBuffer
	if conn == nil {
		return caps
	}
	platformSetSocketBuffers(conn, &caps, defaultSocketBuffer)
	caps.ReadBufferBytes = socketBufferSize(conn, syscall.SO_RCVBUF)
	caps.WriteBufferBytes = socketBufferSize(conn, syscall.SO_SNDBUF)
	return caps
}

func setSocketPacing(conn net.PacketConn, rateMbps int) bool {
	rateBytesPerSecond := socketPacingRateBytesPerSecond(rateMbps)
	if rateBytesPerSecond == 0 {
		return false
	}
	return platformSetSocketPacing(conn, rateBytesPerSecond)
}

func socketPacingRateBytesPerSecond(rateMbps int) uint64 {
	if rateMbps <= 0 {
		return 0
	}
	return uint64(rateMbps) * 1000 * 1000 / 8
}

func pacedBatchLimit(maxBatch int, chunkSize int, rateMbps int) int {
	if maxBatch <= 1 || chunkSize <= 0 || rateMbps <= 0 {
		return maxBatch
	}
	target := probePacedBatchTarget
	if chunkSize >= probeLargeChunkPacedBatchBytes && rateMbps >= probeLargeChunkPacedBatchMinMbps {
		target = probeLargeChunkPacedBatchTarget
	}
	bytesPerTarget := int((float64(rateMbps*1000*1000) / 8.0) * target.Seconds())
	limit := bytesPerTarget / chunkSize
	if limit < 1 {
		return 1
	}
	if limit > maxBatch {
		return maxBatch
	}
	return limit
}

func socketBufferSize(conn net.PacketConn, opt int) int {
	if conn == nil {
		return 0
	}
	syscaller, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0
	}
	rawConn, err := syscaller.SyscallConn()
	if err != nil {
		return 0
	}
	size := 0
	_ = rawConn.Control(func(fd uintptr) {
		size, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
	})
	return size
}

func batchReadDeadline(ctx context.Context, timeout time.Duration) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	deadline := time.Time{}
	if timeout <= 0 {
		deadline = time.Now()
	} else if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if deadline.IsZero() || ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	return deadline, nil
}

func cachedDeadlineNeedsRefresh(now, current, desired time.Time, refreshWindow time.Duration) bool {
	if desired.IsZero() {
		return !current.IsZero()
	}
	if current.IsZero() || desired.Before(current) {
		return true
	}
	if refreshWindow <= 0 {
		return true
	}
	return !current.After(now.Add(refreshWindow / 2))
}

func batchWriteDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		return deadline, nil
	}
	return time.Time{}, nil
}
