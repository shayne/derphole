package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

const (
	probeTransportLegacy  = "legacy"
	probeTransportBatched = "batched"
	probeIdealBatchSize   = 128
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
}

func (c TransportCaps) Summary() string {
	if c.Kind == "" {
		return "none"
	}
	return fmt.Sprintf(
		"%s(req=%s batch=%d read_buf=%d write_buf=%d tx_offload=%t rx_offload=%t rxq_overflow=%t)",
		c.Kind,
		c.RequestedKind,
		c.BatchSize,
		c.ReadBufferBytes,
		c.WriteBufferBytes,
		c.TXOffload,
		c.RXOffload,
		c.RXQOverflow,
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
	conn net.PacketConn
	caps TransportCaps
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
	deadline, err := batchWriteDeadline(ctx)
	if err != nil {
		return 0, err
	}
	if err := b.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer b.conn.SetWriteDeadline(time.Time{})

	for i, packet := range packets {
		if _, err := b.conn.WriteTo(packet, peer); err != nil {
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
	deadline, err := batchReadDeadline(ctx, timeout)
	if err != nil {
		return 0, err
	}
	if err := b.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	defer b.conn.SetReadDeadline(time.Time{})

	n, addr, err := b.conn.ReadFrom(bufs[0].Bytes)
	if err != nil {
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
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if deadline.IsZero() || ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	return deadline, nil
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
