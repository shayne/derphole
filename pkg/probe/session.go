package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"
)

const (
	defaultChunkSize     = 1200
	defaultRetryInterval = 20 * time.Millisecond
	doneSendAttempts     = 5
)

type SendConfig struct {
	Raw        bool
	ChunkSize  int
	WindowSize int
}

type ReceiveConfig struct {
	Raw bool
}

type TransferStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsAcked  int64
	StartedAt     time.Time
	CompletedAt   time.Time
}

func Send(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
	if conn == nil {
		return TransferStats{}, errors.New("nil packet conn")
	}
	if src == nil {
		return TransferStats{}, errors.New("nil source reader")
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}

	peer, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return TransferStats{}, err
	}

	stats := TransferStats{StartedAt: time.Now()}
	buf := make([]byte, cfg.ChunkSize)
	var seq uint64
	var offset uint64

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			packet, err := MarshalPacket(Packet{
				Version: ProtocolVersion,
				Type:    PacketTypeData,
				Seq:     seq,
				Offset:  offset,
				Payload: payload,
			}, nil)
			if err != nil {
				return TransferStats{}, err
			}
			if err := sendUntilAck(ctx, conn, peer, packet, seq+1, &stats); err != nil {
				return TransferStats{}, err
			}
			stats.BytesSent += int64(n)
			seq++
			offset += uint64(n)
		}

		if errors.Is(readErr, io.EOF) {
			donePacket, err := MarshalPacket(Packet{
				Version: ProtocolVersion,
				Type:    PacketTypeDone,
				Seq:     seq,
				Offset:  offset,
			}, nil)
			if err != nil {
				return TransferStats{}, err
			}
			for range doneSendAttempts {
				if err := writePacket(ctx, conn, peer, donePacket, &stats); err != nil {
					return TransferStats{}, err
				}
			}
			stats.CompletedAt = time.Now()
			return stats, nil
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func Receive(ctx context.Context, conn net.PacketConn, remoteAddr string, cfg ReceiveConfig) ([]byte, error) {
	if conn == nil {
		return nil, errors.New("nil packet conn")
	}

	peer, err := resolveRemoteAddr(remoteAddr)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	buf := make([]byte, 64<<10)
	var expectedSeq uint64

	for {
		if err := setReadDeadline(ctx, conn, defaultRetryInterval); err != nil {
			return nil, err
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if isNetTimeout(err) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil, err
			}
			continue
		}
		if peer != nil && addr.String() != peer.String() {
			continue
		}

		packet, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			return nil, err
		}

		switch packet.Type {
		case PacketTypeData:
			if packet.Seq == expectedSeq {
				if _, err := out.Write(packet.Payload); err != nil {
					return nil, err
				}
				expectedSeq++
			}
			if err := sendAck(ctx, conn, addr, expectedSeq); err != nil {
				return nil, err
			}
		case PacketTypeDone:
			if packet.Seq == expectedSeq {
				if err := sendAck(ctx, conn, addr, expectedSeq+1); err != nil {
					return nil, err
				}
				return out.Bytes(), nil
			}
			if err := sendAck(ctx, conn, addr, expectedSeq); err != nil {
				return nil, err
			}
		}
	}
}

func sendUntilAck(ctx context.Context, conn net.PacketConn, peer net.Addr, packet []byte, wantAck uint64, stats *TransferStats) error {
	buf := make([]byte, 64<<10)
	for {
		if err := writePacket(ctx, conn, peer, packet, stats); err != nil {
			return err
		}

		for {
			if err := setReadDeadline(ctx, conn, defaultRetryInterval); err != nil {
				return err
			}
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if isNetTimeout(err) {
					break
				}
				return err
			}
			if peer != nil && addr.String() != peer.String() {
				continue
			}

			packet, err := UnmarshalPacket(buf[:n], nil)
			if err != nil {
				return err
			}
			if packet.Type != PacketTypeAck {
				continue
			}
			if packet.AckFloor >= wantAck {
				stats.PacketsAcked++
				return nil
			}
		}
	}
}

func sendAck(ctx context.Context, conn net.PacketConn, peer net.Addr, ackFloor uint64) error {
	packet, err := MarshalPacket(Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeAck,
		AckFloor: ackFloor,
	}, nil)
	if err != nil {
		return err
	}
	_, err = writeWithContext(ctx, conn, peer, packet)
	return err
}

func writePacket(ctx context.Context, conn net.PacketConn, peer net.Addr, packet []byte, stats *TransferStats) error {
	_, err := writeWithContext(ctx, conn, peer, packet)
	if err != nil {
		return err
	}
	stats.PacketsSent++
	return nil
}

func writeWithContext(ctx context.Context, conn net.PacketConn, peer net.Addr, packet []byte) (int, error) {
	deadline, err := writeDeadline(ctx)
	if err != nil {
		return 0, err
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return conn.WriteTo(packet, peer)
}

func resolveRemoteAddr(remoteAddr string) (net.Addr, error) {
	if remoteAddr == "" {
		return nil, nil
	}
	return net.ResolveUDPAddr("udp", remoteAddr)
}

func setReadDeadline(ctx context.Context, conn net.PacketConn, fallback time.Duration) error {
	deadline := time.Now().Add(fallback)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetReadDeadline(deadline)
}

func writeDeadline(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		return deadline, nil
	}
	return time.Now().Add(defaultRetryInterval), nil
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
