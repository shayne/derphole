package traversal

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	probePayload = "derpcat-probe"
	ackPayload   = "derpcat-ack"
	probeWindow  = 100 * time.Millisecond
)

type Result struct {
	Direct bool
}

func ProbeDirect(ctx context.Context, a net.PacketConn, bAddr string, b net.PacketConn, aAddr string) (Result, error) {
	if a == nil {
		return Result{}, errors.New("nil local packet conn")
	}

	_ = aAddr

	peerAddr, err := net.ResolveUDPAddr("udp", bAddr)
	if err != nil {
		return Result{}, err
	}

	if b != nil {
		go respondToProbe(ctx, b)
	}

	if _, err := a.WriteTo([]byte(probePayload), peerAddr); err != nil {
		return Result{}, err
	}

	if err := a.SetReadDeadline(probeDeadline(ctx)); err != nil {
		return Result{}, err
	}

	buf := make([]byte, len(ackPayload))
	n, _, err := a.ReadFrom(buf)
	if err != nil {
		if isTimeout(err) || ctx.Err() != nil {
			return Result{Direct: false}, nil
		}
		return Result{}, err
	}
	if string(buf[:n]) != ackPayload {
		return Result{Direct: false}, nil
	}
	return Result{Direct: true}, nil
}

func respondToProbe(ctx context.Context, conn net.PacketConn) {
	if conn == nil {
		return
	}
	_ = conn.SetReadDeadline(probeDeadline(ctx))

	buf := make([]byte, len(probePayload))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return
	}
	if string(buf[:n]) != probePayload {
		return
	}
	_, _ = conn.WriteTo([]byte(ackPayload), addr)
}

func probeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(probeWindow)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
