package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"
)

const (
	defaultDiscoveryInterval       = 2 * time.Second
	defaultEndpointRefreshInterval = 15 * time.Second
	defaultDirectStaleTimeout      = 30 * time.Second
)

var (
	discoProbePayload = []byte("derpcat-probe")
	discoAckPayload   = []byte("derpcat-ack")
)

func (m *Manager) discoveryLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.cfg.Clock.After(m.discoveryInterval()):
		}

		m.discoveryTick(ctx)
	}
}

func (m *Manager) discoveryTick(ctx context.Context) {
	_ = m.withDiscoveryLock(func() error {
		if ctx.Err() != nil {
			return nil
		}

		plan := m.snapshotDiscoveryPlan()
		if !plan.shouldAttempt {
			return nil
		}

		if plan.needRefresh {
			_ = m.sendCandidateUpdate(ctx)
		}
		if plan.sendCallMe {
			_ = m.sendCallMeMaybe(ctx)
		}
		if m.cfg.DirectConn == nil {
			return nil
		}

		for _, target := range plan.probeTargets {
			if target == nil {
				continue
			}
			if _, err := m.cfg.DirectConn.WriteTo(discoProbePayload, target); err == nil {
				m.noteProbeSent(m.now(), target)
			}
		}
		return nil
	})
}

func (m *Manager) directReadLoop(ctx context.Context) {
	if m.cfg.DirectConn == nil {
		return
	}

	bufLen := len(discoProbePayload) + 1
	if len(discoAckPayload)+1 > bufLen {
		bufLen = len(discoAckPayload) + 1
	}
	buf := make([]byte, bufLen)
	for {
		if err := m.cfg.DirectConn.SetReadDeadline(m.now().Add(m.discoveryInterval())); err != nil {
			return
		}
		n, addr, err := m.cfg.DirectConn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || isTerminalReadError(err) {
				return
			}
			if isTimeout(err) {
				continue
			}
			if !m.waitForNextDirectRead(ctx) {
				return
			}
			continue
		}
		if n == len(discoProbePayload) && bytes.Equal(buf[:n], discoProbePayload) {
			_, _ = m.cfg.DirectConn.WriteTo(discoAckPayload, addr)
			continue
		}
		if n != len(discoAckPayload) || !bytes.Equal(buf[:n], discoAckPayload) {
			continue
		}
		m.tryPromoteDirect(m.now(), addr)
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isTerminalReadError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func (m *Manager) waitForNextDirectRead(ctx context.Context) bool {
	backoff := m.discoveryInterval() / 4
	if backoff <= 0 {
		backoff = 50 * time.Millisecond
	}
	if backoff > 250*time.Millisecond {
		backoff = 250 * time.Millisecond
	}

	select {
	case <-ctx.Done():
		return false
	case <-m.cfg.Clock.After(backoff):
		return true
	}
}
