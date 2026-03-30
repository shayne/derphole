package transport

import (
	"bytes"
	"context"
	"errors"
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
	if ctx.Err() != nil {
		return
	}

	plan := m.snapshotDiscoveryPlan()
	if !plan.shouldAttempt {
		return
	}

	if plan.needRefresh {
		_ = m.sendCandidateUpdate(ctx)
	}
	if plan.sendCallMe {
		_ = m.sendCallMeMaybe(ctx)
	}
	if m.cfg.DirectConn == nil {
		return
	}

	for _, target := range plan.probeTargets {
		if target == nil {
			continue
		}
		if _, err := m.cfg.DirectConn.WriteTo(discoProbePayload, target); err == nil {
			m.noteProbeSent(m.now(), target)
		}
	}
}

func (m *Manager) directReadLoop(ctx context.Context) {
	if m.cfg.DirectConn == nil {
		return
	}

	bufLen := len(discoProbePayload)
	if len(discoAckPayload) > bufLen {
		bufLen = len(discoAckPayload)
	}
	buf := make([]byte, bufLen)
	for {
		if err := m.cfg.DirectConn.SetReadDeadline(m.now().Add(m.discoveryInterval())); err != nil {
			return
		}
		n, addr, err := m.cfg.DirectConn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if isTimeout(err) {
				continue
			}
			continue
		}
		if bytes.Equal(buf[:n], discoProbePayload) {
			_, _ = m.cfg.DirectConn.WriteTo(discoAckPayload, addr)
			continue
		}
		if !bytes.Equal(buf[:n], discoAckPayload) {
			continue
		}
		m.tryPromoteDirect(m.now(), addr)
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
