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
	ticker := time.NewTicker(m.discoveryInterval())
	defer ticker.Stop()

	for {
		m.discoveryTick(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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
		_, _ = m.cfg.DirectConn.WriteTo(discoProbePayload, target)
	}
}

func (m *Manager) directReadLoop(ctx context.Context) {
	if m.cfg.DirectConn == nil {
		return
	}

	buf := make([]byte, len(discoAckPayload))
	for {
		if err := m.cfg.DirectConn.SetReadDeadline(time.Now().Add(m.discoveryInterval())); err != nil {
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
		if !bytes.Equal(buf[:n], discoAckPayload) {
			continue
		}
		m.noteValidatedDirect(m.now(), addr)
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
