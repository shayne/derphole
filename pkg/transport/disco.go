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

		m.requestDiscovery(ctx, false)
	}
}

func (m *Manager) requestDiscovery(ctx context.Context, forceCandidateRefresh bool) {
	m.discoveryMu.Lock()
	if forceCandidateRefresh {
		m.forceCandidateRefresh = true
	}
	if m.discoveryRun {
		m.discoveryPending = true
		m.discoveryMu.Unlock()
		return
	}
	forceCandidateRefresh = m.forceCandidateRefresh
	m.forceCandidateRefresh = false
	m.discoveryRun = true
	m.discoveryPending = false
	m.discoveryMu.Unlock()

	go m.discoveryWorker(ctx, forceCandidateRefresh)
}

func (m *Manager) discoveryWorker(ctx context.Context, forceCandidateRefresh bool) {
	for {
		m.discoveryTick(ctx, forceCandidateRefresh)

		m.discoveryMu.Lock()
		if ctx.Err() != nil {
			m.discoveryRun = false
			m.discoveryPending = false
			m.forceCandidateRefresh = false
			m.discoveryMu.Unlock()
			return
		}
		if !m.discoveryPending {
			m.discoveryRun = false
			m.discoveryMu.Unlock()
			return
		}
		forceCandidateRefresh = m.forceCandidateRefresh
		m.forceCandidateRefresh = false
		m.discoveryPending = false
		m.discoveryMu.Unlock()
	}
}

func (m *Manager) discoveryTick(ctx context.Context, forceCandidateRefresh bool) {
	if ctx.Err() != nil {
		return
	}

	plan := m.snapshotDiscoveryPlan()
	if !plan.shouldAttempt && !forceCandidateRefresh {
		return
	}

	if forceCandidateRefresh || plan.needRefresh {
		if err := m.sendCandidateUpdate(ctx); err == nil {
			m.noteEndpointRefreshIfCurrent(plan.generation, m.now())
		}
	}
	if plan.sendCallMe {
		if err := m.sendCallMeMaybe(ctx); err == nil {
			m.noteCallMeMaybeIfCurrent(plan.generation, m.now())
		}
	}
	if m.cfg.DirectConn == nil {
		return
	}

	for _, target := range plan.probeTargets {
		if target == nil {
			continue
		}
		if _, err := m.cfg.DirectConn.WriteTo(discoProbePayload, target); err == nil {
			m.noteProbeSentIfCurrent(plan.generation, m.now(), target)
		}
	}
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

func (m *Manager) HandleDirectPacket(conn net.PacketConn, addr net.Addr, payload []byte) bool {
	if addr == nil {
		return false
	}
	if len(payload) == len(discoProbePayload) && bytes.Equal(payload, discoProbePayload) {
		if conn != nil {
			_, _ = conn.WriteTo(discoAckPayload, addr)
		}
		return true
	}
	if len(payload) == len(discoAckPayload) && bytes.Equal(payload, discoAckPayload) {
		m.tryPromoteDirect(m.now(), addr)
		return true
	}
	return false
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
