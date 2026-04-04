package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/batching"
	"tailscale.com/net/stun"
)

const (
	defaultDiscoveryInterval       = 2 * time.Second
	defaultEndpointRefreshInterval = 15 * time.Second
	defaultDirectStaleTimeout      = 30 * time.Second
	maxDirectPayloadSize           = 64 << 10
	directReadBatchSize            = 64
)

var (
	discoProbePayload = []byte("derpcat-probe")
	discoAckPayload   = []byte("derpcat-ack")
)

func (m *Manager) discoveryLoop(ctx context.Context) {
	m.requestDiscovery(ctx, false)
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

	if m.cfg.Portmap != nil && m.cfg.Portmap.Refresh(m.now()) {
		forceCandidateRefresh = true
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

	if batchConn := m.directBatchConn(); batchConn != nil {
		m.directBatchReadLoop(ctx, batchConn)
		return
	}
	m.directPacketReadLoop(ctx)
}

func (m *Manager) directBatchConn() DirectBatchConn {
	if m.cfg.DirectBatchConn != nil {
		return m.cfg.DirectBatchConn
	}
	batchConn, _ := m.cfg.DirectConn.(DirectBatchConn)
	return batchConn
}

func (m *Manager) directPacketReadLoop(ctx context.Context) {
	bufLen := maxDirectPayloadSize
	if len(discoProbePayload)+1 > bufLen {
		bufLen = len(discoProbePayload) + 1
	}
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
		m.handleDirectPacket(addr, buf[:n])
	}
}

func (m *Manager) directBatchReadLoop(ctx context.Context, batchConn DirectBatchConn) {
	msgs := make([]ipv6.Message, directReadBatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, maxDirectPayloadSize)}
		if controlSize := batching.MinControlMessageSize(); controlSize > 0 {
			msgs[i].OOB = make([]byte, controlSize)
		}
	}

	for {
		if err := batchConn.SetReadDeadline(m.now().Add(m.discoveryInterval())); err != nil {
			return
		}
		n, err := batchConn.ReadBatch(msgs, 0)
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
		for i := 0; i < n; i++ {
			if msgs[i].N == 0 {
				continue
			}
			m.handleDirectPacket(msgs[i].Addr, msgs[i].Buffers[0][:msgs[i].N])
		}
	}
}

func (m *Manager) handleDirectPacket(addr net.Addr, payload []byte) {
	if stun.Is(payload) {
		m.handleSTUNPacket(addr, payload)
		return
	}
	if len(payload) == len(discoProbePayload) && bytes.Equal(payload, discoProbePayload) {
		_, _ = m.cfg.DirectConn.WriteTo(discoAckPayload, addr)
		return
	}
	if len(payload) == len(discoAckPayload) && bytes.Equal(payload, discoAckPayload) {
		m.tryPromoteDirect(m.now(), addr)
		return
	}
	if !m.shouldAcceptDirectPayload(addr) {
		m.directRecvRejects.Add(1)
		return
	}
	m.NoteDirectActivity(addr)
	m.enqueuePeerDatagram(m.remotePeerAddr(), payload)
}

func (m *Manager) HandleDirectPacket(conn net.PacketConn, addr net.Addr, payload []byte) bool {
	if addr == nil {
		return false
	}
	if stun.Is(payload) {
		m.handleSTUNPacket(addr, payload)
		return true
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

func (m *Manager) handleSTUNPacket(addr net.Addr, payload []byte) {
	if m.cfg.HandleSTUNPacket == nil || addr == nil {
		return
	}
	m.cfg.HandleSTUNPacket(append([]byte(nil), payload...), cloneAddr(addr))
}

func (m *Manager) shouldAcceptDirectPayload(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.current != PathDirect {
		return true
	}
	if m.state.current == PathDirect && sameAddr(addr, m.state.endpoints[m.state.bestEndpoint]) {
		return true
	}
	return m.state.hasCandidate(addr)
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
