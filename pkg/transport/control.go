package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type ControlType string

const (
	ControlCandidates  ControlType = "candidates"
	ControlCallMeMaybe ControlType = "call-me-maybe"
)

type ControlMessage struct {
	Type       ControlType `json:"type"`
	Candidates []string    `json:"candidates,omitempty"`
}

func (m *Manager) MarkDirectBroken() error {
	return m.withDiscoveryLock(func() error {
		m.noteRelayOnly(m.now())
		return nil
	})
}

func (m *Manager) receiveControlLoop(ctx context.Context) {
	if m.cfg.ReceiveControl == nil {
		return
	}

	for {
		msg, err := m.cfg.ReceiveControl(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isTerminalControlReadError(err) {
				return
			}
			if !m.waitForNextControlRead(ctx) {
				return
			}
			continue
		}
		if err := m.handleControl(ctx, msg); err != nil && ctx.Err() != nil {
			return
		}
	}
}

func (m *Manager) handleControl(ctx context.Context, msg ControlMessage) error {
	switch msg.Type {
	case ControlCandidates:
		m.applyRemoteCandidates(m.now(), parseCandidateAddrs(msg.Candidates))
		m.discoveryTick(ctx)
		return nil
	case ControlCallMeMaybe:
		return m.withDiscoveryLock(func() error {
			return m.sendCandidateUpdate(ctx)
		})
	default:
		return nil
	}
}

func (m *Manager) sendCallMeMaybe(ctx context.Context) error {
	if m.cfg.SendControl == nil {
		return nil
	}
	if err := m.cfg.SendControl(ctx, ControlMessage{Type: ControlCallMeMaybe}); err != nil {
		return err
	}
	m.noteCallMeMaybeSuccess(m.now())
	return nil
}

func (m *Manager) sendCandidateUpdate(ctx context.Context) error {
	if m.cfg.SendControl == nil {
		return nil
	}

	var candidates []string
	if m.cfg.CandidateSource != nil {
		candidates = stringifyCandidates(m.cfg.CandidateSource(ctx))
	}
	if err := m.cfg.SendControl(ctx, ControlMessage{
		Type:       ControlCandidates,
		Candidates: candidates,
	}); err != nil {
		return err
	}
	m.noteEndpointRefresh(m.now())
	return nil
}

func (m *Manager) applyRemoteCandidates(now time.Time, candidates []net.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.noteCandidates(now, candidates)
}

func parseCandidateAddrs(raw []string) []net.Addr {
	addrs := make([]net.Addr, 0, len(raw))
	for _, candidate := range raw {
		if candidate == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", candidate)
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

func stringifyCandidates(addrs []net.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		out = append(out, addr.String())
	}
	return out
}

func (m *Manager) waitForNextControlRead(ctx context.Context) bool {
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

func isTerminalControlReadError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
