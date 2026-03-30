package transport

import (
	"context"
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
	m.noteRelayOnly(m.now())
	return nil
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
			return
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
		return nil
	case ControlCallMeMaybe:
		return m.sendCandidateUpdate(ctx)
	default:
		return nil
	}
}

func (m *Manager) sendCallMeMaybe(ctx context.Context) error {
	if m.cfg.SendControl == nil {
		return nil
	}
	return m.cfg.SendControl(ctx, ControlMessage{Type: ControlCallMeMaybe})
}

func (m *Manager) sendCandidateUpdate(ctx context.Context) error {
	if m.cfg.SendControl == nil {
		return nil
	}

	var candidates []string
	if m.cfg.CandidateSource != nil {
		candidates = stringifyCandidates(m.cfg.CandidateSource(ctx))
	}
	m.noteEndpointRefresh(m.now())
	return m.cfg.SendControl(ctx, ControlMessage{
		Type:       ControlCandidates,
		Candidates: candidates,
	})
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
