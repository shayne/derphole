// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/shayne/derphole/pkg/candidate"
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

const maxControlCandidates = candidate.MaxCount
const maxControlCandidateLength = candidate.MaxLength

func (m *Manager) MarkDirectBroken() error {
	m.noteRelayOnly(m.now())
	return nil
}

func (m *Manager) SeedRemoteCandidates(ctx context.Context, candidates []net.Addr) {
	if len(candidates) == 0 {
		return
	}
	m.applyRemoteCandidates(m.now(), candidates)
	m.requestDiscovery(ctx, false)
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
		candidates := parseCandidateAddrs(msg.Candidates)
		if len(msg.Candidates) > 0 && len(candidates) == 0 {
			return nil
		}
		m.applyRemoteCandidates(m.now(), candidates)
		m.requestDiscovery(ctx, false)
		return nil
	case ControlCallMeMaybe:
		m.requestDiscovery(ctx, true)
		return nil
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
	return nil
}

func (m *Manager) applyRemoteCandidates(now time.Time, candidates []net.Addr) {
	m.mu.Lock()
	if m.state.noteCandidates(now, candidates) {
		m.signalStateChangeLocked()
	}
	m.mu.Unlock()
}

func parseCandidateAddrs(raw []string) []net.Addr {
	return candidate.ParsePeerAddrs(raw)
}

func stringifyCandidates(addrs []net.Addr) []string {
	return candidate.StringifyLocalAddrs(addrs)
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
