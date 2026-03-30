package transport

import (
	"context"
	"net"
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type ManagerConfig struct {
	RelayConn               net.PacketConn
	DirectConn              net.PacketConn
	CandidateSource         func(context.Context) []net.Addr
	SendControl             func(context.Context, ControlMessage) error
	ReceiveControl          func(context.Context) (ControlMessage, error)
	Clock                   Clock
	DiscoveryInterval       time.Duration
	EndpointRefreshInterval time.Duration
	DirectStaleTimeout      time.Duration
}

type Manager struct {
	mu      sync.Mutex
	cfg     ManagerConfig
	state   pathState
	started bool
}

func NewManager(cfg ManagerConfig) *Manager {
	cfg = normalizeConfig(cfg)
	return &Manager{
		cfg:   cfg,
		state: newPathState(cfg.Clock.Now(), cfg.RelayConn != nil, cfg.DirectConn != nil),
	}
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}

	m.started = true
	m.mu.Unlock()

	go m.discoveryLoop(ctx)
	go m.receiveControlLoop(ctx)
	go m.directReadLoop(ctx)
	return nil
}

func (m *Manager) PathState() Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.path()
}

func (m *Manager) now() time.Time {
	return m.cfg.Clock.Now()
}

func (m *Manager) noteValidatedDirect(now time.Time, addr net.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.noteDirect(now, addr)
}

func (m *Manager) noteRelayOnly(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.noteRelay(now)
}

func (m *Manager) noteEndpointRefresh(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.noteEndpointRefresh(now)
}

func (m *Manager) snapshotDiscoveryPlan() discoveryPlan {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.discoveryPlan(now, m.endpointRefreshInterval(), m.directStaleTimeout())
}

func (m *Manager) discoveryInterval() time.Duration {
	if m.cfg.DiscoveryInterval > 0 {
		return m.cfg.DiscoveryInterval
	}
	return defaultDiscoveryInterval
}

func (m *Manager) endpointRefreshInterval() time.Duration {
	if m.cfg.EndpointRefreshInterval > 0 {
		return m.cfg.EndpointRefreshInterval
	}
	return defaultEndpointRefreshInterval
}

func (m *Manager) directStaleTimeout() time.Duration {
	if m.cfg.DirectStaleTimeout > 0 {
		return m.cfg.DirectStaleTimeout
	}
	return defaultDirectStaleTimeout
}

func normalizeConfig(cfg ManagerConfig) ManagerConfig {
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	return cfg
}
