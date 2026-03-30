package transport

import (
	"context"
	"net"
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
	AfterFunc(time.Duration, func()) Timer
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (realClock) AfterFunc(d time.Duration, fn func()) Timer {
	return time.AfterFunc(d, fn)
}

type Timer interface {
	Stop() bool
}

type ManagerConfig struct {
	RelayConn               net.PacketConn
	DirectConn              net.PacketConn
	DisableDirectReads      bool
	CandidateSource         func(context.Context) []net.Addr
	SendControl             func(context.Context, ControlMessage) error
	ReceiveControl          func(context.Context) (ControlMessage, error)
	Clock                   Clock
	DiscoveryInterval       time.Duration
	EndpointRefreshInterval time.Duration
	DirectStaleTimeout      time.Duration
}

type Manager struct {
	mu                    sync.Mutex
	discoveryMu           sync.Mutex
	cfg                   ManagerConfig
	state                 pathState
	stateNotify           chan struct{}
	discoveryGen          uint64
	discoveryRun          bool
	discoveryPending      bool
	forceCandidateRefresh bool
	started               bool
}

type Update struct {
	Path Path
}

func NewManager(cfg ManagerConfig) *Manager {
	cfg = normalizeConfig(cfg)
	return &Manager{
		cfg:         cfg,
		state:       newPathState(cfg.Clock.Now(), cfg.RelayConn != nil, cfg.DirectConn != nil),
		stateNotify: make(chan struct{}),
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
	if !m.cfg.DisableDirectReads {
		go m.directReadLoop(ctx)
	}
	return nil
}

func (m *Manager) PathState() Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.path()
}

func (m *Manager) DirectPath() (string, bool) {
	now := m.now()
	m.mu.Lock()
	if m.state.current == PathDirect && m.state.directIsStale(now, m.directStaleTimeout()) {
		m.discoveryGen++
		if m.state.noteRelay(now) {
			m.signalStateChangeLocked()
		}
	}
	endpoint, active := m.state.directPath()
	m.mu.Unlock()
	return endpoint, active
}

func (m *Manager) now() time.Time {
	return m.cfg.Clock.Now()
}

func (m *Manager) noteRelayOnly(now time.Time) {
	m.mu.Lock()
	m.discoveryGen++
	if m.state.noteRelay(now) {
		m.signalStateChangeLocked()
	}
	m.mu.Unlock()
}

func (m *Manager) NoteDirectActivity(addr net.Addr) {
	if addr == nil {
		return
	}
	m.mu.Lock()
	m.state.noteDirectActivity(m.now(), addr)
	m.mu.Unlock()
}

func (m *Manager) snapshotDiscoveryPlan() discoveryPlan {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	plan := m.state.discoveryPlan(now, m.endpointRefreshInterval(), m.directStaleTimeout())
	plan.generation = m.discoveryGen
	return plan
}

func (m *Manager) tryPromoteDirect(now time.Time, addr net.Addr) bool {
	m.mu.Lock()
	if !m.state.consumeProbe(addr, m.discoveryInterval(), now) {
		m.mu.Unlock()
		return false
	}
	if !m.state.noteDirect(now, addr) {
		m.mu.Unlock()
		return false
	}
	m.signalStateChangeLocked()
	m.mu.Unlock()
	return true
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

func (m *Manager) noteEndpointRefreshIfCurrent(generation uint64, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.discoveryGen != generation {
		return
	}
	m.state.noteRefreshSuccess(now)
}

func (m *Manager) noteCallMeMaybeIfCurrent(generation uint64, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.discoveryGen != generation {
		return
	}
	m.state.noteCallMeMaybeSuccess(now)
}

func (m *Manager) noteProbeSentIfCurrent(generation uint64, now time.Time, addr net.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.discoveryGen != generation {
		return
	}
	m.state.noteProbeSent(now, addr)
}

func (m *Manager) stateChanged() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stateNotify
}

func (m *Manager) snapshotUpdate() (Path, <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.path(), m.stateNotify
}

func (m *Manager) Updates(ctx context.Context) <-chan Update {
	updates := make(chan Update, 1)
	go func() {
		defer close(updates)

		last := PathUnknown
		for {
			path, notify := m.snapshotUpdate()
			if path != last {
				select {
				case updates <- Update{Path: path}:
					last = path
				case <-ctx.Done():
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-notify:
			}
		}
	}()
	return updates
}

func (m *Manager) signalStateChangeLocked() {
	close(m.stateNotify)
	m.stateNotify = make(chan struct{})
}

func normalizeConfig(cfg ManagerConfig) ManagerConfig {
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	return cfg
}
