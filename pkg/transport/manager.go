package transport

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv6"
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
	RelaySend               func(context.Context, []byte) error
	ReceiveRelay            func(context.Context) ([]byte, error)
	RelayAddr               net.Addr
	DirectConn              net.PacketConn
	DirectBatchConn         DirectBatchConn
	DisableDirectReads      bool
	HandleSTUNPacket        func([]byte, net.Addr)
	CandidateSource         func(context.Context) []net.Addr
	Portmap                 Portmap
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
	wg                    sync.WaitGroup
	directWG              sync.WaitGroup
	cfg                   ManagerConfig
	candidateSourceBase   func(context.Context) []net.Addr
	directCtx             context.Context
	directCancel          context.CancelFunc
	state                 pathState
	stateNotify           chan struct{}
	discoveryGen          uint64
	discoveryRun          bool
	discoveryPending      bool
	forceCandidateRefresh bool
	started               bool
	peerRecvCh            chan peerPacket
	peerRecvErrCh         chan error
	peerRecvDrops         atomic.Uint64
	peerRecvMaxDepth      atomic.Uint64
	directRecvRejects     atomic.Uint64
}

type Update struct {
	Path Path
}

type Portmap interface {
	Refresh(time.Time) bool
	SnapshotAddrs() []net.Addr
}

type DirectBatchConn interface {
	ReadBatch([]ipv6.Message, int) (int, error)
	SetReadDeadline(time.Time) error
}

func NewManager(cfg ManagerConfig) *Manager {
	cfg = normalizeConfig(cfg)
	hasRelay := cfg.RelayConn != nil || cfg.RelaySend != nil || cfg.ReceiveRelay != nil || cfg.RelayAddr != nil
	m := &Manager{
		cfg:                 cfg,
		candidateSourceBase: cfg.CandidateSource,
		state:               newPathState(cfg.Clock.Now(), hasRelay, cfg.DirectConn != nil),
		stateNotify:         make(chan struct{}),
		peerRecvCh:          make(chan peerPacket, 256),
		peerRecvErrCh:       make(chan error, 1),
	}
	m.cfg.CandidateSource = m.candidateSource
	return m
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
	if m.cfg.DirectConn != nil || m.candidateSourceBase != nil || m.cfg.Portmap != nil {
		m.directCtx, m.directCancel = context.WithCancel(ctx)
	} else {
		m.directCtx = ctx
	}
	directCtx := m.directCtx
	m.mu.Unlock()

	m.wg.Add(1)
	m.directWG.Add(1)
	go func() {
		defer m.directWG.Done()
		defer m.wg.Done()
		m.discoveryLoop(directCtx)
	}()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.receiveControlLoop(ctx)
	}()
	if m.cfg.ReceiveRelay != nil {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.relayReadLoop(ctx)
		}()
	}
	if !m.cfg.DisableDirectReads {
		m.wg.Add(1)
		m.directWG.Add(1)
		go func() {
			defer m.directWG.Done()
			defer m.wg.Done()
			m.directReadLoop(directCtx)
		}()
	}
	return nil
}

func (m *Manager) Wait() {
	m.wakeDirectReads()
	m.wg.Wait()
}

func (m *Manager) StopDirect() {
	m.noteRelayOnly(m.now())
	m.mu.Lock()
	directCancel := m.directCancel
	m.mu.Unlock()
	if directCancel != nil {
		directCancel()
	}
	m.wakeDirectReads()
	m.directWG.Wait()
}

func (m *Manager) wakeDirectReads() {
	if batchConn := m.directBatchConn(); batchConn != nil {
		_ = batchConn.SetReadDeadline(m.now())
	} else if m.cfg.DirectConn != nil {
		_ = m.cfg.DirectConn.SetReadDeadline(m.now())
	}
}

func (m *Manager) PathState() Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.path()
}

func (m *Manager) DirectPath() (string, bool) {
	now := m.now()
	m.mu.Lock()
	demoted := m.demoteStaleDirectLocked(now)
	endpoint, active := m.state.directPath()
	m.mu.Unlock()
	if demoted {
		m.requestDiscovery(context.Background(), true)
	}
	return endpoint, active
}

func (m *Manager) DirectAddr() (net.Addr, bool) {
	now := m.now()
	m.mu.Lock()
	demoted := m.demoteStaleDirectLocked(now)
	endpoint, active := m.state.directPath()
	addr := m.state.endpoints[endpoint]
	m.mu.Unlock()
	if demoted {
		m.requestDiscovery(context.Background(), true)
	}
	return addr, active && addr != nil
}

func (m *Manager) demoteStaleDirectLocked(now time.Time) bool {
	if m.state.current != PathDirect || !m.state.directIsStale(now, m.directStaleTimeout()) {
		return false
	}
	m.discoveryGen++
	if m.state.noteRelay(now) {
		m.signalStateChangeLocked()
	}
	return true
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

func (m *Manager) DroppedPeerDatagrams() uint64 {
	return m.peerRecvDrops.Load()
}

func (m *Manager) MaxPeerRecvQueueDepth() int {
	return int(m.peerRecvMaxDepth.Load())
}

func (m *Manager) RejectedDirectDatagrams() uint64 {
	return m.directRecvRejects.Load()
}

func (m *Manager) notePeerRecvDepth(depth int) {
	for {
		prev := m.peerRecvMaxDepth.Load()
		if uint64(depth) <= prev {
			return
		}
		if m.peerRecvMaxDepth.CompareAndSwap(prev, uint64(depth)) {
			return
		}
	}
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

func (m *Manager) candidateSource(ctx context.Context) []net.Addr {
	out := make([]net.Addr, 0)
	seen := make(map[string]struct{})

	appendAddrs := func(addrs []net.Addr) {
		for _, addr := range addrs {
			if addr == nil {
				continue
			}
			key := addr.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, addr)
		}
	}

	if m.candidateSourceBase != nil {
		appendAddrs(m.candidateSourceBase(ctx))
	}
	if m.cfg.Portmap != nil {
		appendAddrs(m.cfg.Portmap.SnapshotAddrs())
	}
	return out
}

func (m *Manager) directContext(fallback context.Context) context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.directCtx != nil {
		return m.directCtx
	}
	return fallback
}
