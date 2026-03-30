package transport

import (
	"context"
	"net"
	"sync"
)

type ManagerConfig struct {
	RelayConn  net.PacketConn
	DirectConn net.PacketConn
	NoiseConn  net.PacketConn
}

type Manager struct {
	mu        sync.Mutex
	cfg       ManagerConfig
	state     pathState
	upgradeCh chan struct{}
	startOnce sync.Once
}

func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		cfg:       cfg,
		state:     newPathState(cfg.RelayConn != nil, cfg.DirectConn != nil),
		upgradeCh: make(chan struct{}),
	}
}

func (m *Manager) Start(ctx context.Context) error {
	m.startOnce.Do(func() {
		if m.cfg.DirectConn == nil {
			return
		}

		go func() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			m.promoteDirect()
		}()
	})

	return nil
}

func (m *Manager) PathState() Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.path()
}

func (m *Manager) promoteDirect() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.markDirectReady() {
		return
	}
	close(m.upgradeCh)
}
