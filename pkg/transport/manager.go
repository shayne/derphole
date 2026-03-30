package transport

import (
	"context"
	"net"
	"sync"
)

type ManagerConfig struct {
	RelayConn  net.PacketConn
	DirectConn net.PacketConn
}

type Manager struct {
	mu      sync.Mutex
	cfg     ManagerConfig
	state   pathState
	started bool
}

func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		cfg:   cfg,
		state: newPathState(cfg.RelayConn != nil, cfg.DirectConn != nil),
	}
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	m.started = true
	m.state.activateConfiguredDirect()
	return nil
}

func (m *Manager) PathState() Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.path()
}
