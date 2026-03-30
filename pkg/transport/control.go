package transport

import (
	"context"
	"net"
)

func (m *Manager) WaitForUpgrade(ctx context.Context) error {
	if m.PathState() == PathDirect {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.upgradeCh:
		return nil
	}
}

func (m *Manager) MarkDirectBroken() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.markDirectBroken("direct transport marked broken")
	return nil
}

func (m *Manager) ObserveInboundUDPNoise(_ net.Addr, _ []byte) error {
	return nil
}
