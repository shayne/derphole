package probe

import (
	"context"
	"net"
)

func ListenPacketReusePort(ctx context.Context, network, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	lc.Control = reusePortControl
	return lc.ListenPacket(ctx, network, address)
}
