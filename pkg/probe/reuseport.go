// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
