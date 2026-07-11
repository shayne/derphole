//go:build !darwin && !linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
	"net"
)

func readExternalPacketConnSocketBuffers(net.PacketConn) (int, int, error) {
	return 0, 0, errors.New("UDP socket-buffer inspection is unsupported")
}
