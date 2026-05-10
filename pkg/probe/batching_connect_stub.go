// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !darwin

package probe

import (
	"errors"
	"net"
)

func platformConnectUDP(conn *net.UDPConn, peer *net.UDPAddr) error {
	return errors.New("connected udp unsupported on this platform")
}
