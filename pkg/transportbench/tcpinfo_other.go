// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package transportbench

import "net"

type tcpInfoSnapshot struct {
	retransmits  uint64
	cwndSegments uint32
}

func tcpInfoForConn(net.Conn) (tcpInfoSnapshot, bool) {
	return tcpInfoSnapshot{}, false
}
