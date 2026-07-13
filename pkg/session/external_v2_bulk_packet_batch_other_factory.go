// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !darwin

package session

import "net"

func newExternalV2BulkPacketBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	return newExternalV2BulkPacketPortableBatchConn(conn)
}
