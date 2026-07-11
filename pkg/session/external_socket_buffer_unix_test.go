//go:build darwin || linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"net"
	"testing"
)

func TestTuneExternalPacketConnReportsKernelBuffers(t *testing.T) {
	t.Parallel()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	stats := tuneExternalPacketConn(conn)
	wantRead, wantWrite, err := readExternalPacketConnSocketBuffers(conn)
	if err != nil {
		t.Fatal(err)
	}
	if stats.InspectError != nil ||
		stats.ReadBytes != wantRead ||
		stats.WriteBytes != wantWrite ||
		stats.ReadBytes <= 0 ||
		stats.WriteBytes <= 0 {
		t.Fatalf("stats = %#v, want read=%d write=%d", stats, wantRead, wantWrite)
	}
}
