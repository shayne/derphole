// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netstack

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestCloseUnblocksWriteNotify(t *testing.T) {
	tun := &netTun{
		ep:             channel.New(16, 1500, ""),
		incomingPacket: make(chan *buffer.View),
		closeCh:        make(chan struct{}),
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{0x45, 0x00, 0x00, 0x14}),
	})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if n, tcpErr := tun.ep.WritePackets(pkts); tcpErr != nil || n != 1 {
		t.Fatalf("WritePackets() = (%d, %v), want (1, nil)", n, tcpErr)
	}

	writeDone := make(chan struct{})
	go func() {
		tun.WriteNotify()
		close(writeDone)
	}()

	select {
	case <-writeDone:
		t.Fatal("WriteNotify() returned before Close()")
	case <-time.After(20 * time.Millisecond):
	}

	closeDone := make(chan struct{})
	go func() {
		_ = tun.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked while WriteNotify() was waiting on incomingPacket")
	}

	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteNotify() remained blocked after Close()")
	}
}
