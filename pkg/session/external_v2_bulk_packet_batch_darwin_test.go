// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package session

import (
	"context"
	"fmt"
	"net"
	"testing"
)

func TestExternalV2BulkPacketDarwinReceiveBatchUsesRecvmsgX(t *testing.T) {
	receiverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	senderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderConn.Close()

	const packetCount = 32
	for index := range packetCount {
		payload := []byte(fmt.Sprintf("packet-%02d", index))
		if _, err := senderConn.WriteTo(payload, receiverConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}

	messages := make([]externalV2BulkPacketBatchMessage, externalV2BulkPacketMaxBatch)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, externalV2BulkPacketMaxSize)}
	}
	receiver := newExternalV2BulkPacketBatchConn(receiverConn)
	count, err := receiver.ReadBatch(context.Background(), messages)
	if err != nil {
		t.Fatal(err)
	}
	if count <= 1 {
		t.Fatalf("recvmsg_x batch count = %d, want more than one queued datagram", count)
	}
	stats := receiver.Stats()
	if stats.Backend != "darwin-recvmsg-x" || stats.ReceiveCalls != 1 || stats.ReceiveDatagrams != uint64(count) || stats.MaxReceiveBatch != uint32(count) {
		t.Fatalf("receive stats = %+v", stats)
	}
}
