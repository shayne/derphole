// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestExternalV2BulkPacketProbeSelectsNinetyPercentOfHighestCleanTrain(t *testing.T) {
	result, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{
		{RateMbps: 128, Sent: 560, Received: 560},
		{RateMbps: 512, Sent: 2241, Received: 2200},
		{RateMbps: 1000, Sent: 4377, Received: 4230},
		{RateMbps: 1600, Sent: 7003, Received: 6400, Pressure: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedMbps != 900 {
		t.Fatalf("selected = %d, want 900", result.SelectedMbps)
	}
}

func TestExternalV2BulkPacketProbeUsesIntermediateTwoGigabitTrain(t *testing.T) {
	result, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{
		{RateMbps: 1600, Sent: 7003, Received: 7003},
		{RateMbps: 2000, Sent: 8753, Received: 8700},
		{RateMbps: 2200, Sent: 9628, Received: 9500},
		{RateMbps: 2400, Sent: 10504, Received: 8500},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SelectedMbps != 1980 {
		t.Fatalf("selected = %d, want 1980", result.SelectedMbps)
	}
}

func TestExternalV2BulkPacketProbeRejectsWithoutCleanTrain(t *testing.T) {
	_, err := selectExternalV2BulkPacketProbe([]externalV2BulkPacketProbeTrainResult{{RateMbps: 128, Sent: 560, Received: 400}})
	if !errors.Is(err, errExternalV2BulkPacketProbeRejected) {
		t.Fatalf("error = %v, want probe rejection", err)
	}
}

func TestExternalV2BulkPacketProbeTrainsAreBounded(t *testing.T) {
	for _, rateMbps := range externalV2BulkPacketProbeRatesMbps {
		packets := externalV2BulkPacketProbeDatagramCount(rateMbps)
		wireBytes := int64(packets) * int64(externalV2BulkPacketIPv4WireBytes(externalV2BulkPacketMaxSize))
		if packets == 0 || wireBytes > externalV2BulkPacketProbeMaxBytes {
			t.Fatalf("rate %d packets=%d wire_bytes=%d exceeds cap", rateMbps, packets, wireBytes)
		}
		atRate := time.Duration(wireBytes * 8 * int64(time.Second) / int64(rateMbps*1_000_000))
		if atRate > externalV2BulkPacketProbeDuration+time.Millisecond {
			t.Fatalf("rate %d train duration = %s, want <= %s", rateMbps, atRate, externalV2BulkPacketProbeDuration)
		}
	}
}

func TestExternalV2BulkPacketProbeAcknowledgementIsAuthenticated(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	prefix := encodeExternalV2BulkPacketProbePrefix(externalV2BulkPacketProbePrefix{
		Train: 2, Sequence: 499, Expected: 500, RateMbps: 1000,
	})
	packet, err := sealExternalV2BulkPacket(auth.control, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketProbeAck, runID: 99, index: 7, total: 500,
	}, prefix[:])
	if err != nil {
		t.Fatal(err)
	}
	packet[len(packet)-1] ^= 0xff
	if _, _, ok := openExternalV2BulkPacket(auth.control, packet); ok {
		t.Fatal("forged probe acknowledgement authenticated")
	}
}

func TestExternalV2BulkPacketGroupedProbeUsesAuthenticatedBlockTag(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	prefix := externalV2BulkPacketProbePrefix{
		Train: 2, Sequence: 499, Expected: externalV2BulkPacketProbeDatagramCount(1000), RateMbps: 1000,
	}
	packet, err := encodeExternalV2BulkPacketTaggedProbeData(auth, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketProbeTaggedData, runID: 99, index: 7, total: 500,
	}, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != externalV2BulkPacketMaxSize {
		t.Fatalf("tagged probe bytes = %d, want %d", len(packet), externalV2BulkPacketMaxSize)
	}
	event, ok := decodeExternalV2BulkPacketProbeEvent(auth, 500, externalV2BulkPacketBatchMessage{Buffers: [][]byte{packet}, N: len(packet)})
	if !ok || event.header.kind != externalV2BulkPacketProbeTaggedData || event.prefix != prefix {
		t.Fatalf("tagged probe decode = %#v ok=%t, want prefix %#v", event, ok, prefix)
	}
	for _, offset := range []int{externalV2BulkPacketHeaderSize, externalV2BulkPacketHeaderSize + externalV2BulkPacketProbeTagSize} {
		forged := append([]byte(nil), packet...)
		forged[offset] ^= 0xff
		if _, ok := decodeExternalV2BulkPacketProbeEvent(auth, 500, externalV2BulkPacketBatchMessage{Buffers: [][]byte{forged}, N: len(forged)}); ok {
			t.Fatalf("forged tagged probe at byte %d authenticated", offset)
		}
	}
}

func TestExternalV2BulkPacketProbeRepeatedEndFramesUseDistinctNonces(t *testing.T) {
	auth, err := externalV2BulkPacketAuthForToken(testExternalV2BulkPacketToken(), key.NewNode().Public(), key.NewNode().Public())
	if err != nil {
		t.Fatal(err)
	}
	prefix := encodeExternalV2BulkPacketProbePrefix(externalV2BulkPacketProbePrefix{Train: 1, Expected: 10, RateMbps: 128})
	first, err := sealExternalV2BulkPacket(auth.control, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketProbeEnd, runID: 77, index: 100, total: 10,
	}, prefix[:])
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealExternalV2BulkPacket(auth.control, externalV2BulkPacketHeader{
		kind: externalV2BulkPacketProbeEnd, runID: 77, index: 101, total: 10,
	}, prefix[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("repeated probe end frames reused a nonce")
	}
}
