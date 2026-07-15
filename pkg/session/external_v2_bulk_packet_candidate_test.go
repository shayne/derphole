// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "testing"

func TestExternalV2BulkPacketCandidateConfig(t *testing.T) {
	tests := []struct {
		value string
		want  externalV2BulkPacketCandidateConfig
	}{
		{value: "", want: externalV2BulkPacketCandidateConfig{ID: "baseline-gso3"}},
		{value: "baseline-gso3", want: externalV2BulkPacketCandidateConfig{ID: "baseline-gso3"}},
		{value: "coalesced-gso3", want: externalV2BulkPacketCandidateConfig{ID: "coalesced-gso3", CoalescedReads: true, GSOSegments: 3}},
		{value: "connected-gso3", want: externalV2BulkPacketCandidateConfig{ID: "connected-gso3", NativeConnectedSend: true, GSOSegments: 3}},
		{value: "combined-gso1", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso1", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 1}},
		{value: "combined-gso2", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso2", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 2}},
		{value: "combined-gso3", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso3", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 3}},
		{value: "combined-gso4", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso4", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 4}},
		{value: "combined-gso6", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso6", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 6}},
		{value: "combined-gso8", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso8", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 8}},
		{value: "combined-gso12", want: externalV2BulkPacketCandidateConfig{ID: "combined-gso12", CoalescedReads: true, NativeConnectedSend: true, GSOSegments: 12}},
		{value: "quic-control", want: externalV2BulkPacketCandidateConfig{ID: "quic-control", ForceQUICControl: true}},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := externalV2BulkPacketCandidateConfigFor(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("candidate config = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestExternalV2BulkPacketCandidateRejectsUnknownLinkerValue(t *testing.T) {
	for _, value := range []string{"gso3", "combined-gso5", "combined-gso0", "COMBINED-GSO3", " combined-gso3"} {
		t.Run(value, func(t *testing.T) {
			if _, err := externalV2BulkPacketCandidateConfigFor(value); err == nil {
				t.Fatalf("candidate %q was accepted", value)
			}
		})
	}
}

func TestExternalV2BulkPacketCandidateEmptyUsesSourceControlledDefault(t *testing.T) {
	t.Setenv("DERPHOLE_BULK_PACKET_CANDIDATE", "quic-control")
	t.Setenv("DERPHOLE_GSO_SEGMENTS", "12")
	got, err := externalV2BulkPacketCandidateConfigFor("")
	if err != nil {
		t.Fatal(err)
	}
	want := externalV2BulkPacketCandidateConfig{ID: "baseline-gso3"}
	if got != want {
		t.Fatalf("empty candidate with environment overrides = %+v, want %+v", got, want)
	}
}

func TestExternalV2BulkPacketCandidateQUICControlKeepsBulkUnselected(t *testing.T) {
	previous := externalV2BulkPacketBenchmarkCandidate
	externalV2BulkPacketBenchmarkCandidate = "quic-control"
	t.Cleanup(func() { externalV2BulkPacketBenchmarkCandidate = previous })

	if got := externalV2SelectOptimizedFileTransferMode(externalV2TransferModeBlocks, externalV2DirectTCPMinFileSize, true, true); got != externalV2TransferModeBlocks {
		t.Fatalf("QUIC control selected transfer mode %q, want %q", got, externalV2TransferModeBlocks)
	}

	claim := externalV2Claim{
		TransferMode:            externalV2TransferModeBlocks,
		BlockSize:               externalV2DirectTCPMinFileSize,
		BlockChunkSize:          externalV2DefaultBlockChunkSize,
		BlockPacketCapable:      true,
		BlockPacketBatchCapable: true,
	}
	policy := externalV2AcceptedBlockTransferPolicy(claim, true, true, []string{"203.0.113.10:8123"})
	if policy.Mode != externalV2TransferModeBulkPackets {
		t.Fatalf("preselection policy = %q, want bulk before QUIC control", policy.Mode)
	}
	if got := externalV2SelectOptimizedFileTransferMode(policy.Mode, claim.BlockSize, true, true); got != externalV2TransferModeBlocks {
		t.Fatalf("QUIC control retained preselected mode %q, want %q", got, externalV2TransferModeBlocks)
	}
	advertisement := &externalV2DirectTCPAdvertisement{
		Candidates:        []string{"203.0.113.10:8123"},
		FingerprintSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TransferID:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	selected := externalV2SelectOptimizedFileTransferMode(policy.Mode, claim.BlockSize, true, true)
	selected = externalV2SelectFileTransferMode(selected, claim.BlockSize, true, true, advertisement, nil)
	if selected != externalV2TransferModeBlocks {
		t.Fatalf("QUIC control with direct TCP advertisement selected %q, want %q", selected, externalV2TransferModeBlocks)
	}
}

func TestExternalV2BulkPacketCandidateInvalidValueCannotSelectDirectTCP(t *testing.T) {
	previous := externalV2BulkPacketBenchmarkCandidate
	externalV2BulkPacketBenchmarkCandidate = "combined-gso5"
	t.Cleanup(func() { externalV2BulkPacketBenchmarkCandidate = previous })

	advertisement := &externalV2DirectTCPAdvertisement{
		Candidates:        []string{"203.0.113.10:8123"},
		FingerprintSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TransferID:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if got := externalV2SelectFileTransferMode(externalV2TransferModeBlocks, externalV2DirectTCPMinFileSize, true, true, advertisement, nil); got != externalV2TransferModeBlocks {
		t.Fatalf("invalid candidate selected %q, want fail-closed %q", got, externalV2TransferModeBlocks)
	}
}
