// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "fmt"

const externalV2BulkPacketProductionCandidate = "baseline-gso3"

var externalV2BulkPacketBenchmarkCandidate string

var externalV2BulkPacketCandidateConfigs = map[string]externalV2BulkPacketCandidateConfig{
	"baseline-gso3":  {ID: "baseline-gso3"},
	"coalesced-gso3": {ID: "coalesced-gso3", CoalescedReads: true, GSOSegments: 3},
	"connected-gso3": {ID: "connected-gso3", NativeConnectedSend: true, GSOSegments: 3},
	"combined-gso1":  externalV2BulkPacketCombinedCandidateConfig("combined-gso1", 1),
	"combined-gso2":  externalV2BulkPacketCombinedCandidateConfig("combined-gso2", 2),
	"combined-gso3":  externalV2BulkPacketCombinedCandidateConfig("combined-gso3", 3),
	"combined-gso4":  externalV2BulkPacketCombinedCandidateConfig("combined-gso4", 4),
	"combined-gso6":  externalV2BulkPacketCombinedCandidateConfig("combined-gso6", 6),
	"combined-gso8":  externalV2BulkPacketCombinedCandidateConfig("combined-gso8", 8),
	"combined-gso12": externalV2BulkPacketCombinedCandidateConfig("combined-gso12", 12),
	"quic-control":   {ID: "quic-control", ForceQUICControl: true},
}

type externalV2BulkPacketCandidateConfig struct {
	ID                  string
	CoalescedReads      bool
	NativeConnectedSend bool
	GSOSegments         int
	ForceQUICControl    bool
}

func externalV2BulkPacketCandidateConfigFor(value string) (externalV2BulkPacketCandidateConfig, error) {
	if value == "" {
		value = externalV2BulkPacketProductionCandidate
	}
	config, ok := externalV2BulkPacketCandidateConfigs[value]
	if !ok {
		return externalV2BulkPacketCandidateConfig{}, fmt.Errorf("invalid bulk packet benchmark candidate %q", value)
	}
	return config, nil
}

func externalV2BulkPacketCombinedCandidateConfig(id string, segments int) externalV2BulkPacketCandidateConfig {
	return externalV2BulkPacketCandidateConfig{
		ID:                  id,
		CoalescedReads:      true,
		NativeConnectedSend: true,
		GSOSegments:         segments,
	}
}

func externalV2BulkPacketConfiguredCandidate() (externalV2BulkPacketCandidateConfig, error) {
	return externalV2BulkPacketCandidateConfigFor(externalV2BulkPacketBenchmarkCandidate)
}

func externalV2BulkPacketCandidateSelectedMode(policy string) (string, bool) {
	candidate, err := externalV2BulkPacketConfiguredCandidate()
	if err != nil {
		return policy, true
	}
	if !candidate.ForceQUICControl {
		return policy, false
	}
	if policy == externalV2TransferModeBlocks || policy == externalV2TransferModeBulkPackets {
		return externalV2TransferModeBlocks, true
	}
	return policy, true
}
