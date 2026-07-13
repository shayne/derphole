// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
	"os"

	"github.com/shayne/derphole/pkg/token"
)

const externalV2Protocol = "derphole-transfer-v2"

var (
	errExternalV2Unsupported = errors.New("external v2 transfer unsupported")
	errExternalV2Rejected    = errors.New("external v2 transfer rejected")
)

type externalV2Claim struct {
	Protocol             string                            `json:"protocol"`
	QUICPublic           [32]byte                          `json:"quic_public"`
	Candidates           []string                          `json:"candidates,omitempty"`
	RelayCapable         bool                              `json:"relay_capable"`
	ReceiverLimited      bool                              `json:"receiver_limited,omitempty"`
	ParallelMode         string                            `json:"parallel_mode,omitempty"`
	ParallelInitial      int                               `json:"parallel_initial,omitempty"`
	ParallelCap          int                               `json:"parallel_cap,omitempty"`
	TransferMode         string                            `json:"transfer_mode,omitempty"`
	BlockHeader          []byte                            `json:"block_header,omitempty"`
	BlockSize            int64                             `json:"block_size,omitempty"`
	BlockChunkSize       int                               `json:"block_chunk_size,omitempty"`
	BlockCapable         bool                              `json:"block_capable,omitempty"`
	BlockPacketCapable   bool                              `json:"block_packet_capable,omitempty"`
	DirectTCPFileCapable bool                              `json:"direct_tcp_file_capable,omitempty"`
	DirectTCPFile        *externalV2DirectTCPAdvertisement `json:"direct_tcp_file,omitempty"`
}

type externalV2Accept struct {
	Protocol             string                            `json:"protocol"`
	Accepted             bool                              `json:"accepted"`
	Candidates           []string                          `json:"candidates,omitempty"`
	RelayCapable         bool                              `json:"relay_capable"`
	Reason               string                            `json:"reason,omitempty"`
	ParallelMode         string                            `json:"parallel_mode,omitempty"`
	ParallelInitial      int                               `json:"parallel_initial,omitempty"`
	ParallelCap          int                               `json:"parallel_cap,omitempty"`
	ManagerConnections   int                               `json:"manager_connections,omitempty"`
	RawDirectBudgetMS    int                               `json:"raw_direct_budget_ms,omitempty"`
	TransferMode         string                            `json:"transfer_mode,omitempty"`
	BlockHeader          []byte                            `json:"block_header,omitempty"`
	BlockSize            int64                             `json:"block_size,omitempty"`
	BlockChunkSize       int                               `json:"block_chunk_size,omitempty"`
	DirectTCPFileCapable bool                              `json:"direct_tcp_file_capable,omitempty"`
	DirectTCPFile        *externalV2DirectTCPAdvertisement `json:"direct_tcp_file,omitempty"`
}

type externalV2Complete struct {
	Protocol      string `json:"protocol"`
	BytesReceived int64  `json:"bytes_received"`
}

type externalV2DataPlaneReady struct {
	Protocol      string     `json:"protocol"`
	Phase         string     `json:"phase,omitempty"`
	RawDirect     bool       `json:"raw_direct,omitempty"`
	Candidates    []string   `json:"candidates,omitempty"`
	CandidateSets [][]string `json:"candidate_sets,omitempty"`
}

func validateExternalV2SendToken(tok token.Token) error {
	if tok.Capabilities&token.CapabilityTransferV2 == 0 {
		return errExternalV2Unsupported
	}
	return nil
}

func validateExternalV2Claim(claim externalV2Claim) error {
	if claim.Protocol != externalV2Protocol {
		return errExternalV2Unsupported
	}
	return nil
}

func validateExternalV2Accept(accept externalV2Accept) error {
	if accept.Protocol != externalV2Protocol {
		return errExternalV2Unsupported
	}
	if !accept.Accepted {
		return errExternalV2Rejected
	}
	return nil
}

func (m externalV2Claim) getParallelMode() string { return m.ParallelMode }
func (m externalV2Claim) getParallelInitial() int { return m.ParallelInitial }
func (m externalV2Claim) getParallelCap() int     { return m.ParallelCap }

func (m externalV2Accept) getParallelMode() string { return m.ParallelMode }
func (m externalV2Accept) getParallelInitial() int { return m.ParallelInitial }
func (m externalV2Accept) getParallelCap() int     { return m.ParallelCap }

func externalV2ParallelPolicy(msg interface {
	getParallelMode() string
	getParallelInitial() int
	getParallelCap() int
}) ParallelPolicy {
	policy := parallelPolicyFromFields(msg.getParallelMode(), msg.getParallelInitial(), msg.getParallelCap())
	if policy == (ParallelPolicy{}) {
		return DefaultParallelPolicy()
	}
	return policy.normalized()
}

func externalV2SetParallelPolicy(policy ParallelPolicy) (mode string, initial int, cap int) {
	policy = policy.normalized()
	return string(policy.Mode), policy.Initial, policy.Cap
}

func externalV2StreamCount(policy ParallelPolicy) int {
	return externalParallelQUICConnCount(policy)
}

func externalV2SetManagerConnectionCount(policy ParallelPolicy) int {
	if os.Getenv("DERPHOLE_V2_MANAGER_QUIC_FANOUT") != "1" {
		return 1
	}
	return externalV2StreamCount(policy)
}

func externalV2ManagerConnectionCount(accept externalV2Accept, policy ParallelPolicy) int {
	count := accept.ManagerConnections
	if count < 1 {
		return 1
	}
	if max := externalV2StreamCount(policy); count > max {
		return max
	}
	return count
}

func isV2ClaimPayload(payload []byte) bool {
	env, ok := decodeExternalV2Payload(payload, envelopeV2Claim)
	return ok && env.V2Claim != nil
}

func isV2AcceptPayload(payload []byte) bool {
	env, ok := decodeExternalV2Payload(payload, envelopeV2Accept)
	return ok && env.V2Accept != nil
}

func isV2CompletePayload(payload []byte) bool {
	env, ok := decodeExternalV2Payload(payload, envelopeV2Complete)
	return ok && env.V2Complete != nil
}

func isV2DataPlaneReadyPayload(payload []byte) bool {
	env, ok := decodeExternalV2Payload(payload, envelopeV2DataPlaneReady)
	return ok && env.V2DataPlaneReady != nil
}

func decodeExternalV2Payload(payload []byte, typ string) (envelope, bool) {
	var env envelope
	if len(payload) == 0 || payload[0] != '{' {
		return env, false
	}
	env, err := decodeEnvelope(payload)
	return env, err == nil && env.Type == typ
}
