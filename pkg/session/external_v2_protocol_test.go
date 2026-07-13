// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

type externalV2CompleteV1 struct {
	Protocol      string `json:"protocol"`
	BytesReceived int64  `json:"bytes_received"`
}

type externalV2CompleteEnvelopeV1 struct {
	Type       string                `json:"type"`
	MAC        string                `json:"mac,omitempty"`
	V2Complete *externalV2CompleteV1 `json:"v2_complete,omitempty"`
}

func TestExternalV2CompleteAuthenticatedEnvelopeIsAcceptedByV1Schema(t *testing.T) {
	auth := externalPeerControlAuth{EnvelopeKey: [32]byte{1, 2, 3}}
	payload, err := marshalAuthenticatedEnvelope(envelope{
		Type: envelopeV2Complete,
		V2Complete: &externalV2Complete{
			Protocol:      externalV2Protocol,
			BytesReceived: 42,
		},
	}, auth)
	if err != nil {
		t.Fatal(err)
	}

	var oldEnvelope externalV2CompleteEnvelopeV1
	if err := json.Unmarshal(payload, &oldEnvelope); err != nil {
		t.Fatal(err)
	}
	gotMAC := oldEnvelope.MAC
	oldEnvelope.MAC = ""
	oldPayload, err := json.Marshal(oldEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, auth.EnvelopeKey[:])
	mac.Write([]byte("envelope"))
	mac.Write(oldPayload)
	wantMAC := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotMAC), []byte(wantMAC)) {
		t.Fatalf("v1 schema rejected authenticated v2_complete: got MAC %q, want %q; payload=%s old-payload=%s", gotMAC, wantMAC, payload, oldPayload)
	}
}

func TestExternalV2TokenSupportsTransferV2(t *testing.T) {
	tok := token.Token{Capabilities: token.CapabilityStdio | token.CapabilityTransferV2}
	if err := validateExternalV2SendToken(tok); err != nil {
		t.Fatalf("validateExternalV2SendToken() error = %v", err)
	}
}

func TestExternalV2TokenRejectsMissingCapability(t *testing.T) {
	tok := token.Token{Capabilities: token.CapabilityStdio}
	if err := validateExternalV2SendToken(tok); !errors.Is(err, errExternalV2Unsupported) {
		t.Fatalf("validateExternalV2SendToken() error = %v, want %v", err, errExternalV2Unsupported)
	}
}

func TestExternalV2ClaimValidationRequiresProtocol(t *testing.T) {
	claim := externalV2Claim{Protocol: "unsupported"}
	if err := validateExternalV2Claim(claim); !errors.Is(err, errExternalV2Unsupported) {
		t.Fatalf("validateExternalV2Claim() error = %v, want %v", err, errExternalV2Unsupported)
	}
}

func TestExternalV2AcceptValidationRequiresAccepted(t *testing.T) {
	accept := externalV2Accept{Protocol: externalV2Protocol}
	if err := validateExternalV2Accept(accept); !errors.Is(err, errExternalV2Rejected) {
		t.Fatalf("validateExternalV2Accept() error = %v, want %v", err, errExternalV2Rejected)
	}
}

func TestExternalV2ParallelPolicyDefaultsAndRoundTrips(t *testing.T) {
	if got, want := externalV2ParallelPolicy(externalV2Claim{}), DefaultParallelPolicy(); got != want {
		t.Fatalf("default claim parallel policy = %#v, want %#v", got, want)
	}

	mode, initial, cap := externalV2SetParallelPolicy(AutoParallelPolicy())
	claim := externalV2Claim{ParallelMode: mode, ParallelInitial: initial, ParallelCap: cap}
	if got, want := externalV2ParallelPolicy(claim), AutoParallelPolicy(); got != want {
		t.Fatalf("claim parallel policy = %#v, want %#v", got, want)
	}

	mode, initial, cap = externalV2SetParallelPolicy(FixedParallelPolicy(8))
	accept := externalV2Accept{ParallelMode: mode, ParallelInitial: initial, ParallelCap: cap}
	if got, want := externalV2StreamCount(externalV2ParallelPolicy(accept)), 8; got != want {
		t.Fatalf("accept stream count = %d, want %d", got, want)
	}
}

func TestExternalV2DefaultPolicyStartsAtEmpiricalBulkDefault(t *testing.T) {
	policy := externalV2ParallelPolicy(externalV2Claim{})
	if got := externalV2StreamCount(policy); got != DefaultParallelStripes {
		t.Fatalf("externalV2StreamCount(default) = %d, want %d", got, DefaultParallelStripes)
	}
}

func TestExternalV2CopyBufferSizeMatchesLatencyFriendlyStripedChunk(t *testing.T) {
	if externalV2CopyBufferSize != externalCopyBufferSize {
		t.Fatalf("externalV2CopyBufferSize = %d, want %d", externalV2CopyBufferSize, externalCopyBufferSize)
	}
}

func TestExternalV2BlockTransferPolicyUsesFileReceiverInBothTopologies(t *testing.T) {
	compact := []string{
		"203.0.113.20:20000",
		"203.0.113.20:20001",
		"203.0.113.20:20002",
		"203.0.113.20:20003",
	}
	large := []string{
		"203.0.113.10:10000",
		"203.0.113.10:10001",
		"203.0.113.10:10002",
		"203.0.113.10:10003",
		"203.0.113.10:10004",
	}

	tests := []struct {
		name             string
		claim            externalV2Claim
		acceptCandidates []string
		wantReceiver     string
		wantMode         string
	}{
		{
			name: "receiver is claimant in send receive",
			claim: externalV2Claim{
				BlockCapable:       true,
				BlockPacketCapable: true,
				Candidates:         compact,
			},
			acceptCandidates: large,
			wantReceiver:     "claimant",
			wantMode:         externalV2TransferModeBulkPackets,
		},
		{
			name: "receiver is acceptor in pipe listen",
			claim: externalV2Claim{
				TransferMode:       externalV2TransferModeBlocks,
				BlockSize:          1024,
				BlockChunkSize:     externalV2DefaultBlockChunkSize,
				BlockPacketCapable: true,
				Candidates:         large,
			},
			acceptCandidates: compact,
			wantReceiver:     "acceptor",
			wantMode:         externalV2TransferModeBulkPackets,
		},
		{
			name: "tailscale noise does not change compact receiver",
			claim: externalV2Claim{
				BlockCapable:       true,
				BlockPacketCapable: true,
				Candidates: append(append([]string{}, compact...),
					"100.91.76.77:30000", "[fd7a:115c:a1e0::1]:30001"),
			},
			acceptCandidates: large,
			wantReceiver:     "claimant",
			wantMode:         externalV2TransferModeBulkPackets,
		},
		{
			name: "five public receiver candidates keep quic",
			claim: externalV2Claim{
				BlockCapable:       true,
				BlockPacketCapable: true,
				Candidates:         large,
			},
			acceptCandidates: compact,
			wantReceiver:     "claimant",
			wantMode:         externalV2TransferModeBlocks,
		},
		{
			name: "invalid receiver candidate keeps quic",
			claim: externalV2Claim{
				BlockCapable:       true,
				BlockPacketCapable: true,
				Candidates:         append(append([]string{}, compact...), "not-an-addr-port"),
			},
			acceptCandidates: large,
			wantReceiver:     "claimant",
			wantMode:         externalV2TransferModeBlocks,
		},
		{
			name: "missing packet capability keeps quic",
			claim: externalV2Claim{
				BlockCapable: true,
				Candidates:   compact,
			},
			acceptCandidates: large,
			wantReceiver:     "claimant",
			wantMode:         externalV2TransferModeBlocks,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := externalV2AcceptedBlockTransferPolicy(tt.claim, true, true, tt.acceptCandidates)
			if got.Receiver != tt.wantReceiver || got.Mode != tt.wantMode {
				t.Fatalf("policy = %#v, want receiver=%q mode=%q", got, tt.wantReceiver, tt.wantMode)
			}
		})
	}
}

func TestExternalV2BatchNativePeersPreferBulkForLargeFiles(t *testing.T) {
	claim := externalV2Claim{
		BlockCapable:            true,
		BlockPacketCapable:      true,
		BlockPacketBatchCapable: true,
		BlockPacketGroupCapable: true,
		BlockSize:               3 << 30,
	}
	for port := 10000; port < 10008; port++ {
		claim.Candidates = append(claim.Candidates, fmt.Sprintf("203.0.113.10:%d", port))
	}

	policy := externalV2AcceptedBlockTransferPolicy(claim, true, true, nil)
	if policy.Mode != externalV2TransferModeBulkPackets || !policy.BatchNative {
		t.Fatalf("policy = %#v, want batch-native bulk", policy)
	}
}

func TestExternalV2BatchNativeSelectionRequiresBothPeers(t *testing.T) {
	for _, tt := range []struct {
		name          string
		claim, accept bool
		want          string
	}{
		{name: "both", claim: true, accept: true, want: externalV2TransferModeBulkPackets},
		{name: "old claimant", claim: false, accept: true, want: externalV2TransferModeBlocks},
		{name: "old acceptor", claim: true, accept: false, want: externalV2TransferModeBlocks},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := externalV2SelectOptimizedFileTransferMode(externalV2TransferModeBlocks, 3<<30, tt.claim, tt.accept)
			if got != tt.want {
				t.Fatalf("mode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExternalV2BlockTransferPolicyCanForceBulkPacketsForBenchmarking(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER", "1")

	claim := externalV2Claim{
		BlockCapable:       true,
		BlockPacketCapable: true,
	}
	for port := 10000; port < 10013; port++ {
		claim.Candidates = append(claim.Candidates, fmt.Sprintf("203.0.113.10:%d", port))
	}

	got := externalV2AcceptedBlockTransferPolicy(claim, true, true, nil)
	if got.Mode != externalV2TransferModeBulkPackets {
		t.Fatalf("policy mode = %q, want %q", got.Mode, externalV2TransferModeBulkPackets)
	}
	if !got.ForcedBulkPackets {
		t.Fatal("policy ForcedBulkPackets = false, want true")
	}

	claim.Candidates = append(claim.Candidates, "not-an-addr-port")
	got = externalV2AcceptedBlockTransferPolicy(claim, true, true, nil)
	if got.Mode != externalV2TransferModeBlocks {
		t.Fatalf("policy mode with invalid candidate = %q, want %q", got.Mode, externalV2TransferModeBlocks)
	}
}

func TestExternalV2DirectTCPFileSelectionRequiresLargeQUICPolicyFileAndReachablePeer(t *testing.T) {
	advertisement := &externalV2DirectTCPAdvertisement{
		Candidates:        []string{"203.0.113.10:8123"},
		FingerprintSHA256: strings.Repeat("a", 64),
		TransferID:        strings.Repeat("b", 32),
	}
	tests := []struct {
		name          string
		policy        string
		size          int64
		claimCapable  bool
		acceptCapable bool
		claimAd       *externalV2DirectTCPAdvertisement
		acceptAd      *externalV2DirectTCPAdvertisement
		want          string
	}{
		{name: "receiver listener", policy: externalV2TransferModeBlocks, size: externalV2DirectTCPMinFileSize, claimCapable: true, acceptCapable: true, claimAd: advertisement, want: externalV2TransferModeDirectTCP},
		{name: "sender listener", policy: externalV2TransferModeBlocks, size: externalV2DirectTCPMinFileSize, claimCapable: true, acceptCapable: true, acceptAd: advertisement, want: externalV2TransferModeDirectTCP},
		{name: "bulk policy remains bulk", policy: externalV2TransferModeBulkPackets, size: 1 << 30, claimCapable: true, acceptCapable: true, claimAd: advertisement, want: externalV2TransferModeBulkPackets},
		{name: "small file remains quic", policy: externalV2TransferModeBlocks, size: externalV2DirectTCPMinFileSize - 1, claimCapable: true, acceptCapable: true, claimAd: advertisement, want: externalV2TransferModeBlocks},
		{name: "old claimant", policy: externalV2TransferModeBlocks, size: 1 << 30, acceptCapable: true, claimAd: advertisement, want: externalV2TransferModeBlocks},
		{name: "old acceptor", policy: externalV2TransferModeBlocks, size: 1 << 30, claimCapable: true, claimAd: advertisement, want: externalV2TransferModeBlocks},
		{name: "no reachable listener", policy: externalV2TransferModeBlocks, size: 1 << 30, claimCapable: true, acceptCapable: true, want: externalV2TransferModeBlocks},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := externalV2SelectFileTransferMode(tt.policy, tt.size, tt.claimCapable, tt.acceptCapable, tt.claimAd, tt.acceptAd)
			if got != tt.want {
				t.Fatalf("mode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExternalV2ManagerConnectionCountDefaultsToOne(t *testing.T) {
	t.Setenv("DERPHOLE_V2_MANAGER_QUIC_FANOUT", "")

	if got := externalV2SetManagerConnectionCount(FixedParallelPolicy(4)); got != 1 {
		t.Fatalf("externalV2SetManagerConnectionCount() = %d, want 1", got)
	}
	if got := externalV2ManagerConnectionCount(externalV2Accept{}, FixedParallelPolicy(4)); got != 1 {
		t.Fatalf("externalV2ManagerConnectionCount(empty accept) = %d, want 1", got)
	}
}

func TestExternalV2ManagerConnectionCountNegotiatesOptInFanout(t *testing.T) {
	t.Setenv("DERPHOLE_V2_MANAGER_QUIC_FANOUT", "1")

	if got := externalV2SetManagerConnectionCount(FixedParallelPolicy(4)); got != 4 {
		t.Fatalf("externalV2SetManagerConnectionCount() = %d, want 4", got)
	}
	accept := externalV2Accept{ManagerConnections: 4}
	if got := externalV2ManagerConnectionCount(accept, FixedParallelPolicy(4)); got != 4 {
		t.Fatalf("externalV2ManagerConnectionCount() = %d, want 4", got)
	}
}

func TestExternalV2ManagerConnectionCountClampsAcceptedValue(t *testing.T) {
	if got := externalV2ManagerConnectionCount(externalV2Accept{ManagerConnections: 8}, FixedParallelPolicy(4)); got != 4 {
		t.Fatalf("externalV2ManagerConnectionCount(8 connections, 4 streams) = %d, want 4", got)
	}
	if got := externalV2ManagerConnectionCount(externalV2Accept{ManagerConnections: -1}, FixedParallelPolicy(4)); got != 1 {
		t.Fatalf("externalV2ManagerConnectionCount(-1 connections) = %d, want 1", got)
	}
}

func TestSendExternalUsesV2(t *testing.T) {
	sentinel := errors.New("v2 send")
	prev := sendExternalViaV2Fn
	t.Cleanup(func() { sendExternalViaV2Fn = prev })

	called := false
	sendExternalViaV2Fn = func(context.Context, SendConfig) error {
		called = true
		return sentinel
	}

	err := sendExternal(context.Background(), SendConfig{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("sendExternal() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("sendExternal did not call v2")
	}
}

func TestListenExternalUsesV2(t *testing.T) {
	sentinel := errors.New("v2 listen")
	prev := listenExternalViaV2Fn
	t.Cleanup(func() { listenExternalViaV2Fn = prev })

	called := false
	listenExternalViaV2Fn = func(context.Context, ListenConfig) (string, error) {
		called = true
		return "", sentinel
	}

	_, err := listenExternal(context.Background(), ListenConfig{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("listenExternal() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("listenExternal did not call v2")
	}
}

func TestOfferUsesV2(t *testing.T) {
	sentinel := errors.New("v2 offer")
	prev := offerExternalViaV2Fn
	t.Cleanup(func() { offerExternalViaV2Fn = prev })

	called := false
	offerExternalViaV2Fn = func(context.Context, OfferConfig) (string, error) {
		called = true
		return "", sentinel
	}

	_, err := Offer(context.Background(), OfferConfig{UsePublicDERP: true})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Offer() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("Offer did not call v2")
	}
}

func TestReceiveUsesV2(t *testing.T) {
	rawToken, err := token.Encode(token.Token{
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdioOffer | token.CapabilityTransferV2,
	})
	if err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("v2 receive")
	prev := receiveExternalOfferViaV2Fn
	t.Cleanup(func() { receiveExternalOfferViaV2Fn = prev })

	called := false
	receiveExternalOfferViaV2Fn = func(context.Context, ReceiveConfig) error {
		called = true
		return sentinel
	}

	err = Receive(context.Background(), ReceiveConfig{Token: rawToken, UsePublicDERP: true})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Receive() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("Receive did not call v2")
	}
}
