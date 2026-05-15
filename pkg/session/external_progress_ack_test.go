// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/token"
	"tailscale.com/types/key"
)

func testPeerProgressAuth() externalPeerControlAuth {
	return externalPeerControlAuthForToken(token.Token{
		SessionID:    [16]byte{1, 2, 3},
		BearerSecret: [32]byte{4, 5, 6},
	})
}

func TestVerifyPeerProgressPacketAuthenticatedAccepted(t *testing.T) {
	auth := testPeerProgressAuth()
	payload, err := marshalAuthenticatedEnvelope(envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(1234, 567, 8),
	}, auth)
	if err != nil {
		t.Fatal(err)
	}

	var lastSequence uint64
	got, handled, err := verifyPeerProgressPacket(derpbind.Packet{Payload: payload}, auth, &lastSequence)
	if err != nil {
		t.Fatalf("verifyPeerProgressPacket() error = %v", err)
	}
	if handled {
		t.Fatal("verifyPeerProgressPacket() handled = true, want false")
	}
	if got.BytesReceived != 1234 || got.TransferElapsedMS != 567 || got.Sequence != 8 {
		t.Fatalf("progress = %+v, want bytes=1234 elapsed=567 sequence=8", got)
	}
	if lastSequence != 8 {
		t.Fatalf("lastSequence = %d, want 8", lastSequence)
	}
}

func TestVerifyPeerProgressPacketUnauthenticatedHandledWhenAuthEnabled(t *testing.T) {
	auth := testPeerProgressAuth()
	payload, err := json.Marshal(envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(1234, 567, 8),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, handled, err := verifyPeerProgressPacket(derpbind.Packet{Payload: payload}, auth, nil)
	if err != nil {
		t.Fatalf("verifyPeerProgressPacket() error = %v", err)
	}
	if !handled {
		t.Fatal("verifyPeerProgressPacket() handled = false, want true")
	}
}

func TestPeerProgressReplayedUpdatesOnlyOnNewerSequence(t *testing.T) {
	lastSequence := uint64(10)
	if !peerProgressReplayed(newPeerProgress(1, 2, 10), &lastSequence) {
		t.Fatal("same sequence was not replayed")
	}
	if lastSequence != 10 {
		t.Fatalf("lastSequence after same sequence = %d, want 10", lastSequence)
	}
	if !peerProgressReplayed(newPeerProgress(1, 2, 9), &lastSequence) {
		t.Fatal("older sequence was not replayed")
	}
	if lastSequence != 10 {
		t.Fatalf("lastSequence after older sequence = %d, want 10", lastSequence)
	}
	if peerProgressReplayed(newPeerProgress(1, 2, 11), &lastSequence) {
		t.Fatal("newer sequence was replayed")
	}
	if lastSequence != 11 {
		t.Fatalf("lastSequence after newer sequence = %d, want 11", lastSequence)
	}
	if peerProgressReplayed(newPeerProgress(1, 2, 11), nil) {
		t.Fatal("nil lastSequence reported replay")
	}
}

func TestSendPeerProgressSkipsNilClientOrZeroPeer(t *testing.T) {
	if err := sendPeerProgress(context.Background(), nil, key.NodePublic{}, 1, 2, 3, externalPeerControlAuth{}); err != nil {
		t.Fatalf("sendPeerProgress(nil client) error = %v", err)
	}
	if err := sendPeerProgress(context.Background(), &derpbind.Client{}, key.NodePublic{}, 1, 2, 3, externalPeerControlAuth{}); err != nil {
		t.Fatalf("sendPeerProgress(zero peer) error = %v", err)
	}
}

func TestProgressPayloadIsControl(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type:     envelopeProgress,
		Progress: newPeerProgress(1234, 567, 8),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !isProgressPayload(payload) {
		t.Fatalf("isProgressPayload(%s) = false, want true", payload)
	}
	if isTransportDataPayload(payload) {
		t.Fatalf("isTransportDataPayload(%s) = true, want false for progress", payload)
	}
}
