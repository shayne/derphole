// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"bytes"
	"testing"
)

func TestDiscoveryMACProbeAndAckRoundTrip(t *testing.T) {
	key := DiscoveryKey{1, 2, 3}
	probe, probeToken, err := newDirectProbePayload(key)
	if err != nil {
		t.Fatalf("newDirectProbePayload() error = %v", err)
	}
	if !probeToken.mac {
		t.Fatal("probe token mac = false, want true")
	}
	ack, ok := directAckPayloadForProbe(key, probe)
	if !ok {
		t.Fatal("directAckPayloadForProbe() ok = false, want true")
	}
	ackToken, ok := directAckTokenForPayload(key, ack)
	if !ok {
		t.Fatal("directAckTokenForPayload() ok = false, want true")
	}
	if ackToken != probeToken {
		t.Fatalf("ack token = %+v, want %+v", ackToken, probeToken)
	}
}

func TestDiscoveryMACRejectsWrongKey(t *testing.T) {
	probe, _, err := newDirectProbePayload(DiscoveryKey{1})
	if err != nil {
		t.Fatalf("newDirectProbePayload() error = %v", err)
	}
	if _, ok := directAckPayloadForProbe(DiscoveryKey{2}, probe); ok {
		t.Fatal("directAckPayloadForProbe(wrong key) ok = true, want false")
	}
}

func TestDiscoveryMACRejectsWrongKind(t *testing.T) {
	key := DiscoveryKey{1}
	probe, _, err := newDirectProbePayload(key)
	if err != nil {
		t.Fatalf("newDirectProbePayload() error = %v", err)
	}
	probe[len(discoMACMagic)] = 99
	if _, ok := directAckPayloadForProbe(key, probe); ok {
		t.Fatal("directAckPayloadForProbe(wrong kind) ok = true, want false")
	}
}

func TestDiscoveryMACUsesLegacyStaticPacketsWhenKeyMissing(t *testing.T) {
	probe, token, err := newDirectProbePayload(DiscoveryKey{})
	if err != nil {
		t.Fatalf("newDirectProbePayload(zero) error = %v", err)
	}
	if token.mac {
		t.Fatal("legacy token mac = true, want false")
	}
	if !bytes.Equal(probe, discoProbePayload) {
		t.Fatalf("probe = %q, want legacy %q", probe, discoProbePayload)
	}
	ack, ok := directAckPayloadForProbe(DiscoveryKey{}, discoProbePayload)
	if !ok {
		t.Fatal("legacy directAckPayloadForProbe() ok = false, want true")
	}
	if !bytes.Equal(ack, discoAckPayload) {
		t.Fatalf("ack = %q, want legacy %q", ack, discoAckPayload)
	}
}
