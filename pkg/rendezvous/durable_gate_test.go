// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rendezvous

import (
	"errors"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

func durableTestToken(expires time.Time) token.Token {
	return token.Token{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8},
		ExpiresUnix:  expires.Unix(),
		BearerSecret: [32]byte{9, 8, 7, 6, 5, 4, 3, 2},
		Capabilities: token.CapabilityDerptunTCP,
	}
}

func durableTestClaim(tok token.Token, marker byte) Claim {
	claim := Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   [32]byte{marker},
		QUICPublic:   [32]byte{marker + 1},
		Parallel:     2,
		Candidates:   []string{"203.0.113.10:12345"},
		Capabilities: token.CapabilityDerptunTCP,
	}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}

func TestDurableGateAllowsReconnectAfterRelease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := durableTestToken(now.Add(time.Minute))
	gate := NewDurableGate(tok)

	first := durableTestClaim(tok, 1)
	if _, err := gate.Accept(now, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	gate.Release(first.DERPPublic)

	second := durableTestClaim(tok, 2)
	decision, err := gate.Accept(now, second)
	if err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatalf("Accepted = false, want true")
	}
	if decision.Accept == nil {
		t.Fatalf("Accept = nil, want structured accept info")
	}
}

func TestDurableGateRejectsConcurrentDifferentConnector(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := durableTestToken(now.Add(time.Minute))
	gate := NewDurableGate(tok)

	first := durableTestClaim(tok, 3)
	if _, err := gate.Accept(now, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	second := durableTestClaim(tok, 4)
	decision, err := gate.Accept(now, second)
	if !errors.Is(err, ErrClaimed) {
		t.Fatalf("second Accept() error = %v, want ErrClaimed", err)
	}
	if decision.Accepted {
		t.Fatalf("Accepted = true, want false")
	}
	if decision.Reject == nil {
		t.Fatalf("Reject = nil, want structured reject info")
	}
	if got, want := decision.Reject.Code, RejectClaimed; got != want {
		t.Fatalf("Reject.Code = %q, want %q", got, want)
	}
}

func TestDurableGateRejectsExpiredToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := durableTestToken(now.Add(-time.Second))
	gate := NewDurableGate(tok)

	decision, err := gate.Accept(now, durableTestClaim(tok, 5))
	if !errors.Is(err, token.ErrExpired) {
		t.Fatalf("Accept() error = %v, want token.ErrExpired", err)
	}
	if decision.Accepted {
		t.Fatalf("Accepted = true, want false")
	}
	if decision.Reject == nil {
		t.Fatalf("Reject = nil, want structured reject info")
	}
	if got, want := decision.Reject.Code, RejectExpired; got != want {
		t.Fatalf("Reject.Code = %q, want %q", got, want)
	}
}
