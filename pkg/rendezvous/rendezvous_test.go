// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rendezvous

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

func testToken(now time.Time) token.Token {
	return token.Token{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4},
		ExpiresUnix:  now.Add(time.Minute).Unix(),
		BearerSecret: [32]byte{9, 8, 7, 6},
	}
}

func testClaim(tok token.Token) Claim {
	claim := Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   [32]byte{1, 2, 3, 4},
		QUICPublic:   [32]byte{5, 6, 7, 8},
		Parallel:     4,
		Candidates:   []string{"203.0.113.10:12345", "[2001:db8::10]:12345"},
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}

func TestGateAcceptsFirstValidClaim(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	decision, err := gate.Accept(now, claim)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatalf("Accepted = false, want true")
	}
	if decision.Accept == nil {
		t.Fatalf("Accept = nil, want structured accept info")
	}
	if got, want := decision.Accept.SessionID, tok.SessionID; got != want {
		t.Fatalf("Accept.SessionID = %x, want %x", got, want)
	}
}

func TestGateRejectsExpiredToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	tok.ExpiresUnix = now.Add(-time.Second).Unix()
	gate := NewGate(tok)

	claim := testClaim(tok)
	decision, err := gate.Accept(now, claim)
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

func TestGateAcceptsAtExpiryBoundaryAndRejectsAfter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	tok.ExpiresUnix = now.Unix()
	claim := testClaim(tok)

	expiredGate := NewGate(tok)
	decision, err := expiredGate.Accept(now, claim)
	if !errors.Is(err, token.ErrExpired) {
		t.Fatalf("expired Accept() error = %v, want token.ErrExpired", err)
	}
	if decision.Accepted {
		t.Fatalf("expired Accepted = true, want false")
	}
	if decision.Reject == nil {
		t.Fatalf("expired Reject = nil, want structured reject info")
	}
	if got, want := decision.Reject.Code, RejectExpired; got != want {
		t.Fatalf("expired Reject.Code = %q, want %q", got, want)
	}
}

func TestGateAcceptIsIdempotentForDuplicateClaimFromSamePeer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	if _, err := gate.Accept(now, claim); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	decision, err := gate.Accept(now, claim)
	if err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatalf("Accepted = false, want true")
	}
	if decision.Accept == nil {
		t.Fatalf("Accept = nil, want structured accept info")
	}
	if got, want := decision.Accept.SessionID, tok.SessionID; got != want {
		t.Fatalf("Accept.SessionID = %x, want %x", got, want)
	}
}

func TestGateRejectsSecondClaimFromDifferentPeer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	if _, err := gate.Accept(now, claim); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	claim.DERPPublic[0]++
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := gate.Accept(now, claim)
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

func TestGateAuthenticatesSecondClaimBeforeClaimedRejection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	first := testClaim(tok)
	if _, err := gate.Accept(now, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	second := testClaim(tok)
	second.DERPPublic[0]++
	second.BearerMAC = "bad-mac"

	decision, err := gate.Accept(now, second)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("second Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectBadMAC {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectBadMAC)
	}
}

func TestGateRejectsMalformedCandidateStrings(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)
	claim := testClaim(tok)
	claim.Candidates = []string{"udp4:203.0.113.10:12345"}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectClaimMalformed {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectClaimMalformed)
	}
}

func TestGateRejectsDuplicateCandidates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)
	claim := testClaim(tok)
	claim.Candidates = []string{"203.0.113.10:12345", "203.0.113.10:12345"}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectClaimMalformed {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectClaimMalformed)
	}
}

func TestGateRejectsMismatchedVersion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	claim.Version++

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil {
		t.Fatalf("Reject = nil, want structured reject info")
	}
	if got, want := decision.Reject.Code, RejectVersionMismatch; got != want {
		t.Fatalf("Reject.Code = %q, want %q", got, want)
	}
}

func TestGateRejectsMismatchedSession(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	claim.SessionID[0]++

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil {
		t.Fatalf("Reject = nil, want structured reject info")
	}
	if got, want := decision.Reject.Code, RejectSessionMismatch; got != want {
		t.Fatalf("Reject.Code = %q, want %q", got, want)
	}
}

func TestGateRejectsBadMAC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	claim.BearerMAC = "bad-mac"

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil {
		t.Fatalf("Reject = nil, want structured reject info")
	}
	if got, want := decision.Reject.Code, RejectBadMAC; got != want {
		t.Fatalf("Reject.Code = %q, want %q", got, want)
	}
}

func TestClaimAndDecisionSerializationRoundTrip(t *testing.T) {
	claim := Claim{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4},
		BearerMAC:    "mac",
		DERPPublic:   [32]byte{5, 6, 7, 8},
		QUICPublic:   [32]byte{9, 10, 11, 12},
		Parallel:     8,
		Candidates:   []string{"udp4:127.0.0.1:1", "udp6:[::1]:2"},
		Capabilities: 0x42,
	}
	encodedClaim, err := EncodeClaim(claim)
	if err != nil {
		t.Fatalf("EncodeClaim() error = %v", err)
	}
	decodedClaim, err := DecodeClaim(encodedClaim)
	if err != nil {
		t.Fatalf("DecodeClaim() error = %v", err)
	}
	if !reflect.DeepEqual(decodedClaim, claim) {
		t.Fatalf("decoded claim = %+v, want %+v", decodedClaim, claim)
	}

	decision := Decision{
		Accepted: true,
		Accept: &AcceptInfo{
			Version:      token.SupportedVersion,
			SessionID:    claim.SessionID,
			Parallel:     claim.Parallel,
			Candidates:   claim.Candidates,
			Capabilities: claim.Capabilities,
		},
	}
	encodedDecision, err := EncodeDecision(decision)
	if err != nil {
		t.Fatalf("EncodeDecision() error = %v", err)
	}
	decodedDecision, err := DecodeDecision(encodedDecision)
	if err != nil {
		t.Fatalf("DecodeDecision() error = %v", err)
	}
	if decodedDecision.Accept == nil || !decodedDecision.Accepted {
		t.Fatalf("decoded decision = %+v, want accepted decision", decodedDecision)
	}
	if decodedDecision.Accept.SessionID != claim.SessionID {
		t.Fatalf("decoded decision session = %x, want %x", decodedDecision.Accept.SessionID, claim.SessionID)
	}
}

func TestClaimSerializesClientProof(t *testing.T) {
	claim := Claim{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4},
		BearerMAC:    "mac",
		DERPPublic:   [32]byte{5, 6, 7, 8},
		QUICPublic:   [32]byte{9, 10, 11, 12},
		Candidates:   []string{"udp4:127.0.0.1:1"},
		Capabilities: token.CapabilityDerptunTCP,
		Client: &ClientProof{
			ClientID:    [16]byte{7, 7, 7, 7},
			TokenID:     [16]byte{8, 8, 8, 8},
			ClientName:  "clienthost",
			ExpiresUnix: 1_700_000_600,
			ProofMAC:    "proof",
		},
	}
	encodedClaim, err := EncodeClaim(claim)
	if err != nil {
		t.Fatalf("EncodeClaim() error = %v", err)
	}
	decodedClaim, err := DecodeClaim(encodedClaim)
	if err != nil {
		t.Fatalf("DecodeClaim() error = %v", err)
	}
	if decodedClaim.Client == nil {
		t.Fatalf("Client = nil, want proof")
	}
	if decodedClaim.Client.ClientID != claim.Client.ClientID {
		t.Fatalf("ClientID = %x, want %x", decodedClaim.Client.ClientID, claim.Client.ClientID)
	}
	if decodedClaim.Client.TokenID != claim.Client.TokenID {
		t.Fatalf("TokenID = %x, want %x", decodedClaim.Client.TokenID, claim.Client.TokenID)
	}
	if decodedClaim.Client.ClientName != claim.Client.ClientName {
		t.Fatalf("ClientName = %q, want %q", decodedClaim.Client.ClientName, claim.Client.ClientName)
	}
	if decodedClaim.Client.ExpiresUnix != claim.Client.ExpiresUnix {
		t.Fatalf("ExpiresUnix = %d, want %d", decodedClaim.Client.ExpiresUnix, claim.Client.ExpiresUnix)
	}
	if decodedClaim.Client.ProofMAC != claim.Client.ProofMAC {
		t.Fatalf("ProofMAC = %q, want %q", decodedClaim.Client.ProofMAC, claim.Client.ProofMAC)
	}
}

func TestGateRejectsCapabilityMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	tok.Capabilities = token.CapabilityShare
	gate := NewGate(tok)

	claim := testClaim(tok)
	claim.Capabilities = token.CapabilityStdio
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectCapabilities {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectCapabilities)
	}
}

func TestGateRejectsOversizedCandidateSet(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)

	claim := testClaim(tok)
	claim.Candidates = make([]string, MaxClaimCandidates+1)
	for i := range claim.Candidates {
		claim.Candidates[i] = "udp4:203.0.113.10:12345"
	}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectClaimMalformed {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectClaimMalformed)
	}
}
