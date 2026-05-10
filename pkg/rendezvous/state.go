// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rendezvous

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/candidate"
	"github.com/shayne/derphole/pkg/token"
)

var (
	ErrClaimed = errors.New("session already claimed")
	ErrDenied  = errors.New("claim denied")
)

const MaxClaimCandidates = candidate.MaxCount
const MaxCandidateLength = candidate.MaxLength

type Gate struct {
	mu    sync.Mutex
	token token.Token
	claim *Claim
}

func NewGate(tok token.Token) *Gate {
	return &Gate{token: tok}
}

func (g *Gate) Accept(now time.Time, claim Claim) (Decision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Unix() >= g.token.ExpiresUnix {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectExpired, Reason: "token expired"},
		}, token.ErrExpired
	}
	decision, err := validateClaimForToken(g.token, claim)
	if err != nil {
		return decision, err
	}
	if g.claim != nil {
		if sameClaim(*g.claim, claim) {
			return decision, nil
		}
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectClaimed, Reason: "session already claimed"},
		}, ErrClaimed
	}

	stored := claim
	stored.Candidates = append([]string(nil), claim.Candidates...)
	g.claim = &stored
	return decision, nil
}

func sameClaim(a, b Claim) bool {
	if a.Version != b.Version ||
		a.SessionID != b.SessionID ||
		a.BearerMAC != b.BearerMAC ||
		a.DERPPublic != b.DERPPublic ||
		a.QUICPublic != b.QUICPublic ||
		a.Parallel != b.Parallel ||
		a.Capabilities != b.Capabilities ||
		len(a.Candidates) != len(b.Candidates) {
		return false
	}
	for i := range a.Candidates {
		if a.Candidates[i] != b.Candidates[i] {
			return false
		}
	}
	return true
}

func validBearerMAC(secret [32]byte, claim Claim) bool {
	expected := ComputeBearerMAC(secret, claim)
	got, err := hex.DecodeString(claim.BearerMAC)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func validCandidates(candidates []string) bool {
	if os.Getenv("DERPHOLE_FAKE_TRANSPORT") == "1" {
		return candidate.ValidateClaimStrings(candidates, candidate.AllowLoopback()) == nil
	}
	return candidate.ValidateClaimStrings(candidates) == nil
}
