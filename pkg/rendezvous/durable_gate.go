// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rendezvous

import (
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

type DurableGate struct {
	mu     sync.Mutex
	token  token.Token
	active *Claim
	epoch  uint64
}

func NewDurableGate(tok token.Token) *DurableGate {
	return &DurableGate{token: tok}
}

func (g *DurableGate) Accept(now time.Time, claim Claim) (Decision, error) {
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

	if g.active != nil {
		if sameConnector(*g.active, claim) {
			return decision, nil
		}
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectClaimed, Reason: "session already claimed"},
		}, ErrClaimed
	}

	stored := claim
	stored.Candidates = append([]string(nil), claim.Candidates...)
	g.active = &stored
	g.epoch++
	return decision, nil
}

func (g *DurableGate) Release(derpPublic [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.active == nil {
		return
	}
	if g.active.DERPPublic != derpPublic {
		return
	}
	g.active = nil
	g.epoch++
}

func validateClaimForToken(tok token.Token, claim Claim) (Decision, error) {
	if claim.Version != tok.Version {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectVersionMismatch, Reason: "version mismatch"},
		}, ErrDenied
	}
	if claim.SessionID != tok.SessionID {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectSessionMismatch, Reason: "session mismatch"},
		}, ErrDenied
	}
	if !validBearerMAC(tok.BearerSecret, claim) {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectBadMAC, Reason: "bad bearer mac"},
		}, ErrDenied
	}
	if claim.Capabilities != tok.Capabilities {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectCapabilities, Reason: "capabilities mismatch"},
		}, ErrDenied
	}
	if claim.DERPPublic == [32]byte{} || claim.QUICPublic == [32]byte{} || !validCandidates(claim.Candidates) {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectClaimMalformed, Reason: "claim malformed"},
		}, ErrDenied
	}
	return Decision{
		Accepted: true,
		Accept: &AcceptInfo{
			Version:      tok.Version,
			SessionID:    tok.SessionID,
			Parallel:     claim.Parallel,
			Candidates:   append([]string(nil), claim.Candidates...),
			Capabilities: claim.Capabilities,
		},
	}, nil
}

func sameConnector(a, b Claim) bool {
	return a.DERPPublic == b.DERPPublic && a.QUICPublic == b.QUICPublic
}
