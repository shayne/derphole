package rendezvous

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

var (
	ErrClaimed = errors.New("session already claimed")
	ErrDenied  = errors.New("claim denied")
)

const MaxClaimCandidates = 32
const MaxCandidateLength = 128

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
	if g.claim != nil {
		if sameClaim(*g.claim, claim) {
			return Decision{
				Accepted: true,
				Accept: &AcceptInfo{
					Version:      g.token.Version,
					SessionID:    g.token.SessionID,
					Parallel:     claim.Parallel,
					Candidates:   append([]string(nil), claim.Candidates...),
					Capabilities: claim.Capabilities,
				},
			}, nil
		}
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectClaimed, Reason: "session already claimed"},
		}, ErrClaimed
	}
	if claim.Version != g.token.Version {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectVersionMismatch, Reason: "version mismatch"},
		}, ErrDenied
	}
	if claim.SessionID != g.token.SessionID {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectSessionMismatch, Reason: "session mismatch"},
		}, ErrDenied
	}
	if !validBearerMAC(g.token.BearerSecret, claim) {
		return Decision{
			Accepted: false,
			Reject:   &RejectInfo{Code: RejectBadMAC, Reason: "bad bearer mac"},
		}, ErrDenied
	}
	if claim.Capabilities != g.token.Capabilities {
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

	stored := claim
	stored.Candidates = append([]string(nil), claim.Candidates...)
	g.claim = &stored
	return Decision{
		Accepted: true,
		Accept: &AcceptInfo{
			Version:      g.token.Version,
			SessionID:    g.token.SessionID,
			Parallel:     claim.Parallel,
			Candidates:   append([]string(nil), claim.Candidates...),
			Capabilities: claim.Capabilities,
		},
	}, nil
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
	if len(candidates) > MaxClaimCandidates {
		return false
	}
	for _, candidate := range candidates {
		if candidate == "" || len(candidate) > MaxCandidateLength {
			return false
		}
	}
	return true
}
