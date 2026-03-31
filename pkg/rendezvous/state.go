package rendezvous

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/shayne/derpcat/pkg/token"
)

var (
	ErrClaimed = errors.New("session already claimed")
	ErrDenied  = errors.New("claim denied")
)

const MaxClaimCandidates = 32
const MaxCandidateLength = 128

type Gate struct {
	mu      sync.Mutex
	token   token.Token
	claimed bool
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
	if g.claimed {
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

	g.claimed = true
	return Decision{
		Accepted: true,
		Accept: &AcceptInfo{
			Version:      g.token.Version,
			SessionID:    g.token.SessionID,
			Candidates:   append([]string(nil), claim.Candidates...),
			Capabilities: claim.Capabilities,
		},
	}, nil
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
