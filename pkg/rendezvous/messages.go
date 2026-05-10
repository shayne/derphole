// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rendezvous

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type ClientProof struct {
	ClientID    [16]byte `json:"client_id"`
	TokenID     [16]byte `json:"token_id"`
	ClientName  string   `json:"client_name"`
	ExpiresUnix int64    `json:"expires_unix"`
	ProofMAC    string   `json:"proof_mac"`
}

type Claim struct {
	Version      uint8        `json:"version"`
	SessionID    [16]byte     `json:"session_id"`
	BearerMAC    string       `json:"bearer_mac"`
	DERPPublic   [32]byte     `json:"derp_public"`
	QUICPublic   [32]byte     `json:"quic_public"`
	Parallel     int          `json:"parallel,omitempty"`
	Candidates   []string     `json:"candidates,omitempty"`
	Capabilities uint32       `json:"capabilities,omitempty"`
	Client       *ClientProof `json:"client,omitempty"`
}

type AcceptInfo struct {
	Version      uint8    `json:"version"`
	SessionID    [16]byte `json:"session_id"`
	Parallel     int      `json:"parallel,omitempty"`
	Candidates   []string `json:"candidates,omitempty"`
	Capabilities uint32   `json:"capabilities"`
}

type RejectCode string

const (
	RejectExpired         RejectCode = "expired"
	RejectClaimed         RejectCode = "claimed"
	RejectVersionMismatch RejectCode = "version_mismatch"
	RejectSessionMismatch RejectCode = "session_mismatch"
	RejectBadMAC          RejectCode = "bad_mac"
	RejectCapabilities    RejectCode = "capabilities_mismatch"
	RejectClaimMalformed  RejectCode = "claim_malformed"
)

type RejectInfo struct {
	Code   RejectCode `json:"code"`
	Reason string     `json:"reason,omitempty"`
}

type Decision struct {
	Accepted bool        `json:"accepted"`
	Accept   *AcceptInfo `json:"accept,omitempty"`
	Reject   *RejectInfo `json:"reject,omitempty"`
}

func ComputeBearerMAC(secret [32]byte, claim Claim) string {
	payload, err := json.Marshal(struct {
		Version      uint8    `json:"version"`
		SessionID    [16]byte `json:"session_id"`
		DERPPublic   [32]byte `json:"derp_public"`
		QUICPublic   [32]byte `json:"quic_public"`
		Parallel     int      `json:"parallel,omitempty"`
		Candidates   []string `json:"candidates,omitempty"`
		Capabilities uint32   `json:"capabilities"`
	}{
		Version:      claim.Version,
		SessionID:    claim.SessionID,
		DERPPublic:   claim.DERPPublic,
		QUICPublic:   claim.QUICPublic,
		Parallel:     claim.Parallel,
		Candidates:   claim.Candidates,
		Capabilities: claim.Capabilities,
	})
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func EncodeClaim(claim Claim) ([]byte, error) {
	return json.Marshal(claim)
}

func DecodeClaim(raw []byte) (Claim, error) {
	var claim Claim
	err := json.Unmarshal(raw, &claim)
	return claim, err
}

func EncodeDecision(decision Decision) ([]byte, error) {
	return json.Marshal(decision)
}

func DecodeDecision(raw []byte) (Decision, error) {
	var decision Decision
	err := json.Unmarshal(raw, &decision)
	return decision, err
}
