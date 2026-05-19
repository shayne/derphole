// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"

	"github.com/shayne/derphole/pkg/token"
)

const externalV2Protocol = "derphole-transfer-v2"

var (
	errExternalV2Unsupported = errors.New("external v2 transfer unsupported")
	errExternalV2Rejected    = errors.New("external v2 transfer rejected")
)

type externalV2Claim struct {
	Protocol        string   `json:"protocol"`
	QUICPublic      [32]byte `json:"quic_public"`
	Candidates      []string `json:"candidates,omitempty"`
	RelayCapable    bool     `json:"relay_capable"`
	ReceiverLimited bool     `json:"receiver_limited,omitempty"`
}

type externalV2Accept struct {
	Protocol     string   `json:"protocol"`
	Accepted     bool     `json:"accepted"`
	Candidates   []string `json:"candidates,omitempty"`
	RelayCapable bool     `json:"relay_capable"`
	Reason       string   `json:"reason,omitempty"`
}

type externalV2Complete struct {
	Protocol      string `json:"protocol"`
	BytesReceived int64  `json:"bytes_received"`
}

func validateExternalV2SendToken(tok token.Token) error {
	if tok.Capabilities&token.CapabilityTransferV2 == 0 {
		return errExternalV2Unsupported
	}
	return nil
}

func validateExternalV2Claim(claim externalV2Claim) error {
	if claim.Protocol != externalV2Protocol {
		return errExternalV2Unsupported
	}
	return nil
}

func validateExternalV2Accept(accept externalV2Accept) error {
	if accept.Protocol != externalV2Protocol {
		return errExternalV2Unsupported
	}
	if !accept.Accepted {
		return errExternalV2Rejected
	}
	return nil
}
