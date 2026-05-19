// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"errors"
	"testing"

	"github.com/shayne/derphole/pkg/token"
)

func TestExternalV2TokenSupportsTransferV2(t *testing.T) {
	tok := token.Token{Capabilities: token.CapabilityStdio | token.CapabilityTransferV2}
	if err := validateExternalV2SendToken(tok); err != nil {
		t.Fatalf("validateExternalV2SendToken() error = %v", err)
	}
}

func TestExternalV2TokenRejectsMissingCapability(t *testing.T) {
	tok := token.Token{Capabilities: token.CapabilityStdio}
	if err := validateExternalV2SendToken(tok); !errors.Is(err, errExternalV2Unsupported) {
		t.Fatalf("validateExternalV2SendToken() error = %v, want %v", err, errExternalV2Unsupported)
	}
}

func TestExternalV2ClaimValidationRequiresProtocol(t *testing.T) {
	claim := externalV2Claim{Protocol: "legacy"}
	if err := validateExternalV2Claim(claim); !errors.Is(err, errExternalV2Unsupported) {
		t.Fatalf("validateExternalV2Claim() error = %v, want %v", err, errExternalV2Unsupported)
	}
}

func TestExternalV2AcceptValidationRequiresAccepted(t *testing.T) {
	accept := externalV2Accept{Protocol: externalV2Protocol}
	if err := validateExternalV2Accept(accept); !errors.Is(err, errExternalV2Rejected) {
		t.Fatalf("validateExternalV2Accept() error = %v, want %v", err, errExternalV2Rejected)
	}
}

func TestExternalV2ParallelPolicyDefaultsAndRoundTrips(t *testing.T) {
	if got, want := externalV2ParallelPolicy(externalV2Claim{}), DefaultParallelPolicy(); got != want {
		t.Fatalf("default claim parallel policy = %#v, want %#v", got, want)
	}

	mode, initial, cap := externalV2SetParallelPolicy(AutoParallelPolicy())
	claim := externalV2Claim{ParallelMode: mode, ParallelInitial: initial, ParallelCap: cap}
	if got, want := externalV2ParallelPolicy(claim), AutoParallelPolicy(); got != want {
		t.Fatalf("claim parallel policy = %#v, want %#v", got, want)
	}

	mode, initial, cap = externalV2SetParallelPolicy(FixedParallelPolicy(8))
	accept := externalV2Accept{ParallelMode: mode, ParallelInitial: initial, ParallelCap: cap}
	if got, want := externalV2StreamCount(externalV2ParallelPolicy(accept)), 8; got != want {
		t.Fatalf("accept stream count = %d, want %d", got, want)
	}
}
