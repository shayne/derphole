// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestSendExternalIgnoresLegacySelectorEnvAndUsesV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "blast")

	sentinel := errors.New("v2 send")
	prev := sendExternalViaV2Fn
	t.Cleanup(func() { sendExternalViaV2Fn = prev })

	called := false
	sendExternalViaV2Fn = func(context.Context, SendConfig) error {
		called = true
		return sentinel
	}

	err := sendExternal(context.Background(), SendConfig{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("sendExternal() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("sendExternal did not call v2")
	}
}

func TestListenExternalIgnoresLegacySelectorEnvAndUsesV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "blast")

	sentinel := errors.New("v2 listen")
	prev := listenExternalViaV2Fn
	t.Cleanup(func() { listenExternalViaV2Fn = prev })

	called := false
	listenExternalViaV2Fn = func(context.Context, ListenConfig) (string, error) {
		called = true
		return "", sentinel
	}

	_, err := listenExternal(context.Background(), ListenConfig{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("listenExternal() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("listenExternal did not call v2")
	}
}

func TestOfferIgnoresLegacySelectorEnvAndUsesV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "blast")

	sentinel := errors.New("v2 offer")
	prev := offerExternalViaV2Fn
	t.Cleanup(func() { offerExternalViaV2Fn = prev })

	called := false
	offerExternalViaV2Fn = func(context.Context, OfferConfig) (string, error) {
		called = true
		return "", sentinel
	}

	_, err := Offer(context.Background(), OfferConfig{UsePublicDERP: true})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Offer() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("Offer did not call v2")
	}
}

func TestReceiveIgnoresLegacySelectorEnvAndUsesV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "blast")

	rawToken, err := token.Encode(token.Token{
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityStdioOffer | token.CapabilityTransferV2,
	})
	if err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("v2 receive")
	prev := receiveExternalOfferViaV2Fn
	t.Cleanup(func() { receiveExternalOfferViaV2Fn = prev })

	called := false
	receiveExternalOfferViaV2Fn = func(context.Context, ReceiveConfig) error {
		called = true
		return sentinel
	}

	err = Receive(context.Background(), ReceiveConfig{Token: rawToken, UsePublicDERP: true})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Receive() error = %v, want %v", err, sentinel)
	}
	if !called {
		t.Fatal("Receive did not call v2")
	}
}
