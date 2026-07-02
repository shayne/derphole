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
	claim := externalV2Claim{Protocol: "unsupported"}
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

func TestExternalV2ManagerConnectionCountDefaultsToOne(t *testing.T) {
	t.Setenv("DERPHOLE_V2_MANAGER_QUIC_FANOUT", "")

	if got := externalV2SetManagerConnectionCount(FixedParallelPolicy(4)); got != 1 {
		t.Fatalf("externalV2SetManagerConnectionCount() = %d, want 1", got)
	}
	if got := externalV2ManagerConnectionCount(externalV2Accept{}, FixedParallelPolicy(4)); got != 1 {
		t.Fatalf("externalV2ManagerConnectionCount(empty accept) = %d, want 1", got)
	}
}

func TestExternalV2ManagerConnectionCountNegotiatesOptInFanout(t *testing.T) {
	t.Setenv("DERPHOLE_V2_MANAGER_QUIC_FANOUT", "1")

	if got := externalV2SetManagerConnectionCount(FixedParallelPolicy(4)); got != 4 {
		t.Fatalf("externalV2SetManagerConnectionCount() = %d, want 4", got)
	}
	accept := externalV2Accept{ManagerConnections: 4}
	if got := externalV2ManagerConnectionCount(accept, FixedParallelPolicy(4)); got != 4 {
		t.Fatalf("externalV2ManagerConnectionCount() = %d, want 4", got)
	}
}

func TestExternalV2ManagerConnectionCountClampsAcceptedValue(t *testing.T) {
	if got := externalV2ManagerConnectionCount(externalV2Accept{ManagerConnections: 8}, FixedParallelPolicy(4)); got != 4 {
		t.Fatalf("externalV2ManagerConnectionCount(8 connections, 4 streams) = %d, want 4", got)
	}
	if got := externalV2ManagerConnectionCount(externalV2Accept{ManagerConnections: -1}, FixedParallelPolicy(4)); got != 1 {
		t.Fatalf("externalV2ManagerConnectionCount(-1 connections) = %d, want 1", got)
	}
}

func TestSendExternalUsesV2(t *testing.T) {
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

func TestListenExternalUsesV2(t *testing.T) {
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

func TestOfferUsesV2(t *testing.T) {
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

func TestReceiveUsesV2(t *testing.T) {
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
