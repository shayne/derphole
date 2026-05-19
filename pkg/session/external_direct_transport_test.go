// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"testing"
)

func TestExternalDirectTransportFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want externalDirectTransportKind
	}{
		{name: "empty", env: "", want: externalDirectTransportBlast},
		{name: "blast", env: "blast", want: externalDirectTransportBlast},
		{name: "quic", env: "quic", want: externalDirectTransportQUIC},
		{name: "auto", env: "auto", want: externalDirectTransportAuto},
		{name: "unknown", env: "unknown", want: externalDirectTransportBlast},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DERPHOLE_DIRECT_TRANSPORT", tt.env)
			if got := externalDirectTransportFromEnv(); got != tt.want {
				t.Fatalf("externalDirectTransportFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSendExternalDispatchesQUICWhenSelected(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "quic")

	sentinel := errors.New("quic send")
	prevUDP := sendExternalViaDirectUDPFn
	prevQUIC := sendExternalViaDirectQUICFn
	t.Cleanup(func() {
		sendExternalViaDirectUDPFn = prevUDP
		sendExternalViaDirectQUICFn = prevQUIC
	})

	sendExternalViaDirectUDPFn = func(context.Context, SendConfig) error {
		t.Fatal("sendExternal called Direct UDP hook, want QUIC")
		return nil
	}
	quicCalled := false
	sendExternalViaDirectQUICFn = func(context.Context, SendConfig) error {
		quicCalled = true
		return sentinel
	}

	err := sendExternal(context.Background(), SendConfig{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("sendExternal() error = %v, want %v", err, sentinel)
	}
	if !quicCalled {
		t.Fatal("sendExternal did not call QUIC hook")
	}
}

func TestListenExternalDispatchesQUICWhenSelected(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	t.Setenv("DERPHOLE_DIRECT_TRANSPORT", "quic")

	sentinel := errors.New("quic listen")
	prevUDP := listenExternalViaDirectUDPFn
	prevQUIC := listenExternalViaDirectQUICFn
	t.Cleanup(func() {
		listenExternalViaDirectUDPFn = prevUDP
		listenExternalViaDirectQUICFn = prevQUIC
	})

	listenExternalViaDirectUDPFn = func(context.Context, ListenConfig) (string, error) {
		t.Fatal("listenExternal called Direct UDP hook, want QUIC")
		return "", nil
	}
	quicCalled := false
	listenExternalViaDirectQUICFn = func(context.Context, ListenConfig) (string, error) {
		quicCalled = true
		return "", sentinel
	}

	_, err := listenExternal(context.Background(), ListenConfig{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("listenExternal() error = %v, want %v", err, sentinel)
	}
	if !quicCalled {
		t.Fatal("listenExternal did not call QUIC hook")
	}
}
