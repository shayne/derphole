// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"net/netip"
	"testing"
)

func TestExternalNativeTCPTokenBootstrapAddrRequiresBindOverride(t *testing.T) {
	t.Setenv(externalNativeTCPAdvertiseAddrEnv, "198.51.100.10:443")

	if got, ok := externalNativeTCPTokenBootstrapAddr(); ok || got.IsValid() {
		t.Fatalf("externalNativeTCPTokenBootstrapAddr() = (%v, %t), want disabled without bind override", got, ok)
	}
}

func TestExternalNativeTCPTokenBootstrapAddrUsesAdvertisedPort(t *testing.T) {
	t.Setenv(externalNativeTCPBindAddrEnv, "127.0.0.1:443")
	t.Setenv(externalNativeTCPAdvertiseAddrEnv, "bad, 198.51.100.10:0, 198.51.100.20:8443")

	got, ok := externalNativeTCPTokenBootstrapAddr()
	if !ok {
		t.Fatal("externalNativeTCPTokenBootstrapAddr() ok = false, want true")
	}
	want := netip.MustParseAddrPort("198.51.100.20:8443")
	if got != want {
		t.Fatalf("externalNativeTCPTokenBootstrapAddr() = %v, want %v", got, want)
	}
}

func TestExternalNativeTCPTokenBootstrapAddrRejectsInvalidAdvertiseValues(t *testing.T) {
	t.Setenv(externalNativeTCPBindAddrEnv, "127.0.0.1:443")
	t.Setenv(externalNativeTCPAdvertiseAddrEnv, "bad, 198.51.100.10:0")

	if got, ok := externalNativeTCPTokenBootstrapAddr(); ok || got.IsValid() {
		t.Fatalf("externalNativeTCPTokenBootstrapAddr() = (%v, %t), want no valid advertise addr", got, ok)
	}
}
