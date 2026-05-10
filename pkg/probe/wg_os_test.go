// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestWireGuardOSRejectsInvalidConfigBeforeCreatingDevice(t *testing.T) {
	_, err := SendWireGuardOS(context.Background(), nil, strings.NewReader("x"), WireGuardConfig{})
	if err == nil || !strings.Contains(err.Error(), "nil packet conn") {
		t.Fatalf("SendWireGuardOS(nil conn) error = %v, want nil packet conn", err)
	}
	_, err = ReceiveWireGuardOSToWriter(context.Background(), nil, io.Discard, WireGuardConfig{})
	if err == nil || !strings.Contains(err.Error(), "nil packet conn") {
		t.Fatalf("ReceiveWireGuardOSToWriter(nil conn) error = %v, want nil packet conn", err)
	}
}

func TestWireGuardOSUAPIAndAddressHelpers(t *testing.T) {
	var privateKey [32]byte
	var peerPublic [32]byte
	privateKey[0] = 0x11
	peerPublic[31] = 0x22
	cfg := resolvedWireGuardConfig{
		privateKey: privateKey,
		peerPublic: peerPublic,
		localAddr:  netip.MustParseAddr("169.254.100.1"),
		peerAddr:   netip.MustParseAddr("fd7a:115c:a1e0::1"),
	}

	uapi := wireGuardUAPI(cfg, "127.0.0.1:54321")
	for _, want := range []string{
		"private_key=11",
		"public_key=000000",
		"allowed_ip=fd7a:115c:a1e0::1/128",
		"endpoint=127.0.0.1:54321",
	} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("wireGuardUAPI() = %q, want substring %q", uapi, want)
		}
	}
	if got := wireGuardAllowedIP(netip.MustParseAddr("169.254.100.2")); got != "169.254.100.2/32" {
		t.Fatalf("wireGuardAllowedIP(v4) = %q, want /32", got)
	}
	if got := wireGuardInitialEndpoint(""); got != "derp" {
		t.Fatalf("wireGuardInitialEndpoint(empty) = %q, want derp", got)
	}
	if got := encodeHex32(privateKey); len(got) != 64 || !strings.HasPrefix(got, "11") {
		t.Fatalf("encodeHex32() = %q, want 64-char hex with prefix 11", got)
	}
}

func TestPlatformWGInterfaceHintUsesPlatformConvention(t *testing.T) {
	got := platformWGInterfaceHint()
	if runtime.GOOS == "darwin" {
		if got != "utun" {
			t.Fatalf("platformWGInterfaceHint() = %q, want utun", got)
		}
		return
	}
	if !strings.HasPrefix(got, "dcpwg") {
		t.Fatalf("platformWGInterfaceHint() = %q, want dcpwg prefix", got)
	}
}

func TestRunInterfaceCommandReportsCommandOutput(t *testing.T) {
	err := runInterfaceCommand("sh", "-c", "echo interface failure >&2; exit 7")
	if err == nil || !strings.Contains(err.Error(), "interface failure") {
		t.Fatalf("runInterfaceCommand(failing sh) error = %v, want stderr detail", err)
	}
	err = runInterfaceCommand("sh", "-c", "exit 7")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("runInterfaceCommand(failing quiet sh) error = %v, want ExitError wrapper", err)
	}
}
