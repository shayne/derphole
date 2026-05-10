// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

func TestRunReportsDirectFriendlyMapping(t *testing.T) {
	oldProbe := probeSTUNServer
	oldInterfaces := interfaceAddrs
	defer func() {
		probeSTUNServer = oldProbe
		interfaceAddrs = oldInterfaces
	}()
	probeSTUNServer = func(ctx context.Context, server string, localPort int) STUNServerResult {
		return STUNServerResult{
			Server:         server,
			LocalEndpoint:  fmt.Sprintf("0.0.0.0:%d", localPort),
			MappedEndpoint: fmt.Sprintf("203.0.113.10:%d", localPort),
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{mustCIDR(t, "192.168.1.20/24")}, nil
	}

	report, err := Run(context.Background(), Config{
		STUNServers:       []string{"stun-a:3478", "stun-b:3478"},
		FreshSocketChecks: 2,
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Verdict != VerdictDirectFriendly {
		t.Fatalf("Verdict = %q, want %q", report.Verdict, VerdictDirectFriendly)
	}
	if !report.UDP.MappingStable || !report.UDP.PortPreserving {
		t.Fatalf("UDP = %#v, want stable port-preserving mapping", report.UDP)
	}
	if len(report.UDP.PublicEndpoints) == 0 || report.UDP.PublicEndpoints[0] == "" {
		t.Fatalf("PublicEndpoints = %v, want at least one public endpoint", report.UDP.PublicEndpoints)
	}
	if len(report.Candidates.LAN) != 1 || report.Candidates.LAN[0] != "192.168.1.20" {
		t.Fatalf("LAN candidates = %v, want interface address", report.Candidates.LAN)
	}
	if report.Recommendation == "" {
		t.Fatal("Recommendation is empty")
	}
}

func TestRunReportsDirectLimitedWhenMappingChanges(t *testing.T) {
	oldProbe := probeSTUNServer
	oldInterfaces := interfaceAddrs
	defer func() {
		probeSTUNServer = oldProbe
		interfaceAddrs = oldInterfaces
	}()
	count := 0
	probeSTUNServer = func(ctx context.Context, server string, localPort int) STUNServerResult {
		count++
		return STUNServerResult{
			Server:         server,
			LocalEndpoint:  fmt.Sprintf("0.0.0.0:%d", localPort),
			MappedEndpoint: fmt.Sprintf("198.51.100.20:%d", 50000+count),
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, nil
	}

	report, err := Run(context.Background(), Config{
		STUNServers:       []string{"stun-a:3478", "stun-b:3478"},
		FreshSocketChecks: 1,
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Verdict != VerdictDirectLimited {
		t.Fatalf("Verdict = %q, want %q", report.Verdict, VerdictDirectLimited)
	}
	if report.UDP.MappingStable {
		t.Fatalf("MappingStable = true, want false")
	}
	if report.UDP.PortPreserving {
		t.Fatalf("PortPreserving = true, want false")
	}
}

func TestRunReportsRelayOnlyLikelyWhenSTUNFails(t *testing.T) {
	oldProbe := probeSTUNServer
	oldInterfaces := interfaceAddrs
	defer func() {
		probeSTUNServer = oldProbe
		interfaceAddrs = oldInterfaces
	}()
	probeSTUNServer = func(ctx context.Context, server string, localPort int) STUNServerResult {
		return STUNServerResult{
			Server:        server,
			LocalEndpoint: fmt.Sprintf("0.0.0.0:%d", localPort),
			Error:         "timeout",
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, nil
	}

	report, err := Run(context.Background(), Config{
		STUNServers:       []string{"stun-a:3478"},
		FreshSocketChecks: 0,
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Verdict != VerdictRelayOnlyLikely {
		t.Fatalf("Verdict = %q, want %q", report.Verdict, VerdictRelayOnlyLikely)
	}
	if report.UDP.Outbound || report.UDP.STUN {
		t.Fatalf("UDP = %#v, want blocked", report.UDP)
	}
}

func TestSTUNListenAddress(t *testing.T) {
	if got, want := stunListenAddress(0), "0.0.0.0:0"; got != want {
		t.Fatalf("stunListenAddress(0) = %q, want %q", got, want)
	}
	if got, want := stunListenAddress(19302), "0.0.0.0:19302"; got != want {
		t.Fatalf("stunListenAddress(19302) = %q, want %q", got, want)
	}
}

func TestDefaultProbeSTUNServerReceivesMappedEndpoint(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	mapped := netip.MustParseAddrPort("203.0.113.42:45678")
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		txID, err := stun.ParseBindingRequest(buf[:n])
		if err != nil {
			done <- err
			return
		}
		_, err = server.WriteTo(stun.Response(txID, mapped), addr)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := defaultProbeSTUNServer(ctx, server.LocalAddr().String(), 0)
	if result.Error != "" {
		t.Fatalf("defaultProbeSTUNServer() error = %q", result.Error)
	}
	if result.MappedEndpoint != mapped.String() {
		t.Fatalf("MappedEndpoint = %q, want %q", result.MappedEndpoint, mapped)
	}
	if result.LocalEndpoint == "" {
		t.Fatal("LocalEndpoint is empty")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("STUN server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("STUN server did not receive request")
	}
}

func TestDefaultProbeSTUNServerReportsResolveError(t *testing.T) {
	result := defaultProbeSTUNServer(context.Background(), "not a valid udp addr", 0)
	if result.Error == "" {
		t.Fatal("defaultProbeSTUNServer() Error is empty, want resolver error")
	}
}

func TestReadSTUNResponseOnceIgnoresTimeoutAndMismatchedResponse(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	txID := stun.NewTxID()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if mapped, done, err := readSTUNResponseOnce(ctx, conn, txID, make([]byte, 2048)); mapped != "" || done || err != nil {
		t.Fatalf("readSTUNResponseOnce(timeout) = %q, %v, %v; want empty retry", mapped, done, err)
	}

	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	otherTxID := stun.NewTxID()
	if _, err := sender.WriteTo(stun.Response(otherTxID, netip.MustParseAddrPort("198.51.100.1:1234")), conn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if mapped, done, err := readSTUNResponseOnce(ctx, conn, txID, make([]byte, 2048)); mapped != "" || done || err != nil {
		t.Fatalf("readSTUNResponseOnce(mismatch) = %q, %v, %v; want ignored packet", mapped, done, err)
	}
}

func TestSTUNServerResultStringIncludesPresentFields(t *testing.T) {
	result := STUNServerResult{
		Server:         "stun.example:3478",
		LocalEndpoint:  "0.0.0.0:1234",
		MappedEndpoint: "203.0.113.5:1234",
		Error:          "timeout",
	}
	got := result.String()
	for _, want := range []string{"stun.example:3478", "local=0.0.0.0:1234", "mapped=203.0.113.5:1234", "error=timeout"} {
		if !strings.Contains(got, want) {
			t.Fatalf("STUNServerResult.String() = %q, missing %q", got, want)
		}
	}
}

func TestSTUNReadDeadlineUsesSoonerContextDeadline(t *testing.T) {
	now := time.Unix(100, 0)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(50*time.Millisecond))
	defer cancel()

	if got, want := stunReadDeadline(ctx, now), now.Add(50*time.Millisecond); !got.Equal(want) {
		t.Fatalf("stunReadDeadline() = %v, want %v", got, want)
	}
}

func TestSTUNReadDeadlineCapsAtProbeInterval(t *testing.T) {
	now := time.Unix(100, 0)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel()

	if got, want := stunReadDeadline(ctx, now), now.Add(250*time.Millisecond); !got.Equal(want) {
		t.Fatalf("stunReadDeadline() = %v, want %v", got, want)
	}
}

func TestMappingStableUsesSharedLocalEndpointBeforeGlobalComparison(t *testing.T) {
	results := []STUNServerResult{
		{LocalEndpoint: "0.0.0.0:1000", MappedEndpoint: "203.0.113.10:1000"},
		{LocalEndpoint: "0.0.0.0:1000", MappedEndpoint: "203.0.113.10:1000"},
		{LocalEndpoint: "0.0.0.0:1001", MappedEndpoint: "203.0.113.11:1001"},
	}

	if !mappingStable(results) {
		t.Fatal("mappingStable() = false, want true from repeated local endpoint")
	}
}

func TestMappingStableFallsBackToAllMappedEndpoints(t *testing.T) {
	stable := []STUNServerResult{
		{LocalEndpoint: "0.0.0.0:1000", MappedEndpoint: "203.0.113.10:1000"},
		{LocalEndpoint: "0.0.0.0:1001", MappedEndpoint: "203.0.113.10:1000"},
	}
	unstable := []STUNServerResult{
		{LocalEndpoint: "0.0.0.0:1000", MappedEndpoint: "203.0.113.10:1000"},
		{LocalEndpoint: "0.0.0.0:1001", MappedEndpoint: "203.0.113.11:1001"},
	}

	if !mappingStable(stable) {
		t.Fatal("mappingStable(stable) = false, want true")
	}
	if mappingStable(unstable) {
		t.Fatal("mappingStable(unstable) = true, want false")
	}
}

func mustCIDR(t *testing.T, raw string) net.Addr {
	t.Helper()
	prefix := netip.MustParsePrefix(raw)
	return &net.IPNet{
		IP:   append(net.IP(nil), prefix.Addr().AsSlice()...),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}
