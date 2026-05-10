// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestClassifyTopologyDetectsSSHFrontDoorMismatch(t *testing.T) {
	report := TopologyReport{
		DNSAddresses: []string{"161.210.92.1"},
		Remote: TopologyHost{
			EgressIP: "44.240.253.236",
			Interfaces: []TopologyInterface{
				{Name: "eth0", Addrs: []string{"10.42.0.64/16"}},
			},
		},
	}

	got := ClassifyTopology(report)

	if !slices.Contains(got, TopologyClassSSHFrontDoorMismatch) {
		t.Fatalf("ClassifyTopology() = %v, want %s", got, TopologyClassSSHFrontDoorMismatch)
	}
}

func TestClassifyTopologyDetectsRemoteUDPUnreachable(t *testing.T) {
	report := TopologyReport{
		UDPReachability: []UDPReachabilityResult{
			{Target: "dns-a", Address: "161.210.92.1:47000", Received: false},
			{Target: "egress", Address: "44.240.253.236:47000", Received: false},
		},
	}

	got := ClassifyTopology(report)

	if !slices.Contains(got, TopologyClassRemoteUDPUnreachable) {
		t.Fatalf("ClassifyTopology() = %v, want %s", got, TopologyClassRemoteUDPUnreachable)
	}
}

func TestClassifyTopologyDetectsDirectUDPPossible(t *testing.T) {
	report := TopologyReport{
		UDPReachability: []UDPReachabilityResult{
			{Target: "egress", Address: "203.0.113.10:47000", Received: true},
		},
		PunchTests: []UDPPunchResult{
			{Name: "simultaneous", LocalReceived: true, RemoteReceived: true},
		},
	}

	got := ClassifyTopology(report)

	if !slices.Contains(got, TopologyClassDirectUDPPossible) {
		t.Fatalf("ClassifyTopology() = %v, want %s", got, TopologyClassDirectUDPPossible)
	}
}

func TestTopologySSHCommandFormatsTarget(t *testing.T) {
	cmd := topologySSHCommand(SSHRunner{User: "exedev", Host: "ion-rain.exe.xyz"}, "printf ok")

	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, "exedev@ion-rain.exe.xyz") {
		t.Fatalf("topologySSHCommand() = %v, missing ssh target", cmd)
	}
	if got := cmd[len(cmd)-1]; got != "printf ok" {
		t.Fatalf("topologySSHCommand() last arg = %q, want remote script", got)
	}
}

func TestDecodeRemoteTopologyHost(t *testing.T) {
	raw := []byte(`{
		"hostname": "ion-rain",
		"egress_ip": "44.240.253.236",
		"interfaces": [{"name": "eth0", "addrs": ["10.42.0.64/16"]}],
		"firewall": ["iptables -S: -P INPUT ACCEPT"],
		"udp_listen": ["UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*"]
	}`)

	got, err := decodeRemoteTopologyHost(raw)
	if err != nil {
		t.Fatalf("decodeRemoteTopologyHost() error = %v", err)
	}
	if got.Hostname != "ion-rain" {
		t.Fatalf("hostname = %q, want ion-rain", got.Hostname)
	}
	if got.EgressIP != "44.240.253.236" {
		t.Fatalf("egress IP = %q, want 44.240.253.236", got.EgressIP)
	}
	if len(got.Interfaces) != 1 || got.Interfaces[0].Name != "eth0" || got.Interfaces[0].Addrs[0] != "10.42.0.64/16" {
		t.Fatalf("interfaces = %#v, want eth0 private address", got.Interfaces)
	}
	if len(got.Firewall) == 0 {
		t.Fatal("firewall summary is empty")
	}
	if len(got.UDPListen) == 0 {
		t.Fatal("UDP listener summary is empty")
	}
}

func TestTopologyUDPReachabilityResultRecordsSuccessAndFailure(t *testing.T) {
	success := topologyUDPReachabilityResult("dns-a", "203.0.113.10:47000", true, true, 42*time.Millisecond, nil, "received from 198.51.100.1")
	if !success.Received || !success.Reply {
		t.Fatalf("success result = %#v, want received reply", success)
	}
	if success.ElapsedMS != 42 {
		t.Fatalf("success elapsed = %d, want 42", success.ElapsedMS)
	}
	if success.Error != "" {
		t.Fatalf("success error = %q, want empty", success.Error)
	}

	failure := topologyUDPReachabilityResult("egress", "203.0.113.20:47000", false, false, 2*time.Second, errors.New("timeout"), "")
	if failure.Received || failure.Reply {
		t.Fatalf("failure result = %#v, want no received/reply", failure)
	}
	if failure.Error != "timeout" {
		t.Fatalf("failure error = %q, want timeout", failure.Error)
	}
}

func TestRunTopologyDiagnosticsBuildsReportAndClassifies(t *testing.T) {
	oldLookupDNS := topologyLookupDNS
	oldGatherLocal := topologyGatherLocalHost
	oldGatherRemote := topologyGatherRemoteHost
	oldUDPReachability := topologyCheckUDPReachability
	oldPunchTests := topologyRunPunchTests
	defer func() {
		topologyLookupDNS = oldLookupDNS
		topologyGatherLocalHost = oldGatherLocal
		topologyGatherRemoteHost = oldGatherRemote
		topologyCheckUDPReachability = oldUDPReachability
		topologyRunPunchTests = oldPunchTests
	}()

	topologyLookupDNS = func(ctx context.Context, host string) ([]string, error) {
		if host != "ion-rain.exe.xyz" {
			t.Fatalf("lookup host = %q, want ion-rain.exe.xyz", host)
		}
		return []string{"161.210.92.1"}, nil
	}
	topologyGatherLocalHost = func(ctx context.Context, cfg TopologyConfig) (TopologyHost, error) {
		return TopologyHost{Hostname: "mac", EgressIP: "108.18.210.122"}, nil
	}
	topologyGatherRemoteHost = func(ctx context.Context, cfg TopologyConfig) (TopologyHost, error) {
		if cfg.User != "exedev" {
			t.Fatalf("remote user = %q, want exedev", cfg.User)
		}
		return TopologyHost{
			Hostname: "ion-rain",
			EgressIP: "44.240.253.236",
			Interfaces: []TopologyInterface{
				{Name: "eth0", Addrs: []string{"10.42.0.64/16"}},
			},
		}, nil
	}
	topologyCheckUDPReachability = func(ctx context.Context, cfg TopologyConfig, dns []string, remote TopologyHost) ([]UDPReachabilityResult, error) {
		if len(dns) != 1 || dns[0] != "161.210.92.1" {
			t.Fatalf("dns = %v, want DNS A", dns)
		}
		if remote.EgressIP != "44.240.253.236" {
			t.Fatalf("remote egress = %q, want 44.240.253.236", remote.EgressIP)
		}
		return []UDPReachabilityResult{
			{Target: "dns-a", Address: "161.210.92.1:47000", Received: false},
			{Target: "remote-egress", Address: "44.240.253.236:47000", Received: false},
		}, nil
	}
	topologyRunPunchTests = func(ctx context.Context, cfg TopologyConfig, remote TopologyHost) ([]UDPPunchResult, error) {
		return []UDPPunchResult{{Name: "simultaneous", LocalReceived: false, RemoteReceived: false}}, nil
	}

	got, err := RunTopologyDiagnostics(context.Background(), TopologyConfig{
		Host:    "ion-rain.exe.xyz",
		User:    "exedev",
		UDPPort: 47000,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("RunTopologyDiagnostics() error = %v", err)
	}
	if got.Target != "exedev@ion-rain.exe.xyz" {
		t.Fatalf("target = %q, want exedev@ion-rain.exe.xyz", got.Target)
	}
	if !slices.Contains(got.Classifications, TopologyClassSSHFrontDoorMismatch) {
		t.Fatalf("classifications = %v, want front door mismatch", got.Classifications)
	}
	if !slices.Contains(got.Classifications, TopologyClassRemoteUDPUnreachable) {
		t.Fatalf("classifications = %v, want UDP unreachable", got.Classifications)
	}
}
