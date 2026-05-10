// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
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

func TestTopologyUDPTargetsDedupesDNSAndAddsRemoteEgress(t *testing.T) {
	got := topologyUDPTargets([]string{
		"203.0.113.10",
		"203.0.113.10",
		"2001:db8::1",
		"not-an-ip",
	}, "198.51.100.20", 47000)

	want := []topologyUDPTarget{
		{label: "dns-a", address: "203.0.113.10:47000"},
		{label: "dns-aaaa-2", address: "[2001:db8::1]:47000"},
		{label: "remote-egress", address: "198.51.100.20:47000"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("topologyUDPTargets() = %#v, want %#v", got, want)
	}
}

func TestTopologyRemoteEchoLogCombinesPacketsAndErrors(t *testing.T) {
	got := topologyRemoteEchoLog(topologyRemoteEchoReport{
		Received: []topologyEchoPacket{
			{Payload: "probe-1", Peer: "203.0.113.10:47000"},
			{},
		},
		Error: "remote timeout",
	}, "ssh stderr")

	for _, want := range []string{"probe-1 from 203.0.113.10:47000", "error: remote timeout", "stderr: ssh stderr"} {
		if !strings.Contains(got, want) {
			t.Fatalf("topologyRemoteEchoLog() = %q, missing %q", got, want)
		}
	}
}

func TestTopologyUDPReachabilityErrorUsesRemoteReportAndTimeouts(t *testing.T) {
	target := topologyUDPTarget{label: "dns-a", address: "203.0.113.10:47000"}
	if err := topologyUDPReachabilityError(target, map[string]bool{"dns-a": true}, nil, topologyRemoteEchoReport{Error: "remote failed"}, errors.New("read timeout")); err != nil {
		t.Fatalf("received target error = %v, want nil", err)
	}
	if err := topologyUDPReachabilityError(target, nil, nil, topologyRemoteEchoReport{}, errors.New("read timeout")); err == nil || err.Error() != "read timeout" {
		t.Fatalf("wait error = %v, want read timeout", err)
	}
	if err := topologyUDPReachabilityError(target, nil, nil, topologyRemoteEchoReport{Error: "remote failed"}, errors.New("read timeout")); err == nil || err.Error() != "timeout" {
		t.Fatalf("remote-report error = %v, want timeout", err)
	}
}

func TestTopologyLookupEgressIPUsesFirstValidHTTPResponse(t *testing.T) {
	oldClient := topologyHTTPClient
	defer func() { topologyHTTPClient = oldClient }()

	var calls int
	topologyHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("first endpoint unavailable")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(" 203.0.113.44\n")),
		}, nil
	})}

	got, err := topologyLookupEgressIP(context.Background(), TopologyConfig{})
	if err != nil {
		t.Fatalf("topologyLookupEgressIP() error = %v", err)
	}
	if got != "203.0.113.44" {
		t.Fatalf("egress IP = %q, want 203.0.113.44", got)
	}
	if calls != 2 {
		t.Fatalf("HTTP calls = %d, want fallback second call", calls)
	}
}

func TestTopologyLookupEgressIPReportsAllFailures(t *testing.T) {
	oldClient := topologyHTTPClient
	defer func() { topologyHTTPClient = oldClient }()

	topologyHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Body:       io.NopCloser(strings.NewReader("bad gateway")),
		}, nil
	})}

	_, err := topologyLookupEgressIP(context.Background(), TopologyConfig{EgressURL: "https://example.invalid/ip"})
	if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("topologyLookupEgressIP() error = %v, want status failure", err)
	}
}

func TestDefaultTopologyLookupDNSAndLocalHostFacts(t *testing.T) {
	t.Parallel()

	got, err := defaultTopologyLookupDNS(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("defaultTopologyLookupDNS(localhost) error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("defaultTopologyLookupDNS(localhost) returned no addresses")
	}

	oldClient := topologyHTTPClient
	defer func() { topologyHTTPClient = oldClient }()
	topologyHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("2001:db8::44\n")),
		}, nil
	})}
	host, err := defaultTopologyGatherLocalHost(context.Background(), TopologyConfig{EgressURL: "https://example.test/ip"})
	if err != nil {
		t.Fatalf("defaultTopologyGatherLocalHost() error = %v", err)
	}
	if host.Hostname == "" {
		t.Fatal("local hostname is empty")
	}
	if host.EgressIP != "2001:db8::44" {
		t.Fatalf("local egress IP = %q, want 2001:db8::44", host.EgressIP)
	}
}

func TestTopologyReadAndBuildReachabilityHelpers(t *testing.T) {
	t.Parallel()

	proc := &topologySSHProcess{
		scanner: bufio.NewScanner(strings.NewReader(`{"error":"remote bind failed"}` + "\n")),
		stderr:  bytes.NewBufferString("ssh stderr\n"),
		wait:    func() error { return errors.New("ssh exit") },
	}
	report, stderr, err := topologyReadRemoteEchoReport(context.Background(), proc)
	if report.Error != "remote bind failed" || stderr != "ssh stderr" || err == nil {
		t.Fatalf("topologyReadRemoteEchoReport() = %#v %q %v, want remote error, stderr, wait error", report, stderr, err)
	}

	results := topologyBuildUDPReachabilityResults(
		[]topologyUDPTarget{{label: "dns-a", address: "203.0.113.10:47000"}},
		map[string]bool{},
		map[string]bool{},
		report,
		errors.New("wait failed"),
		"stderr text",
		25*time.Millisecond,
	)
	if len(results) != 1 || results[0].Error != "timeout" || !strings.Contains(results[0].RemoteLog, "remote bind failed") {
		t.Fatalf("topologyBuildUDPReachabilityResults() = %#v, want timeout with remote log", results)
	}
}

func TestTopologyReadUDPReachabilityReplyMarksAcks(t *testing.T) {
	t.Parallel()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(sender) error = %v", err)
	}
	defer sender.Close()

	payloadByLabel := map[string]string{"local": "derphole-topology:local"}
	replyByLabel := map[string]bool{}
	if _, err := sender.WriteTo([]byte("ack:derphole-topology:local"), conn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if !topologyReadUDPReachabilityReply(conn, make([]byte, 128), payloadByLabel, replyByLabel) {
		t.Fatal("topologyReadUDPReachabilityReply() = false, want true after packet")
	}
	if !replyByLabel["local"] {
		t.Fatalf("replyByLabel = %#v, want local ack", replyByLabel)
	}

	topologyMarkReplyByLabel("ack:unknown", payloadByLabel, replyByLabel)
	if len(replyByLabel) != 1 {
		t.Fatalf("replyByLabel = %#v, unknown ack should not add labels", replyByLabel)
	}
}

func TestTopologyPunchCandidateAndFinalizeHelpers(t *testing.T) {
	oldDiscover := topologyDiscoverCandidates
	defer func() { topologyDiscoverCandidates = oldDiscover }()

	topologyDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return []net.Addr{
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 47000},
			&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 47000},
		}, nil
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()
	candidates, early, err := topologyPunchLocalCandidates(context.Background(), conn)
	if err != nil || early != nil || len(candidates) != 1 || candidates[0] != "203.0.113.10:47000" {
		t.Fatalf("topologyPunchLocalCandidates() = %v %#v %v, want deduped candidate", candidates, early, err)
	}

	topologyDiscoverCandidates = func(ctx context.Context, conn net.PacketConn) ([]net.Addr, error) {
		return nil, errors.New("stun failed")
	}
	candidates, early, err = topologyPunchLocalCandidates(context.Background(), conn)
	if err != nil || candidates != nil || len(early) != 1 || !strings.Contains(early[0].Error, "stun failed") {
		t.Fatalf("topologyPunchLocalCandidates(error) = %v %#v %v, want early error result", candidates, early, err)
	}

	result := topologyInitialPunchResult([]string{"127.0.0.1:1"}, topologyPunchReady{address: "198.51.100.10:2", candidates: []string{"198.51.100.10:2"}})
	topologyHandleLocalPunchMessage(conn, "ignored", conn.LocalAddr(), &result)
	if result.LocalReceived {
		t.Fatal("ignored local punch message marked LocalReceived")
	}
	topologyFinalizePunchResult(&result, topologyRemotePunchReport{
		LocalAddress: "198.51.100.10:47000",
		Candidates:   []string{"198.51.100.10:47000"},
		Received:     []topologyEchoPacket{{Payload: "derphole-topology:punch-local"}},
	}, nil, "")
	if !result.RemoteReceived || result.Error != "" {
		t.Fatalf("finalized punch result = %#v, want remote success", result)
	}

	var timedOut UDPPunchResult
	topologyFinalizePunchResult(&timedOut, topologyRemotePunchReport{}, nil, "")
	if timedOut.Error != "timeout" {
		t.Fatalf("timeout result error = %q, want timeout", timedOut.Error)
	}
}

func TestTopologyScriptsAndReadyParsing(t *testing.T) {
	t.Parallel()

	echo := remoteUDPEchoScript(47000, 1500*time.Millisecond)
	if !strings.Contains(echo, "port = 47000") || !strings.Contains(echo, "duration = 1.500") {
		t.Fatalf("remoteUDPEchoScript() = %q, want port and duration", echo)
	}
	punch := remoteUDPPunchScript(`["127.0.0.1:1"]`, 2*time.Second)
	for _, want := range []string{`local_candidates = ["127.0.0.1:1"]`, "discover_stun_candidate", "duration = 2.000"} {
		if !strings.Contains(punch, want) {
			t.Fatalf("remoteUDPPunchScript() missing %q", want)
		}
	}

	ready := topologyParsePunchReady("READY 47001 198.51.100.10:47001,198.51.100.11:47001", TopologyHost{EgressIP: "198.51.100.12"})
	if ready.port != "47001" || ready.address != "198.51.100.10:47001" || len(ready.candidates) != 2 {
		t.Fatalf("topologyParsePunchReady() = %#v, want parsed candidates", ready)
	}
	ready = topologyParsePunchReady("READY ", TopologyHost{EgressIP: "198.51.100.12"})
	if ready.port != "" || ready.address != "" || ready.candidates != nil {
		t.Fatalf("topologyParsePunchReady(empty) = %#v, want zero fields", ready)
	}
}

func TestTopologyRunUDPReachabilityExchangeRecordsLocalAndRemoteAck(t *testing.T) {
	t.Parallel()

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(server) error = %v", err)
	}
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = server.WriteTo([]byte("ack:"+string(buf[:n])), addr)
		serverDone <- err
	}()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer conn.Close()

	proc := &topologySSHProcess{
		scanner: bufio.NewScanner(strings.NewReader(`{"received":[{"payload":"derphole-topology:loop","peer":"127.0.0.1:1"}]}` + "\n")),
		stderr:  &bytes.Buffer{},
		wait:    func() error { return nil },
	}
	results := topologyRunUDPReachabilityExchange(
		context.Background(),
		conn,
		proc,
		[]topologyUDPTarget{{label: "loop", address: server.LocalAddr().String()}},
		250*time.Millisecond,
	)
	if err := <-serverDone; err != nil {
		t.Fatalf("server echo error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if !results[0].Received || !results[0].Reply || results[0].Error != "" {
		t.Fatalf("reachability result = %#v, want received reply without error", results[0])
	}
	if !strings.Contains(results[0].RemoteLog, "derphole-topology:loop") {
		t.Fatalf("remote log = %q, want payload", results[0].RemoteLog)
	}
}

func TestTopologyRunPunchExchangeRecordsLocalAndRemoteReports(t *testing.T) {
	t.Parallel()

	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(local) error = %v", err)
	}
	defer local.Close()
	remote, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(remote) error = %v", err)
	}
	defer remote.Close()

	remoteDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		_, addr, err := remote.ReadFrom(buf)
		if err != nil {
			remoteDone <- err
			return
		}
		_, err = remote.WriteTo([]byte("derphole-topology:punch-remote"), addr)
		remoteDone <- err
	}()

	proc := &topologySSHProcess{
		scanner: bufio.NewScanner(strings.NewReader(`{"local_address":"198.51.100.10:47000","candidates":["198.51.100.10:47000"],"received":[{"payload":"derphole-topology:punch-local"}]}` + "\n")),
		stderr:  &bytes.Buffer{},
		wait:    func() error { return nil },
	}
	results := topologyRunPunchExchange(
		context.Background(),
		local,
		proc,
		50*time.Millisecond,
		[]string{local.LocalAddr().String()},
		topologyPunchReady{address: remote.LocalAddr().String(), candidates: []string{remote.LocalAddr().String()}},
	)
	if err := <-remoteDone; err != nil {
		t.Fatalf("remote punch error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	got := results[0]
	if !got.LocalReceived || !got.RemoteReceived || got.Error != "" {
		t.Fatalf("punch result = %#v, want local and remote success", got)
	}
}

func TestTopologyPunchReadyParsingAndErrors(t *testing.T) {
	t.Parallel()

	proc := &topologySSHProcess{
		scanner: bufio.NewScanner(strings.NewReader("READY 47000\n")),
		stderr:  &bytes.Buffer{},
		wait:    func() error { return nil },
	}
	ready, err := topologyReadPunchReady(context.Background(), proc, TopologyHost{EgressIP: "198.51.100.20"})
	if err != nil {
		t.Fatalf("topologyReadPunchReady() error = %v", err)
	}
	if ready.address != "198.51.100.20:47000" {
		t.Fatalf("ready address = %q, want egress fallback", ready.address)
	}

	bad := &topologySSHProcess{
		scanner: bufio.NewScanner(strings.NewReader("NOPE\n")),
		stderr:  &bytes.Buffer{},
		wait:    func() error { return nil },
	}
	if _, err := topologyReadPunchReady(context.Background(), bad, TopologyHost{}); err == nil {
		t.Fatal("topologyReadPunchReady() error = nil, want bad ready line")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
