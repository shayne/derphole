// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTopologyUDPPort = 47000
	defaultTopologyTimeout = 5 * time.Second
)

var (
	topologyLookupDNS            = defaultTopologyLookupDNS
	topologyGatherLocalHost      = defaultTopologyGatherLocalHost
	topologyGatherRemoteHost     = defaultTopologyGatherRemoteHost
	topologyCheckUDPReachability = defaultTopologyCheckUDPReachability
	topologyRunPunchTests        = defaultTopologyRunPunchTests
	topologyDiscoverCandidates   = DiscoverCandidates
	topologyHTTPClient           = http.DefaultClient
)

type TopologyConfig struct {
	Host      string
	User      string
	UDPPort   int
	Timeout   time.Duration
	EgressURL string
}

type topologyEchoPacket struct {
	Payload string `json:"payload,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Error   string `json:"error,omitempty"`
}

type topologyRemoteEchoReport struct {
	Received []topologyEchoPacket `json:"received,omitempty"`
	Error    string               `json:"error,omitempty"`
}

type topologyRemotePunchReport struct {
	LocalAddress string               `json:"local_address,omitempty"`
	Candidates   []string             `json:"candidates,omitempty"`
	Received     []topologyEchoPacket `json:"received,omitempty"`
	SentTo       []string             `json:"sent_to,omitempty"`
	Error        string               `json:"error,omitempty"`
}

type topologyUDPTarget struct {
	label   string
	address string
}

type topologyPunchReady struct {
	port       string
	candidates []string
	address    string
}

type topologySSHProcess struct {
	scanner *bufio.Scanner
	stderr  *bytes.Buffer
	wait    func() error
}

func RunTopologyDiagnostics(ctx context.Context, cfg TopologyConfig) (TopologyReport, error) {
	if ctx == nil {
		return TopologyReport{}, errors.New("nil context")
	}
	cfg = normalizeTopologyConfig(cfg)
	if err := validateTopologyConfig(cfg); err != nil {
		return TopologyReport{}, err
	}

	runner := SSHRunner{User: cfg.User, Host: cfg.Host}
	report := TopologyReport{
		Host:   cfg.Host,
		Target: runner.target(),
	}
	collectTopologyDNS(ctx, cfg, &report)
	collectTopologyLocal(ctx, cfg, &report)
	collectTopologyRemote(ctx, cfg, &report)
	collectTopologyUDP(ctx, cfg, &report)
	report.Classifications = ClassifyTopology(report)
	return report, nil
}

func validateTopologyConfig(cfg TopologyConfig) error {
	if cfg.Host == "" {
		return errors.New("host is required")
	}
	if cfg.UDPPort <= 0 || cfg.UDPPort > 65535 {
		return fmt.Errorf("udp port must be between 1 and 65535")
	}
	return nil
}

func collectTopologyDNS(ctx context.Context, cfg TopologyConfig, report *TopologyReport) {
	stepCtx, cancel := topologyStepContext(ctx, cfg)
	dns, err := topologyLookupDNS(stepCtx, cfg.Host)
	cancel()
	if err != nil {
		report.Errors = append(report.Errors, "dns lookup: "+err.Error())
	} else {
		report.DNSAddresses = dns
	}
}

func collectTopologyLocal(ctx context.Context, cfg TopologyConfig, report *TopologyReport) {
	stepCtx, cancel := topologyStepContext(ctx, cfg)
	local, err := topologyGatherLocalHost(stepCtx, cfg)
	cancel()
	if err != nil {
		report.Local = TopologyHost{Error: err.Error()}
		report.Errors = append(report.Errors, "local facts: "+err.Error())
	} else {
		report.Local = local
	}
}

func collectTopologyRemote(ctx context.Context, cfg TopologyConfig, report *TopologyReport) {
	stepCtx, cancel := topologyStepContextWithTimeout(ctx, cfg.Timeout+10*time.Second)
	remote, err := topologyGatherRemoteHost(stepCtx, cfg)
	cancel()
	if err != nil {
		report.Remote = TopologyHost{Error: err.Error()}
		report.Errors = append(report.Errors, "remote facts: "+err.Error())
	} else {
		report.Remote = remote
	}
}

func collectTopologyUDP(ctx context.Context, cfg TopologyConfig, report *TopologyReport) {
	if report.Remote.Error != "" {
		return
	}
	udpResults, err := topologyCheckUDPReachability(ctx, cfg, report.DNSAddresses, report.Remote)
	if err != nil {
		report.Errors = append(report.Errors, "udp reachability: "+err.Error())
	} else {
		report.UDPReachability = udpResults
	}

	punchResults, err := topologyRunPunchTests(ctx, cfg, report.Remote)
	if err != nil {
		report.Errors = append(report.Errors, "udp punch: "+err.Error())
	} else {
		report.PunchTests = punchResults
	}
}

func normalizeTopologyConfig(cfg TopologyConfig) TopologyConfig {
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.User = strings.TrimSpace(cfg.User)
	if cfg.UDPPort == 0 {
		cfg.UDPPort = defaultTopologyUDPPort
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTopologyTimeout
	}
	cfg.EgressURL = strings.TrimSpace(cfg.EgressURL)
	return cfg
}

func topologyStepContext(ctx context.Context, cfg TopologyConfig) (context.Context, context.CancelFunc) {
	return topologyStepContextWithTimeout(ctx, cfg.Timeout)
}

func topologyStepContextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func topologySSHCommand(runner SSHRunner, script string) []string {
	argv := []string{
		"ssh",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", defaultSSHConnectTimeoutSec),
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		argv = append(argv, "-o", "UserKnownHostsFile="+home+"/.ssh/known_hosts")
	}
	return append(argv, runner.target(), script)
}

func defaultTopologyLookupDNS(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ip := addr.IP.String()
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

func defaultTopologyGatherLocalHost(ctx context.Context, cfg TopologyConfig) (TopologyHost, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return TopologyHost{}, err
	}
	host := TopologyHost{Hostname: hostname}
	ifaces, err := topologyInterfaceSummaries()
	if err != nil {
		host.Error = err.Error()
	} else {
		host.Interfaces = ifaces
	}
	if egress, err := topologyLookupEgressIP(ctx, cfg); err == nil {
		host.EgressIP = egress
	} else if host.Error == "" {
		host.Error = "egress IP: " + err.Error()
	}
	return host, nil
}

func topologyInterfaceSummaries() ([]TopologyInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]TopologyInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		if summary, ok := topologyInterfaceSummary(iface); ok {
			out = append(out, summary)
		}
	}
	return out, nil
}

func topologyInterfaceSummary(iface net.Interface) (TopologyInterface, bool) {
	addrs, err := iface.Addrs()
	if err != nil {
		return TopologyInterface{}, false
	}
	summary := TopologyInterface{Name: iface.Name}
	for _, addr := range addrs {
		summary.Addrs = append(summary.Addrs, addr.String())
	}
	return summary, len(summary.Addrs) > 0
}

func topologyLookupEgressIP(ctx context.Context, cfg TopologyConfig) (string, error) {
	urls := []string{cfg.EgressURL}
	if cfg.EgressURL == "" {
		urls = []string{"https://api.ipify.org", "https://ifconfig.me/ip"}
	}
	var errs []string
	for _, url := range urls {
		if url == "" {
			continue
		}
		ip, err := lookupEgressURL(ctx, url)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return ip, nil
	}
	return "", fmt.Errorf("all egress lookups failed: %s", strings.Join(errs, "; "))
}

func lookupEgressURL(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := topologyHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := readAndCloseLimited(resp.Body, 128)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", errors.New(resp.Status)
	}
	return parseEgressIP(url, body)
}

func readAndCloseLimited(body io.ReadCloser, limit int64) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(body, limit))
	closeErr := body.Close()
	if readErr != nil {
		return nil, readErr
	}
	return data, closeErr
}

func parseEgressIP(url string, body []byte) (string, error) {
	ip := strings.TrimSpace(string(body))
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", fmt.Errorf("%s returned non-IP %q", url, ip)
	}
	return ip, nil
}

func defaultTopologyGatherRemoteHost(ctx context.Context, cfg TopologyConfig) (TopologyHost, error) {
	runner := SSHRunner{User: cfg.User, Host: cfg.Host}
	out, err := runCommand(ctx, topologySSHCommand(runner, remoteTopologyFactsScript()))
	if err != nil {
		return TopologyHost{}, err
	}
	return decodeRemoteTopologyHost(out)
}

func decodeRemoteTopologyHost(raw []byte) (TopologyHost, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return TopologyHost{}, errors.New("empty remote topology JSON")
	}
	start := bytes.IndexByte(raw, '{')
	end := bytes.LastIndexByte(raw, '}')
	if start < 0 || end < start {
		return TopologyHost{}, fmt.Errorf("remote topology output was not JSON: %q", string(raw))
	}
	var host TopologyHost
	if err := json.Unmarshal(raw[start:end+1], &host); err != nil {
		return TopologyHost{}, err
	}
	return host, nil
}

func remoteTopologyFactsScript() string {
	return `python3 - <<'PY'
import json
import shutil
import socket
import subprocess

def run(argv, limit=80):
    if not shutil.which(argv[0]):
        return []
    try:
        proc = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3)
    except Exception as exc:
        return [argv[0] + ": " + str(exc)]
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if proc.returncode != 0 and not lines:
        lines = [argv[0] + ": exit " + str(proc.returncode)]
    return lines[:limit]

def privileged(argv):
    if shutil.which("sudo"):
        return ["sudo", "-n"] + argv
    return argv

def permission_limited(lines):
    text = "\n".join(lines).lower()
    return (
        "password" in text
        or "permission denied" in text
        or "need to be root" in text
        or "operation not permitted" in text
    )

def run_privileged(argv, limit=80):
    lines = run(privileged(argv), limit=limit)
    if lines and not permission_limited(lines):
        return lines
    fallback = run(argv, limit=limit)
    if fallback:
        return fallback
    return lines

facts = {
    "hostname": socket.gethostname(),
    "egress_ip": "",
    "interfaces": [],
    "firewall": [],
    "udp_listen": [],
}

for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
    out = run(["curl", "-4", "-fsS", "--max-time", "3", url], limit=1)
    if out:
        facts["egress_ip"] = out[0]
        break

interfaces = {}
for line in run(["ip", "-o", "addr", "show"], limit=300):
    parts = line.split()
    if len(parts) < 4:
        continue
    name = parts[1].split("@", 1)[0]
    addr = parts[3]
    interfaces.setdefault(name, []).append(addr)
if not interfaces:
    addrs = run(["hostname", "-I"], limit=1)
    if addrs:
        interfaces["host"] = addrs[0].split()
facts["interfaces"] = [{"name": name, "addrs": addrs} for name, addrs in sorted(interfaces.items())]

for label, argv, limit in (
    ("iptables -S", ["iptables", "-S"], 80),
    ("ufw status", ["ufw", "status"], 40),
    ("nft list ruleset", ["nft", "list", "ruleset"], 80),
):
    lines = run_privileged(argv, limit=limit)
    if lines:
        facts["firewall"].extend([label + ": " + line for line in lines])

facts["udp_listen"] = run_privileged(["ss", "-H", "-lunp"], limit=120)
if not facts["udp_listen"]:
    facts["udp_listen"] = run_privileged(["netstat", "-anu"], limit=120)

print(json.dumps(facts, sort_keys=True))
PY`
}

func defaultTopologyCheckUDPReachability(ctx context.Context, cfg TopologyConfig, dns []string, remote TopologyHost) ([]UDPReachabilityResult, error) {
	targets := topologyUDPTargets(dns, remote.EgressIP, cfg.UDPPort)
	if len(targets) == 0 {
		return nil, nil
	}
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	runCtx, cancel, proc, err := startTopologyRemoteEcho(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := topologyWaitRemoteEchoReady(runCtx, proc); err != nil {
		return nil, err
	}
	return topologyRunUDPReachabilityExchange(runCtx, conn, proc, targets, cfg.Timeout), nil
}

func startTopologyRemoteEcho(ctx context.Context, cfg TopologyConfig) (context.Context, context.CancelFunc, *topologySSHProcess, error) {
	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout+2*time.Second)
	runner := SSHRunner{User: cfg.User, Host: cfg.Host}
	proc, err := startTopologySSHCommand(runCtx, runner, remoteUDPEchoScript(cfg.UDPPort, cfg.Timeout))
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return runCtx, cancel, proc, nil
}

func topologyWaitRemoteEchoReady(ctx context.Context, proc *topologySSHProcess) error {
	ready, err := proc.readLine(ctx)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(ready, "READY ") {
		return fmt.Errorf("remote UDP echo did not become ready: %s", ready)
	}
	return nil
}

func topologyRunUDPReachabilityExchange(ctx context.Context, conn net.PacketConn, proc *topologySSHProcess, targets []topologyUDPTarget, timeout time.Duration) []UDPReachabilityResult {
	payloadByLabel, started := topologySendUDPReachabilityProbes(conn, targets)
	replyByLabel := topologyCollectUDPReachabilityReplies(conn, payloadByLabel, timeout)
	remoteReport, stderr, waitErr := topologyReadRemoteEchoReport(ctx, proc)
	receivedByLabel := topologyEchoReceivedByLabel(remoteReport, payloadByLabel)
	return topologyBuildUDPReachabilityResults(targets, receivedByLabel, replyByLabel, remoteReport, waitErr, stderr, time.Since(started))
}

func topologySendUDPReachabilityProbes(conn net.PacketConn, targets []topologyUDPTarget) (map[string]string, time.Time) {
	payloadByLabel := make(map[string]string, len(targets))
	started := time.Now()
	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp", target.address)
		if err != nil {
			continue
		}
		payload := "derphole-topology:" + target.label
		payloadByLabel[target.label] = payload
		_, _ = conn.WriteTo([]byte(payload), addr)
	}
	return payloadByLabel, started
}

func topologyCollectUDPReachabilityReplies(conn net.PacketConn, payloadByLabel map[string]string, timeout time.Duration) map[string]bool {
	replyByLabel := make(map[string]bool, len(payloadByLabel))
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if !topologyReadUDPReachabilityReply(conn, buf, payloadByLabel, replyByLabel) {
			break
		}
	}
	return replyByLabel
}

func topologyReadUDPReachabilityReply(conn net.PacketConn, buf []byte, payloadByLabel map[string]string, replyByLabel map[string]bool) bool {
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return false
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		return false
	}
	topologyMarkReplyByLabel(string(buf[:n]), payloadByLabel, replyByLabel)
	return true
}

func topologyMarkReplyByLabel(msg string, payloadByLabel map[string]string, replyByLabel map[string]bool) {
	for label, payload := range payloadByLabel {
		if msg == "ack:"+payload {
			replyByLabel[label] = true
		}
	}
}

func topologyReadRemoteEchoReport(ctx context.Context, proc *topologySSHProcess) (topologyRemoteEchoReport, string, error) {
	var remoteReport topologyRemoteEchoReport
	if line, err := proc.readLine(ctx); err == nil {
		_ = json.Unmarshal([]byte(line), &remoteReport)
	}
	return remoteReport, strings.TrimSpace(proc.stderr.String()), proc.wait()
}

func topologyEchoReceivedByLabel(report topologyRemoteEchoReport, payloadByLabel map[string]string) map[string]bool {
	receivedByLabel := make(map[string]bool, len(payloadByLabel))
	for _, packet := range report.Received {
		for label, payload := range payloadByLabel {
			if packet.Payload == payload {
				receivedByLabel[label] = true
			}
		}
	}
	return receivedByLabel
}

func topologyBuildUDPReachabilityResults(
	targets []topologyUDPTarget,
	receivedByLabel map[string]bool,
	replyByLabel map[string]bool,
	remoteReport topologyRemoteEchoReport,
	waitErr error,
	stderr string,
	elapsed time.Duration,
) []UDPReachabilityResult {
	results := make([]UDPReachabilityResult, 0, len(targets))
	remoteLog := topologyRemoteEchoLog(remoteReport, stderr)
	for _, target := range targets {
		resultErr := topologyUDPReachabilityError(target, receivedByLabel, replyByLabel, remoteReport, waitErr)
		results = append(results, topologyUDPReachabilityResult(target.label, target.address, receivedByLabel[target.label], replyByLabel[target.label], elapsed, resultErr, remoteLog))
	}
	return results
}

func topologyUDPReachabilityError(target topologyUDPTarget, receivedByLabel map[string]bool, replyByLabel map[string]bool, remoteReport topologyRemoteEchoReport, waitErr error) error {
	if waitErr != nil && remoteReport.Error == "" {
		return waitErr
	}
	if !receivedByLabel[target.label] && !replyByLabel[target.label] {
		return errors.New("timeout")
	}
	return nil
}

func topologyUDPTargets(dns []string, remoteEgress string, port int) []topologyUDPTarget {
	seen := make(map[string]bool)
	var targets []topologyUDPTarget
	dnsCount := 0
	for _, ip := range dns {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
		if seen[address] {
			continue
		}
		seen[address] = true
		label := "dns-a"
		if addr.Is6() {
			label = "dns-aaaa"
		}
		dnsCount++
		if dnsCount > 1 {
			label = fmt.Sprintf("%s-%d", label, dnsCount)
		}
		targets = append(targets, topologyUDPTarget{label: label, address: address})
	}
	remoteEgress = strings.TrimSpace(remoteEgress)
	if remoteEgress != "" {
		if addr, err := netip.ParseAddr(remoteEgress); err == nil {
			address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
			if !seen[address] {
				targets = append(targets, topologyUDPTarget{label: "remote-egress", address: address})
			}
		}
	}
	return targets
}

func topologyUDPReachabilityResult(target, address string, received, reply bool, elapsed time.Duration, err error, remoteLog string) UDPReachabilityResult {
	result := UDPReachabilityResult{
		Target:    target,
		Address:   address,
		Received:  received,
		Reply:     reply,
		ElapsedMS: elapsed.Milliseconds(),
		RemoteLog: remoteLog,
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func remoteUDPEchoScript(port int, timeout time.Duration) string {
	duration := fmt.Sprintf("%.3f", timeout.Seconds())
	return fmt.Sprintf(`python3 -u - <<'PY'
import json
import socket
import time

port = %d
duration = %s
received = []
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.settimeout(0.1)
print("READY " + str(sock.getsockname()[1]), flush=True)
end = time.time() + duration
while time.time() < end:
    try:
        data, peer = sock.recvfrom(4096)
    except socket.timeout:
        continue
    msg = data.decode("utf-8", "replace")
    entry = {"payload": msg, "peer": peer[0] + ":" + str(peer[1])}
    try:
        sock.sendto(("ack:" + msg).encode("utf-8"), peer)
    except Exception as exc:
        entry["error"] = str(exc)
    received.append(entry)
print(json.dumps({"received": received}, sort_keys=True), flush=True)
PY`, port, duration)
}

func topologyRemoteEchoLog(report topologyRemoteEchoReport, stderr string) string {
	var parts []string
	for _, packet := range report.Received {
		parts = appendTopologyEchoPacketLog(parts, packet)
	}
	parts = appendTopologyLogField(parts, "error: ", report.Error)
	parts = appendTopologyLogField(parts, "stderr: ", stderr)
	return strings.Join(parts, "\n")
}

func appendTopologyEchoPacketLog(parts []string, packet topologyEchoPacket) []string {
	entry, ok := topologyEchoPacketLog(packet)
	if !ok {
		return parts
	}
	return append(parts, entry)
}

func topologyEchoPacketLog(packet topologyEchoPacket) (string, bool) {
	if packet.Payload == "" && packet.Peer == "" {
		return "", false
	}
	return strings.TrimSpace(packet.Payload + " from " + packet.Peer), true
}

func appendTopologyLogField(parts []string, prefix, value string) []string {
	if value == "" {
		return parts
	}
	return append(parts, prefix+value)
}

func defaultTopologyRunPunchTests(ctx context.Context, cfg TopologyConfig, remote TopologyHost) ([]UDPPunchResult, error) {
	conn, closeConn, err := topologyListenPunchPacket()
	if err != nil {
		return nil, err
	}
	defer closeConn()
	return runDefaultTopologyPunchTests(ctx, cfg, remote, conn)
}

func topologyListenPunchPacket() (net.PacketConn, func(), error) {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, nil, err
	}
	return conn, func() { _ = conn.Close() }, nil
}

func runDefaultTopologyPunchTests(ctx context.Context, cfg TopologyConfig, remote TopologyHost, conn net.PacketConn) ([]UDPPunchResult, error) {
	localCandidates, result, err := topologyPunchLocalCandidates(ctx, conn)
	if err != nil {
		return nil, err
	}
	if result != nil {
		return result, nil
	}
	return runTopologyRemotePunch(ctx, cfg, remote, conn, localCandidates)
}

func runTopologyRemotePunch(ctx context.Context, cfg TopologyConfig, remote TopologyHost, conn net.PacketConn, localCandidates []string) ([]UDPPunchResult, error) {
	runCtx, cancel, proc, err := startTopologyRemotePunch(ctx, cfg, remote, localCandidates)
	if err != nil {
		return nil, err
	}
	defer cancel()
	readyInfo, err := topologyReadPunchReady(runCtx, proc, remote)
	if err != nil {
		return nil, err
	}
	return topologyRunPunchExchange(runCtx, conn, proc, cfg.Timeout, localCandidates, readyInfo), nil
}

func topologyPunchLocalCandidates(ctx context.Context, conn net.PacketConn) ([]string, []UDPPunchResult, error) {
	candidates, err := topologyDiscoverCandidates(ctx, conn)
	if err != nil {
		return nil, []UDPPunchResult{{Name: "simultaneous", Error: err.Error()}}, nil
	}
	return CandidateStringsInOrder(candidates), nil, nil
}

func startTopologyRemotePunch(ctx context.Context, cfg TopologyConfig, remote TopologyHost, localCandidates []string) (context.Context, context.CancelFunc, *topologySSHProcess, error) {
	candidateJSON, err := json.Marshal(localCandidates)
	if err != nil {
		return nil, nil, nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout+2*time.Second)
	runner := SSHRunner{User: cfg.User, Host: cfg.Host}
	proc, err := startTopologySSHCommand(runCtx, runner, remoteUDPPunchScript(string(candidateJSON), cfg.Timeout))
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return runCtx, cancel, proc, nil
}

func topologyReadPunchReady(ctx context.Context, proc *topologySSHProcess, remote TopologyHost) (topologyPunchReady, error) {
	ready, err := proc.readLine(ctx)
	if err != nil {
		return topologyPunchReady{}, err
	}
	if !strings.HasPrefix(ready, "READY ") {
		return topologyPunchReady{}, fmt.Errorf("remote UDP punch did not become ready: %s", ready)
	}
	return topologyParsePunchReady(ready, remote), nil
}

func topologyRunPunchExchange(ctx context.Context, conn net.PacketConn, proc *topologySSHProcess, timeout time.Duration, localCandidates []string, readyInfo topologyPunchReady) []UDPPunchResult {
	result := topologyInitialPunchResult(localCandidates, readyInfo)

	var remoteUDP *net.UDPAddr
	if readyInfo.address != "" {
		remoteUDP, _ = net.ResolveUDPAddr("udp", readyInfo.address)
	}

	topologyRunLocalPunchLoop(conn, remoteUDP, timeout, &result)

	remoteReport, stderr, waitErr := topologyReadRemotePunchReport(ctx, proc)
	topologyFinalizePunchResult(&result, remoteReport, waitErr, stderr)
	return []UDPPunchResult{result}
}

func topologyParsePunchReady(ready string, remote TopologyHost) topologyPunchReady {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(ready, "READY ")))
	info := topologyPunchReady{
		port:       topologyPunchReadyPort(fields),
		candidates: topologyPunchReadyCandidates(fields),
	}
	info.address = topologyPunchReadyAddress(info, remote)
	return info
}

func topologyPunchReadyPort(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func topologyPunchReadyCandidates(fields []string) []string {
	if len(fields) <= 1 {
		return nil
	}
	return strings.Split(fields[1], ",")
}

func topologyPunchReadyAddress(info topologyPunchReady, remote TopologyHost) string {
	if len(info.candidates) > 0 {
		return info.candidates[0]
	}
	if remote.EgressIP == "" || info.port == "" {
		return ""
	}
	return net.JoinHostPort(remote.EgressIP, info.port)
}

func topologyInitialPunchResult(localCandidates []string, ready topologyPunchReady) UDPPunchResult {
	return UDPPunchResult{
		Name:             "simultaneous",
		LocalAddress:     strings.Join(localCandidates, ","),
		RemoteAddress:    ready.address,
		RemoteCandidates: ready.candidates,
	}
}

func topologyRunLocalPunchLoop(conn net.PacketConn, remoteUDP *net.UDPAddr, timeout time.Duration, result *UDPPunchResult) {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !topologyLocalPunchRound(conn, remoteUDP, buf, result) {
			return
		}
	}
}

func topologyLocalPunchRound(conn net.PacketConn, remoteUDP *net.UDPAddr, buf []byte, result *UDPPunchResult) bool {
	if remoteUDP != nil {
		_, _ = conn.WriteTo([]byte("derphole-topology:punch-local"), remoteUDP)
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return topologyHandleLocalPunchReadError(err, result)
	}
	topologyHandleLocalPunchMessage(conn, string(buf[:n]), addr, result)
	return true
}

func topologyHandleLocalPunchReadError(err error, result *UDPPunchResult) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	result.Error = err.Error()
	return false
}

func topologyHandleLocalPunchMessage(conn net.PacketConn, msg string, addr net.Addr, result *UDPPunchResult) {
	if !strings.HasPrefix(msg, "derphole-topology:punch-remote") && !strings.HasPrefix(msg, "ack:") {
		return
	}
	result.LocalReceived = true
	result.RemoteAddress = addr.String()
	_, _ = conn.WriteTo([]byte("ack:derphole-topology:punch-remote"), addr)
}

func topologyReadRemotePunchReport(ctx context.Context, proc *topologySSHProcess) (topologyRemotePunchReport, string, error) {
	var remoteReport topologyRemotePunchReport
	if line, err := proc.readLine(ctx); err == nil {
		_ = json.Unmarshal([]byte(line), &remoteReport)
	}
	return remoteReport, strings.TrimSpace(proc.stderr.String()), proc.wait()
}

func topologyFinalizePunchResult(result *UDPPunchResult, remoteReport topologyRemotePunchReport, waitErr error, stderr string) {
	topologySetPunchError(result, remoteReport, waitErr, stderr)
	topologyApplyRemotePunchReport(result, remoteReport)
	topologySetPunchTimeout(result)
}

func topologySetPunchError(result *UDPPunchResult, remoteReport topologyRemotePunchReport, waitErr error, stderr string) {
	result.Error = topologyPunchError(result.Error, remoteReport.Error, waitErr, stderr)
}

func topologyPunchError(current string, remoteError string, waitErr error, stderr string) string {
	if current != "" {
		return current
	}
	if waitErr != nil {
		return waitErr.Error()
	}
	if stderr != "" {
		return stderr
	}
	return remoteError
}

func topologyApplyRemotePunchReport(result *UDPPunchResult, remoteReport topologyRemotePunchReport) {
	if remoteReport.LocalAddress != "" && result.RemoteAddress == "" {
		result.RemoteAddress = remoteReport.LocalAddress
	}
	topologyApplyRemotePunchCandidates(result, remoteReport.Candidates)
	if len(remoteReport.Received) > 0 {
		result.RemoteReceived = true
	}
}

func topologyApplyRemotePunchCandidates(result *UDPPunchResult, candidates []string) {
	if len(candidates) == 0 {
		return
	}
	result.RemoteCandidates = candidates
	if result.RemoteAddress == "" {
		result.RemoteAddress = candidates[0]
	}
}

func topologySetPunchTimeout(result *UDPPunchResult) {
	if !result.LocalReceived && !result.RemoteReceived && result.Error == "" {
		result.Error = "timeout"
	}
}

func remoteUDPPunchScript(localCandidatesJSON string, timeout time.Duration) string {
	duration := fmt.Sprintf("%.3f", timeout.Seconds())
	return fmt.Sprintf(`python3 -u - <<'PY'
import json
import os
import socket
import struct
import time

local_candidates = %s
duration = %s
received = []
sent_to = []

def parse_stun_response(data, txid):
    if len(data) < 20:
        return ""
    msg_type, msg_len, cookie, got_txid = struct.unpack("!HHI12s", data[:20])
    if msg_type != 0x0101 or cookie != 0x2112A442 or got_txid != txid:
        return ""
    pos = 20
    while pos + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[pos:pos+4])
        val = data[pos+4:pos+4+attr_len]
        if attr_type == 0x0020 and len(val) >= 8 and val[1] == 1:
            port = struct.unpack("!H", val[2:4])[0] ^ (0x2112A442 >> 16)
            cookie_bytes = struct.pack("!I", 0x2112A442)
            ip = bytes(a ^ b for a, b in zip(val[4:8], cookie_bytes))
            return socket.inet_ntoa(ip) + ":" + str(port)
        if attr_type == 0x0001 and len(val) >= 8 and val[1] == 1:
            port = struct.unpack("!H", val[2:4])[0]
            return socket.inet_ntoa(val[4:8]) + ":" + str(port)
        pos += 4 + ((attr_len + 3) // 4) * 4
    return ""

def discover_stun_candidate(sock):
    txid = os.urandom(12)
    request = struct.pack("!HHI12s", 0x0001, 0, 0x2112A442, txid)
    old_timeout = sock.gettimeout()
    sock.settimeout(1.0)
    try:
        sock.sendto(request, ("stun.l.google.com", 19302))
        data, _ = sock.recvfrom(2048)
        return parse_stun_response(data, txid)
    except Exception:
        return ""
    finally:
        sock.settimeout(old_timeout)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 0))
sock.settimeout(0.05)
remote_candidates = []
candidate = discover_stun_candidate(sock)
if candidate:
    remote_candidates.append(candidate)
ready_parts = ["READY", str(sock.getsockname()[1])]
if remote_candidates:
    ready_parts.append(",".join(remote_candidates))
print(" ".join(ready_parts), flush=True)
end = time.time() + duration
while time.time() < end:
    for candidate in local_candidates:
        try:
            host, port = candidate.rsplit(":", 1)
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            peer = (host, int(port))
            sock.sendto(b"derphole-topology:punch-remote", peer)
            sent_to.append(candidate)
        except Exception:
            pass
    try:
        data, peer = sock.recvfrom(4096)
    except socket.timeout:
        continue
    received.append({
        "payload": data.decode("utf-8", "replace"),
        "peer": peer[0] + ":" + str(peer[1]),
    })
    try:
        sock.sendto(b"ack:derphole-topology:punch-local", peer)
    except Exception:
        pass
    time.sleep(0.05)
print(json.dumps({
    "local_address": "0.0.0.0:" + str(sock.getsockname()[1]),
    "candidates": remote_candidates,
    "received": received,
    "sent_to": sorted(set(sent_to)),
}, sort_keys=True), flush=True)
PY`, localCandidatesJSON, duration)
}

func startTopologySSHCommand(ctx context.Context, runner SSHRunner, script string) (*topologySSHProcess, error) {
	argv := topologySSHCommand(runner, script)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	return &topologySSHProcess{
		scanner: scanner,
		stderr:  stderr,
		wait: func() error {
			err := cmd.Wait()
			if err != nil && stderr.Len() > 0 {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
			}
			return err
		},
	}, nil
}

func (p *topologySSHProcess) readLine(ctx context.Context) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		if p.scanner.Scan() {
			ch <- result{line: p.scanner.Text()}
			return
		}
		if err := p.scanner.Err(); err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{err: io.EOF}
	}()
	select {
	case got := <-ch:
		return got.line, got.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
