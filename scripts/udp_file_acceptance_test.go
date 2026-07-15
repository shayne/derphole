// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readUDPFileAcceptance(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("udp-file-acceptance.sh")
	if err != nil {
		t.Fatalf("read UDP file acceptance driver: %v", err)
	}
	return string(data)
}

func TestUDPFileAcceptanceHasStrictPublicUDPContract(t *testing.T) {
	body := readUDPFileAcceptance(t)
	for _, want := range []string{
		`size_mib=3072`, `runs=3`, `getconf _NPROCESSORS_ONLN`,
		`DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`,
		`DERPHOLE_BENCH_TOOL=derphole`,
		`DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1`,
		`-require-direct-transport udp`, `-forbid-relay-payload`,
		`benchmark-goodput-mbps`, `sender_cpu_seconds_per_gib`,
		`receiver_cpu_seconds_per_gib`, `oom_kill`, `sha256`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`DERPHOLE_TEST_BULK_BATCHED_IO`, `DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER`,
		`DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`, `-expected-bytes "${size_bytes}"`,
		`pkill`, `killall`, `rm -rf /`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("script contains forbidden %q", forbidden)
		}
	}
}

func TestUDPFileAcceptanceTraceCheckerProvesEveryBulkPayloadByte(t *testing.T) {
	body := readUDPFileAcceptance(t)
	for value, wantCount := range map[string]int{
		`-expected-payload-bytes "${size_bytes}"`:                2,
		`-require-file-payload-engine bulk-packets-v1`:           2,
		`-require-engine-telemetry`:                              2,
		` -expected-selected-public-ipv4 "${sender_peer}"`:       1,
		` -expected-selected-public-ipv4 "${receiver_peer}"`:     1,
		`-peer-expected-selected-public-ipv4 "${receiver_peer}"`: 1,
	} {
		if count := strings.Count(body, value); count != wantCount {
			t.Fatalf("script contains %d copies of %q, want %d", count, value, wantCount)
		}
	}
}

func TestUDPFileAcceptanceRequiresExplicitEndpointsWithoutArtifacts(t *testing.T) {
	command := exec.Command("bash", "./udp-file-acceptance.sh")
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	output, err := command.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("driver error = %v, output = %q; want exit 2", err, output)
	}
	for _, want := range []string{
		"DERPHOLE_UDP_ACCEPT_REMOTE",
		"DERPHOLE_UDP_ACCEPT_REMOTE_PUBLIC_ADDR",
		"DERPHOLE_UDP_ACCEPT_LOCAL_PUBLIC_ADDR",
		"DERPHOLE_UDP_ACCEPT_TCP_PORT",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("missing-environment output %q does not mention %s", output, want)
		}
	}
}

func TestUDPFileAcceptanceRejectsNonPublicAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "224.0.0.1"} {
		command := exec.Command("bash", "./udp-file-acceptance.sh", "--validate-public-address", address)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("address %s accepted as public; output=%q", address, output)
		}
	}
	command := exec.Command("bash", "./udp-file-acceptance.sh", "--validate-public-address", "8.8.8.8")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("public address rejected: %v; output=%q", err, output)
	}
}

func TestUDPFileAcceptanceHasScopedCleanupAndInterleavedRuns(t *testing.T) {
	body := readUDPFileAcceptance(t)
	for _, want := range []string{
		`run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"`,
		`remote_root=`, `local_pids=()`,
		`trap cleanup EXIT INT TERM`, `results.csv`, `decision.json`,
		`"local-to-remote remote-to-local"`,
		`"remote-to-local local-to-remote"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}

func TestUDPFileAcceptanceUsesForwardedMacIperfServerForBothDirections(t *testing.T) {
	body := readUDPFileAcceptance(t)
	for _, want := range []string{
		`iperf3 -s -4 -p "${tcp_port}" --one-off --forceflush`,
		`reverse_args=(-R)`,
		`if ! remote_shell "iperf3 -4 -J -c '${local_public}'`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public capacity control missing %q", want)
		}
	}
	for _, forbidden := range []string{`start_remote_wrapped`, `remote_pid_files`, `-c "${remote_public}"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public capacity control still contains %q", forbidden)
		}
	}
}

func TestUDPFileAcceptanceTakesOneBeforeSnapshotPerCase(t *testing.T) {
	body := readUDPFileAcceptance(t)
	want := `health_snapshot "before-${direction}-run-${run}"`
	if count := strings.Count(body, want); count != 1 {
		t.Fatalf("before-case health snapshot count = %d, want 1", count)
	}
}

func TestUDPFileAcceptanceAnalysisAllowsFramedAppBytes(t *testing.T) {
	output, err := runUDPFileAcceptanceAnalysisFixture(t, "20000000")
	if err != nil {
		t.Fatalf("analysis error = %v, output = %q", err, output)
	}
}

func TestUDPFileAcceptanceAnalysisRequiresExactCommittedPayload(t *testing.T) {
	output, err := runUDPFileAcceptanceAnalysisFixture(t, "19999999")
	if err == nil || !strings.Contains(output, "receiver direct committed bytes are 19999999, want 20000000") {
		t.Fatalf("analysis error = %v, output = %q; want exact committed-payload rejection", err, output)
	}
}

func runUDPFileAcceptanceAnalysisFixture(t *testing.T, committedBytes string) (string, error) {
	t.Helper()
	body := readUDPFileAcceptance(t)
	const startMarker = "<<'PY'\nimport csv\nimport json\nimport math\nimport sys\n\n(out, promotion"
	start := strings.Index(body, startMarker)
	if start < 0 {
		t.Fatal("acceptance analysis Python start marker not found")
	}
	codeStart := start + len("<<'PY'\n")
	endOffset := strings.Index(body[codeStart:], "\nPY\n  tail -n 1")
	if endOffset < 0 {
		t.Fatal("acceptance analysis Python end marker not found")
	}
	code := body[codeStart : codeStart+endOffset]

	dir := t.TempDir()
	paths := map[string]string{
		"analysis":          filepath.Join(dir, "analysis.py"),
		"result":            filepath.Join(dir, "result.csv"),
		"promotion":         filepath.Join(dir, "promotion.out"),
		"sender_trace":      filepath.Join(dir, "sender.trace.csv"),
		"receiver_trace":    filepath.Join(dir, "receiver.trace.csv"),
		"sender_resource":   filepath.Join(dir, "sender.resource.json"),
		"receiver_resource": filepath.Join(dir, "receiver.resource.json"),
	}
	files := map[string]string{
		"analysis":          code,
		"promotion":         "benchmark-success=true\nbenchmark-transfer-mode=bulk-packets-v1\nbenchmark-size-bytes=20000000\nbenchmark-goodput-mbps=2285.714285714286\nbenchmark-wall-goodput-mbps=2200\nsha256=fixture-sha\n",
		"sender_trace":      "timestamp_unix_ms,app_bytes,transfer_elapsed_ms,direct_transport,relay_bytes,direct_packet_bytes,repair_bytes,missing_scan_checks,bulk_probe_pressure\n2000,20000104,70,udp,0,20000000,0,0,false\n",
		"receiver_trace":    fmt.Sprintf("timestamp_unix_ms,app_bytes,direct_transport,relay_bytes,direct_packet_bytes,direct_committed_bytes,missing_scan_checks,bulk_probe_pressure\n2000,20000104,udp,0,20000000,%s,0,false\n", committedBytes),
		"sender_resource":   `{"resource_stats_available":true,"exit_code":0,"user_cpu_seconds":0.01,"system_cpu_seconds":0.01}`,
		"receiver_resource": `{"resource_stats_available":true,"exit_code":0,"user_cpu_seconds":0.01,"system_cpu_seconds":0.01}`,
	}
	for name, contents := range files {
		if err := os.WriteFile(paths[name], []byte(contents), 0o600); err != nil {
			t.Fatalf("write %s fixture: %v", name, err)
		}
	}

	command := exec.Command("python3", paths["analysis"],
		paths["result"], paths["promotion"], paths["sender_trace"], paths["receiver_trace"],
		paths["sender_resource"], paths["receiver_resource"], "local-to-remote", "1", "2500",
		"fixture-revision", "fixture-sha", "20000000", "6", "6")
	output, err := command.CombinedOutput()
	return string(output), err
}
