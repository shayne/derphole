// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"os/exec"
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
		`DERPHOLE_TEST_BULK_INITIAL_WIRE_MBPS`, `pkill`, `killall`, `rm -rf /`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("script contains forbidden %q", forbidden)
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
