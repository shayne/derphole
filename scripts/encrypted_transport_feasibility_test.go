// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readEncryptedTransportFeasibility(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", "encrypted-transport-feasibility.sh"))
	if err != nil {
		t.Fatalf("read encrypted transport feasibility driver: %v", err)
	}
	return string(data)
}

func TestEncryptedTransportFeasibilityRequiresExplicitPublicEndpoints(t *testing.T) {
	command := exec.Command("bash", "./encrypted-transport-feasibility.sh")
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("driver succeeded without required environment")
	}
	for _, want := range []string{
		"DERPHOLE_FEASIBILITY_REMOTE",
		"DERPHOLE_FEASIBILITY_REMOTE_PUBLIC_ADDR",
		"DERPHOLE_FEASIBILITY_LOCAL_PUBLIC_ADDR",
		"DERPHOLE_FEASIBILITY_TCP_PORT",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("missing-environment output %q does not mention %s", output, want)
		}
	}
}

func TestEncryptedTransportFeasibilityRejectsNonPublicAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "224.0.0.1"} {
		command := exec.Command("bash", "./encrypted-transport-feasibility.sh", "--validate-public-address", address)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("address %s accepted as public; output=%q", address, output)
		}
	}
	command := exec.Command("bash", "./encrypted-transport-feasibility.sh", "--validate-public-address", "8.8.8.8")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("documentation public address rejected: %v; output=%q", err, output)
	}
}

func TestEncryptedTransportFeasibilityHasScopedCleanupAndArtifacts(t *testing.T) {
	body := readEncryptedTransportFeasibility(t)
	for _, forbidden := range []string{"pkill", "killall", "apt-get", "dnf install", "brew install"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("feasibility driver contains unsafe operation %q", forbidden)
		}
	}
	for _, want := range []string{
		`run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"`,
		`remote_root=`,
		`local_pids=()`,
		`remote_pid_files=()`,
		`trap cleanup EXIT INT TERM`,
		`manifest.json`,
		`source.bin`,
		`source.sha256`,
		`results.jsonl`,
		`decision.json`,
		`bulk-udp-batched-v1`,
		`tls-stream-8-v1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("feasibility driver missing %q", want)
		}
	}
}

func TestEncryptedTransportFeasibilityUsesStrictWorkloadAndCapacityControls(t *testing.T) {
	body := readEncryptedTransportFeasibility(t)
	for _, want := range []string{
		`size_mib=3072`,
		`-P 8`,
		`-t 20`,
		`DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`,
		`DERPHOLE_TEST_BULK_BATCHED_IO=1`,
		`DERPHOLE_TEST_FORCE_BULK_PACKET_TRANSFER=1`,
		`DERPHOLE_BENCH_EXPECT_TRANSFER_MODE=bulk-packets-v1`,
		`DERPHOLE_BENCH_WORKLOAD=file`,
		`DERPHOLE_BENCH_LOCAL_PAYLOAD=`,
		`DERPHOLE_BENCH_REMOTE_PAYLOAD=`,
		`getconf _NPROCESSORS_ONLN`,
		`-stall-window 999ms`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("feasibility driver missing %q", want)
		}
	}
}
