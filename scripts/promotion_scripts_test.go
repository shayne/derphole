// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"bytes"
	"encoding/csv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromotionWrappersUseSharedDriver(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		file      string
		tool      string
		direction string
	}{
		{
			name:      "derphole forward",
			file:      "promotion-test.sh",
			tool:      "derphole",
			direction: "forward",
		},
		{
			name:      "derphole reverse",
			file:      "promotion-test-reverse.sh",
			tool:      "derphole",
			direction: "reverse",
		},
		{
			name:      "derphole forward",
			file:      "derphole-promotion-test.sh",
			tool:      "derphole",
			direction: "forward",
		},
		{
			name:      "derphole reverse",
			file:      "derphole-promotion-test-reverse.sh",
			tool:      "derphole",
			direction: "reverse",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(".", tc.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}
			body := string(data)

			if !strings.Contains(body, `promotion-benchmark-driver.sh`) {
				t.Fatalf("%s does not invoke the shared benchmark driver", tc.file)
			}
			if !strings.Contains(body, `DERPHOLE_BENCH_TOOL=`+tc.tool) {
				t.Fatalf("%s does not declare DERPHOLE_BENCH_TOOL=%s", tc.file, tc.tool)
			}
			if !strings.Contains(body, `DERPHOLE_BENCH_DIRECTION=`+tc.direction) {
				t.Fatalf("%s does not declare DERPHOLE_BENCH_DIRECTION=%s", tc.file, tc.direction)
			}
		})
	}
}

func TestPromotionDriverUsesV2TransferTraceMetrics(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"DERPHOLE_TRANSFER_TRACE_CSV",
		"require_direct_trace",
		"send_goodput_mbps",
		"direct_bytes",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing %q", want)
		}
	}
	for _, retired := range []string{
		"udp-" + "send",
		"udp-" + "receive",
		"DERPHOLE_TRACE_" + "HANDOFF",
	} {
		if strings.Contains(body, retired) {
			t.Fatalf("promotion driver still references retired telemetry %q", retired)
		}
	}
}

func TestPromotionDriverReportsAverageTraceGoodput(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"trace_average_mbps",
		`sender_goodput_mbps="$(trace_average_mbps "${sender_trace_csv}" "app_bytes" "elapsed_ms")"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing average-goodput logic %q", want)
		}
	}
	averageIndex := strings.Index(body, `sender_goodput_mbps="$(trace_average_mbps "${sender_trace_csv}" "app_bytes" "elapsed_ms")"`)
	fallbackIndex := strings.Index(body, `sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "send_goodput_mbps")"`)
	if fallbackIndex >= 0 && fallbackIndex < averageIndex {
		t.Fatal("promotion driver checks final instantaneous send_goodput_mbps before average trace goodput")
	}
}

func TestPromotionBenchmarkDriverPropagatesTransportExperimentEnv(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES",
		"DERPHOLE_V2_RAW_DIRECT",
		"DERPHOLE_V2_RAW_DIRECT_BUDGET_MS",
		"DERPHOLE_V2_MANAGER_QUIC_FANOUT",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion-benchmark-driver.sh missing remote env propagation for %s", want)
		}
	}
}

func TestPublicPathPerformanceHarnessRunsForwardFourHostMatrix(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`DERPHOLE_PUBLIC_PATH_HOSTS:-ubuntu@derphole-testing ubuntu@eric-nuc root@hetz root@canlxc`,
		`DERPHOLE_PUBLIC_PATH_SIZE_MIB:-1024`,
		`DERPHOLE_PUBLIC_PATH_RUNS:-3`,
		`DERPHOLE_PUBLIC_IPERF_PORT:-8123`,
		`DERPHOLE_PUBLIC_PATH_DIRECTION:-forward`,
		`DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1`,
		`DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT=`,
		`promotion-test.sh`,
		`transfertracecheck`,
		`summary.csv`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path-performance-harness.sh missing %q", want)
		}
	}
}

func TestPromotionBenchmarkDriverSupportsRemoteOutputRootAndDiagnosticParallel(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT`,
		`DERPHOLE_BENCH_PARALLEL`,
		`parallel_args=()`,
		`--parallel "${DERPHOLE_BENCH_PARALLEL}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion-benchmark-driver.sh missing %q", want)
		}
	}
}

func TestPromotionBenchmarkDriverDoesNotInheritLegacyParallelArgs(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	if strings.Contains(body, "DERPHOLE_PARALLEL_ARGS") {
		t.Fatal("promotion-benchmark-driver.sh still inherits DERPHOLE_PARALLEL_ARGS")
	}
	if !strings.Contains(body, `parallel_args=(--parallel "${DERPHOLE_BENCH_PARALLEL}")`) {
		t.Fatal("promotion-benchmark-driver.sh does not use DERPHOLE_BENCH_PARALLEL for diagnostic parallel override")
	}
}

func TestBenchmarkDocsUseDiagnosticBenchParallelEnv(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "docs", "benchmarks.md"))
	if err != nil {
		t.Fatalf("read docs/benchmarks.md: %v", err)
	}
	body := string(data)

	if strings.Contains(body, "DERPHOLE_PARALLEL_ARGS") {
		t.Fatal("docs/benchmarks.md still documents DERPHOLE_PARALLEL_ARGS")
	}
	for _, want := range []string{
		"DERPHOLE_BENCH_PARALLEL",
		"leave `DERPHOLE_BENCH_PARALLEL` unset",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs/benchmarks.md missing %q", want)
		}
	}
}

func TestPublicPathPerformanceHarnessRecordsFailedTraceSamples(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`trace_ok="true"`,
		`trace_ok="false"`,
		`trace_status=0`,
		`append_summary_row "${host_label}" "${run}" "derphole" "${derphole_mbps}" "${iperf_mbps}" "${trace_ok}"`,
		`trace_failures=1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path-performance-harness.sh missing trace failure summary handling %q", want)
		}
	}
	if strings.Contains(body, `append_summary_row "${host_label}" "${run}" "derphole" "${derphole_mbps}" "${iperf_mbps}" "true"`) {
		t.Fatal("public-path-performance-harness.sh hard-codes successful derphole trace summaries")
	}
}

func TestPublicPathPerformanceHarnessWritesSummaryRowWhenPromotionFails(t *testing.T) {
	t.Parallel()

	root := copyPublicPathHarness(t)
	fakeBin := filepath.Join(root, "bin")
	scriptDir := filepath.Join(root, "scripts")
	logDir := filepath.Join(root, "logs")
	mustMkdirAll(t, fakeBin)

	writeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
printf '203.0.113.9\n'
`)
	writeExecutable(t, filepath.Join(fakeBin, "ssh"), `#!/bin/sh
case "$*" in
  *"-J"*) printf '{"end":{"sum_received":{"bits_per_second":100000000}}}\n' ;;
  *) exit 0 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "iperf3"), `#!/bin/sh
exit 0
`)
	writeExecutable(t, filepath.Join(scriptDir, "promotion-test.sh"), `#!/bin/sh
set -eu
mkdir -p "${DERPHOLE_BENCH_LOG_DIR}"
{
  printf 'raw=%s\n' "${DERPHOLE_V2_RAW_DIRECT:-unset}"
  printf 'budget=%s\n' "${DERPHOLE_V2_RAW_DIRECT_BUDGET_MS:-unset}"
  printf 'fanout=%s\n' "${DERPHOLE_V2_MANAGER_QUIC_FANOUT:-unset}"
  printf 'parallel=%s\n' "${DERPHOLE_BENCH_PARALLEL:-unset}"
} >"${DERPHOLE_BENCH_LOG_DIR}/env.txt"
printf 'benchmark-goodput-mbps=12.34\n'
exit 42
`)

	cmd := exec.Command("bash", "scripts/public-path-performance-harness.sh")
	cmd.Dir = root
	cmd.Env = harnessTestEnv(fakeBin, map[string]string{
		"DERPHOLE_PUBLIC_PATH_HOSTS":                 "stub@example",
		"DERPHOLE_PUBLIC_PATH_RUNS":                  "1",
		"DERPHOLE_PUBLIC_PATH_SIZE_MIB":              "1",
		"DERPHOLE_PUBLIC_IPERF_PORT":                 "8123",
		"DERPHOLE_BENCH_LOG_DIR":                     logDir,
		"DERPHOLE_BENCH_PARALLEL":                    "auto",
		"DERPHOLE_V2_RAW_DIRECT":                     "1",
		"DERPHOLE_V2_RAW_DIRECT_BUDGET_MS":           "850",
		"DERPHOLE_V2_MANAGER_QUIC_FANOUT":            "1",
		"DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES": "ambient",
	})
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	if err == nil {
		t.Fatal("public-path harness succeeded despite promotion-test failure")
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
		t.Fatalf("public-path harness error = %v, want nonzero exit", err)
	}

	records := readSummaryCSV(t, filepath.Join(logDir, "summary.csv"))
	derphole := findSummaryRecord(t, records, "derphole")
	if got := derphole["mbps"]; got != "12.34" {
		t.Fatalf("derphole mbps = %q, want 12.34; output:\n%s", got, output.String())
	}
	if got := derphole["trace_ok"]; got != "false" {
		t.Fatalf("derphole trace_ok = %q, want false; output:\n%s", got, output.String())
	}
	if got := derphole["max_peer_recv_queue_depth"]; got != "0" {
		t.Fatalf("derphole max_peer_recv_queue_depth = %q, want 0", got)
	}
	if got := derphole["max_flatline"]; got != "0s" {
		t.Fatalf("derphole max_flatline = %q, want 0s", got)
	}
	if got := derphole["log_dir"]; got == "" || !strings.Contains(got, "derphole-run-1") {
		t.Fatalf("derphole log_dir = %q, want derphole run log dir", got)
	}

	envFile := filepath.Join(logDir, "stub_example", "derphole-run-1", "env.txt")
	envData, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read promotion env capture: %v", err)
	}
	envBody := string(envData)
	for _, want := range []string{
		"raw=unset\n",
		"budget=unset\n",
		"fanout=unset\n",
		"parallel=auto\n",
	} {
		if !strings.Contains(envBody, want) {
			t.Fatalf("promotion env capture missing %q; got:\n%s", want, envBody)
		}
	}
}

func TestPublicPathPerformanceHarnessRejectsNonForwardDirection(t *testing.T) {
	t.Parallel()

	root := copyPublicPathHarness(t)
	fakeBin := filepath.Join(root, "bin")
	mustMkdirAll(t, fakeBin)
	writeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
echo curl should not run >&2
exit 73
`)

	cmd := exec.Command("bash", "scripts/public-path-performance-harness.sh")
	cmd.Dir = root
	cmd.Env = harnessTestEnv(fakeBin, map[string]string{
		"DERPHOLE_PUBLIC_PATH_DIRECTION": "reverse",
		"DERPHOLE_BENCH_LOG_DIR":         filepath.Join(root, "logs"),
	})
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	if err == nil {
		t.Fatal("public-path harness accepted non-forward direction")
	}
	if !strings.Contains(output.String(), "DERPHOLE_PUBLIC_PATH_DIRECTION only supports forward") {
		t.Fatalf("non-forward direction output = %q, want clear direction error", output.String())
	}
	if strings.Contains(output.String(), "curl should not run") {
		t.Fatalf("non-forward direction reached network setup:\n%s", output.String())
	}
}

func copyPublicPathHarness(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	scriptDir := filepath.Join(root, "scripts")
	mustMkdirAll(t, scriptDir)

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "public-path-performance-harness.sh"), data, 0o755); err != nil {
		t.Fatalf("write harness copy: %v", err)
	}
	return root
}

func harnessTestEnv(fakeBin string, values map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(values)+1)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "DERPHOLE_") || strings.HasPrefix(item, "PATH=") {
			continue
		}
		env = append(env, item)
	}
	env = append(env, "PATH="+fakeBin+":/usr/bin:/bin")
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func writeExecutable(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readSummaryCSV(t *testing.T, path string) []map[string]string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open summary csv: %v", err)
	}
	defer func() {
		_ = f.Close()
	}()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read summary csv: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("summary csv has %d rows, want header and data", len(rows))
	}
	header := rows[0]
	records := make([]map[string]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		record := make(map[string]string, len(header))
		for i, key := range header {
			if i < len(row) {
				record[key] = row[i]
			}
		}
		records = append(records, record)
	}
	return records
}

func findSummaryRecord(t *testing.T, records []map[string]string, tool string) map[string]string {
	t.Helper()
	for _, record := range records {
		if record["tool"] == tool {
			return record
		}
	}
	t.Fatalf("summary csv missing tool %q in %#v", tool, records)
	return nil
}
