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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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

func readPromotionDriver(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	return string(data)
}

func TestPromotionBenchmarkDefaultsToFileSendReceive(t *testing.T) {
	body := readPromotionDriver(t)
	for _, want := range []string{
		`workload="${DERPHOLE_BENCH_WORKLOAD:-file}"`,
		`--verbose send "${payload}"`,
		`--verbose receive -o '${remote_base}.out'`,
		`benchmark-workload=${workload}`,
		`benchmark-transfer-mode=${transfer_mode}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing %q", want)
		}
	}
}

func TestPromotionStreamWorkloadIsExplicit(t *testing.T) {
	body := readPromotionDriver(t)
	if !strings.Contains(body, `stream) run_forward_derphole_stream ;;`) {
		t.Fatal("promotion driver does not isolate listen/pipe as stream workload")
	}
}

type promotionDriverTest struct {
	root     string
	fakeBin  string
	stateDir string
}

func newPromotionDriverTest(t *testing.T) promotionDriverTest {
	t.Helper()
	root := t.TempDir()
	scriptDir := filepath.Join(root, "scripts")
	fakeBin := filepath.Join(root, "bin")
	distDir := filepath.Join(root, "dist")
	stateDir := filepath.Join(root, "state")
	for _, dir := range []string{scriptDir, fakeBin, distDir, stateDir} {
		mustMkdirAll(t, dir)
	}

	driver, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion driver: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "promotion-benchmark-driver.sh"), driver, 0o755); err != nil {
		t.Fatalf("write promotion driver: %v", err)
	}

	fakeDerphole := `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--help" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--verbose" ]]; then
  shift
fi
command="${1:?missing command}"
shift
trace="${DERPHOLE_TRANSFER_TRACE_CSV:?missing trace path}"
case "${command}" in
  send)
    payload="${1:?missing payload}"
    printf 'send\n' >>"${FAKE_DERPHOLE_STATE}/events"
    printf '%s\n' "${payload}" >"${FAKE_DERPHOLE_STATE}/payload-path"
	if [[ "${FAKE_SEND_STAY_RUNNING:-0}" == "1" ]]; then
	  printf '%s\n' "$$" >"${FAKE_DERPHOLE_STATE}/remote-child-pid"
	  trap 'touch "${FAKE_DERPHOLE_STATE}/remote-child-term"' TERM INT
	fi
    printf 'derphole receive AAAAAAAAAAAAAAAAAAAAAAAA\n' >&2
    printf 'connected-relay\nconnected-direct\nv2-block-transfer=bulk-packets\n' >&2
	if [[ "${FAKE_SEND_STAY_RUNNING:-0}" == "1" ]]; then
	  while :; do
	    sleep 1
	  done
	fi
    for _ in $(seq 1 200); do
      [[ -f "${FAKE_DERPHOLE_STATE}/received" ]] && break
      sleep 0.01
    done
    [[ -f "${FAKE_DERPHOLE_STATE}/received" ]]
    printf 'app_bytes,transfer_elapsed_ms,send_goodput_mbps,quic_first_byte_ms,direct_bytes,direct_validated\n1048576,10,838.86,1,1048576,true\n' >"${trace}"
    touch "${FAKE_DERPHOLE_STATE}/send-finished"
    exit "${FAKE_SEND_STATUS:-0}"
    ;;
  receive)
    [[ "${1:-}" == "-o" ]]
    output="${2:?missing output}"
    token="${3:?missing token}"
    [[ "${token}" == "AAAAAAAAAAAAAAAAAAAAAAAA" ]]
    printf 'receive\n' >>"${FAKE_DERPHOLE_STATE}/events"
    payload="$(cat "${FAKE_DERPHOLE_STATE}/payload-path")"
    printf 'connected-relay\nconnected-direct\nv2-block-transfer=bulk-packets\nremote-receive-diagnostic\n' >&2
    printf 'app_bytes,transfer_elapsed_ms,send_goodput_mbps,quic_first_byte_ms,direct_bytes,direct_validated\n1048576,10,838.86,1,1048576,true\n' >"${trace}"
    if [[ "${FAKE_RECEIVE_STATUS:-0}" != "0" ]]; then
      if [[ "${FAKE_SIGNAL_SENDER_ON_RECEIVE_FAILURE:-0}" == "1" ]]; then
        touch "${FAKE_DERPHOLE_STATE}/received"
        for _ in $(seq 1 200); do
          [[ -f "${FAKE_DERPHOLE_STATE}/send-finished" ]] && break
          sleep 0.01
        done
      fi
      exit "${FAKE_RECEIVE_STATUS}"
    fi
    cp "${payload}" "${output}"
    touch "${FAKE_DERPHOLE_STATE}/received"
    ;;
  *)
    printf 'unexpected derphole command: %s\n' "${command}" >&2
    exit 64
    ;;
esac
`
	writeExecutable(t, filepath.Join(distDir, "derphole"), fakeDerphole)
	writeExecutable(t, filepath.Join(distDir, "derphole-linux-amd64"), fakeDerphole)
	writeExecutable(t, filepath.Join(fakeBin, "mise"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(fakeBin, "pgrep"), "#!/bin/sh\nexit 1\n")
	writeExecutable(t, filepath.Join(fakeBin, "sha256sum"), `#!/bin/sh
exec shasum -a 256 "$@"
`)
	writeExecutable(t, filepath.Join(fakeBin, "wc"), `#!/bin/sh
/usr/bin/wc "$@" | tr -d '[:space:]'
printf '\n'
`)
	writeExecutable(t, filepath.Join(fakeBin, "ssh"), `#!/bin/sh
exec /bin/bash -se
`)
	writeExecutable(t, filepath.Join(fakeBin, "scp"), `#!/bin/sh
set -eu
source=$1
destination=${2#*:}
mkdir -p "$(dirname "${destination}")"
cp "${source}" "${destination}"
`)
	return promotionDriverTest{root: root, fakeBin: fakeBin, stateDir: stateDir}
}

func (h promotionDriverTest) command(direction string, extraEnv map[string]string) *exec.Cmd {
	values := map[string]string{
		"DERPHOLE_BENCH_TOOL":                 "derphole",
		"DERPHOLE_BENCH_DIRECTION":            direction,
		"DERPHOLE_BENCH_LOCAL_TMP_ROOT":       filepath.Join(h.root, "tmp"),
		"DERPHOLE_BENCH_REMOTE_OUTPUT_ROOT":   filepath.Join(h.root, "remote"),
		"DERPHOLE_BENCH_EXPECT_TRANSFER_MODE": "bulk-packets-v1",
		"FAKE_DERPHOLE_STATE":                 h.stateDir,
	}
	for key, value := range extraEnv {
		values[key] = value
	}
	cmd := exec.Command("bash", "scripts/promotion-benchmark-driver.sh", "stub@example", "1")
	cmd.Dir = h.root
	cmd.Env = harnessTestEnv(h.fakeBin, values)
	return cmd
}

func (h promotionDriverTest) assertCleaned(t *testing.T, direction string) {
	t.Helper()
	for _, pattern := range []string{
		filepath.Join(h.root, "tmp", "derphole-"+direction+".*"),
		filepath.Join(h.root, "remote", "derphole-promotion-*"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob cleanup path %s: %v", pattern, err)
		}
		if len(matches) != 0 {
			t.Fatalf("benchmark cleanup left paths matching %s: %v", pattern, matches)
		}
	}
}

func TestPromotionBenchmarkDefaultExecutesSendBeforeReceive(t *testing.T) {
	harness := newPromotionDriverTest(t)

	cmd := harness.command("forward", nil)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("default file benchmark failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "benchmark-workload=file") ||
		!strings.Contains(string(output), "benchmark-transfer-mode=bulk-packets-v1") {
		t.Fatalf("default file benchmark output missing workload or mode:\n%s", output)
	}

	events, err := os.ReadFile(filepath.Join(harness.stateDir, "events"))
	if err != nil {
		t.Fatalf("read derphole events: %v", err)
	}
	if got, want := string(events), "send\nreceive\n"; got != want {
		t.Fatalf("derphole command order = %q, want %q", got, want)
	}
	if strings.Contains(string(events), "listen") || strings.Contains(string(events), "pipe") {
		t.Fatalf("default file benchmark invoked stream command:\n%s", events)
	}
	harness.assertCleaned(t, "forward")
}

func TestPromotionBenchmarkReverseRejectsRemoteSenderFailure(t *testing.T) {
	harness := newPromotionDriverTest(t)
	cmd := harness.command("reverse", map[string]string{"FAKE_SEND_STATUS": "23"})
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("reverse benchmark accepted remote sender failure:\n%s", output)
	}
	if !strings.Contains(string(output), "remote derphole process exited with status 23") {
		t.Fatalf("reverse sender failure output missing exit status:\n%s", output)
	}
	harness.assertCleaned(t, "reverse")
}

func TestPromotionBenchmarkReverseAcceptsRemoteSenderSuccess(t *testing.T) {
	harness := newPromotionDriverTest(t)
	cmd := harness.command("reverse", nil)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reverse benchmark rejected successful remote sender: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "benchmark-success=true") {
		t.Fatalf("reverse sender success output missing success footer:\n%s", output)
	}
	harness.assertCleaned(t, "reverse")
}

func TestPromotionBenchmarkReverseFailureTerminatesRemoteSenderChild(t *testing.T) {
	harness := newPromotionDriverTest(t)
	cmd := harness.command("reverse", map[string]string{
		"FAKE_RECEIVE_STATUS":    "42",
		"FAKE_SEND_STAY_RUNNING": "1",
	})
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("reverse benchmark accepted local receiver failure:\n%s", output)
	}

	childPIDData, readErr := os.ReadFile(filepath.Join(harness.stateDir, "remote-child-pid"))
	if readErr != nil {
		t.Fatalf("read exact remote child PID: %v\n%s", readErr, output)
	}
	childPID, parseErr := strconv.Atoi(strings.TrimSpace(string(childPIDData)))
	if parseErr != nil || childPID <= 0 {
		t.Fatalf("parse exact remote child PID %q: %v", childPIDData, parseErr)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	})

	deadline := time.Now().Add(2 * time.Second)
	for processExists(childPID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processExists(childPID) {
		t.Fatalf("remote sender child PID %d survived wrapper cleanup; output:\n%s", childPID, output)
	}
	if _, statErr := os.Stat(filepath.Join(harness.stateDir, "remote-child-term")); statErr != nil {
		t.Fatalf("remote sender child PID %d did not receive TERM before cleanup: %v", childPID, statErr)
	}
	harness.assertCleaned(t, "reverse")
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func TestPromotionBenchmarkPreservesRemoteFailureArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		direction string
		role      string
		extraEnv  map[string]string
	}{
		{
			name:      "forward remote receive failure",
			direction: "forward",
			role:      "receiver",
			extraEnv:  map[string]string{"FAKE_RECEIVE_STATUS": "42"},
		},
		{
			name:      "reverse local receive failure",
			direction: "reverse",
			role:      "sender",
			extraEnv: map[string]string{
				"FAKE_RECEIVE_STATUS":                   "42",
				"FAKE_SIGNAL_SENDER_ON_RECEIVE_FAILURE": "1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			harness := newPromotionDriverTest(t)
			logDir := filepath.Join(harness.root, "logs")
			tc.extraEnv["DERPHOLE_BENCH_LOG_DIR"] = logDir
			cmd := harness.command(tc.direction, tc.extraEnv)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("%s benchmark accepted receiver failure:\n%s", tc.direction, output)
			}

			for _, artifact := range []struct {
				suffix string
				want   string
			}{
				{suffix: ".log", want: "connected-direct"},
				{suffix: ".trace.csv", want: "direct_validated"},
			} {
				pattern := "*-" + tc.role + artifact.suffix
				matches, globErr := filepath.Glob(filepath.Join(logDir, pattern))
				if globErr != nil {
					t.Fatalf("glob preserved artifact %s: %v", pattern, globErr)
				}
				if len(matches) != 1 {
					t.Fatalf("preserved artifacts matching %s = %v, want one; output:\n%s", pattern, matches, output)
				}
				data, readErr := os.ReadFile(matches[0])
				if readErr != nil {
					t.Fatalf("read preserved artifact %s: %v", matches[0], readErr)
				}
				if !strings.Contains(string(data), artifact.want) {
					t.Fatalf("preserved artifact %s missing %q:\n%s", matches[0], artifact.want, data)
				}
			}
			harness.assertCleaned(t, tc.direction)
		})
	}
}

func scriptSection(t *testing.T, body, start, end string) string {
	t.Helper()
	startIndex := strings.Index(body, start)
	if startIndex < 0 {
		t.Fatalf("script missing section start %q", start)
	}
	rest := body[startIndex:]
	endIndex := strings.Index(rest, end)
	if endIndex < 0 {
		t.Fatalf("script section %q missing end %q", start, end)
	}
	return rest[:endIndex]
}

func TestPromotionRemoteArtifactRecollectionIsAtomic(t *testing.T) {
	t.Parallel()

	body := readPromotionDriver(t)
	collectDefinition := scriptSection(
		t,
		body,
		"collect_remote_artifacts() {",
		"\nrefresh_benchmark_operands() {",
	)

	for _, mode := range []string{"failure", "empty"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			logPath := filepath.Join(root, "sender.err")
			tracePath := filepath.Join(root, "sender.trace.csv")
			if err := os.WriteFile(logPath, []byte("valid earlier log\n"), 0o600); err != nil {
				t.Fatalf("write canonical log: %v", err)
			}
			if err := os.WriteFile(tracePath, []byte("valid,earlier,trace\n"), 0o600); err != nil {
				t.Fatalf("write canonical trace: %v", err)
			}

			cmd := exec.Command("bash", "-c", `
direction=reverse
remote_base=run
sender_log="$1"
sender_trace_csv="$2"
receiver_log=/unused/receiver.err
receiver_trace_csv=/unused/receiver.trace.csv
mode="$3"
remote() {
  if [[ "${mode}" == "failure" ]]; then
    return 23
  fi
  return 0
}
`+collectDefinition+`
collect_remote_artifacts
collect_status=$?
if [[ "${collect_status}" == "0" ]]; then
  echo "collection unexpectedly succeeded"
  exit 90
fi
printf 'collect-status=%s\n' "${collect_status}"
`, "test", logPath, tracePath, mode)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("artifact recollection probe failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "collect-status=1") {
				t.Fatalf("artifact recollection output = %q, want failed collection", output)
			}

			for path, want := range map[string]string{
				logPath:   "valid earlier log\n",
				tracePath: "valid,earlier,trace\n",
			} {
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatalf("read canonical artifact %s: %v", path, readErr)
				}
				if got := string(data); got != want {
					t.Fatalf("canonical artifact %s = %q after %s recollection, want %q", path, got, mode, want)
				}
				matches, globErr := filepath.Glob(path + ".collect.*")
				if globErr != nil {
					t.Fatalf("glob temporary artifacts for %s: %v", path, globErr)
				}
				if len(matches) != 0 {
					t.Fatalf("temporary recollection artifacts remain for %s: %v", path, matches)
				}
			}
		})
	}
}

func assertScriptOrder(t *testing.T, body string, markers ...string) {
	t.Helper()
	offset := 0
	for _, marker := range markers {
		index := strings.Index(body[offset:], marker)
		if index < 0 {
			t.Fatalf("script section missing ordered marker %q", marker)
		}
		offset += index + len(marker)
	}
}

func TestPromotionDriverReportsReceiverAnchoredGoodput(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		`sender_transfer_elapsed_ms="$(last_trace_value "${sender_trace_csv}" "transfer_elapsed_ms")"`,
		`sender_goodput_mbps="$(trace_transfer_goodput_mbps "${sender_trace_csv}" "${expected_size}")"`,
		`benchmark-transfer-elapsed-ms=`,
		`benchmark-command-duration-ms=`,
		`benchmark-wall-goodput-mbps=`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing receiver-anchored accounting %q", want)
		}
	}
	for _, forbidden := range []string{
		`"app_bytes" "elapsed_ms"`,
		`sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "send_goodput_mbps")"`,
		`sender_goodput_mbps="$(last_trace_value "${sender_trace_csv}" "app_mbps")"`,
		`sender_goodput_mbps="${wall_goodput}"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("promotion driver retains ambiguous goodput fallback %q", forbidden)
		}
	}
}

func TestPromotionTraceTransferGoodputUsesReceiverClock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	definitions := scriptSection(
		t,
		string(data),
		"goodput_mbps() {",
		"\ntrace_has_direct_bytes() {",
	)

	for _, tc := range []struct {
		name    string
		elapsed string
		want    string
		wantErr bool
	}{
		{name: "receiver anchored", elapsed: "28819", want: "894.19\n"},
		{name: "missing receiver clock", elapsed: "", wantErr: true},
		{name: "zero receiver clock", elapsed: "0", wantErr: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			trace := filepath.Join(t.TempDir(), "sender.csv")
			content := "app_bytes,elapsed_ms,transfer_elapsed_ms\n" +
				"3221225472,32185," + tc.elapsed + "\n"
			if err := os.WriteFile(trace, []byte(content), 0o600); err != nil {
				t.Fatalf("write trace: %v", err)
			}
			cmd := exec.Command(
				"bash",
				"-c",
				definitions+"\n"+`trace_transfer_goodput_mbps "$1" 3221225472`,
				"test",
				trace,
			)
			output, err := cmd.CombinedOutput()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("goodput succeeded with invalid transfer clock: %q", output)
				}
				return
			}
			if err != nil {
				t.Fatalf("goodput failed: %v\n%s", err, output)
			}
			if got := string(output); got != tc.want {
				t.Fatalf("goodput = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPromotionDriverStopsCommandClockBeforePostflight(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	forwardStream := scriptSection(t, body, "run_forward_derphole_stream() {", "\nrun_forward_derphole_file() {")
	assertScriptOrder(t, forwardStream,
		"wait_remote_pid_exit",
		`command_end_ms="$(now_ms)"`,
		`remote "cat '${remote_base}.err'"`,
	)

	forwardFile := scriptSection(t, body, "run_forward_derphole_file() {", "\nrun_reverse_derphole_stream() {")
	assertScriptOrder(t, forwardFile,
		`start_ms="$(now_ms)"`,
		`--verbose send "${payload}"`,
		`--verbose receive -o '${remote_base}.out'`,
		`wait "${send_pid}"`,
		`command_end_ms="$(now_ms)"`,
		`remote "cat '${remote_base}.err'"`,
	)

	reverseStream := scriptSection(t, body, "run_reverse_derphole_stream() {", "\nrun_reverse_derphole_file() {")
	assertScriptOrder(t, reverseStream,
		`wait "${listener_pid}"`,
		`listener_pid=""`,
		`command_end_ms="$(now_ms)"`,
		`remote "cat '${remote_base}.err'"`,
	)

	reverseFile := scriptSection(t, body, "run_reverse_derphole_file() {", "\nfinalize_run() {")
	assertScriptOrder(t, reverseFile,
		`start_ms="$(now_ms)"`,
		`--verbose receive -o "${receiver_out}"`,
		"wait_remote_pid_status",
		`command_end_ms="$(now_ms)"`,
		`remote "cat '${remote_base}.err'"`,
	)

	finalize := scriptSection(t, body, "finalize_run() {", "\nbuild_and_install_remote_binary")
	assertScriptOrder(t, finalize,
		`command_duration_ms="$((command_end_ms - start_ms))"`,
		"assert_no_tool_leaks",
		`end_ms="$(now_ms)"`,
		`duration_ms="$((end_ms - start_ms))"`,
	)
}

func TestPromotionRemoteWaitTimeoutFailsBeforeCommandClock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)
	waitDefinition := scriptSection(t, body, "wait_remote_pid_exit() {", "\ndump_failure() {")

	cmd := exec.Command("bash", "-c", `
tool=derphole
target=stub@example
remote_base=run
remote() { echo running; }
seq() { printf '1\n'; }
sleep() { :; }
`+waitDefinition+`
if wait_remote_pid_exit; then
  echo "wait unexpectedly succeeded"
  exit 90
fi
`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("timeout probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "timed out waiting for remote derphole process on stub@example") {
		t.Fatalf("timeout output = %q, want hard timeout error", output)
	}

	forward := scriptSection(t, body, "run_forward_derphole_stream() {", "\nrun_forward_derphole_file() {")
	assertScriptOrder(t, forward,
		"wait_remote_pid_exit",
		`command_end_ms="$(now_ms)"`,
	)
}

func TestPromotionRemoteWaitDistinguishesConfirmedExitFromQueryFailure(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	waitDefinition := scriptSection(
		t,
		string(data),
		"wait_remote_pid_exit() {",
		"\ndump_failure() {",
	)

	for _, tc := range []struct {
		name       string
		remoteBody string
		want       string
		wantError  string
	}{
		{
			name:       "confirmed exit",
			remoteBody: "echo exited",
			want:       "wait-status=0 command-end=123\n",
		},
		{
			name:       "remote query failure",
			remoteBody: "return 255",
			want:       "wait-status=1 command-end=0\n",
			wantError:  "failed to query remote derphole process on stub@example",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `
tool=derphole
target=stub@example
remote_base=run
remote() { `+tc.remoteBody+`; }
seq() { printf '1\n'; }
sleep() { :; }
`+waitDefinition+`
command_end_ms=0
if wait_remote_pid_exit; then
  wait_status=0
  command_end_ms=123
else
  wait_status=$?
fi
printf 'wait-status=%s command-end=%s\n' "$wait_status" "$command_end_ms"
`)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("remote wait probe failed: %v\n%s", err, output)
			}
			body := string(output)
			if !strings.Contains(body, tc.want) {
				t.Fatalf("remote wait output = %q, want %q", body, tc.want)
			}
			if tc.wantError != "" && !strings.Contains(body, tc.wantError) {
				t.Fatalf("remote wait output = %q, want error %q", body, tc.wantError)
			}
		})
	}
}

func TestPromotionRefreshFailureOperandsUsesKnownClocksAndTrace(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	refreshDefinition := scriptSection(
		t,
		string(data),
		"refresh_benchmark_operands() {",
		"\ndump_failure() {",
	)

	trace := filepath.Join(t.TempDir(), "sender.csv")
	if err := os.WriteFile(trace, []byte("trace\n"), 0o600); err != nil {
		t.Fatalf("write trace: %v", err)
	}
	cmd := exec.Command("bash", "-c", `
start_ms=1000
command_end_ms=2200
command_duration_ms=0
duration_ms=0
sender_trace_csv="$1"
sender_transfer_elapsed_ms=0
sender_goodput_mbps=0
sender_peak_goodput_mbps=0
sender_first_byte_ms=0
wall_goodput=0
expected_size=40000000
now_ms() { echo 2600; }
last_trace_value() {
  case "$2" in
    transfer_elapsed_ms) echo 800 ;;
    quic_first_byte_ms) echo 9 ;;
  esac
}
trace_transfer_goodput_mbps() { echo 400.00; }
max_trace_value() { echo 500.00; }
goodput_mbps() { echo 300.00; }
`+refreshDefinition+`
refresh_benchmark_operands
printf '%s,%s,%s,%s,%s,%s,%s\n' \
  "$sender_transfer_elapsed_ms" \
  "$command_duration_ms" \
  "$duration_ms" \
  "$sender_goodput_mbps" \
  "$wall_goodput" \
  "$sender_peak_goodput_mbps" \
  "$sender_first_byte_ms"
`, "test", trace)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("refresh operands failed: %v\n%s", err, output)
	}
	if got, want := string(output), "800,1200,1600,400.00,300.00,500.00,9\n"; got != want {
		t.Fatalf("refreshed operands = %q, want %q", got, want)
	}
}

func TestPromotionPreserveLogsPropagatesSetupFailure(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	preserveDefinition := scriptSection(
		t,
		string(data),
		"preserve_logs() {",
		"\nassert_no_tool_leaks() {",
	)

	cmd := exec.Command("bash", "-c", `
DERPHOLE_BENCH_LOG_DIR=/unwritable
tool=derphole
direction=forward
target=stub@example
size_mib=1
sender_log=/missing/sender.log
receiver_log=/missing/receiver.log
sender_trace_csv=/missing/sender.csv
receiver_trace_csv=/missing/receiver.csv
mkdir() { return 7; }
`+preserveDefinition+`
if preserve_logs; then
  echo "preserve unexpectedly succeeded"
  exit 90
else
  printf 'preserve-status=%s\n' "$?"
fi
`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("preserve failure probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "preserve-status=1") {
		t.Fatalf("preserve failure output = %q, want propagated setup failure", output)
	}
}

func TestPromotionFailureHandlerAlwaysEmitsFooterAndCleansUp(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	handlerDefinition := scriptSection(t, string(data), "handle_exit() {", "\ntrap ")

	cmd := exec.Command("bash", "-c", `
refresh_benchmark_operands() {
  sender_transfer_elapsed_ms=321
  command_duration_ms=654
  duration_ms=987
  sender_goodput_mbps=111.11
  wall_goodput=99.99
  sender_peak_goodput_mbps=222.22
  sender_first_byte_ms=3
  echo refresh
}
dump_failure() { echo dump; }
preserve_logs() { echo preserve; return 7; }
cleanup() { echo cleanup; return 9; }
emit_benchmark_footer() {
  printf 'footer success=%s goodput=%s peak=%s first=%s transfer=%s command=%s total=%s wall=%s\n' \
    "$2" "$4" "$5" "$6" "$sender_transfer_elapsed_ms" \
    "$command_duration_ms" "$duration_ms" "$wall_goodput"
}
`+handlerDefinition+`
handle_exit 23
`)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("failure handler unexpectedly succeeded:\n%s", output)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 23 {
		t.Fatalf("failure handler error = %v, want exit 23\n%s", err, output)
	}
	body := string(output)
	assertScriptOrder(t, body, "refresh", "dump", "preserve", "cleanup", "footer success=false")
	for _, want := range []string{
		"failed to preserve benchmark logs",
		"benchmark cleanup failed",
		"goodput=111.11",
		"transfer=321",
		"command=654",
		"total=987",
		"wall=99.99",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("failure handler output missing %q:\n%s", want, body)
		}
	}
}

func TestPromotionCleanupFailurePreventsSuccessFooter(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)
	cleanupDefinition := scriptSection(t, body, "terminate_remote_processes() {", "\nhandle_exit() {")

	tmp := filepath.Join(t.TempDir(), "local-tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir temp cleanup path: %v", err)
	}
	cmd := exec.Command("bash", "-c", `
send_pid=""
listener_pid=""
tmp="$1"
remote() { return 1; }
`+cleanupDefinition+`
if cleanup; then
  echo "cleanup unexpectedly succeeded"
  exit 90
else
  printf 'cleanup-status=%s\n' "$?"
fi
`, "test", tmp)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cleanup failure probe failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "remote benchmark cleanup incomplete") ||
		!strings.Contains(string(output), "cleanup-status=1") {
		t.Fatalf("cleanup failure output = %q, want propagated verification failure", output)
	}

	finalize := scriptSection(t, body, "finalize_run() {", "\nbuild_and_install_remote_binary")
	if strings.Contains(finalize, "emit_benchmark_footer 1 true") {
		t.Fatal("finalize_run emits success before cleanup")
	}
	start := strings.LastIndex(body, "\nbuild_and_install_remote_binary\n")
	if start < 0 {
		t.Fatal("promotion driver missing main execution sequence")
	}
	mainSequence := body[start:]
	assertScriptOrder(t, mainSequence,
		"finalize_run",
		"if ! cleanup; then",
		"exit 1",
		"emit_benchmark_footer 1 true",
	)
}

func TestPromotionDriverUsesRunScopedRemoteBinary(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "promotion-benchmark-driver.sh"))
	if err != nil {
		t.Fatalf("read promotion-benchmark-driver.sh: %v", err)
	}
	body := string(data)

	for _, forbidden := range []string{
		`DERPHOLE_REMOTE_BIN_DIR:-/usr/local/bin`,
		"requested_remote_bin_dir",
		`if [[ '${remote_bin_dir}' != '${requested_remote_bin_dir}' ]]`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("promotion driver retains unsafe remote binary behavior %q", forbidden)
		}
	}
	for _, want := range []string{
		`remote_bin_dir="${remote_run_dir}/bin"`,
		`remote_bin_dir="${DERPHOLE_REMOTE_BIN_DIR%/}/${tool}-promotion${remote_suffix}-$$"`,
		`rm -f '${remote_bin}'`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("promotion driver missing run-scoped remote binary behavior %q", want)
		}
	}
}

func TestPublicPathPerformanceHarnessCarriesBenchmarkOperands(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"DERPHOLE_BENCH_WORKLOAD=file",
		"workload,transfer_mode",
		"trace_mbps",
		"wall_mbps",
		"wall_ratio_to_iperf",
		"transfer_elapsed_ms",
		"command_duration_ms",
		"total_duration_ms",
		"benchmark accounting mismatch",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path harness missing benchmark operand %q", want)
		}
	}
}

func TestPublicPathPerformanceHarnessRejectsOneSecondFlatline(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)
	if got := strings.Count(body, "-stall-window 999ms"); got != 2 {
		t.Fatalf("public-path harness has %d strict flatline thresholds, want 2", got)
	}
	if strings.Contains(body, "-stall-window 1s") {
		t.Fatal("public-path harness still accepts an exact one-second flatline")
	}

	trace := filepath.Join(t.TempDir(), "exact-one-second-flatline.csv")
	content := "timestamp_unix_ms,role,phase,app_bytes,last_error\n" +
		"1000,send,direct_execute,1,\n" +
		"2000,send,direct_execute,1,\n" +
		"2001,send,complete,2,\n"
	if err := os.WriteFile(trace, []byte(content), 0o600); err != nil {
		t.Fatalf("write exact flatline trace: %v", err)
	}
	cmd := exec.Command(
		"go",
		"run",
		"../tools/transfertracecheck",
		"-role",
		"send",
		"-stall-window",
		"999ms",
		trace,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("exact one-second flatline unexpectedly passed:\n%s", output)
	}
	if !strings.Contains(string(output), "app bytes stalled for 1s") {
		t.Fatalf("exact flatline output = %q, want one-second stall rejection", output)
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
		`append_summary_row "${host_label}" "${run}" "derphole" "${workload}" "${transfer_mode}" "${derphole_mbps}" "${iperf_mbps}" "${trace_sender_mbps}" "${wall_mbps}"`,
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
  printf 'workload=%s\n' "${DERPHOLE_BENCH_WORKLOAD:-unset}"
} >"${DERPHOLE_BENCH_LOG_DIR}/env.txt"
printf 'benchmark-goodput-mbps=12.34\n'
printf 'benchmark-workload=file\n'
printf 'benchmark-transfer-mode=bulk-packets-v1\n'
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
	if got := derphole["workload"]; got != "file" {
		t.Fatalf("derphole workload = %q, want file", got)
	}
	if got := derphole["transfer_mode"]; got != "bulk-packets-v1" {
		t.Fatalf("derphole transfer_mode = %q, want bulk-packets-v1", got)
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
		"workload=file\n",
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
