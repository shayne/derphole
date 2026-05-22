// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransferStallHarnessCapturesProgressAndCounters(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "transfer-stall-harness.sh"))
	if err != nil {
		t.Fatalf("read transfer-stall-harness.sh: %v", err)
	}
	body := string(data)

	required := []string{
		"mktemp -d",
		"clean_ssh",
		"LC_ALL=C LANG=C ssh",
		"samples.csv",
		"DERPHOLE_STALL_CAPTURE_SENDER_PROGRESS",
		"sender_progress_flag",
		"receive --hide-progress",
		"bytes_sent",
		"bytes_received",
		"sender_state",
		"receiver_state",
		"kill -QUIT",
		"DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES",
		"DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES",
		"ip -s -s link",
		"nstat -az",
		"/proc/net/snmp",
		"/proc/net/netstat",
		"/proc/net/udp",
		"stall-timeout-sec",
		"</dev/null >/dev/null 2>/dev/null &",
		"child=\\$!",
		"wait \\\"\\${child}\\\"",
		"--exclude=payload.bin",
		"--exclude=received.bin",
		"DERPHOLE_TRANSFER_TRACE_CSV",
		"send.trace.csv",
		"receive.trace.csv",
		"sender_trace_local",
		"receiver_trace_local",
		"transfertracecheck",
		"-stall-window",
		"-peer-trace",
		"receive_checker_output",
		"receive_checker_status",
		"sender_checker_output",
		"sender_checker_status",
		"app bytes stalled",
		"stall-proof-role=",
		"stall-proof-error=unexpected-checker-failure",
		"DERPHOLE_TRANSFER_TRACE_INTEGRITY_STALL_WINDOW",
		"trace_integrity_stall_window",
		"876000h",
		"Trace app_bytes are session stream bytes",
		"Payload size and SHA verification above validate file bytes",
		"DERPHOLE_STALL_TOOL_NAME",
		"DERPHOLE_STALL_ASSERT_NO_LEAKS",
		"DERPHOLE_STALL_KILL_LEAKS",
		"assert_no_remote_leaks",
		"remote_leak_snapshot",
		"terminate_remote_children",
		"preflight sender",
		"preflight receiver",
		"postrun sender",
		"postrun receiver",
		"/proc/net/udp6",
		"socket:[",
		"leak-check",
		"DERPHOLE_IPERF_PORT",
		"DERPHOLE_IPERF_SERVER_HOST",
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Fatalf("transfer-stall-harness.sh missing %q", want)
		}
	}

	stallProof := `if [[ "${receive_checker_output}" == *"app bytes stalled"* ]]; then`
	integrityCheck := `-stall-window "${trace_integrity_stall_window}" "${receiver_trace_local}"`
	stallProofIndex := strings.Index(body, stallProof)
	if stallProofIndex < 0 {
		t.Fatalf("transfer-stall-harness.sh missing expected-stall proof match")
	}
	integrityCheckIndex := strings.Index(body[stallProofIndex:], integrityCheck)
	if integrityCheckIndex < 0 {
		t.Fatalf("transfer-stall-harness.sh missing receive integrity checker after expected-stall proof")
	}

	preflightIndex := strings.Index(body, `assert_no_remote_leaks "${sender_target}" "preflight sender"`)
	startIndex := strings.Index(body, `DERPHOLE_TRANSFER_TRACE_CSV=$(quote "${sender_trace}")`)
	if preflightIndex < 0 {
		t.Fatalf("transfer-stall-harness.sh missing sender preflight leak gate")
	}
	if startIndex < 0 {
		t.Fatalf("transfer-stall-harness.sh missing sender start")
	}
	if preflightIndex > startIndex {
		t.Fatalf("transfer-stall-harness.sh checks leaks after starting sender")
	}
}
