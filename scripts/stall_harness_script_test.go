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
		"transfertracecheck",
		"-stall-window",
		"receive_checker_output",
		"receive_checker_status",
		"app bytes stalled",
		"stall-proof-error=unexpected-checker-failure",
		"DERPHOLE_TRANSFER_TRACE_INTEGRITY_STALL_WINDOW",
		"trace_integrity_stall_window",
		"876000h",
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Fatalf("transfer-stall-harness.sh missing %q", want)
		}
	}

	stallProof := `if [[ "${receive_checker_output}" == *"app bytes stalled"* ]]; then`
	integrityCheck := `-stall-window "${trace_integrity_stall_window}" "${log_dir}/receiver/receive.trace.csv"`
	stallProofIndex := strings.Index(body, stallProof)
	if stallProofIndex < 0 {
		t.Fatalf("transfer-stall-harness.sh missing expected-stall proof match")
	}
	integrityCheckIndex := strings.Index(body[stallProofIndex:], integrityCheck)
	if integrityCheckIndex < 0 {
		t.Fatalf("transfer-stall-harness.sh missing receive integrity checker after expected-stall proof")
	}
}
