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

func TestDirectUDPDiagnosticBenchmarkScriptShape(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "direct-udp-diagnostic-benchmark.sh"))
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"usage: $0 <sender-host> <receiver-host> [size-mib]",
		"DERPHOLE_DIAG_LOG_DIR",
		"diagnostic-summary.env",
		"iperf3",
		"transfer-stall-harness.sh",
		"udp-rate-probe-samples",
		"diagnostic-iperf-goodput-mbps=",
		"diagnostic-iperf-tcp-goodput-mbps=",
		"diagnostic-iperf-udp-goodput-mbps=",
		"diagnostic-transfer-sender-goodput-mbps=",
		"DERPHOLE_DIAG_IPERF_EXTERNAL_HOST",
		"--connect-timeout",
		"stop_remote_iperf_server",
		"printf 'iperf-%s-exit-%s\\n'",
		"grep -Ih",
		"diagnostic-transfer-status=",
		"PIPESTATUS[0]",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}
