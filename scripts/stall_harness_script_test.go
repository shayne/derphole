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
		"samples.tsv",
		"send --hide-progress",
		"receive --hide-progress",
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
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Fatalf("transfer-stall-harness.sh missing %q", want)
		}
	}
}
