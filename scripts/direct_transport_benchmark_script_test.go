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

func TestDirectTransportBenchmarkDocumentsQUICSelector(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "direct-transport-benchmark.sh"))
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"DERPHOLE_DIRECT_TRANSPORT=quic",
		"diagnostic-direct-transport=quic",
		"diagnostic-iperf-tcp-goodput-mbps",
		"diagnostic-transfer-sender-goodput-mbps",
		"diagnostic-transfer-receiver-goodput-mbps",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}
