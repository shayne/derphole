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

func TestIperfBenchmarkScriptsForceIPv4ForForwardedPorts(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"iperf-benchmark.sh", "iperf-benchmark-reverse.sh"} {
		file := file
		t.Run(file, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join(".", file))
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			body := string(data)
			if !strings.Contains(body, `-s -4 -p "${iperf_port}"`) {
				t.Fatalf("%s does not force IPv4 for the local iperf server", file)
			}
			if !strings.Contains(body, `-4 -J -c '${server_host}'`) {
				t.Fatalf("%s does not force IPv4 for the remote iperf client", file)
			}
		})
	}
}
