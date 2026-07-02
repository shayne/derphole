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

func TestPublicPathPerformanceHarnessDocumentsBaselineMatrix(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "public-path-performance-harness.sh"))
	if err != nil {
		t.Fatalf("read public-path-performance-harness.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"DERPHOLE_PUBLIC_IPERF_PORT:-8321",
		"DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1",
		"DERPHOLE_V2_RAW_DIRECT_BUDGET_MS",
		"DERPHOLE_V2_MANAGER_QUIC_FANOUT",
		"iperf_reverse_received_mbps",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public-path-performance-harness.sh missing %q", want)
		}
	}
}
