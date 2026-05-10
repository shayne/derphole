// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseIperf3ResultPrefersReceivedTotals(t *testing.T) {
	report, err := parseIperf3Result([]byte(`{
  "end": {
    "sum_sent": {
      "seconds": 1.5,
      "bytes": 1048576,
      "bits_per_second": 5592405.3
    },
    "sum_received": {
      "seconds": 1.4,
      "bytes": 2097152,
      "bits_per_second": 11983725.7
    }
  }
}`))
	if err != nil {
		t.Fatalf("parseIperf3Result() error = %v", err)
	}
	if report.Bytes != 2097152 {
		t.Fatalf("report.Bytes = %d, want 2097152", report.Bytes)
	}
	if report.DurationMS != 1400 {
		t.Fatalf("report.DurationMS = %d, want 1400", report.DurationMS)
	}
	if report.BitsPerSecond != 11983725.7 {
		t.Fatalf("report.BitsPerSecond = %f, want 11983725.7", report.BitsPerSecond)
	}
}

func TestParseIperf3ResultFallsBackToSentTotals(t *testing.T) {
	report, err := parseIperf3Result([]byte(`{
  "end": {
    "sum_sent": {
      "seconds": 2.0,
      "bytes": 5242880,
      "bits_per_second": 20971520.0
    }
  }
}`))
	if err != nil {
		t.Fatalf("parseIperf3Result() error = %v", err)
	}
	if report.Bytes != 5242880 {
		t.Fatalf("report.Bytes = %d, want 5242880", report.Bytes)
	}
	if report.DurationMS != 2000 {
		t.Fatalf("report.DurationMS = %d, want 2000", report.DurationMS)
	}
	if report.BitsPerSecond != 20971520.0 {
		t.Fatalf("report.BitsPerSecond = %f, want 20971520.0", report.BitsPerSecond)
	}
}

func TestIperf3BaseArgsFindsIperf3OnPath(t *testing.T) {
	dir := t.TempDir()
	writeFakeIperf3(t, filepath.Join(dir, "iperf3"))
	t.Setenv("PATH", dir)

	argv, err := iperf3BaseArgs()
	if err != nil {
		t.Fatalf("iperf3BaseArgs() error = %v", err)
	}
	if got, want := filepath.Base(argv[0]), "iperf3"; got != want {
		t.Fatalf("iperf3BaseArgs()[0] = %q, want %q", got, want)
	}
}

func TestIperf3BaseArgsReportsMissingExecutable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := iperf3BaseArgs()
	if err == nil || !strings.Contains(err.Error(), "iperf3 not found") {
		t.Fatalf("iperf3BaseArgs() error = %v, want missing iperf3", err)
	}
}

func TestStartIperf3ServerWaitParsesJSON(t *testing.T) {
	dir := t.TempDir()
	writeFakeIperf3(t, filepath.Join(dir, "iperf3"))
	t.Setenv("PATH", dir)

	handle, err := startIperf3Server(context.Background(), "127.0.0.1", 5201)
	if err != nil {
		t.Fatalf("startIperf3Server() error = %v", err)
	}
	result, err := handle.Wait()
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if result.Bytes != 1234 || result.DurationMS != 250 {
		t.Fatalf("Wait() = %#v, want fake iperf3 totals", result)
	}
}

func TestIperf3ServerWaitHandlesNilAndProcessErrors(t *testing.T) {
	if _, err := (*iperf3ServerHandle)(nil).Wait(); err == nil {
		t.Fatal("nil Wait() error = nil, want error")
	}

	dir := t.TempDir()
	fake := filepath.Join(dir, "iperf3")
	writeFakeIperf3(t, fake)
	result, err := runIperf3ClientCommand(context.Background(), []string{fake, "--fail"})
	if err == nil || !strings.Contains(err.Error(), "simulated iperf3 failure") {
		t.Fatalf("runIperf3ClientCommand() = %#v, %v; want stderr error", result, err)
	}
}

func TestRunIperf3ClientBuildsCommandAndParsesResult(t *testing.T) {
	dir := t.TempDir()
	writeFakeIperf3(t, filepath.Join(dir, "iperf3"))
	t.Setenv("PATH", dir)

	result, err := runIperf3Client(context.Background(), iperf3ClientConfig{
		BindAddr:  "127.0.0.1",
		Target:    "127.0.0.1",
		Port:      5201,
		SizeBytes: 4096,
		Parallel:  4,
		Reverse:   true,
	})
	if err != nil {
		t.Fatalf("runIperf3Client() error = %v", err)
	}
	if result.Bytes != 1234 {
		t.Fatalf("runIperf3Client().Bytes = %d, want 1234", result.Bytes)
	}
}

func TestValidateAndAppendIperf3ClientArgs(t *testing.T) {
	for _, cfg := range []iperf3ClientConfig{
		{Target: "127.0.0.1", Port: 1},
		{BindAddr: "127.0.0.1", Port: 1},
		{BindAddr: "127.0.0.1", Target: "127.0.0.1"},
	} {
		if err := validateIperf3ClientConfig(cfg); err == nil {
			t.Fatalf("validateIperf3ClientConfig(%#v) error = nil, want invalid config", cfg)
		}
	}

	argv := appendIperf3ClientArgs([]string{"iperf3"}, iperf3ClientConfig{
		BindAddr:  "127.0.0.1",
		Target:    "198.51.100.10",
		Port:      5202,
		SizeBytes: 8192,
		Parallel:  2,
		Reverse:   true,
	})
	joined := strings.Join(argv, " ")
	for _, want := range []string{"-c 198.51.100.10", "-B 127.0.0.1", "-p 5202", "-n 8192", "-P 2", "-R"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("appendIperf3ClientArgs() = %q, missing %q", joined, want)
		}
	}
}

func writeFakeIperf3(t *testing.T, path string) {
	t.Helper()
	script := `#!/bin/sh
if [ "$1" = "--fail" ]; then
  echo "simulated iperf3 failure" >&2
  exit 3
fi
printf '%s\n' '{"end":{"sum_sent":{"seconds":0.25,"bytes":1234,"bits_per_second":39488}}}'
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}
