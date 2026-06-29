// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCLIUsageFailures(t *testing.T) {
	var stderr bytes.Buffer
	if code := runCLI(nil, &stderr); code != 2 {
		t.Fatalf("runCLI(nil) = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "derpssh-latency run") {
		t.Fatalf("usage output missing run example: %q", stderr.String())
	}

	stderr.Reset()
	if code := runCLI([]string{"unknown"}, &stderr); code != 2 {
		t.Fatalf("runCLI(unknown) = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("unknown command output missing usage: %q", stderr.String())
	}
}

func TestParseUnameTarget(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		wantOS   string
		wantArch string
		wantErr  string
	}{
		{name: "linux amd64", output: "Linux x86_64\n", wantOS: "linux", wantArch: "amd64"},
		{name: "darwin arm64", output: "Darwin arm64\n", wantOS: "darwin", wantArch: "arm64"},
		{name: "missing arch", output: "Linux\n", wantErr: "unexpected uname output"},
		{name: "bad os", output: "FreeBSD amd64\n", wantErr: "unsupported remote OS"},
		{name: "bad arch", output: "Linux riscv64\n", wantErr: "unsupported remote arch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOS, gotArch, err := parseUnameTarget(tt.output)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseUnameTarget error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseUnameTarget returned error: %v", err)
			}
			if gotOS != tt.wantOS || gotArch != tt.wantArch {
				t.Fatalf("parseUnameTarget = %s/%s, want %s/%s", gotOS, gotArch, tt.wantOS, tt.wantArch)
			}
		})
	}
}

func TestEchoLines(t *testing.T) {
	var output bytes.Buffer
	if err := echoLines(strings.NewReader("one\ntwo"), &output); err != nil {
		t.Fatalf("echoLines returned error: %v", err)
	}
	if got, want := output.String(), "one\ntwo"; got != want {
		t.Fatalf("echoLines output = %q, want %q", got, want)
	}
}

func TestMeasureEchoRecordsWarmupAndMeasuredSamples(t *testing.T) {
	var echo bytes.Buffer
	endpoint := lineEndpoint{reader: bufio.NewReader(&echo), writer: &echo}
	var records []sample

	durations, err := measureEcho(context.Background(), "fake", endpoint, 1, 2, 12, func(s sample) {
		records = append(records, s)
	})
	if err != nil {
		t.Fatalf("measureEcho returned error: %v", err)
	}
	if len(durations) != 2 {
		t.Fatalf("durations length = %d, want 2", len(durations))
	}
	if len(records) != 3 {
		t.Fatalf("records length = %d, want 3", len(records))
	}
	if !records[0].Warmup || records[1].Warmup || records[2].Warmup {
		t.Fatalf("warmup flags = %v, %v, %v; want true, false, false", records[0].Warmup, records[1].Warmup, records[2].Warmup)
	}
	for i, record := range records {
		if record.Seq != i {
			t.Fatalf("record %d seq = %d, want %d", i, record.Seq, i)
		}
		if record.PayloadBytes != 12 {
			t.Fatalf("record %d payload bytes = %d, want 12", i, record.PayloadBytes)
		}
	}
}

func TestSummarizeResultsComputesRatios(t *testing.T) {
	results, ratios := summarizeResults(map[string][]time.Duration{
		"ssh-stdio":            {80 * time.Millisecond, 82 * time.Millisecond},
		"derptun-mux-over-ssh": {81 * time.Millisecond, 83 * time.Millisecond},
	})
	if results["ssh-stdio"].Count != 2 {
		t.Fatalf("ssh count = %d, want 2", results["ssh-stdio"].Count)
	}
	if got := ratios["derptun-mux-over-ssh_p50_vs_ssh"]; got <= 1.0 {
		t.Fatalf("p50 ratio = %f, want greater than 1", got)
	}
	if got := ratios["derptun-mux-over-ssh_p95_vs_ssh"]; got <= 1.0 {
		t.Fatalf("p95 ratio = %f, want greater than 1", got)
	}
}

func TestPrintSummary(t *testing.T) {
	sum := summary{
		Remote:       "tester@example",
		CompletedAt:  time.Date(2026, 6, 29, 4, 52, 19, 0, time.UTC),
		Samples:      2,
		Warmup:       1,
		RemoteGOOS:   "linux",
		RemoteGOARCH: "amd64",
		Results: map[string]stats{
			"ssh-stdio":            {P50US: 80_000, P90US: 82_000, P95US: 83_000, MaxUS: 84_000},
			"derptun-mux-over-ssh": {P50US: 81_000, P90US: 83_000, P95US: 84_000, MaxUS: 85_000},
		},
		Ratios: map[string]float64{"derptun-mux-over-ssh_p50_vs_ssh": 1.01},
	}

	var output bytes.Buffer
	printSummary(&output, sum)
	text := output.String()
	for _, want := range []string{"tester@example", "derptun-mux-over-ssh", "ssh-stdio", "ratios:", "1.01x"} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary output missing %q:\n%s", want, text)
		}
	}
}

func TestCompareWithOutput(t *testing.T) {
	beforeDir := t.TempDir()
	afterDir := t.TempDir()
	writeSummaryForTest(t, filepath.Join(beforeDir, "summary.json"), summary{
		Results: map[string]stats{"ssh-stdio": {P50US: 80_000, P95US: 83_000}},
	})
	writeSummaryForTest(t, filepath.Join(afterDir, "summary.json"), summary{
		Results: map[string]stats{"ssh-stdio": {P50US: 79_000, P95US: 82_000}},
	})

	var stdout bytes.Buffer
	if err := compareWithOutput([]string{beforeDir, afterDir}, &stdout, io.Discard); err != nil {
		t.Fatalf("compareWithOutput returned error: %v", err)
	}
	text := stdout.String()
	for _, want := range []string{"scenario", "ssh-stdio", "80.0ms", "79.0ms", "83.0ms", "82.0ms"} {
		if !strings.Contains(text, want) {
			t.Fatalf("compare output missing %q:\n%s", want, text)
		}
	}
}

func TestRunWithDepsValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "remote required", args: nil, wantErr: "--remote is required"},
		{name: "samples positive", args: []string{"--remote", "tester", "--samples", "0"}, wantErr: "--samples must be greater than zero"},
		{name: "warmup nonnegative", args: []string{"--remote", "tester", "--warmup", "-1"}, wantErr: "--warmup must be zero or greater"},
		{name: "payload nonnegative", args: []string{"--remote", "tester", "--payload-bytes", "-1"}, wantErr: "--payload-bytes must be zero or greater"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runWithDeps(tt.args, testRunDeps(nil), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runWithDeps error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunWithDepsWritesArtifacts(t *testing.T) {
	outDir := t.TempDir()
	var builtPath, uploadedRemote, uploadedLocal, uploadedPath, removedRemote, removedPath string
	now := time.Date(2026, 6, 29, 4, 52, 19, 0, time.UTC)
	nowCalls := 0
	deps := testRunDeps([]scenarioSpec{
		{name: "ssh-stdio", run: fakeScenarioRunner([]time.Duration{80 * time.Millisecond, 82 * time.Millisecond})},
		{name: "derptun-mux-over-ssh", run: fakeScenarioRunner([]time.Duration{81 * time.Millisecond, 83 * time.Millisecond})},
	})
	deps.now = func() time.Time {
		current := now.Add(time.Duration(nowCalls) * time.Second)
		nowCalls++
		return current
	}
	deps.buildHelper = func(path, goos, goarch string) error {
		builtPath = path
		if goos != "linux" || goarch != "amd64" {
			t.Fatalf("build target = %s/%s, want linux/amd64", goos, goarch)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("helper"), 0o755)
	}
	deps.uploadHelper = func(remote, localPath, remotePath string) error {
		uploadedRemote = remote
		uploadedLocal = localPath
		uploadedPath = remotePath
		return nil
	}
	deps.removeRemote = func(remote, path string) {
		removedRemote = remote
		removedPath = path
	}

	var stdout bytes.Buffer
	err := runWithDeps([]string{
		"--remote", "tester@example",
		"--out", outDir,
		"--samples", "2",
		"--warmup", "1",
		"--payload-bytes", "12",
		"--timeout", "1s",
	}, deps, &stdout, io.Discard)
	if err != nil {
		t.Fatalf("runWithDeps returned error: %v", err)
	}
	if builtPath == "" || uploadedLocal != builtPath {
		t.Fatalf("helper path not wired through build/upload: built=%q uploaded=%q", builtPath, uploadedLocal)
	}
	if uploadedRemote != "tester@example" || removedRemote != "tester@example" {
		t.Fatalf("remote cleanup/upload mismatch: uploaded=%q removed=%q", uploadedRemote, removedRemote)
	}
	if uploadedPath == "" || removedPath != uploadedPath {
		t.Fatalf("remote helper cleanup mismatch: uploaded=%q removed=%q", uploadedPath, removedPath)
	}
	if !strings.Contains(stdout.String(), "derptun-mux-over-ssh_p50_vs_ssh") {
		t.Fatalf("stdout missing ratio:\n%s", stdout.String())
	}

	var sum summary
	readJSONForTest(t, filepath.Join(outDir, "summary.json"), &sum)
	if sum.Remote != "tester@example" || sum.RemoteGOOS != "linux" || sum.RemoteGOARCH != "amd64" {
		t.Fatalf("summary remote fields = %q %s/%s", sum.Remote, sum.RemoteGOOS, sum.RemoteGOARCH)
	}
	if sum.Results["ssh-stdio"].Count != 2 || sum.Results["derptun-mux-over-ssh"].Count != 2 {
		t.Fatalf("summary counts = %#v", sum.Results)
	}
	if sum.Ratios["derptun-mux-over-ssh_p50_vs_ssh"] <= 1.0 {
		t.Fatalf("summary ratio = %f, want greater than 1", sum.Ratios["derptun-mux-over-ssh_p50_vs_ssh"])
	}
	assertJSONLLineCount(t, filepath.Join(outDir, "samples.jsonl"), 6)
	assertJSONLLineCount(t, filepath.Join(outDir, "events.jsonl"), 7)
}

func testRunDeps(scenarios []scenarioSpec) runDeps {
	return runDeps{
		detectTarget: func(string) (string, string, error) { return "linux", "amd64", nil },
		buildHelper:  func(string, string, string) error { return nil },
		uploadHelper: func(string, string, string) error { return nil },
		removeRemote: func(string, string) {},
		now:          func() time.Time { return time.Date(2026, 6, 29, 4, 52, 19, 0, time.UTC) },
		gitCommit:    func() string { return "abcdef123456" },
		scenarios:    scenarios,
	}
}

func fakeScenarioRunner(durations []time.Duration) scenarioRunner {
	return func(_ context.Context, scenario, remote, remotePath, outDir string, warmup, samples, payloadBytes int, record func(sample)) ([]time.Duration, error) {
		if remote == "" || remotePath == "" || outDir == "" {
			return nil, errorsForTest("missing scenario wiring")
		}
		for i := 0; i < warmup+samples; i++ {
			record(sample{
				Scenario:     scenario,
				Seq:          i,
				Warmup:       i < warmup,
				DurationUS:   int64(i + 1),
				PayloadBytes: payloadBytes,
			})
		}
		return durations, nil
	}
}

type errorsForTest string

func (e errorsForTest) Error() string {
	return string(e)
}

func writeSummaryForTest(t *testing.T, path string, sum summary) {
	t.Helper()
	if err := writeJSON(path, sum); err != nil {
		t.Fatalf("write summary: %v", err)
	}
}

func readJSONForTest(t *testing.T, path string, target any) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func assertJSONLLineCount(t *testing.T, path string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		t.Fatalf("%s is empty, want %d lines", path, want)
	}
	got := strings.Count(text, "\n") + 1
	if got != want {
		t.Fatalf("%s has %d lines, want %d:\n%s", path, got, want, text)
	}
}
