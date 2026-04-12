package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shayne/derpcat/pkg/probe"
)

func TestParsePromotionSummaryReadsBenchmarkFooter(t *testing.T) {
	raw := strings.Join([]string{
		"target=ktzlxc",
		"size_mib=1024",
		"benchmark-host=ktzlxc",
		"benchmark-direction=forward",
		"benchmark-size-bytes=1073741824",
		"benchmark-total-duration-ms=4210",
		"benchmark-goodput-mbps=2039.1",
		"benchmark-peak-goodput-mbps=2210.4",
		"benchmark-first-byte-ms=18",
		"benchmark-success=true",
	}, "\n")

	got, err := parsePromotionSummary([]byte(raw))
	if err != nil {
		t.Fatalf("parsePromotionSummary() error = %v", err)
	}
	if got.Host != "ktzlxc" {
		t.Fatalf("Host = %q, want %q", got.Host, "ktzlxc")
	}
	if got.Direction != "forward" {
		t.Fatalf("Direction = %q, want %q", got.Direction, "forward")
	}
	if got.PeakGoodputMbps != 2210.4 {
		t.Fatalf("PeakGoodputMbps = %.1f, want 2210.4", got.PeakGoodputMbps)
	}
	if got.Success == nil || !*got.Success {
		t.Fatalf("Success = %#v, want true", got.Success)
	}
}

func TestParsePromotionSummaryRejectsMalformedNumericFooter(t *testing.T) {
	raw := strings.Join([]string{
		"benchmark-host=ktzlxc",
		"benchmark-direction=forward",
		"benchmark-size-bytes=1073741824",
		"benchmark-total-duration-ms=not-a-number",
		"benchmark-goodput-mbps=2039.1",
		"benchmark-peak-goodput-mbps=2210.4",
		"benchmark-first-byte-ms=18",
		"benchmark-success=true",
	}, "\n")

	if _, err := parsePromotionSummary([]byte(raw)); err == nil {
		t.Fatal("parsePromotionSummary() error = nil, want malformed footer error")
	}
}

func TestParsePromotionSummaryRejectsMalformedSuccessFooter(t *testing.T) {
	raw := strings.Join([]string{
		"benchmark-host=ktzlxc",
		"benchmark-direction=forward",
		"benchmark-size-bytes=1073741824",
		"benchmark-total-duration-ms=4210",
		"benchmark-goodput-mbps=2039.1",
		"benchmark-peak-goodput-mbps=2210.4",
		"benchmark-first-byte-ms=18",
		"benchmark-success=maybe",
	}, "\n")

	if _, err := parsePromotionSummary([]byte(raw)); err == nil {
		t.Fatal("parsePromotionSummary() error = nil, want malformed success footer error")
	}
}

func TestRunMatrixIteratesAllHostsDirectionsAndIterations(t *testing.T) {
	prev := runMatrixCommand
	defer func() { runMatrixCommand = prev }()

	var calls []string
	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		calls = append(calls, script+":"+host)
		return []byte(strings.Join([]string{
			"benchmark-host=" + host,
			"benchmark-direction=forward",
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=5000",
			"benchmark-goodput-mbps=1700.0",
			"benchmark-peak-goodput-mbps=2000.0",
			"benchmark-first-byte-ms=20",
			"benchmark-success=true",
		}, "\n")), nil
	}

	_, err := runMatrix(context.Background(), matrixConfig{
		Hosts:      []string{"ktzlxc", "canlxc"},
		Iterations: 2,
		SizeMiB:    1024,
	})
	if err != nil {
		t.Fatalf("runMatrix() error = %v", err)
	}
	if got, want := len(calls), 8; got != want {
		t.Fatalf("len(calls) = %d, want %d", got, want)
	}
}

func TestRunMatrixIteratesRequestedTools(t *testing.T) {
	prev := runMatrixCommand
	defer func() { runMatrixCommand = prev }()

	var calls []string
	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		calls = append(calls, script+":"+host)
		return []byte(strings.Join([]string{
			"benchmark-host=" + host,
			"benchmark-direction=forward",
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=5000",
			"benchmark-goodput-mbps=1700.0",
			"benchmark-peak-goodput-mbps=2000.0",
			"benchmark-first-byte-ms=20",
			"benchmark-success=true",
		}, "\n")), nil
	}

	_, err := runMatrix(context.Background(), matrixConfig{
		Hosts:      []string{"ktzlxc"},
		Tools:      []string{"derpcat", "derphole", "iperf"},
		Iterations: 1,
		SizeMiB:    1024,
	})
	if err != nil {
		t.Fatalf("runMatrix() error = %v", err)
	}
	if got, want := len(calls), 6; got != want {
		t.Fatalf("len(calls) = %d, want %d", got, want)
	}
}

func TestRunMatrixCmdReturnsNonZeroWhenAnyRunFails(t *testing.T) {
	prev := runMatrixCommand
	defer func() { runMatrixCommand = prev }()

	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		raw := []string{
			"benchmark-host=" + host,
			"benchmark-direction=forward",
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=5000",
			"benchmark-goodput-mbps=1700.0",
			"benchmark-peak-goodput-mbps=2000.0",
			"benchmark-first-byte-ms=20",
		}
		if strings.Contains(script, "reverse") {
			raw = append(raw,
				"benchmark-success=false",
				"benchmark-error=simulated failure",
			)
		} else {
			raw = append(raw, "benchmark-success=true")
		}
		return []byte(strings.Join(raw, "\n")), nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMatrixCmd([]string{"--hosts", "ktzlxc", "--iterations", "1", "--size-mib", "1024"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runMatrixCmd() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "\"error\": \"simulated failure\"") {
		t.Fatalf("stdout missing failure report: %s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunMatrixCmdWritesOutFile(t *testing.T) {
	prev := runMatrixCommand
	defer func() { runMatrixCommand = prev }()

	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		direction := "forward"
		if strings.Contains(script, "reverse") {
			direction = "reverse"
		}
		return []byte(strings.Join([]string{
			"benchmark-host=" + host,
			"benchmark-direction=" + direction,
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=5000",
			"benchmark-goodput-mbps=1700.0",
			"benchmark-peak-goodput-mbps=2000.0",
			"benchmark-first-byte-ms=20",
			"benchmark-success=true",
		}, "\n")), nil
	}

	outPath := filepath.Join(t.TempDir(), "matrix.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMatrixCmd([]string{"--hosts", "ktzlxc", "--iterations", "1", "--size-mib", "1024", "--out", outPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMatrixCmd() code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", outPath, err)
	}
	var report matrixReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("json.Unmarshal(out file) error = %v", err)
	}
	if got, want := len(report.Runs), 2; got != want {
		t.Fatalf("len(report.Runs) = %d, want %d", got, want)
	}
}

func TestSummarizeMatrixRunsSeparatesTools(t *testing.T) {
	runs := []probe.RunReport{
		{Host: "ktzlxc", Mode: "derpcat", Direction: "forward", DurationMS: 1000, GoodputMbps: 100, Success: boolPtr(true)},
		{Host: "ktzlxc", Mode: "derphole", Direction: "forward", DurationMS: 1000, GoodputMbps: 90, Success: boolPtr(true)},
	}

	got := summarizeMatrixRuns(runs)
	if gotCount, wantCount := len(got), 2; gotCount != wantCount {
		t.Fatalf("len(summaries) = %d, want %d", gotCount, wantCount)
	}
	if got[0].Tool == got[1].Tool {
		t.Fatalf("summaries = %#v, want distinct tool keys", got)
	}
}

func TestRunMatrixCmdReturnsNonZeroOnBaselineRegression(t *testing.T) {
	prev := runMatrixCommand
	defer func() { runMatrixCommand = prev }()

	runMatrixCommand = func(_ context.Context, script string, host string, sizeMiB int) ([]byte, error) {
		direction := "forward"
		if strings.Contains(script, "reverse") {
			direction = "reverse"
		}
		return []byte(strings.Join([]string{
			"benchmark-host=" + host,
			"benchmark-direction=" + direction,
			"benchmark-size-bytes=1073741824",
			"benchmark-total-duration-ms=6000",
			"benchmark-goodput-mbps=1500.0",
			"benchmark-peak-goodput-mbps=1600.0",
			"benchmark-first-byte-ms=20",
			"benchmark-success=true",
		}, "\n")), nil
	}

	baseline := matrixReport{
		Config: matrixConfig{
			Hosts:      []string{"ktzlxc"},
			Iterations: 1,
			SizeMiB:    1024,
		},
		Summaries: []matrixSeries{
			{
				Host:      "ktzlxc",
				Direction: "forward",
				Summary: probe.SeriesSummary{
					RunCount:           1,
					SuccessCount:       1,
					AverageGoodputMbps: 2000.0,
					PeakGoodputMbps:    2100.0,
					AverageWallTimeMS:  5000,
				},
			},
			{
				Host:      "ktzlxc",
				Direction: "reverse",
				Summary: probe.SeriesSummary{
					RunCount:           1,
					SuccessCount:       1,
					AverageGoodputMbps: 2000.0,
					PeakGoodputMbps:    2100.0,
					AverageWallTimeMS:  5000,
				},
			},
		},
	}
	basePath := filepath.Join(t.TempDir(), "baseline.json")
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatalf("json.Marshal(baseline) error = %v", err)
	}
	if err := os.WriteFile(basePath, raw, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", basePath, err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMatrixCmd([]string{"--hosts", "ktzlxc", "--iterations", "1", "--size-mib", "1024", "--baseline", basePath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runMatrixCmd() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "\"goodput_regression\": true") {
		t.Fatalf("stdout missing regression result: %s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
