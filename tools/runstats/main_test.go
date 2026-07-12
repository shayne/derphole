// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type resourceResult struct {
	UserCPUSeconds         float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds       float64 `json:"system_cpu_seconds"`
	MaxRSSBytes            uint64  `json:"max_rss_bytes"`
	ResourceStatsAvailable bool    `json:"resource_stats_available"`
	ExitCode               int     `json:"exit_code"`
}

func TestRunWritesResourceStatsForSuccessfulChild(t *testing.T) {
	out := filepath.Join(t.TempDir(), "resource.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"-out", out, "--", "/bin/sh", "-c", "printf child-out; printf child-err >&2"}, nil, &stdout, &stderr, func(*os.ProcessState) (uint64, bool) {
		return 12345, true
	})
	if code != 0 {
		t.Fatalf("run exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "child-out"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := stderr.String(), "child-err"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}

	result := readResourceResult(t, out)
	if result.ExitCode != 0 {
		t.Fatalf("resource exit code = %d, want 0", result.ExitCode)
	}
	if result.UserCPUSeconds < 0 || result.SystemCPUSeconds < 0 {
		t.Fatalf("negative CPU result: %+v", result)
	}
	if result.MaxRSSBytes != 12345 || !result.ResourceStatsAvailable {
		t.Fatalf("resource result = %+v, want RSS 12345 available", result)
	}
}

func TestRunPreservesChildExitCodeAfterWritingStats(t *testing.T) {
	out := filepath.Join(t.TempDir(), "resource.json")

	code := run([]string{"-out", out, "--", "/bin/sh", "-c", "exit 7"}, nil, &bytes.Buffer{}, &bytes.Buffer{}, func(*os.ProcessState) (uint64, bool) {
		return 99, true
	})
	if code != 7 {
		t.Fatalf("run exit code = %d, want 7", code)
	}
	if got := readResourceResult(t, out).ExitCode; got != 7 {
		t.Fatalf("resource exit code = %d, want 7", got)
	}
}

func TestRunAtomicallyReplacesResourceJSON(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "resource.json")
	ready := filepath.Join(dir, "ready")
	gate := filepath.Join(dir, "gate")
	old := []byte(`{"previous":true}`)
	if err := os.WriteFile(out, old, 0o600); err != nil {
		t.Fatalf("write old result: %v", err)
	}

	done := make(chan int, 1)
	go func() {
		done <- run([]string{"-out", out, "--", "/bin/sh", "-c", `touch "$1"; while [ ! -e "$2" ]; do sleep 0.01; done`, "sh", ready, gate}, nil, &bytes.Buffer{}, &bytes.Buffer{}, func(*os.ProcessState) (uint64, bool) {
			return 1, true
		})
	}()
	waitForPath(t, ready)

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read in-flight result: %v", err)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("in-flight result = %q, want unchanged old result %q", got, old)
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatalf("open gate: %v", err)
	}
	if code := <-done; code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	if result := readResourceResult(t, out); result.ExitCode != 0 {
		t.Fatalf("final resource result = %+v", result)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".resource.json.*"))
	if err != nil {
		t.Fatalf("glob temporary results: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary resource files remain: %v", matches)
	}
}

func TestRunRecordsUnavailableResourceFallback(t *testing.T) {
	out := filepath.Join(t.TempDir(), "resource.json")

	code := run([]string{"-out", out, "--", "/bin/sh", "-c", "exit 0"}, nil, &bytes.Buffer{}, &bytes.Buffer{}, func(*os.ProcessState) (uint64, bool) {
		return 0, false
	})
	if code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	result := readResourceResult(t, out)
	if result.ResourceStatsAvailable || result.MaxRSSBytes != 0 {
		t.Fatalf("resource result = %+v, want unavailable zero RSS", result)
	}
}

func TestRunWrites127WhenChildCannotStart(t *testing.T) {
	out := filepath.Join(t.TempDir(), "resource.json")

	code := run([]string{"-out", out, "--", filepath.Join(t.TempDir(), "missing")}, nil, &bytes.Buffer{}, &bytes.Buffer{}, func(*os.ProcessState) (uint64, bool) {
		return 0, false
	})
	if code != 127 {
		t.Fatalf("run exit code = %d, want 127", code)
	}
	if got := readResourceResult(t, out).ExitCode; got != 127 {
		t.Fatalf("resource exit code = %d, want 127", got)
	}
}

func TestRunRejectsMissingCommandDelimiter(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "resource.json")
	marker := filepath.Join(dir, "child-ran")
	var stderr bytes.Buffer

	code := run([]string{"-out", out, "/bin/sh", "-c", `touch "$1"`, "sh", marker}, nil, &bytes.Buffer{}, &stderr, maxRSSBytes)
	if code != 2 {
		t.Fatalf("run exit code = %d, want usage status 2; stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child marker stat error = %v, want child not executed", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("resource output stat error = %v, want no JSON", err)
	}
}

func TestMaxRSSBytesIsAvailableOnSupportedPlatforms(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("resource usage is only required on darwin and linux")
	}
	out := filepath.Join(t.TempDir(), "resource.json")
	code := run([]string{"-out", out, "--", "/bin/sh", "-c", "exit 0"}, nil, &bytes.Buffer{}, &bytes.Buffer{}, maxRSSBytes)
	if code != 0 {
		t.Fatalf("run exit code = %d, want 0", code)
	}
	if result := readResourceResult(t, out); !result.ResourceStatsAvailable {
		t.Fatalf("resource result = %+v, want available stats on %s", result, runtime.GOOS)
	}
}

func readResourceResult(t *testing.T, path string) resourceResult {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read resource result: %v", err)
	}
	var result resourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode resource result %q: %v", data, err)
	}
	return result
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
