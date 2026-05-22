// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRankHotspotsStableAndDeterministic(t *testing.T) {
	signals := map[string]*signal{
		"pkg/b.go": {churn: 1},
		"pkg/a.go": {churn: 1},
		"pkg/c.go": {churn: 1, issues: 1},
	}

	got := rankHotspots(signals)
	gotPaths := hotspotPaths(got)
	wantPaths := []string{"pkg/c.go", "pkg/a.go", "pkg/b.go"}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("ranked paths = %#v, want %#v", gotPaths, wantPaths)
	}

	again := rankHotspots(signals)
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("rankHotspots not deterministic:\n got: %#v\nagain: %#v", got, again)
	}
}

func TestBuildReportWithMissingInputs(t *testing.T) {
	dir := t.TempDir()

	report, err := buildReport(options{
		Root:         dir,
		CoveragePath: "missing-cover.out",
		GolangCIPath: "missing-golangci.json",
		CRAPPath:     "missing-crap.txt",
		Limit:        10,
		ChurnCommits: 1,
	})
	if err != nil {
		t.Fatalf("buildReport returned error: %v", err)
	}
	if !strings.Contains(report, "git-churn=no coverage=no golangci=no crap=no") {
		t.Fatalf("report inputs = %q, want all no", report)
	}
	if !strings.Contains(report, "No hotspots found from available inputs.") {
		t.Fatalf("report = %q, want no hotspots message", report)
	}
}

func TestBuildReportCombinesAvailableInputsAndSkipsNoise(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "coverage.out"), []byte(`mode: set
github.com/shayne/derphole/pkg/risk.go:1.1,3.2 4 0
pkg/steady.go:1.1,3.2 10 10
vendor/example/noise.go:1.1,2.2 1 0
`))
	mustWrite(t, filepath.Join(dir, "golangci.json"), []byte(`{
  "Issues": [
    {"Pos": {"Filename": "pkg/risk.go"}},
    {"Pos": {"Filename": "pkg/risk.go"}},
    {"Pos": {"Filename": "cache/noise.go"}}
  ]
}`))
	mustWrite(t, filepath.Join(dir, "crap.txt"), []byte(`
       CRAP     Complexity   Coverage   Function       Location
FAIL   50.0     6            0.0%       riskyFunction  pkg/risk.go:10
FAIL   999.0    99           0.0%       generated      pkg/thing.pb.go:10
`))

	report, err := buildReport(options{
		Root:         dir,
		CoveragePath: "coverage.out",
		GolangCIPath: "golangci.json",
		CRAPPath:     "crap.txt",
		Limit:        10,
		ChurnCommits: 1,
	})
	if err != nil {
		t.Fatalf("buildReport returned error: %v", err)
	}
	for _, want := range []string{
		"git-churn=no coverage=yes golangci=yes crap=yes",
		"pkg/risk.go",
		"  200.0",
		"0.0%",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	for _, unwanted := range []string{"vendor/example/noise.go", "cache/noise.go", "pkg/thing.pb.go"} {
		if strings.Contains(report, unwanted) {
			t.Fatalf("report includes skipped path %q:\n%s", unwanted, report)
		}
	}
}

func TestBuildReportIgnoresDeletedFilesInGitChurn(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.invalid")
	runGit(t, dir, "config", "user.name", "Test User")

	mustWrite(t, filepath.Join(dir, "pkg/active.go"), []byte("package pkg\n\nfunc active() {}\n"))
	mustWrite(t, filepath.Join(dir, "pkg/retired.go"), []byte("package pkg\n\nfunc retired() {}\n"))
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial")

	if err := os.Remove(filepath.Join(dir, "pkg/retired.go")); err != nil {
		t.Fatalf("remove retired file: %v", err)
	}
	mustWrite(t, filepath.Join(dir, "pkg/active.go"), []byte("package pkg\n\nfunc active() {}\nfunc changed() {}\n"))
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", "retire old file")

	report, err := buildReport(options{
		Root:         dir,
		CoveragePath: "missing-cover.out",
		GolangCIPath: "missing-golangci.json",
		CRAPPath:     "missing-crap.txt",
		Limit:        10,
		ChurnCommits: 10,
	})
	if err != nil {
		t.Fatalf("buildReport returned error: %v", err)
	}
	if !strings.Contains(report, "pkg/active.go") {
		t.Fatalf("report missing active file churn:\n%s", report)
	}
	if strings.Contains(report, "pkg/retired.go") {
		t.Fatalf("report includes deleted file churn:\n%s", report)
	}
}

func TestRunCLIWritesOutputWhenRequested(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "coverage.out"), []byte(`mode: set
pkg/risk.go:1.1,3.2 5 0
`))
	outPath := filepath.Join(dir, ".tmp/quality/hotspots.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{
		"-root", dir,
		"-coverage", "coverage.out",
		"-golangci", "missing.json",
		"-crap", "missing.txt",
		"-churn-commits", "1",
		"-write",
		"-output", outPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCLI code=%d stderr=%s", code, stderr.String())
	}
	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Contains(written, []byte("pkg/risk.go")) {
		t.Fatalf("written report missing hotspot:\n%s", string(written))
	}
	if !bytes.Contains(stdout.Bytes(), []byte("pkg/risk.go")) {
		t.Fatalf("stdout missing hotspot:\n%s", stdout.String())
	}
}

func TestParseCoverageLine(t *testing.T) {
	file, stmts, covered, ok := parseCoverageLine("github.com/shayne/derphole/pkg/risk.go:1.1,2.2 3 0")
	if !ok || file != "pkg/risk.go" || stmts != 3 || covered {
		t.Fatalf("parseCoverageLine = %q %d %v %v", file, stmts, covered, ok)
	}
	if _, _, _, ok := parseCoverageLine("bad"); ok {
		t.Fatalf("parseCoverageLine succeeded for bad input")
	}
}

func TestSkipPath(t *testing.T) {
	for _, path := range []string{
		"vendor/pkg/file.go",
		".tmp/quality/file.go",
		"pkg/demo.pb.go",
		"pkg/zz_generated.deepcopy.go",
		"pkg/cache/file.go",
		"README.md",
		"website",
	} {
		if !skipPath(path) {
			t.Fatalf("skipPath(%q) = false, want true", path)
		}
	}
	if skipPath("pkg/service.go") {
		t.Fatalf("skipPath for normal file = true, want false")
	}
}

func hotspotPaths(hotspots []hotspot) []string {
	out := make([]string, 0, len(hotspots))
	for _, h := range hotspots {
		out = append(out, h.path)
	}
	return out
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}
