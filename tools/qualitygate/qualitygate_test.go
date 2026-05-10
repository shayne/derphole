// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCRAPReportKeys(t *testing.T) {
	report := `
FAIL: 2 function(s) exceed max CRAP score 30
exit status 1
       CRAP     Complexity   Coverage   Function                         Location
FAIL   2550.0   50           0.0%       (*Session).sendLoop      pkg/session/send.go:533
FAIL   361.0    61           56.8%      HandleTransfer          pkg/derphole/transfer.go:89
`

	got, err := parseCRAPReport([]byte(report))
	if err != nil {
		t.Fatalf("parseCRAPReport returned error: %v", err)
	}

	want := []hotspot{
		{Key: "crap|pkg/derphole/transfer.go|HandleTransfer", Detail: "pkg/derphole/transfer.go HandleTransfer"},
		{Key: "crap|pkg/session/send.go|(*Session).sendLoop", Detail: "pkg/session/send.go (*Session).sendLoop"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCRAPReport mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseGolangCIJSONKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pkg/session"), 0o755); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	source := []byte(`package session

func Call() {
	defer resp.Body.Close()
}
`)
	if err := os.WriteFile(filepath.Join(dir, "pkg/session/client.go"), source, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	t.Chdir(dir)

	report := `{
  "Issues": [
    {
      "FromLinter": "cyclop",
      "Text": "calculated cyclomatic complexity for function main is 18, max is 10",
      "Pos": {"Filename": "cmd/derphole/root.go", "Line": 103}
    },
    {
      "FromLinter": "gocognit",
      "Text": "cognitive complexity 94 of func ` + "`HandleTransfer`" + ` is high (> 30)",
      "Pos": {"Filename": "pkg/derphole/transfer.go", "Line": 89}
    },
    {
      "FromLinter": "errcheck",
      "Text": "Error return value of ` + "`resp.Body.Close`" + ` is not checked",
      "Pos": {"Filename": "pkg/session/client.go", "Line": 4},
      "SourceLines": ["\tdefer resp.Body.Close()"]
    },
    {
      "FromLinter": "staticcheck",
      "Text": "SA1019: deprecated. ",
      "Pos": {"Filename": "pkg/session/client.go", "Line": 4},
      "SourceLines": ["\tdefer resp.Body.Close()"]
    }
  ]
}`

	got, err := parseGolangCIJSON([]byte(report))
	if err != nil {
		t.Fatalf("parseGolangCIJSON returned error: %v", err)
	}

	want := []hotspot{
		{Key: "cyclop|cmd/derphole/root.go|main", Detail: "cmd/derphole/root.go main (cyclop)"},
		{Key: "errcheck|pkg/session/client.go|Call|source:defer resp.Body.Close()|Error return value of `resp.Body.Close` is not checked", Detail: "pkg/session/client.go:4 Error return value of `resp.Body.Close` is not checked (errcheck)"},
		{Key: "gocognit|pkg/derphole/transfer.go|HandleTransfer", Detail: "pkg/derphole/transfer.go HandleTransfer (gocognit)"},
		{Key: "staticcheck|pkg/session/client.go|Call|source:defer resp.Body.Close()|SA1019: deprecated.", Detail: "pkg/session/client.go:4 SA1019: deprecated. (staticcheck)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGolangCIJSON mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseReportAndGolangCIErrorPaths(t *testing.T) {
	if got, err := parseGolangCIJSON([]byte(" \n\t")); err != nil || got != nil {
		t.Fatalf("parseGolangCIJSON empty = %#v, %v; want nil nil", got, err)
	}
	if _, err := parseGolangCIJSON([]byte("{")); err == nil {
		t.Fatalf("parseGolangCIJSON succeeded for invalid JSON")
	}
	if _, err := parseReport("unknown", nil); err == nil || !strings.Contains(err.Error(), "unknown report kind") {
		t.Fatalf("parseReport unknown error = %v, want unknown report kind", err)
	}

	report := `{"Issues":[{"FromLinter":"staticcheck","Text":"bad","Pos":{"Filename":"","Line":99}}]}`
	got, err := parseGolangCIJSON([]byte(report))
	if err != nil {
		t.Fatalf("parseGolangCIJSON fallback returned error: %v", err)
	}
	want := []hotspot{{
		Key:    "staticcheck|unknown|line:99|bad",
		Detail: "unknown:99 bad (staticcheck)",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback hotspot = %#v, want %#v", got, want)
	}
}

func TestFunctionAtLineIncludesReceiver(t *testing.T) {
	source := []byte(`package demo

type Server struct{}

func (s *Server) Run() error {
	return nil
}
`)
	got := functionAtLine(source, 5)
	if got != "(*Server).Run" {
		t.Fatalf("functionAtLine = %q, want %q", got, "(*Server).Run")
	}
}

func TestFunctionRangesHandlesParseErrorsAndReceiverForms(t *testing.T) {
	if got := functionAtLine([]byte("package demo\nfunc {"), 1); got != "" {
		t.Fatalf("functionAtLine invalid source = %q, want empty", got)
	}

	source := []byte(`package demo

type Server struct{}

func (s Server) Value() {}

func topLevel() {}
`)
	if got := functionAtLine(source, 5); got != "(Server).Value" {
		t.Fatalf("value receiver functionAtLine = %q, want (Server).Value", got)
	}
	if got := functionAtLine(source, 7); got != "topLevel" {
		t.Fatalf("top-level functionAtLine = %q, want topLevel", got)
	}
	if got := functionAtLine(source, 1); got != "" {
		t.Fatalf("non-function line = %q, want empty", got)
	}
}

func TestFallbackIssueLocationPartsVariants(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "demo.go")
	source := []byte(`package demo

func Run() {
	println("hello")
}
`)
	if err := os.WriteFile(sourcePath, source, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	functions := map[string][]funcRange{}
	withSourceAndFunction := golangCIIssue{
		Text:        "issue",
		SourceLines: []string{"\tprintln(\"hello\")"},
	}
	withSourceAndFunction.Pos.Filename = sourcePath
	withSourceAndFunction.Pos.Line = 4
	if got := fallbackIssueLocationParts(withSourceAndFunction, sourcePath, functions); !reflect.DeepEqual(got, []string{"Run", "source:println(\"hello\")"}) {
		t.Fatalf("source/function parts = %#v", got)
	}

	sourceOnly := golangCIIssue{Text: "issue", SourceLines: []string{"a | b"}}
	sourceOnly.Pos.Line = 100
	if got := fallbackIssueLocationParts(sourceOnly, "missing.go", functions); !reflect.DeepEqual(got, []string{"source:a / b"}) {
		t.Fatalf("source-only parts = %#v", got)
	}

	fnOnly := golangCIIssue{Text: "issue"}
	fnOnly.Pos.Line = 3
	if got := fallbackIssueLocationParts(fnOnly, sourcePath, functions); !reflect.DeepEqual(got, []string{"Run", "line:3"}) {
		t.Fatalf("function-only parts = %#v", got)
	}

	if got := issueSourceKey(golangCIIssue{SourceLines: []string{" ", "\t"}}); got != "" {
		t.Fatalf("blank source key = %q, want empty", got)
	}
}

func TestCompareHotspotsAllowsBurnDownButRejectsNew(t *testing.T) {
	baseline := map[string]bool{
		"crap|pkg/old.go|oldRisk":   true,
		"crap|pkg/gone.go|goneRisk": true,
	}
	current := []hotspot{
		{Key: "crap|pkg/old.go|oldRisk", Detail: "pkg/old.go oldRisk"},
		{Key: "crap|pkg/new.go|newRisk", Detail: "pkg/new.go newRisk"},
	}

	gotNew, gotResolved := compareHotspots(baseline, current)

	if len(gotNew) != 1 || gotNew[0].Key != "crap|pkg/new.go|newRisk" {
		t.Fatalf("new hotspots mismatch: %#v", gotNew)
	}
	if !reflect.DeepEqual(gotResolved, []string{"crap|pkg/gone.go|goneRisk"}) {
		t.Fatalf("resolved hotspots mismatch: %#v", gotResolved)
	}
}

func TestBaselineFilesUniqueAndFirstHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.txt")
	hotspots := []hotspot{
		{Key: "b", Detail: "detail b"},
		{Key: "a", Detail: "detail a"},
		{Key: "a", Detail: "detail a duplicate"},
	}
	unique := uniqueHotspots(hotspots)
	if !reflect.DeepEqual(unique, []hotspot{{Key: "a", Detail: "detail a duplicate"}, {Key: "b", Detail: "detail b"}}) {
		t.Fatalf("uniqueHotspots = %#v", unique)
	}
	if err := writeBaselineFile(path, unique); err != nil {
		t.Fatalf("writeBaselineFile returned error: %v", err)
	}
	baseline, err := readBaselineFile(path)
	if err != nil {
		t.Fatalf("readBaselineFile returned error: %v", err)
	}
	if !baseline["a"] || !baseline["b"] || len(baseline) != 2 {
		t.Fatalf("baseline = %#v, want a and b", baseline)
	}
	if got := firstHotspots(unique, 1); len(got) != 1 || got[0].Key != "a" {
		t.Fatalf("firstHotspots = %#v, want first a", got)
	}
	if got := firstStrings([]string{"a", "b"}, 1); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("firstStrings = %#v, want [a]", got)
	}
	if got := stripLine("pkg/file.go"); got != "pkg/file.go" {
		t.Fatalf("stripLine without line = %q", got)
	}
}

func TestRunCLIWritesBaselineAndRejectsNewHotspot(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "crap.txt")
	baselinePath := filepath.Join(dir, "baseline.txt")

	report := []byte(`
       CRAP     Complexity   Coverage   Function       Location
FAIL   42.0     6            0.0%       riskyFunction  pkg/risk.go:10
`)
	if err := os.WriteFile(reportPath, report, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{
		"-kind", "crap",
		"-report", reportPath,
		"-baseline", baselinePath,
		"-write-baseline",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("write baseline code=%d stderr=%s", code, stderr.String())
	}

	code = runCLI([]string{
		"-kind", "crap",
		"-report", reportPath,
		"-baseline", baselinePath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("baseline check code=%d stderr=%s", code, stderr.String())
	}

	newReportPath := filepath.Join(dir, "new-crap.txt")
	newReport := []byte(`
       CRAP     Complexity   Coverage   Function       Location
FAIL   42.0     6            0.0%       riskyFunction  pkg/risk.go:10
FAIL   90.0     9            0.0%       newRisk        pkg/new.go:20
`)
	if err := os.WriteFile(newReportPath, newReport, 0o644); err != nil {
		t.Fatalf("write new report: %v", err)
	}

	code = runCLI([]string{
		"-kind", "crap",
		"-report", newReportPath,
		"-baseline", baselinePath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("new hotspot check code=%d, want 1", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("pkg/new.go newRisk")) {
		t.Fatalf("stderr does not mention new hotspot: %s", stderr.String())
	}
}

func TestRunCLIUsageAndFailurePaths(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCLI(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("runCLI missing args code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: qualitygate") {
		t.Fatalf("missing args stderr = %q, want usage", stderr.String())
	}

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.txt")
	stderr.Reset()
	code := runCLI([]string{"-kind", "crap", "-report", filepath.Join(dir, "missing.txt"), "-baseline", baselinePath}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "read report") {
		t.Fatalf("missing report code=%d stderr=%q, want read report", code, stderr.String())
	}

	reportPath := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(reportPath, []byte("not-json"), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	stderr.Reset()
	code = runCLI([]string{"-kind", "golangci-json", "-report", reportPath, "-baseline", baselinePath}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "parse report") {
		t.Fatalf("parse error code=%d stderr=%q, want parse report", code, stderr.String())
	}

	validReport := filepath.Join(dir, "valid.txt")
	if err := os.WriteFile(validReport, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write valid report: %v", err)
	}
	stderr.Reset()
	code = runCLI([]string{"-kind", "golangci-json", "-report", validReport, "-baseline", filepath.Join(dir, "missing-baseline.txt")}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "read baseline") {
		t.Fatalf("baseline read code=%d stderr=%q, want read baseline", code, stderr.String())
	}
}

func TestWritersIgnoreWriteErrors(t *testing.T) {
	writef(errorWriter{}, "hello %s", "world")
	writeLine(errorWriter{}, "hello", "world")
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

var _ io.Writer = errorWriter{}
