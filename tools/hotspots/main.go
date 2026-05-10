// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultOutputPath = ".tmp/quality/hotspots.txt"

type options struct {
	Root         string
	CoveragePath string
	GolangCIPath string
	CRAPPath     string
	OutputPath   string
	WriteOutput  bool
	Limit        int
	ChurnCommits int
}

type signal struct {
	churn       int
	issues      int
	crap        float64
	coverage    float64
	hasCoverage bool
}

type hotspot struct {
	path  string
	score float64
	sig   signal
}

type inputSummary struct {
	gitChurn bool
	coverage bool
	golangci bool
	crap     bool
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	opts, ok := parseOptions(args, stderr)
	if !ok {
		return 2
	}
	report, err := buildReport(opts)
	if err != nil {
		writef(stderr, "hotspots: %v\n", err)
		return 2
	}
	writeLine(stdout, report)
	if opts.WriteOutput {
		if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
			writef(stderr, "write output: %v\n", err)
			return 2
		}
		if err := os.WriteFile(opts.OutputPath, []byte(report), 0o644); err != nil {
			writef(stderr, "write output: %v\n", err)
			return 2
		}
	}
	return 0
}

func parseOptions(args []string, stderr io.Writer) (options, bool) {
	opts := options{
		Root:         ".",
		CoveragePath: ".tmp/quality/coverage.out",
		GolangCIPath: ".tmp/quality/golangci.json",
		CRAPPath:     ".tmp/quality/crap.txt",
		OutputPath:   defaultOutputPath,
		Limit:        25,
		ChurnCommits: 200,
	}
	flags := flag.NewFlagSet("hotspots", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.Root, "root", opts.Root, "repository root")
	flags.StringVar(&opts.CoveragePath, "coverage", opts.CoveragePath, "Go coverage profile path")
	flags.StringVar(&opts.GolangCIPath, "golangci", opts.GolangCIPath, "golangci-lint JSON report path")
	flags.StringVar(&opts.CRAPPath, "crap", opts.CRAPPath, "CRAP report path")
	flags.BoolVar(&opts.WriteOutput, "write", false, "also write the report to .tmp/quality/hotspots.txt")
	flags.StringVar(&opts.OutputPath, "output", opts.OutputPath, "path used with -write")
	flags.IntVar(&opts.Limit, "limit", opts.Limit, "maximum hotspots to print")
	flags.IntVar(&opts.ChurnCommits, "churn-commits", opts.ChurnCommits, "git commits to scan for churn")
	if err := flags.Parse(args); err != nil {
		return options{}, false
	}
	if opts.Limit < 1 || opts.ChurnCommits < 1 {
		writeLine(stderr, "usage: hotspots [-root DIR] [-coverage PATH] [-golangci PATH] [-crap PATH] [-limit N] [-churn-commits N] [-write [-output PATH]]")
		return options{}, false
	}
	return opts, true
}

func buildReport(opts options) (string, error) {
	signals := map[string]*signal{}
	var summary inputSummary

	summary.gitChurn = addChurnSignals(signals, opts.Root, opts.ChurnCommits)
	var err error
	if summary.coverage, err = addCoverageSignals(signals, filepath.Join(opts.Root, opts.CoveragePath)); err != nil {
		return "", err
	}
	if summary.golangci, err = addCountSignals(signals, filepath.Join(opts.Root, opts.GolangCIPath), readGolangCI, func(sig *signal, count int) {
		sig.issues = count
	}); err != nil {
		return "", err
	}
	if summary.crap, err = addFloatSignals(signals, filepath.Join(opts.Root, opts.CRAPPath), readCRAP, func(sig *signal, score float64) {
		sig.crap = score
	}); err != nil {
		return "", err
	}

	hotspots := rankHotspots(signals)
	return formatReport(hotspots, summary, opts.Limit), nil
}

func addChurnSignals(signals map[string]*signal, root string, commits int) bool {
	churn, ok := gitChurn(root, commits)
	if !ok {
		return false
	}
	for path, count := range churn {
		signalsFor(signals, path).churn = count
	}
	return true
}

func addCoverageSignals(signals map[string]*signal, path string) (bool, error) {
	coverage, ok, err := readCoverage(path)
	if err != nil || !ok {
		return ok, err
	}
	for path, pct := range coverage {
		sig := signalsFor(signals, path)
		sig.coverage = pct
		sig.hasCoverage = true
	}
	return true, nil
}

func addCountSignals(
	signals map[string]*signal,
	path string,
	read func(string) (map[string]int, bool, error),
	apply func(*signal, int),
) (bool, error) {
	counts, ok, err := read(path)
	if err != nil || !ok {
		return ok, err
	}
	for path, count := range counts {
		apply(signalsFor(signals, path), count)
	}
	return true, nil
}

func addFloatSignals(
	signals map[string]*signal,
	path string,
	read func(string) (map[string]float64, bool, error),
	apply func(*signal, float64),
) (bool, error) {
	values, ok, err := read(path)
	if err != nil || !ok {
		return ok, err
	}
	for path, value := range values {
		apply(signalsFor(signals, path), value)
	}
	return true, nil
}

func signalsFor(signals map[string]*signal, path string) *signal {
	path = cleanPath(path)
	if signals[path] == nil {
		signals[path] = &signal{}
	}
	return signals[path]
}

func gitChurn(root string, commits int) (map[string]int, bool) {
	cmd := exec.Command("git", "log", "--name-only", "--format=", fmt.Sprintf("--max-count=%d", commits), "--", ".")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}
	churn := map[string]int{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		path := cleanPath(scanner.Text())
		if path == "" || skipPath(path) {
			continue
		}
		churn[path]++
	}
	return churn, true
}

func readCoverage(path string) (map[string]float64, bool, error) {
	b, ok, err := readOptional(path)
	if err != nil || !ok {
		return nil, ok, err
	}
	byFile, err := parseCoverageProfile(b)
	if err != nil {
		return nil, true, err
	}
	return coveragePercentages(byFile), true, nil
}

type coverageCounts struct {
	covered int
	total   int
}

func parseCoverageProfile(profile []byte) (map[string]coverageCounts, error) {
	byFile := map[string]coverageCounts{}
	scanner := bufio.NewScanner(bytes.NewReader(profile))
	for scanner.Scan() {
		addCoverageProfileLine(byFile, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return byFile, nil
}

func addCoverageProfileLine(byFile map[string]coverageCounts, line string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "mode:") {
		return
	}
	file, stmts, covered, ok := parseCoverageLine(line)
	if !ok || skipPath(file) {
		return
	}
	c := byFile[file]
	c.total += stmts
	if covered {
		c.covered += stmts
	}
	byFile[file] = c
}

func coveragePercentages(byFile map[string]coverageCounts) map[string]float64 {
	out := map[string]float64{}
	for file, c := range byFile {
		if c.total > 0 {
			out[file] = float64(c.covered) * 100 / float64(c.total)
		}
	}
	return out
}

func parseCoverageLine(line string) (string, int, bool, bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", 0, false, false
	}
	file := fields[0]
	if idx := strings.Index(file, ":"); idx != -1 {
		file = file[:idx]
	}
	file = cleanPath(file)
	stmts, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, false, false
	}
	count, err := strconv.Atoi(fields[2])
	if err != nil {
		return "", 0, false, false
	}
	return file, stmts, count > 0, true
}

type golangCIReport struct {
	Issues []struct {
		Pos struct {
			Filename string `json:"Filename"`
		} `json:"Pos"`
	} `json:"Issues"`
}

func readGolangCI(path string) (map[string]int, bool, error) {
	b, ok, err := readOptional(path)
	if err != nil || !ok {
		return nil, ok, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]int{}, true, nil
	}
	var report golangCIReport
	if err := json.Unmarshal(b, &report); err != nil {
		return nil, true, err
	}
	out := map[string]int{}
	for _, issue := range report.Issues {
		path := cleanPath(issue.Pos.Filename)
		if path == "" || skipPath(path) {
			continue
		}
		out[path]++
	}
	return out, true, nil
}

func readCRAP(path string) (map[string]float64, bool, error) {
	b, ok, err := readOptional(path)
	if err != nil || !ok {
		return nil, ok, err
	}
	out := map[string]float64{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != "FAIL" {
			continue
		}
		score, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		path := cleanPath(stripLine(fields[5]))
		if path == "" || skipPath(path) {
			continue
		}
		out[path] += score
	}
	return out, true, scanner.Err()
}

func readOptional(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return b, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func rankHotspots(signals map[string]*signal) []hotspot {
	out := make([]hotspot, 0, len(signals))
	for path, sig := range signals {
		if skipPath(path) {
			continue
		}
		score := float64(sig.churn*10) + float64(sig.issues*25) + sig.crap
		if sig.hasCoverage {
			score += 100 - sig.coverage
		}
		if score <= 0 {
			continue
		}
		out = append(out, hotspot{path: path, score: score, sig: *sig})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].path < out[j].path
	})
	return out
}

func formatReport(hotspots []hotspot, summary inputSummary, limit int) string {
	var b strings.Builder
	_, _ = fmt.Fprintln(&b, "Code-quality hotspots ranked by empirical risk")
	_, _ = fmt.Fprintf(&b, "Inputs: git-churn=%s coverage=%s golangci=%s crap=%s\n", yesNo(summary.gitChurn), yesNo(summary.coverage), yesNo(summary.golangci), yesNo(summary.crap))
	if len(hotspots) == 0 {
		_, _ = fmt.Fprintln(&b, "No hotspots found from available inputs.")
		return b.String()
	}
	_, _ = fmt.Fprintln(&b)
	_, _ = fmt.Fprintln(&b, "Rank Score    Churn Issues CRAP     Coverage Path")
	for i, h := range firstHotspots(hotspots, limit) {
		coverage := "n/a"
		if h.sig.hasCoverage {
			coverage = fmt.Sprintf("%.1f%%", h.sig.coverage)
		}
		_, _ = fmt.Fprintf(&b, "%4d %7.1f %5d %6d %8.1f %8s %s\n", i+1, h.score, h.sig.churn, h.sig.issues, h.sig.crap, coverage, h.path)
	}
	return b.String()
}

func firstHotspots(in []hotspot, limit int) []hotspot {
	if len(in) <= limit {
		return in
	}
	return in[:limit]
}

func cleanPath(path string) string {
	path = strings.TrimSpace(filepath.ToSlash(path))
	path = strings.TrimPrefix(path, "./")
	const modulePrefix = "github.com/shayne/derphole/"
	path = strings.TrimPrefix(path, modulePrefix)
	return path
}

func skipPath(path string) bool {
	path = cleanPath(path)
	if path == "" {
		return true
	}
	for _, part := range strings.Split(path, "/") {
		switch part {
		case ".git", ".tmp", "bin", "cache", "dist", "node_modules", "vendor":
			return true
		}
		if strings.HasSuffix(part, "_generated") {
			return true
		}
	}
	base := filepath.Base(path)
	return filepath.Ext(base) != ".go" || strings.HasSuffix(base, ".pb.go") || strings.HasSuffix(base, "_generated.go") || strings.HasPrefix(base, "zz_generated.")
}

func stripLine(location string) string {
	idx := strings.LastIndex(location, ":")
	if idx == -1 {
		return location
	}
	return location[:idx]
}

func yesNo(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeLine(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}
