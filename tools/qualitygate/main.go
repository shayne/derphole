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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type hotspot struct {
	Key    string
	Detail string
}

type cliOptions struct {
	Kind          string
	ReportPath    string
	BaselinePath  string
	WriteBaseline bool
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	opts, ok := parseCLIOptions(args, stderr)
	if !ok {
		return 2
	}
	return runQualityGate(opts, stdout, stderr)
}

func parseCLIOptions(args []string, stderr io.Writer) (cliOptions, bool) {
	var opts cliOptions
	flags := flag.NewFlagSet("qualitygate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.Kind, "kind", "", "report kind: crap or golangci-json")
	flags.StringVar(&opts.ReportPath, "report", "", "path to the tool report")
	flags.StringVar(&opts.BaselinePath, "baseline", "", "path to the baseline file")
	flags.BoolVar(&opts.WriteBaseline, "write-baseline", false, "write the parsed report as the new baseline")
	if err := flags.Parse(args); err != nil {
		return cliOptions{}, false
	}
	if opts.Kind == "" || opts.ReportPath == "" || opts.BaselinePath == "" {
		writeLine(stderr, "usage: qualitygate -kind crap|golangci-json -report PATH -baseline PATH [-write-baseline]")
		return cliOptions{}, false
	}
	return opts, true
}

func runQualityGate(opts cliOptions, stdout io.Writer, stderr io.Writer) int {
	report, err := os.ReadFile(opts.ReportPath)
	if err != nil {
		writef(stderr, "read report: %v\n", err)
		return 2
	}

	hotspots, err := parseReport(opts.Kind, report)
	if err != nil {
		writef(stderr, "parse report: %v\n", err)
		return 2
	}
	hotspots = uniqueHotspots(hotspots)

	if opts.WriteBaseline {
		if err := writeBaselineFile(opts.BaselinePath, hotspots); err != nil {
			writef(stderr, "write baseline: %v\n", err)
			return 2
		}
		writef(stdout, "wrote %d %s baseline entries to %s\n", len(hotspots), opts.Kind, opts.BaselinePath)
		return 0
	}

	baseline, err := readBaselineFile(opts.BaselinePath)
	if err != nil {
		writef(stderr, "read baseline: %v\n", err)
		return 2
	}

	newHotspots, resolved := compareHotspots(baseline, hotspots)
	writef(stdout, "%s baseline: current=%d baseline=%d resolved=%d new=%d\n", opts.Kind, len(hotspots), len(baseline), len(resolved), len(newHotspots))
	if len(resolved) > 0 {
		writef(stdout, "%s burn-down candidates:\n", opts.Kind)
		for _, key := range firstStrings(resolved, 10) {
			writef(stdout, "  - %s\n", key)
		}
	}
	if len(newHotspots) == 0 {
		return 0
	}

	writef(stderr, "%s has new quality hotspots not present in the baseline:\n", opts.Kind)
	for _, h := range firstHotspots(newHotspots, 20) {
		writef(stderr, "  - %s\n", h.Detail)
	}
	writef(stderr, "Update tests/refactor code, or intentionally refresh %s after review.\n", opts.BaselinePath)
	return 1
}

func parseReport(kind string, report []byte) ([]hotspot, error) {
	switch kind {
	case "crap":
		return parseCRAPReport(report)
	case "golangci-json":
		return parseGolangCIJSON(report)
	default:
		return nil, fmt.Errorf("unknown report kind %q", kind)
	}
}

func parseCRAPReport(report []byte) ([]hotspot, error) {
	var out []hotspot
	scanner := bufio.NewScanner(bytes.NewReader(report))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != "FAIL" {
			continue
		}
		fn := fields[4]
		file := stripLine(fields[5])
		key := strings.Join([]string{"crap", file, fn}, "|")
		out = append(out, hotspot{
			Key:    key,
			Detail: file + " " + fn,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sortHotspots(out)
	return out, nil
}

type golangCIReport struct {
	Issues []golangCIIssue `json:"Issues"`
}

type golangCIIssue struct {
	FromLinter string `json:"FromLinter"`
	Text       string `json:"Text"`
	Pos        struct {
		Filename string `json:"Filename"`
		Line     int    `json:"Line"`
	} `json:"Pos"`
	SourceLines []string `json:"SourceLines"`
}

var (
	cyclopFunctionRE = regexp.MustCompile(`function ([^[:space:]]+) is `)
	backtickFuncRE   = regexp.MustCompile("func `([^`]+)`")
	legacyFunctionRE = regexp.MustCompile(`func ([^[:space:]]+) `)
)

func parseGolangCIJSON(report []byte) ([]hotspot, error) {
	if len(bytes.TrimSpace(report)) == 0 {
		return nil, nil
	}

	var parsed golangCIReport
	if err := json.Unmarshal(report, &parsed); err != nil {
		return nil, err
	}

	out := make([]hotspot, 0, len(parsed.Issues))
	functions := map[string][]funcRange{}
	for _, issue := range parsed.Issues {
		file := issue.Pos.Filename
		if file == "" {
			file = "unknown"
		}
		text := strings.TrimSpace(issue.Text)
		fn := issueFunction(text)
		if fn != "" {
			key := strings.Join([]string{issue.FromLinter, file, fn}, "|")
			out = append(out, hotspot{
				Key:    key,
				Detail: fmt.Sprintf("%s %s (%s)", file, fn, issue.FromLinter),
			})
			continue
		}

		locationParts := fallbackIssueLocationParts(issue, file, functions)
		keyParts := append([]string{issue.FromLinter, file}, locationParts...)
		keyParts = append(keyParts, text)
		key := strings.Join(keyParts, "|")
		out = append(out, hotspot{
			Key:    key,
			Detail: fmt.Sprintf("%s:%d %s (%s)", file, issue.Pos.Line, text, issue.FromLinter),
		})
	}
	sortHotspots(out)
	return out, nil
}

func issueFunction(text string) string {
	for _, re := range []*regexp.Regexp{backtickFuncRE, cyclopFunctionRE, legacyFunctionRE} {
		if match := re.FindStringSubmatch(text); len(match) == 2 {
			return match[1]
		}
	}
	return ""
}

func fallbackIssueLocationParts(issue golangCIIssue, file string, functions map[string][]funcRange) []string {
	sourceKey := issueSourceKey(issue)
	fn := functionForFileLine(file, issue.Pos.Line, functions)
	if sourceKey != "" && fn != "" {
		return []string{fn, sourceKey}
	}
	if sourceKey != "" {
		return []string{sourceKey}
	}
	if fn != "" {
		return []string{fn, fmt.Sprintf("line:%d", issue.Pos.Line)}
	}
	return []string{fmt.Sprintf("line:%d", issue.Pos.Line)}
}

func issueSourceKey(issue golangCIIssue) string {
	lines := make([]string, 0, len(issue.SourceLines))
	for _, line := range issue.SourceLines {
		normalized := strings.Join(strings.Fields(line), " ")
		if normalized != "" {
			lines = append(lines, normalized)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "source:" + sanitizeKeyPart(strings.Join(lines, " "))
}

func sanitizeKeyPart(value string) string {
	return strings.ReplaceAll(value, "|", "/")
}

type funcRange struct {
	name      string
	lineStart int
	lineEnd   int
}

func functionForFileLine(file string, line int, cache map[string][]funcRange) string {
	ranges, ok := cache[file]
	if !ok {
		ranges = loadFunctionRanges(file)
		cache[file] = ranges
	}
	for _, fn := range ranges {
		if line >= fn.lineStart && line <= fn.lineEnd {
			return fn.name
		}
	}
	return ""
}

func loadFunctionRanges(path string) []funcRange {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return functionRanges(source)
}

func functionAtLine(source []byte, line int) string {
	for _, fn := range functionRanges(source) {
		if line >= fn.lineStart && line <= fn.lineEnd {
			return fn.name
		}
	}
	return ""
}

func functionRanges(source []byte) []funcRange {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", source, 0)
	if err != nil {
		return nil
	}
	out := make([]funcRange, 0, len(file.Decls))
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		out = append(out, funcRange{
			name:      funcName(fn),
			lineStart: fset.Position(fn.Pos()).Line,
			lineEnd:   fset.Position(fn.End()).Line,
		})
	}
	return out
}

func funcName(fn *ast.FuncDecl) string {
	name := fn.Name.Name
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return name
	}
	if recv := receiverName(fn.Recv.List[0].Type); recv != "" {
		return recv + "." + name
	}
	return name
}

func receiverName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return "(" + typed.Name + ")"
	case *ast.StarExpr:
		if inner, ok := typed.X.(*ast.Ident); ok {
			return "(*" + inner.Name + ")"
		}
	}
	return ""
}

func compareHotspots(baseline map[string]bool, current []hotspot) ([]hotspot, []string) {
	currentSet := make(map[string]hotspot, len(current))
	for _, h := range current {
		currentSet[h.Key] = h
	}

	var newHotspots []hotspot
	for key, h := range currentSet {
		if !baseline[key] {
			newHotspots = append(newHotspots, h)
		}
	}
	sortHotspots(newHotspots)

	var resolved []string
	for key := range baseline {
		if _, ok := currentSet[key]; !ok {
			resolved = append(resolved, key)
		}
	}
	sort.Strings(resolved)

	return newHotspots, resolved
}

func readBaselineFile(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out, scanner.Err()
}

func writeBaselineFile(path string, hotspots []hotspot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# Generated by tools/qualitygate. Remove entries as hotspots are fixed.\n")
	_, _ = fmt.Fprintf(&b, "# Entries are stable keys, not scores; rerun the quality task for current detail.\n")
	for _, h := range hotspots {
		_, _ = fmt.Fprintln(&b, h.Key)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func uniqueHotspots(in []hotspot) []hotspot {
	seen := map[string]hotspot{}
	for _, h := range in {
		seen[h.Key] = h
	}
	out := make([]hotspot, 0, len(seen))
	for _, h := range seen {
		out = append(out, h)
	}
	sortHotspots(out)
	return out
}

func sortHotspots(hotspots []hotspot) {
	sort.Slice(hotspots, func(i, j int) bool {
		return hotspots[i].Key < hotspots[j].Key
	})
}

func stripLine(location string) string {
	idx := strings.LastIndex(location, ":")
	if idx == -1 {
		return location
	}
	return location[:idx]
}

func firstHotspots(hotspots []hotspot, limit int) []hotspot {
	if len(hotspots) <= limit {
		return hotspots
	}
	return hotspots[:limit]
}

func firstStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeLine(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}
