// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const maxScanBytes = 10 << 20

type Finding struct {
	Path    string
	Line    int
	Pattern string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	findings, err := ScanRepo(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "private-info-scan: %v\n", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr, "private-info-scan: private host/service references found")
	for _, finding := range findings {
		fmt.Fprintf(os.Stderr, "%s:%d: matched private pattern\n", finding.Path, finding.Line)
	}
	os.Exit(1)
}

func ScanRepo(root string) ([]Finding, error) {
	patterns, err := loadPrivatePatterns(root)
	if err != nil {
		return nil, err
	}
	files, err := gitCandidateFiles(root)
	if err == nil {
		return scanFiles(root, files, patterns)
	}
	return scanDir(root, patterns)
}

func ScanDir(root string) ([]Finding, error) {
	patterns, err := loadPrivatePatterns(root)
	if err != nil {
		return nil, err
	}
	return scanDir(root, patterns)
}

func scanDir(root string, patterns []string) ([]Finding, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if shouldIgnoreDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldIgnoreFile(rel) {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return scanFiles(root, files, patterns)
}

func gitCandidateFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-co", "--exclude-standard", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}

	parts := bytes.Split(out, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		files = append(files, filepath.ToSlash(string(part)))
	}
	return files, nil
}

func scanFiles(root string, files []string, patterns []string) ([]Finding, error) {
	var findings []Finding
	for _, rel := range files {
		rel = filepath.ToSlash(rel)
		if shouldIgnorePath(rel) {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			continue
		}
		fileFindings, err := scanFile(path, patterns)
		if err != nil {
			if errors.Is(err, errBinaryFile) {
				continue
			}
			return nil, err
		}
		for _, finding := range fileFindings {
			finding.Path = rel
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

var errBinaryFile = errors.New("binary file")

func scanFile(path string, patterns []string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxScanBytes+1))
	if err != nil {
		return nil, err
	}
	if isBinary(data) {
		return nil, errBinaryFile
	}
	if len(data) > maxScanBytes {
		return nil, fmt.Errorf("%s exceeds private scan size limit", path)
	}

	var findings []Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		for _, pattern := range patterns {
			if strings.Contains(line, pattern) {
				findings = append(findings, Finding{
					Line:    lineNo,
					Pattern: pattern,
				})
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func isBinary(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0
}

func loadPrivatePatterns(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, "AGENTS.local.md"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parsePrivatePatterns(string(data)), nil
}

func parsePrivatePatterns(data string) []string {
	patterns := map[string]bool{}
	for _, line := range privatePatternLines(data) {
		addPatternCells(patterns, line)
	}
	return sortedPatterns(patterns)
}

func privatePatternLines(data string) []string {
	var lines []string
	inHostTable := false
	for _, line := range strings.Split(data, "\n") {
		switch {
		case strings.HasPrefix(line, "## Host reference"):
			inHostTable = true
			continue
		case inHostTable && strings.HasPrefix(line, "## "):
			inHostTable = false
		}
		if !inHostTable || !strings.HasPrefix(line, "|") || strings.Contains(line, "---") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func addPatternCells(patterns map[string]bool, line string) {
	for _, cell := range strings.Split(line, "|") {
		token := cleanHostToken(cell)
		if token == "" || strings.EqualFold(token, "host label") || strings.EqualFold(token, "real hostname") {
			continue
		}
		addPattern(patterns, token)
	}
}

func sortedPatterns(patterns map[string]bool) []string {
	out := make([]string, 0, len(patterns))
	for pattern := range patterns {
		out = append(out, pattern)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) > len(out[j])
	})
	return out
}

func cleanHostToken(cell string) string {
	token := strings.TrimSpace(cell)
	token = strings.Trim(token, "`")
	token = strings.TrimSuffix(token, ".")
	return token
}

func addPattern(patterns map[string]bool, token string) {
	if strings.ContainsAny(token, " <>") {
		return
	}
	patterns[token] = true
	if idx := strings.IndexByte(token, '.'); idx > 0 && !strings.Contains(token[:idx], "@") {
		patterns[token[:idx]] = true
	}
}

func shouldIgnorePath(rel string) bool {
	if shouldIgnoreFile(rel) {
		return true
	}
	parts := strings.Split(rel, "/")
	for i := range parts[:len(parts)-1] {
		if shouldIgnoreDir(strings.Join(parts[:i+1], "/")) {
			return true
		}
	}
	return false
}

func shouldIgnoreFile(rel string) bool {
	return rel == "AGENTS.local.md"
}

func shouldIgnoreDir(rel string) bool {
	base := pathBase(rel)
	switch base {
	case ".git", ".hg", ".svn", ".tmp", "tmp", "bin", "node_modules", ".next", ".cache", ".direnv", "dist", "build", "coverage":
		return true
	default:
		return false
	}
}

func pathBase(path string) string {
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}
