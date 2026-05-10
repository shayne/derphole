// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shayne/yargs"
)

func TestRunTokenServerPrintsServerToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"token", "server", "--days", "7"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "dts1_") {
		t.Fatalf("stdout = %q, want server token", stdout.String())
	}
}

func TestRunTokenClientPrintsClientToken(t *testing.T) {
	var serverOut bytes.Buffer
	code := run([]string{"token", "server", "--days", "7"}, strings.NewReader(""), &serverOut, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("server code = %d", code)
	}
	var stdout, stderr bytes.Buffer
	code = run([]string{"token", "client", "--token", strings.TrimSpace(serverOut.String()), "--days", "1"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "dtc1_") {
		t.Fatalf("stdout = %q, want client token", stdout.String())
	}
}

func TestRunTokenClientReadsServerTokenFromFile(t *testing.T) {
	var serverOut bytes.Buffer
	code := run([]string{"token", "server", "--days", "7"}, strings.NewReader(""), &serverOut, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("server code = %d", code)
	}
	tokenPath := filepath.Join(t.TempDir(), "server.dts")
	if err := os.WriteFile(tokenPath, []byte(strings.TrimSpace(serverOut.String())+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	code = run([]string{"token", "client", "--token-file", tokenPath, "--days", "1"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "dtc1_") {
		t.Fatalf("stdout = %q, want client token", stdout.String())
	}
}

func TestRunTokenClientReadsServerTokenFromStdin(t *testing.T) {
	var serverOut bytes.Buffer
	code := run([]string{"token", "server", "--days", "7"}, strings.NewReader(""), &serverOut, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("server code = %d", code)
	}

	var stdout, stderr bytes.Buffer
	code = run([]string{"token", "client", "--token-stdin", "--days", "1"}, strings.NewReader(serverOut.String()), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "dtc1_") {
		t.Fatalf("stdout = %q, want client token", stdout.String())
	}
}

func TestRunTokenRequiresRole(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"token", "--days", "7"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "server") || !strings.Contains(stderr.String(), "client") {
		t.Fatalf("stderr = %q, want role help", stderr.String())
	}
}

func TestParseTokenExpiresAcceptsRFC3339AndDate(t *testing.T) {
	rfc3339 := "2026-05-09T12:34:56Z"
	got, err := parseTokenExpires(rfc3339)
	if err != nil {
		t.Fatalf("parseTokenExpires(RFC3339) error = %v", err)
	}
	if got.Format(time.RFC3339) != rfc3339 {
		t.Fatalf("parseTokenExpires(RFC3339) = %s, want %s", got.Format(time.RFC3339), rfc3339)
	}

	got, err = parseTokenExpires("2026-05-09")
	if err != nil {
		t.Fatalf("parseTokenExpires(date) error = %v", err)
	}
	if got.Year() != 2026 || got.Month() != 5 || got.Day() != 9 {
		t.Fatalf("parseTokenExpires(date) = %s, want 2026-05-09", got)
	}
}

func TestParseTokenExpiresRejectsInvalidValue(t *testing.T) {
	if _, err := parseTokenExpires("tomorrow-ish"); err == nil {
		t.Fatal("parseTokenExpires() error = nil, want invalid date")
	}
}

func TestRunTokenHelpAndUnknownRole(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runToken(args, strings.NewReader("ignored"), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("runToken() = %d, want 0", code)
			}
			if got := stderr.String(); !strings.Contains(got, "Generate a server credential or client access token") {
				t.Fatalf("stderr = %q, want token help", got)
			}
		})
	}

	var stdout, stderr bytes.Buffer
	code := runToken([]string{"bogus"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runToken() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Generate a server credential or client access token") {
		t.Fatalf("stderr = %q, want token help", got)
	}
}

func TestTokenParseHelpers(t *testing.T) {
	for _, err := range []error{yargs.ErrHelp, yargs.ErrSubCommandHelp, yargs.ErrHelpLLM} {
		var stderr bytes.Buffer
		if code := handleTokenParseError[tokenCommonFlags](nil, err, &stderr); code != 0 {
			t.Fatalf("handleTokenParseError(%v) = %d, want 0", err, code)
		}
		if got := stderr.String(); !strings.Contains(got, "Generate a server credential or client access token") {
			t.Fatalf("stderr = %q, want token help", got)
		}
	}

	var stderr bytes.Buffer
	if code := handleTokenParseError[tokenCommonFlags](nil, os.ErrInvalid, &stderr); code != 2 {
		t.Fatalf("handleTokenParseError(non-help) = %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, "invalid argument") {
		t.Fatalf("stderr = %q, want parse error", got)
	}

	if got := tokenParseHelpText[tokenCommonFlags](nil); !strings.Contains(got, "Generate a server credential or client access token") {
		t.Fatalf("tokenParseHelpText(nil) = %q, want token help", got)
	}
}

func TestParseOptionalTokenExpires(t *testing.T) {
	var stderr bytes.Buffer
	got, ok := parseOptionalTokenExpires("", &stderr)
	if !ok {
		t.Fatal("parseOptionalTokenExpires(empty) ok = false, want true")
	}
	if !got.IsZero() {
		t.Fatalf("parseOptionalTokenExpires(empty) = %s, want zero time", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}

	_, ok = parseOptionalTokenExpires("tomorrow-ish", &stderr)
	if ok {
		t.Fatal("parseOptionalTokenExpires(invalid) ok = true, want false")
	}
	if got := stderr.String(); !strings.Contains(got, "invalid --expires value") {
		t.Fatalf("stderr = %q, want invalid expiry", got)
	}
}
