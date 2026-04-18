package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
