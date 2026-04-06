package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunOrchestratePrintsJSONReport(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runOrchestrate([]string{"--host", "ktzlxc", "--user", "root", "--mode", "raw", "--size-bytes", "1024"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runOrchestrate() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"host\": \"ktzlxc\"") {
		t.Fatalf("stdout missing host JSON: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"mode\": \"raw\"") {
		t.Fatalf("stdout missing mode JSON: %s", stdout.String())
	}
}
