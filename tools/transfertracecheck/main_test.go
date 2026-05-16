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

	"github.com/shayne/derphole/pkg/transfertrace"
)

func TestRunPrintsUsageForBadArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "usage: transfertracecheck") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunPrintsSuccess(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,4096,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-expected-bytes", "4096", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "trace-ok rows=1 final_app_bytes=4096") {
		t.Fatalf("stdout = %q, want trace-ok", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunChecksPeerTraceSuccess(t *testing.T) {
	sendPath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,send,complete,1024,0,1024,1024,0.00,1024,1024,,500,false,,,,,,,,,,,,stream-complete,\n")
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,receive,complete,1024,0,1024,1024,0.00,0,0,,500,false,,,,,,,,,,,,stream-complete,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-expected-bytes", "1024", "-progress-lead-tolerance", "0", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "peer_delta_bytes=0") {
		t.Fatalf("stdout = %q, want peer pair summary", stdout.String())
	}
}

func TestRunChecksPeerTraceFailure(t *testing.T) {
	sendPath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,send,complete,2048,0,2048,2048,0.00,2048,2048,,500,false,,,,,,,,,,,,stream-complete,\n")
	receivePath := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,receive,complete,1024,0,1024,1024,0.00,0,0,,500,false,,,,,,,,,,,,stream-complete,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "send", "-expected-bytes", "2048", "-peer-trace", receivePath, sendPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "sender peer_received_bytes") {
		t.Fatalf("stderr = %q, want peer progress error", stderr.String())
	}
}

func TestRunReturnsFailureForCheckError(t *testing.T) {
	path := writeTrace(t, transfertrace.HeaderLine+"\n"+
		"1000,0,receive,error,0,0,0,0,0.00,0,0,,,false,,,,,,,,,,,,connected-direct,message too long\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "message too long") {
		t.Fatalf("stderr = %q, want check error", stderr.String())
	}
}

func TestRunValidatesExplicitExpectedZeroBytes(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,1024,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-expected-bytes", "0", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "final app bytes") {
		t.Fatalf("stderr = %q, want byte mismatch", stderr.String())
	}
}

func TestRunRejectsNegativeExpectedBytes(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,0,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-expected-bytes", "-1", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "expected-bytes must be non-negative") {
		t.Fatalf("stderr = %q, want expected-bytes validation", stderr.String())
	}
}

func TestRunRejectsNegativeProgressLeadTolerance(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,0,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "receive", "-progress-lead-tolerance", "-1", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "progress-lead-tolerance must be non-negative") {
		t.Fatalf("stderr = %q, want progress-lead-tolerance validation", stderr.String())
	}
}

func TestRunRejectsInvalidRole(t *testing.T) {
	path := writeTrace(t, "timestamp_unix_ms,role,phase,app_bytes,last_error\n"+
		"1000,receive,complete,4096,\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-role", "both", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "role must be send or receive") {
		t.Fatalf("stderr = %q, want role validation", stderr.String())
	}
}

func writeTrace(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trace.csv")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatalf("write trace: %v", err)
	}
	return path
}
