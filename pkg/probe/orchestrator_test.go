package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteCommandIncludesProbeBinaryAndServerMode(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ServerCommand(ServerConfig{ListenAddr: ":0", Mode: "raw"})

	if got, want := cmd[0], "ssh"; got != want {
		t.Fatalf("cmd[0] = %q, want %q", got, want)
	}

	found := false
	for _, part := range cmd {
		if part == "/tmp/derpcat-probe server --listen :0 --mode raw" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("server command missing expected remote invocation: %#v", cmd)
	}
}

func TestOrchestratorRejectsMissingHost(t *testing.T) {
	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Fatalf("RunOrchestrate() error = %v, want host validation error", err)
	}
}

func TestRunOrchestrateInvokesSSHAndReturnsDirectReport(t *testing.T) {
	oldRunCommand := runCommand
	defer func() { runCommand = oldRunCommand }()

	var gotArgv []string
	runCommand = func(ctx context.Context, argv []string) ([]byte, error) {
		gotArgv = append([]string(nil), argv...)
		return []byte("ok"), nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "raw",
		SizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if report.Direct {
		t.Fatal("RunOrchestrate() report.Direct = true, want false")
	}
	if report.Host != "ktzlxc" || report.Mode != "raw" || report.Direction != "forward" {
		t.Fatalf("RunOrchestrate() report = %#v", report)
	}
	if len(gotArgv) < 7 || gotArgv[0] != "ssh" || !strings.Contains(strings.Join(gotArgv, " "), "BatchMode=yes") || !strings.Contains(strings.Join(gotArgv, " "), "ConnectTimeout=5") || !strings.Contains(strings.Join(gotArgv, " "), "/tmp/derpcat-probe server --help") {
		t.Fatalf("RunOrchestrate() argv = %#v", gotArgv)
	}
}

func TestRunOrchestrateRejectsAeadMode(t *testing.T) {
	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      "ktzlxc",
		User:      "root",
		Mode:      "aead",
		SizeBytes: 1024,
	})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want aead rejection")
	}
	if !strings.Contains(err.Error(), "aead not implemented yet") {
		t.Fatalf("RunOrchestrate() error = %v, want aead rejection", err)
	}
}

func TestRunOrchestrateTrimsHost(t *testing.T) {
	oldRunCommand := runCommand
	defer func() { runCommand = oldRunCommand }()

	var gotArgv []string
	runCommand = func(ctx context.Context, argv []string) ([]byte, error) {
		gotArgv = append([]string(nil), argv...)
		return []byte("ok"), nil
	}

	report, err := RunOrchestrate(context.Background(), OrchestrateConfig{
		Host:      " ktzlxc ",
		User:      "root",
		Mode:      "raw",
		SizeBytes: 1024,
	})
	if err != nil {
		t.Fatalf("RunOrchestrate() error = %v", err)
	}
	if report.Host != "ktzlxc" {
		t.Fatalf("report.Host = %q, want %q", report.Host, "ktzlxc")
	}
	if strings.Contains(strings.Join(gotArgv, " "), " ktzlxc ") {
		t.Fatalf("RunOrchestrate() argv = %#v, want trimmed host", gotArgv)
	}
}

func TestRunCommandIncludesCombinedOutputOnFailure(t *testing.T) {
	scriptDir := t.TempDir()
	scriptPath := filepath.Join(scriptDir, "fail.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho permission denied >&2\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := runCommand(context.Background(), []string{scriptPath})
	if err == nil {
		t.Fatal("runCommand() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("runCommand() error = %v, want combined stderr", err)
	}
}
