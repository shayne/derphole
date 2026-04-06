package probe

import (
	"context"
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
	if len(gotArgv) < 3 || gotArgv[0] != "ssh" || !strings.Contains(strings.Join(gotArgv, " "), "/tmp/derpcat-probe server --help") {
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
