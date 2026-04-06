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
