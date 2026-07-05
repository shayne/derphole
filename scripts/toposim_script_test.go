// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToposimLinuxScriptRunsTaggedLinuxSuite(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(".", "toposim-linux.sh"))
	if err != nil {
		t.Fatalf("read toposim-linux.sh: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"uname -s",
		"require_tool ip",
		"require_tool iptables",
		"require_tool tc",
		"go build -o .tmp/toposim/toposimnode ./tools/toposimnode",
		"go test -tags=toposim ./pkg/toposim",
		"--run",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("toposim-linux.sh missing %q", want)
		}
	}

	for _, forbidden := range []string{"xcodebuild", "simctl", "ssh"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("toposim-linux.sh references forbidden tool or private host marker %q", forbidden)
		}
	}
}

func TestToposimIsWiredIntoMiseAndChecksWorkflow(t *testing.T) {
	t.Parallel()

	miseData, err := os.ReadFile(filepath.Join("..", ".mise.toml"))
	if err != nil {
		t.Fatalf("read .mise.toml: %v", err)
	}
	miseBody := string(miseData)
	for _, want := range []string{
		"[tasks.toposim]",
		"bash ./scripts/toposim-linux.sh --quick",
	} {
		if !strings.Contains(miseBody, want) {
			t.Fatalf(".mise.toml missing %q", want)
		}
	}

	workflowData, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "checks.yml"))
	if err != nil {
		t.Fatalf("read checks workflow: %v", err)
	}
	workflowBody := string(workflowData)
	for _, want := range []string{
		"iproute2",
		"iptables",
		"iputils-ping",
		"mise run toposim",
	} {
		if !strings.Contains(workflowBody, want) {
			t.Fatalf("checks workflow missing %q", want)
		}
	}
}
