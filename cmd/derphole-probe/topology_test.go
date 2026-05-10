// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/probe"
)

func TestRunTopologyPrintsJSONReport(t *testing.T) {
	oldRunTopologyProbe := runTopologyProbe
	defer func() { runTopologyProbe = oldRunTopologyProbe }()

	var gotCfg probe.TopologyConfig
	runTopologyProbe = func(ctx context.Context, cfg probe.TopologyConfig) (probe.TopologyReport, error) {
		gotCfg = cfg
		return probe.TopologyReport{
			Host:            cfg.Host,
			Target:          cfg.User + "@" + cfg.Host,
			Classifications: []string{probe.TopologyClassRemoteUDPUnreachable},
		}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runTopology([]string{"--host", "example.com", "--user", "alice", "--udp-port", "47001", "--timeout", "2s"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runTopology() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if gotCfg.Host != "example.com" {
		t.Fatalf("host = %q, want example.com", gotCfg.Host)
	}
	if gotCfg.User != "alice" {
		t.Fatalf("user = %q, want alice", gotCfg.User)
	}
	if gotCfg.UDPPort != 47001 {
		t.Fatalf("udp port = %d, want 47001", gotCfg.UDPPort)
	}
	if gotCfg.Timeout != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s", gotCfg.Timeout)
	}
	if !strings.Contains(stdout.String(), `"classifications": [`) {
		t.Fatalf("stdout missing classifications: %s", stdout.String())
	}
}

func TestRunTopologyRejectsEmptyHost(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runTopology([]string{"--user", "alice"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runTopology() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "host is required") {
		t.Fatalf("stderr = %q, want host validation", stderr.String())
	}
}
