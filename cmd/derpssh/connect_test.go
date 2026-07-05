// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	derpsshsession "github.com/shayne/derphole/pkg/derpssh/session"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/endpointlookup"
	"github.com/shayne/derphole/pkg/telemetry"
)

func TestRunConnectHelpPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConnect([]string{"--help"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runConnect(--help) = %d, want 0", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Usage: derpssh connect [--name NAME] (--service NAME|<invite>) [--registry PATH]") {
		t.Fatalf("stderr = %q, want usage", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunConnectNamePassesDisplayName(t *testing.T) {
	old := runConnectSession
	defer func() { runConnectSession = old }()
	var got connectSessionConfig
	runConnectSession = func(ctx context.Context, cfg connectSessionConfig) error {
		_ = ctx
		got = cfg
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := runConnect([]string{"--name", "Alex", "DSH1test"}, telemetry.LevelDefault, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runConnect() = %d, want 0; stderr:\n%s", code, stderr.String())
	}
	if got.DisplayName != "Alex" {
		t.Fatalf("DisplayName = %q, want Alex", got.DisplayName)
	}
	if got.Invite != "DSH1test" {
		t.Fatalf("Invite = %q, want DSH1test", got.Invite)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunConnectServiceResolvesInvite(t *testing.T) {
	invite := newDerpsshInvite(t)
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"service", "set", "ops-shell", invite, "--registry", registryPath}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("service set code = %d stderr=%s", code, stderr.String())
	}

	code = runMain([]string{"service", "list", "--registry", registryPath}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("service list code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ops-shell") {
		t.Fatalf("service list output = %q, want service name", stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), invite) {
		t.Fatalf("service list output leaks invite")
	}

	old := runConnectSession
	defer func() { runConnectSession = old }()
	var got connectSessionConfig
	runConnectSession = func(ctx context.Context, cfg connectSessionConfig) error {
		_ = ctx
		got = cfg
		return nil
	}

	stdout.Reset()
	stderr.Reset()
	code = runMain([]string{"connect", "--service", "ops-shell", "--registry", registryPath, "--name", "Alex"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("connect --service code = %d stderr=%s", code, stderr.String())
	}
	if got.Invite != invite {
		t.Fatalf("Invite = %q, want registry invite", got.Invite)
	}
	if got.DisplayName != "Alex" {
		t.Fatalf("DisplayName = %q, want Alex", got.DisplayName)
	}
}

func TestRunConnectRejectsServiceAndInvite(t *testing.T) {
	var stderr bytes.Buffer
	code := runMain([]string{"connect", "--service", "ops-shell", "DSH1test"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--service and invite argument are mutually exclusive") {
		t.Fatalf("stderr = %q, want service/invite conflict", stderr.String())
	}
}

func TestRunDerpsshServiceRemoveDeletesInvite(t *testing.T) {
	invite := newDerpsshInvite(t)
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	var stderr bytes.Buffer
	code := runMain([]string{"service", "set", "ops-shell", invite, "--registry", registryPath}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("service set code = %d stderr=%s", code, stderr.String())
	}

	code = runMain([]string{"service", "rm", "ops-shell", "--registry", registryPath}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("service rm code = %d stderr=%s", code, stderr.String())
	}
	_, err := (endpointlookup.FileRegistry{Path: registryPath}).Resolve(context.Background(), "ops-shell", endpointlookup.KindDerpsshInvite)
	if !errors.Is(err, endpointlookup.ErrNotFound) {
		t.Fatalf("Resolve(removed) error = %v, want ErrNotFound", err)
	}
}

func newDerpsshInvite(t *testing.T) string {
	t.Helper()
	now := time.Now()
	serverToken, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: serverToken, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	invite, err := derpsshsession.EncodeInvite(derpsshsession.Invite{ClientToken: clientToken})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	return invite
}
