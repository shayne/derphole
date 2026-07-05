// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && toposim

package toposim

import (
	"os/exec"
	"strings"
	"testing"
)

func TestLinuxLabCreatesAndCleansNamespaces(t *testing.T) {
	lab := NewLinuxLab(t.Name())
	defer func() {
		_ = lab.Cleanup()
	}()

	left, err := lab.AddNamespace("left")
	if err != nil {
		t.Fatalf("AddNamespace(left) error = %v", err)
	}
	right, err := lab.AddNamespace("right")
	if err != nil {
		t.Fatalf("AddNamespace(right) error = %v", err)
	}
	if _, err := lab.AddVeth(left, right, "smoke", "10.250.0.0/24", ""); err != nil {
		t.Fatalf("AddVeth() error = %v", err)
	}

	before := mustNetnsList(t)
	if !strings.Contains(before, left.Name) || !strings.Contains(before, right.Name) {
		t.Fatalf("ip netns list missing created namespaces %q and %q:\n%s", left.Name, right.Name, before)
	}

	if err := lab.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	after := mustNetnsList(t)
	if strings.Contains(after, left.Name) || strings.Contains(after, right.Name) {
		t.Fatalf("ip netns list still contains cleaned namespaces %q or %q:\n%s", left.Name, right.Name, after)
	}
}

func mustNetnsList(t *testing.T) string {
	t.Helper()

	out, err := exec.Command("ip", "netns", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("ip netns list error = %v\n%s", err, out)
	}
	return string(out)
}
