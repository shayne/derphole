// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"testing"

	"github.com/shayne/derphole/pkg/session"
)

func TestParseParallelPolicyEmptyUsesDefault(t *testing.T) {
	policy, code, failed := parseParallelPolicy("", io.Discard, func() string { return "" })
	if failed || code != 0 || policy != session.DefaultParallelPolicy() {
		t.Fatalf("empty parallel policy = %#v code=%d failed=%v, want default", policy, code, failed)
	}
}

func TestParseParallelPolicyFixedValueIsDiagnosticOverride(t *testing.T) {
	policy, code, failed := parseParallelPolicy("8", io.Discard, func() string { return "" })
	if failed || code != 0 || policy != session.FixedParallelPolicy(8) {
		t.Fatalf("parallel 8 policy = %#v code=%d failed=%v, want fixed 8", policy, code, failed)
	}
}
