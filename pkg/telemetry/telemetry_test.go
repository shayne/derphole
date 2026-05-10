// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package telemetry

import (
	"bytes"
	"io"
	"testing"
)

func TestEmitterOutputByLevel(t *testing.T) {
	tests := []struct {
		name      string
		level     Level
		method    func(*Emitter)
		wantEmpty bool
	}{
		{
			name:  "quiet suppresses status",
			level: LevelQuiet,
			method: func(e *Emitter) {
				e.Status("waiting-for-claim")
			},
			wantEmpty: true,
		},
		{
			name:  "verbose prints status",
			level: LevelVerbose,
			method: func(e *Emitter) {
				e.Status("probing-direct")
			},
			wantEmpty: false,
		},
		{
			name:  "verbose prints debug",
			level: LevelVerbose,
			method: func(e *Emitter) {
				e.Debug("probing-debug")
			},
			wantEmpty: false,
		},
		{
			name:  "default suppresses debug",
			level: LevelDefault,
			method: func(e *Emitter) {
				e.Debug("probing-debug")
			},
			wantEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			e := New(&buf, tc.level)
			tc.method(e)
			if got := buf.String(); tc.wantEmpty && got != "" {
				t.Fatalf("output = %q, want empty", got)
			} else if !tc.wantEmpty && got == "" {
				t.Fatal("output empty, want text")
			}
		})
	}
}

func TestEmitterDebugEnabled(t *testing.T) {
	var nilEmitter *Emitter
	if nilEmitter.DebugEnabled() {
		t.Fatal("nil DebugEnabled() = true, want false")
	}
	if !New(io.Discard, LevelVerbose).DebugEnabled() {
		t.Fatal("verbose DebugEnabled() = false, want true")
	}
	if New(io.Discard, LevelDefault).DebugEnabled() {
		t.Fatal("default DebugEnabled() = true, want false")
	}
}
