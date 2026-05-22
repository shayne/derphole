// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunShowsHelpForNoArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
	if bytes.Contains(stderr.Bytes(), []byte("raw UDP path benchmark")) {
		t.Fatalf("stderr help = %q, want retired raw UDP benchmark wording removed", stderr.String())
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "production benchmark") {
		t.Fatalf("stderr help = %q, want production benchmark wording", stderr.String())
	}
}

func TestRunShowsHelpForHelpFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}

func TestRunHelpCommandRejectsRetiredRawProbeCommands(t *testing.T) {
	for _, command := range []string{"server", "client", "orchestrate"} {
		t.Run(command, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run([]string{"help", command}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run(help %s) code = %d, want 2", command, code)
			}
			if got, want := stderr.String(), "unknown command: "+command+"\n"; got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
		})
	}
}

func TestRunHelpCommandShowsMatrixSubcommandHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "matrix"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if got, want := stderr.String(), "usage: derphole-probe matrix\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunHelpCommandShowsTopologySubcommandHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "topology"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if got, want := stderr.String(), "usage: derphole-probe topology\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunHelpCommandRejectsExtraArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "matrix", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}

func TestRunHelpCommandRejectsUnknownSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "bogus", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if got, want := stderr.String(), "unknown command: bogus\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}
