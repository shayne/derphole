// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteSendInstructionUsesNpxLatestCommand(t *testing.T) {
	var stderr bytes.Buffer
	WriteSendInstruction(&stderr, "token-123")

	const want = "On the other machine, run:\n" +
		"npx -y derphole@latest receive token-123\n"
	if got := stderr.String(); got != want {
		t.Fatalf("WriteSendInstruction() = %q, want %q", got, want)
	}
}

func TestWriteSendQRInstructionUsesAppPayload(t *testing.T) {
	var stderr bytes.Buffer
	WriteSendQRInstruction(&stderr, "token-123")

	got := stderr.String()
	if strings.Contains(got, "npx -y derphole@latest receive") {
		t.Fatalf("QR instruction printed npm command: %q", got)
	}
	for _, want := range []string{"Scan this QR code", "Derphole iOS app"} {
		if !strings.Contains(got, want) {
			t.Fatalf("QR instruction missing %q in %q", want, got)
		}
	}
}
