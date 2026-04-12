package derphole

import (
	"bytes"
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
