package main

import (
	"bytes"
	"strings"
	"time"
	"testing"

	"github.com/shayne/derpcat/pkg/token"
)

func TestListenPrintTokenOnlyTargetsStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"listen", "--print-token-only"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if stdout.String() == "" {
		t.Fatal("stdout empty, want token")
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestListenWithoutFlagsPrintsStatusAndToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runListen() = %d, want 0", code)
	}
	if stdout.String() == "" {
		t.Fatal("stdout empty, want token")
	}
	if got := stderr.String(); got != "waiting-for-claim\n" {
		t.Fatalf("stderr = %q, want status text", got)
	}
}

func TestListenEmitsStructurallyValidToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runListen() = %d, want 0", code)
	}

	encoded := stdout.String()
	if encoded == "" {
		t.Fatal("stdout empty, want token")
	}

	decoded, err := token.Decode(strings.TrimSpace(encoded), time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.SessionID == ([16]byte{}) {
		t.Fatal("SessionID zero, want random bytes")
	}
	if decoded.BearerSecret == ([32]byte{}) {
		t.Fatal("BearerSecret zero, want random bytes")
	}
}

func TestListenEmitsDifferentTokensBackToBack(t *testing.T) {
	var stdout1, stderr1 bytes.Buffer
	if code := runListen([]string{}, &stdout1, &stderr1); code != 0 {
		t.Fatalf("first runListen() = %d, want 0", code)
	}

	var stdout2, stderr2 bytes.Buffer
	if code := runListen([]string{}, &stdout2, &stderr2); code != 0 {
		t.Fatalf("second runListen() = %d, want 0", code)
	}

	if stdout1.String() == stdout2.String() {
		t.Fatal("tokens matched, want distinct session material")
	}
}

func TestListenRejectsStrayPositionalArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runListen([]string{"extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runListen() = %d, want 2", code)
	}
	if got := stderr.String(); !strings.HasPrefix(got, "usage: derpcat listen") {
		t.Fatalf("stderr = %q, want usage text", got)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}
