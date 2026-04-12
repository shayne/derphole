package derphole

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestSendTextIssuesTokenAndTransfersPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	var sendStderr bytes.Buffer
	go func() {
		sendDone <- Send(ctx, SendConfig{
			Text:   "hello derphole",
			Stderr: &sendStderr,
		})
	}()

	token := waitForTokenLine(t, &sendStderr)
	var out bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:  token,
		Stdout: &out,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := out.String(); got != "hello derphole" {
		t.Fatalf("stdout = %q, want %q", got, "hello derphole")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestReceiveAllocateIssuesTokenAndAcceptsText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var recvOut, recvErr bytes.Buffer
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- Receive(ctx, ReceiveConfig{
			Allocate: true,
			Stdout:   &recvOut,
			Stderr:   &recvErr,
		})
	}()

	token := waitForTokenLine(t, &recvErr)
	if err := Send(ctx, SendConfig{
		Token: token,
		Text:  "allocated flow",
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := recvOut.String(); got != "allocated flow" {
		t.Fatalf("stdout = %q, want %q", got, "allocated flow")
	}
}

func waitForTokenLine(t *testing.T, stderr *bytes.Buffer) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(stderr.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "On the other machine") {
				continue
			}
			if strings.HasPrefix(line, "derphole receive ") {
				fields := strings.Fields(line)
				return fields[len(fields)-1]
			}
			return line
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("token line not found in stderr %q", stderr.String())
	return ""
}
