package derphole

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/token"
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

func TestSendFileTransfersSuggestedFilename(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(srcPath, []byte("hello file"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			What:   srcPath,
			Stderr: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:      token,
		OutputPath: recvDir,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "hello file" {
		t.Fatalf("received = %q, want %q", got, "hello file")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestSendDirectoryTransfersTopLevelDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcParent := t.TempDir()
	srcDir := filepath.Join(srcParent, "project")
	if err := os.MkdirAll(filepath.Join(srcDir, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "nested", "child.txt"), []byte("child"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			What:   srcDir,
			Stderr: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:      token,
		OutputPath: recvDir,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "project", "root.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "root" {
		t.Fatalf("root.txt = %q, want %q", got, "root")
	}

	got, err = os.ReadFile(filepath.Join(recvDir, "project", "nested", "child.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "child" {
		t.Fatalf("child.txt = %q, want %q", got, "child")
	}

	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestSendFileReportsProgressOnBothSides(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(srcPath, bytes.Repeat([]byte("a"), 64*1024), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr, recvErr bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			What:           srcPath,
			Stderr:         &sendErr,
			ProgressOutput: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:          token,
		OutputPath:     recvDir,
		Stderr:         &recvErr,
		ProgressOutput: &recvErr,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := sendErr.String(); !strings.Contains(got, "Sending ") || !strings.Contains(got, "file named") || !strings.Contains(got, "100%|") {
		t.Fatalf("send stderr = %q, want summary and progress", got)
	}
	if got := recvErr.String(); !strings.Contains(got, "Receiving file") || !strings.Contains(got, "100%|") {
		t.Fatalf("receive stderr = %q, want summary and progress", got)
	}
}

func TestSendTextDoesNotEmitProgressBar(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sendErr, recvErr, out bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{
			Text:           "hello progressless text",
			Stderr:         &sendErr,
			ProgressOutput: &sendErr,
		})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:          token,
		Stdout:         &out,
		Stderr:         &recvErr,
		ProgressOutput: &recvErr,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if got := out.String(); got != "hello progressless text" {
		t.Fatalf("stdout = %q, want %q", got, "hello progressless text")
	}
	if got := sendErr.String(); !strings.Contains(got, "Sending text message") {
		t.Fatalf("send stderr = %q, want text summary", got)
	}
	if strings.Contains(sendErr.String(), "100%|") {
		t.Fatalf("send stderr = %q, want no progress bar for text", sendErr.String())
	}
	if strings.Contains(recvErr.String(), "100%|") {
		t.Fatalf("receive stderr = %q, want no progress bar for text", recvErr.String())
	}
}

func TestSendDefaultsParallelPolicyForOffer(t *testing.T) {
	prev := derpholeSessionOffer
	t.Cleanup(func() {
		derpholeSessionOffer = prev
	})

	sentinel := errors.New("sentinel-offer")
	var got session.OfferConfig
	derpholeSessionOffer = func(_ context.Context, cfg session.OfferConfig) (string, error) {
		got = cfg
		return "", sentinel
	}

	err := Send(context.Background(), SendConfig{Text: "hello"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send() error = %v, want %v", err, sentinel)
	}
	if got.TokenSink == nil {
		t.Fatal("got.TokenSink = nil, want allocated sink")
	}
	if gotPolicy, want := got.ParallelPolicy, session.DefaultParallelPolicy(); gotPolicy != want {
		t.Fatalf("got.ParallelPolicy = %#v, want %#v", gotPolicy, want)
	}
}

func TestReceiveDefaultsParallelPolicyForAttachDial(t *testing.T) {
	prev := derpholeSessionDialAttach
	t.Cleanup(func() {
		derpholeSessionDialAttach = prev
	})

	sentinel := errors.New("sentinel-attach")
	var got session.AttachDialConfig
	derpholeSessionDialAttach = func(_ context.Context, cfg session.AttachDialConfig) (net.Conn, error) {
		got = cfg
		return nil, sentinel
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityAttach,
	})
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}

	err = Receive(context.Background(), ReceiveConfig{Token: tok})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Receive() error = %v, want %v", err, sentinel)
	}
	if got.Token != tok {
		t.Fatalf("got.Token = %q, want %q", got.Token, tok)
	}
	if gotPolicy, want := got.ParallelPolicy, session.DefaultParallelPolicy(); gotPolicy != want {
		t.Fatalf("got.ParallelPolicy = %#v, want %#v", gotPolicy, want)
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
			if strings.Contains(line, " receive ") {
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
