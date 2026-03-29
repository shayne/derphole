package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func TestDERPPublicKeyRaw32RoundTrip(t *testing.T) {
	want := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	pub := key.NodePublicFromRaw32(mem.B(want[:]))
	if got := derpPublicKeyRaw32(pub); got != want {
		t.Fatalf("derpPublicKeyRaw32() = %x, want %x", got, want)
	}
}

func TestRelayOnlyStdioRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var senderIn bytes.Buffer
	senderIn.WriteString("hello over derp")

	listenerReady := make(chan string, 1)
	go func() {
		token, err := Listen(ctx, ListenConfig{
			Attachment: nil,
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  listenerReady,
			StdioOut:   &listenerOut,
		})
		if err != nil || token == "" {
			t.Errorf("Listen() err=%v token=%q", err, token)
		}
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:      token,
		StdioIn:    &senderIn,
		Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		ForceRelay: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := listenerOut.String(); got != "hello over derp" {
		t.Fatalf("listener output = %q, want %q", got, "hello over derp")
	}
}

func TestSessionPromotesDirectStateWhenProbeSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var senderIn bytes.Buffer
	var listenerStatus bytes.Buffer
	var senderStatus bytes.Buffer
	senderIn.WriteString("hello direct")

	listenerReady := make(chan string, 1)
	go func() {
		token, err := Listen(ctx, ListenConfig{
			Emitter:   telemetry.New(&listenerStatus, telemetry.LevelDefault),
			TokenSink: listenerReady,
			StdioOut:  &listenerOut,
		})
		if err != nil || token == "" {
			t.Errorf("Listen() err=%v token=%q", err, token)
		}
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:   token,
		StdioIn: &senderIn,
		Emitter: telemetry.New(&senderStatus, telemetry.LevelDefault),
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if !strings.Contains(listenerStatus.String(), string(StateDirect)) {
		t.Fatalf("listener statuses = %q, want %q", listenerStatus.String(), StateDirect)
	}
	if !strings.Contains(senderStatus.String(), string(StateDirect)) {
		t.Fatalf("sender statuses = %q, want %q", senderStatus.String(), StateDirect)
	}
	if got := listenerOut.String(); got != "hello direct" {
		t.Fatalf("listener output = %q, want %q", got, "hello direct")
	}
}

func TestRelayOnlyTCPConnectRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sourceLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(source) error = %v", err)
	}
	defer sourceLn.Close()

	sinkLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(sink) error = %v", err)
	}
	defer sinkLn.Close()

	const payload = "hello over tcp-connect"
	sourceDone := make(chan error, 1)
	go func() {
		conn, err := sourceLn.Accept()
		if err != nil {
			sourceDone <- err
			return
		}
		defer conn.Close()
		_, err = io.WriteString(conn, payload)
		sourceDone <- err
	}()

	sinkPayload := make(chan string, 1)
	sinkDone := make(chan error, 1)
	go func() {
		conn, err := sinkLn.Accept()
		if err != nil {
			sinkDone <- err
			return
		}
		defer conn.Close()
		buf, err := io.ReadAll(conn)
		if err != nil {
			sinkDone <- err
			return
		}
		sinkPayload <- string(buf)
		sinkDone <- nil
	}()

	listenerReady := make(chan string, 1)
	listenerErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  listenerReady,
			TCPConnect: sinkLn.Addr().String(),
		})
		listenerErr <- err
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:      token,
		Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		TCPConnect: sourceLn.Addr().String(),
		ForceRelay: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if err := <-sourceDone; err != nil {
		t.Fatalf("source server error = %v", err)
	}
	if err := <-sinkDone; err != nil {
		t.Fatalf("sink server error = %v", err)
	}
	if got := <-sinkPayload; got != payload {
		t.Fatalf("sink payload = %q, want %q", got, payload)
	}
	if err := <-listenerErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
}

func TestRelayOnlyTCPListenRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sourceAddr := reserveTCPAddr(t)
	sinkAddr := reserveTCPAddr(t)
	const payload = "hello over tcp-listen"

	listenerReady := make(chan string, 1)
	listenerErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:   telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink: listenerReady,
			TCPListen: sinkAddr,
		})
		listenerErr <- err
	}()

	token := <-listenerReady

	received := make(chan string, 1)
	sinkClientErr := make(chan error, 1)
	go func() {
		conn, err := connectWithRetry(ctx, sinkAddr)
		if err != nil {
			sinkClientErr <- err
			return
		}
		defer conn.Close()
		buf, err := io.ReadAll(conn)
		if err != nil {
			sinkClientErr <- err
			return
		}
		received <- string(buf)
		sinkClientErr <- nil
	}()

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:      token,
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TCPListen:  sourceAddr,
			ForceRelay: true,
		})
	}()

	sourceConn, err := connectWithRetry(ctx, sourceAddr)
	if err != nil {
		t.Fatalf("connectWithRetry(source) error = %v", err)
	}
	if _, err := io.WriteString(sourceConn, payload); err != nil {
		t.Fatalf("sourceConn WriteString() error = %v", err)
	}
	if err := sourceConn.Close(); err != nil {
		t.Fatalf("sourceConn Close() error = %v", err)
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-sinkClientErr; err != nil {
		t.Fatalf("sink client error = %v", err)
	}
	if got := <-received; got != payload {
		t.Fatalf("received = %q, want %q", got, payload)
	}
	if err := <-listenerErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return addr
}

func connectWithRetry(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
