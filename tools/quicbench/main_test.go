package main

import (
	"net"
	"testing"
	"time"
)

func TestParseSendArgs(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.addr != "127.0.0.1:1234" {
		t.Fatalf("addr = %q, want %q", got.addr, "127.0.0.1:1234")
	}
	if got.bytesToSend != 128<<20 {
		t.Fatalf("bytesToSend = %d, want %d", got.bytesToSend, int64(128<<20))
	}
	if got.reverse {
		t.Fatal("reverse = true, want false")
	}
}

func TestParseSendArgsReverse(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"--reverse", "127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.addr != "127.0.0.1:1234" {
		t.Fatalf("addr = %q, want %q", got.addr, "127.0.0.1:1234")
	}
	if got.bytesToSend != 128<<20 {
		t.Fatalf("bytesToSend = %d, want %d", got.bytesToSend, int64(128<<20))
	}
	if !got.reverse {
		t.Fatal("reverse = false, want true")
	}
}

func TestParseSendArgsStreams(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"--streams", "4", "127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.addr != "127.0.0.1:1234" {
		t.Fatalf("addr = %q, want %q", got.addr, "127.0.0.1:1234")
	}
	if got.bytesToSend != 128<<20 {
		t.Fatalf("bytesToSend = %d, want %d", got.bytesToSend, int64(128<<20))
	}
	if got.reverse {
		t.Fatal("reverse = true, want false")
	}
	if got.streams != 4 {
		t.Fatalf("streams = %d, want 4", got.streams)
	}
}

func TestParseSendArgsStreamsRejectsZero(t *testing.T) {
	t.Parallel()

	_, err := parseSendArgs([]string{"--streams", "0", "127.0.0.1:1234", "128MiB"})
	if err == nil {
		t.Fatal("parseSendArgs() error = nil, want usage error")
	}
}

func TestParseSendArgsConnections(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"--connections", "4", "127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.connections != 4 {
		t.Fatalf("connections = %d, want 4", got.connections)
	}
	if got.streams != 1 {
		t.Fatalf("streams = %d, want 1", got.streams)
	}
}

func TestParseByteCount(t *testing.T) {
	t.Parallel()

	got, err := parseByteCount("128MiB")
	if err != nil {
		t.Fatalf("parseByteCount() error = %v", err)
	}
	if got != 128<<20 {
		t.Fatalf("parseByteCount() = %d, want %d", got, int64(128<<20))
	}
}

func TestThroughputMbps(t *testing.T) {
	t.Parallel()

	got := throughputMbps(64<<20, 4*time.Second)
	if got != 134.217728 {
		t.Fatalf("throughputMbps() = %f, want %f", got, 134.217728)
	}
}

func TestSendLocalBindAddrUsesPeerRouteIP(t *testing.T) {
	t.Parallel()

	addr := sendLocalBindAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("bind addr type = %T, want *net.UDPAddr", addr)
	}
	if got := udpAddr.IP.String(); got != "127.0.0.1" {
		t.Fatalf("bind addr IP = %q, want %q", got, "127.0.0.1")
	}
	if got := udpAddr.Port; got != 0 {
		t.Fatalf("bind addr port = %d, want 0", got)
	}
}
