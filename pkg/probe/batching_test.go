package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNormalizeTransportDefaultsToLegacy(t *testing.T) {
	got, err := normalizeTransport("")
	if err != nil {
		t.Fatalf("normalizeTransport(\"\") error = %v", err)
	}
	if got != probeTransportLegacy {
		t.Fatalf("normalizeTransport(\"\") = %q, want %q", got, probeTransportLegacy)
	}
}

func TestNormalizeTransportAcceptsKnownValues(t *testing.T) {
	for _, tc := range []string{probeTransportLegacy, probeTransportBatched} {
		got, err := normalizeTransport(tc)
		if err != nil {
			t.Fatalf("normalizeTransport(%q) error = %v", tc, err)
		}
		if got != tc {
			t.Fatalf("normalizeTransport(%q) = %q, want %q", tc, got, tc)
		}
	}
}

func TestNormalizeTransportRejectsUnknownValue(t *testing.T) {
	if _, err := normalizeTransport("bogus"); err == nil {
		t.Fatal("normalizeTransport() error = nil, want validation error")
	}
}

func TestLegacyBatcherWritesAndReadsSinglePacket(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	batcher := newLegacyBatcher(a)
	if batcher.Capabilities().Kind != probeTransportLegacy {
		t.Fatalf("Capabilities().Kind = %q, want %q", batcher.Capabilities().Kind, probeTransportLegacy)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	packets := [][]byte{[]byte("one"), []byte("two")}
	if n, err := batcher.WriteBatch(ctx, b.LocalAddr(), packets); err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	} else if n != len(packets) {
		t.Fatalf("WriteBatch() = %d, want %d", n, len(packets))
	}

	bufs := []batchReadBuffer{{Bytes: make([]byte, 32)}, {Bytes: make([]byte, 32)}}
	if n, err := readBatchWith(newLegacyBatcher(b), ctx, time.Second, bufs); err != nil {
		t.Fatalf("readBatchWith() error = %v", err)
	} else if n != 1 {
		t.Fatalf("readBatchWith() = %d, want 1 on legacy path", n)
	}
	if got := string(bufs[0].Bytes[:bufs[0].N]); got != "one" {
		t.Fatalf("first payload = %q, want %q", got, "one")
	}
}
