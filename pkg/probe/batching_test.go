package probe

import (
	"context"
	"net"
	"runtime"
	"strings"
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

func TestSocketPacingRateBytesPerSecond(t *testing.T) {
	if got := socketPacingRateBytesPerSecond(2000); got != 250_000_000 {
		t.Fatalf("socketPacingRateBytesPerSecond(2000) = %d, want 250000000", got)
	}
	if got := socketPacingRateBytesPerSecond(0); got != 0 {
		t.Fatalf("socketPacingRateBytesPerSecond(0) = %d, want 0", got)
	}
}

func TestPacedBatchLimitTargetsMillisecondScaleBursts(t *testing.T) {
	if got := pacedBatchLimit(128, 1400, 350); got != 62 {
		t.Fatalf("pacedBatchLimit(128, 1400, 350) = %d, want 62", got)
	}
	if got := pacedBatchLimit(128, 1400, 800); got != 128 {
		t.Fatalf("pacedBatchLimit(128, 1400, 800) = %d, want capped max batch 128", got)
	}
	if got := pacedBatchLimit(128, 1400, 2000); got != 128 {
		t.Fatalf("pacedBatchLimit(128, 1400, 2000) = %d, want capped max batch 128", got)
	}
	if got := pacedBatchLimit(128, 1400, 0); got != 128 {
		t.Fatalf("pacedBatchLimit(128, 1400, 0) = %d, want max batch 128", got)
	}
	if got := pacedBatchLimit(128, 1400, 1); got != 1 {
		t.Fatalf("pacedBatchLimit(128, 1400, 1) = %d, want at least one packet", got)
	}
}

func TestPacedBatchLimitAllowsSmallBurstsForLargeChunkHighRatePaths(t *testing.T) {
	if got := pacedBatchLimit(128, 64<<10, 150); got != 1 {
		t.Fatalf("pacedBatchLimit(128, 64KiB, 150) = %d, want thresholded large-chunk path to stay at 1", got)
	}
	if got := pacedBatchLimit(128, 64<<10, 225); got != 3 {
		t.Fatalf("pacedBatchLimit(128, 64KiB, 225) = %d, want 3", got)
	}
	if got := pacedBatchLimit(128, 64<<10, 300); got != 4 {
		t.Fatalf("pacedBatchLimit(128, 64KiB, 300) = %d, want 4", got)
	}
	if got := pacedBatchLimit(128, 16<<10, 300); got != 4 {
		t.Fatalf("pacedBatchLimit(128, 16KiB, 300) = %d, want small-chunk path to keep 2ms target and return 4", got)
	}
}

func TestCachedDeadlineRefreshesOnlyNearExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	current := now.Add(time.Second)

	if !cachedDeadlineNeedsRefresh(now, time.Time{}, current, time.Second) {
		t.Fatal("empty cached deadline did not request refresh")
	}
	if cachedDeadlineNeedsRefresh(now, current, current, time.Second) {
		t.Fatal("fresh cached deadline requested refresh")
	}
	if !cachedDeadlineNeedsRefresh(now.Add(600*time.Millisecond), current, current, time.Second) {
		t.Fatal("near-expired cached deadline did not request refresh")
	}
	if !cachedDeadlineNeedsRefresh(now, current, now.Add(100*time.Millisecond), time.Second) {
		t.Fatal("earlier desired deadline did not request refresh")
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

func TestPlatformBatcherUsesDarwinMultiDatagramPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("darwin multi-datagram batching is not available on %s", runtime.GOOS)
	}

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

	batcher := newPacketBatcher(a, probeTransportBatched)
	if got, want := batcher.Capabilities().Kind, probeTransportBatched; got != want {
		t.Fatalf("Capabilities().Kind = %q, want %q", got, want)
	}
	if batcher.MaxBatch() <= 1 {
		t.Fatalf("MaxBatch() = %d, want multi-datagram batching", batcher.MaxBatch())
	}
}

func TestPlatformBatcherWritesAndReadsMultiplePacketsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("darwin multi-datagram batching is not available on %s", runtime.GOOS)
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	packets := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	if n, err := newPacketBatcher(a, probeTransportBatched).WriteBatch(ctx, b.LocalAddr(), packets); err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	} else if n != len(packets) {
		t.Fatalf("WriteBatch() = %d, want %d", n, len(packets))
	}

	batcher := newPacketBatcher(b, probeTransportBatched)
	bufs := make([]batchReadBuffer, 8)
	for i := range bufs {
		bufs[i].Bytes = make([]byte, 32)
	}
	var got []string
	for len(got) < len(packets) {
		n, err := batcher.ReadBatch(ctx, time.Second, bufs)
		if err != nil {
			t.Fatalf("ReadBatch() error after %d packets = %v", len(got), err)
		}
		if n == 0 {
			t.Fatalf("ReadBatch() = 0 after %d packets", len(got))
		}
		for i := 0; i < n; i++ {
			got = append(got, string(bufs[i].Bytes[:bufs[i].N]))
		}
	}
	want := []string{"one", "two", "three"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packet %d = %q, want %q; all packets: %v", i, got[i], want[i], got)
		}
	}
}

func TestPlatformBatcherWritesIdealBatchOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("darwin multi-datagram batching is not available on %s", runtime.GOOS)
	}

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

	packets := make([][]byte, probeIdealBatchSize)
	for i := range packets {
		packets[i] = make([]byte, 1452)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if n, err := newPacketBatcher(a, probeTransportBatched).WriteBatch(ctx, b.LocalAddr(), packets); err != nil {
		t.Fatalf("WriteBatch(%d packets) wrote %d before error: %v", len(packets), n, err)
	}
}

func TestPlatformBatcherSendsIPv4PeerFromDualStackSocketOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("darwin multi-datagram batching is not available on %s", runtime.GOOS)
	}

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if strings.HasPrefix(client.LocalAddr().String(), "127.0.0.1:") {
		t.Skipf("udp listener is not dual-stack on this platform: %s", client.LocalAddr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if n, err := newPacketBatcher(client, probeTransportBatched).WriteBatch(ctx, server.LocalAddr(), [][]byte{[]byte("mapped")}); err != nil {
		t.Fatalf("dual-stack WriteBatch() error after %d packets: %v", n, err)
	} else if n != 1 {
		t.Fatalf("dual-stack WriteBatch() = %d, want 1", n)
	}
}

func TestConnectedUDPBatcherWritesAndReadsConnectedSocket(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux":
	default:
		t.Skipf("connected UDP batcher unsupported on %s", runtime.GOOS)
	}

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	batcher, ok := newConnectedUDPBatcher(client, server.LocalAddr(), probeTransportLegacy)
	if !ok {
		t.Fatal("newConnectedUDPBatcher() ok = false, want true")
	}
	if !batcher.Capabilities().Connected {
		t.Fatalf("Capabilities().Connected = false, want true: %#v", batcher.Capabilities())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if n, err := batcher.WriteBatch(ctx, nil, [][]byte{[]byte("hello")}); err != nil {
		t.Fatalf("connected WriteBatch() error = %v", err)
	} else if n != 1 {
		t.Fatalf("connected WriteBatch() = %d, want 1", n)
	}

	buf := make([]byte, 16)
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, addr, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom() error = %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("server payload = %q, want hello", got)
	}
	if _, err := server.WriteTo([]byte("world"), addr); err != nil {
		t.Fatalf("server WriteTo() error = %v", err)
	}

	bufs := []batchReadBuffer{{Bytes: make([]byte, 16)}}
	if n, err := batcher.ReadBatch(ctx, time.Second, bufs); err != nil {
		t.Fatalf("connected ReadBatch() error = %v", err)
	} else if n != 1 {
		t.Fatalf("connected ReadBatch() = %d, want 1", n)
	}
	if got := string(bufs[0].Bytes[:bufs[0].N]); got != "world" {
		t.Fatalf("client payload = %q, want world", got)
	}
	if !sameAddr(bufs[0].Addr, server.LocalAddr()) {
		t.Fatalf("ReadBatch addr = %v, want %v", bufs[0].Addr, server.LocalAddr())
	}
}

func TestConnectedUDPBatcherConnectsDualStackSocketToIPv4Peer(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "linux":
	default:
		t.Skipf("connected UDP batcher unsupported on %s", runtime.GOOS)
	}

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if strings.HasPrefix(client.LocalAddr().String(), "127.0.0.1:") {
		t.Skipf("udp listener is not dual-stack on this platform: %s", client.LocalAddr())
	}

	batcher, ok := newConnectedUDPBatcher(client, server.LocalAddr(), probeTransportLegacy)
	if !ok {
		t.Fatalf("newConnectedUDPBatcher(%s -> %s) ok = false, want true", client.LocalAddr(), server.LocalAddr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if n, err := batcher.WriteBatch(ctx, nil, [][]byte{[]byte("mapped")}); err != nil {
		t.Fatalf("connected WriteBatch() error = %v", err)
	} else if n != 1 {
		t.Fatalf("connected WriteBatch() = %d, want 1", n)
	}
}
