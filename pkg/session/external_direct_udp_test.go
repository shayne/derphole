package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/derpcat/pkg/telemetry"
	"tailscale.com/types/key"
)

func TestExternalDirectUDPDefaultUsesEightSectionedLanesWithFEC(t *testing.T) {
	if got, want := externalDirectUDPParallelism, 8; got != want {
		t.Fatalf("externalDirectUDPParallelism = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPMaxRateMbps, 10_000; got != want {
		t.Fatalf("externalDirectUDPMaxRateMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPInitialProbeFallbackMbps, 150; got != want {
		t.Fatalf("externalDirectUDPInitialProbeFallbackMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPRateProbeMinMbps, 1; got != want {
		t.Fatalf("externalDirectUDPRateProbeMinMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPTransportLabel, "batched"; got != want {
		t.Fatalf("externalDirectUDPTransportLabel = %q, want %q", got, want)
	}
	if got, want := externalDirectUDPFECGroupSize, 32; got != want {
		t.Fatalf("externalDirectUDPFECGroupSize = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPStreamFECGroupSize, 0; got != want {
		t.Fatalf("externalDirectUDPStreamFECGroupSize = %d, want %d", got, want)
	}
	if externalDirectUDPStripedBlast {
		t.Fatal("externalDirectUDPStripedBlast = true, want false")
	}
}

func TestExternalDirectUDPWaitCoversPunchHandshakeWindow(t *testing.T) {
	minWait := 5 * time.Second
	if externalDirectUDPWait < minWait {
		t.Fatalf("externalDirectUDPWait = %v, want at least %v", externalDirectUDPWait, minWait)
	}
}

func writeExternalDirectUDPProbePacket(t *testing.T, conn net.PacketConn, dst net.Addr, packet probe.Packet) {
	t.Helper()
	wire, err := probe.MarshalPacket(packet, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
}

func readExternalDirectUDPProbePacket(t *testing.T, conn net.PacketConn, timeout time.Duration) probe.Packet {
	t.Helper()
	buf := make([]byte, 64<<10)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	packet, err := probe.UnmarshalPacket(buf[:n], nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	return packet
}

func TestWaitForPeerAckWithTimeoutReturnsWhenPeerNeverAcks(t *testing.T) {
	ackCh := make(chan derpbind.Packet)
	start := time.Now()

	err := waitForPeerAckWithTimeout(context.Background(), ackCh, 25*time.Millisecond)
	if err == nil {
		t.Fatal("waitForPeerAckWithTimeout() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForPeerAckWithTimeout() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("waitForPeerAckWithTimeout() returned after %v, want to wait for timeout", elapsed)
	}
}

func TestExternalDirectUDPBufferedWriterUsesDiscardForNullDevice(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(os.DevNull) error = %v", err)
	}
	defer devNull.Close()

	writer, flush := externalDirectUDPBufferedWriter(nopWriteCloser{Writer: devNull})
	if writer != io.Discard {
		t.Fatalf("externalDirectUDPBufferedWriter(/dev/null) writer = %T, want io.Discard", writer)
	}
	if err := flush(); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
}

func TestEmitExternalDirectUDPStatsIncludesDataGoodputFromFirstByte(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	startedAt := time.Unix(0, 0)
	firstByteAt := startedAt.Add(500 * time.Millisecond)
	completedAt := startedAt.Add(1500 * time.Millisecond)

	emitExternalDirectUDPStats(emitter, "udp-receive", 125_000_000, startedAt, firstByteAt, completedAt)

	got := buf.String()
	for _, want := range []string{
		"udp-receive-duration-ms=1500\n",
		"udp-receive-goodput-mbps=666.67\n",
		"udp-receive-first-byte-ms=500\n",
		"udp-receive-data-duration-ms=1000\n",
		"udp-receive-data-goodput-mbps=1000.00\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted stats = %q, want %q", got, want)
		}
	}
}

func TestEmitExternalDirectUDPStatsIncludesDataGoodputWithoutFirstByte(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	startedAt := time.Unix(0, 0)
	completedAt := startedAt.Add(1 * time.Second)

	emitExternalDirectUDPStats(emitter, "udp-send", 125_000_000, startedAt, time.Time{}, completedAt)

	got := buf.String()
	for _, want := range []string{
		"udp-send-duration-ms=1000\n",
		"udp-send-goodput-mbps=1000.00\n",
		"udp-send-first-byte-ms=0\n",
		"udp-send-data-duration-ms=1000\n",
		"udp-send-data-goodput-mbps=1000.00\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted stats = %q, want %q", got, want)
		}
	}
}

func TestExternalDirectUDPConnsUseDedicatedBlastSockets(t *testing.T) {
	base, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	conns, _, cleanup, err := externalDirectUDPConns(base, nil, 2, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	if len(conns) != 2 {
		t.Fatalf("len(conns) = %d, want 2", len(conns))
	}
	for i, conn := range conns {
		if conn == base {
			t.Fatalf("conns[%d] reuses the transport-manager socket; want a dedicated blast socket", i)
		}
	}
}

func TestExternalDirectUDPConnsUseProbeCompatibleDualStackSockets(t *testing.T) {
	conns, _, cleanup, err := externalDirectUDPConns(nil, nil, 1, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	udpAddr, ok := conns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", conns[0].LocalAddr())
	}
	if udpAddr.IP == nil || udpAddr.IP.To4() != nil {
		t.Fatalf("LocalAddr() = %v, want dual-stack UDP wildcard like the probe benchmark", conns[0].LocalAddr())
	}
}

func TestExternalDirectUDPConnsUseLoopbackIPv4SocketsForFakeTransport(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")

	conns, _, cleanup, err := externalDirectUDPConns(nil, nil, 1, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	udpAddr, ok := conns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", conns[0].LocalAddr())
	}
	if !udpAddr.IP.IsLoopback() || udpAddr.IP.To4() == nil {
		t.Fatalf("LocalAddr() = %v, want IPv4 loopback for fake transport", conns[0].LocalAddr())
	}
}

func TestExternalDirectUDPConnsPrimeBlastSockets(t *testing.T) {
	oldPreview := externalDirectUDPPreviewTransportCaps
	defer func() { externalDirectUDPPreviewTransportCaps = oldPreview }()

	var calls int
	externalDirectUDPPreviewTransportCaps = func(conn net.PacketConn, requested string) probe.TransportCaps {
		calls++
		if conn == nil {
			t.Fatal("primed nil packet conn")
		}
		if requested != externalDirectUDPTransportLabel {
			t.Fatalf("requested transport = %q, want %q", requested, externalDirectUDPTransportLabel)
		}
		return probe.TransportCaps{Kind: "test", RequestedKind: requested}
	}

	_, _, cleanup, err := externalDirectUDPConns(nil, nil, 2, nil)
	if err != nil {
		t.Fatalf("externalDirectUDPConns() error = %v", err)
	}
	defer cleanup()

	if calls != 2 {
		t.Fatalf("prime calls = %d, want 2", calls)
	}
}

func TestExternalDirectUDPFastDiscardReceiveConfigAcceptsDiscoveredRuns(t *testing.T) {
	cfg := externalDirectUDPFastDiscardReceiveConfig()
	if !cfg.Blast {
		t.Fatal("Blast = false, want true")
	}
	if cfg.Transport != externalDirectUDPTransportLabel {
		t.Fatalf("Transport = %q, want %q", cfg.Transport, externalDirectUDPTransportLabel)
	}
	if cfg.RequireComplete {
		t.Fatal("RequireComplete = true, want false for probe-style fast-discard receive")
	}
	if len(cfg.ExpectedRunIDs) != 0 {
		t.Fatalf("ExpectedRunIDs = %d entries, want probe-compatible discovered run IDs", len(cfg.ExpectedRunIDs))
	}
}

func TestWaitForDirectUDPReadyAckReturnsFastDiscard(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type:              envelopeDirectUDPReadyAck,
		DirectUDPReadyAck: &directUDPReadyAck{FastDiscard: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	readyAckCh := make(chan derpbind.Packet, 1)
	readyAckCh <- derpbind.Packet{
		From:    key.NodePublic{},
		Payload: payload,
	}

	got, err := waitForDirectUDPReadyAck(context.Background(), readyAckCh)
	if err != nil {
		t.Fatalf("waitForDirectUDPReadyAck() error = %v", err)
	}
	if !got.FastDiscard {
		t.Fatalf("waitForDirectUDPReadyAck() FastDiscard = false, want true")
	}
}

func TestWaitForDirectUDPStartReturnsExpectedBytes(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type: envelopeDirectUDPStart,
		DirectUDPStart: &directUDPStart{
			ExpectedBytes: 12345,
			SectionSizes:  []int64{6173, 6172},
			SectionAddrs:  []string{"68.20.14.192:38183", "68.20.14.192:34375"},
			Stream:        true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	startCh := make(chan derpbind.Packet, 1)
	startCh <- derpbind.Packet{
		From:    key.NodePublic{},
		Payload: payload,
	}

	got, err := waitForDirectUDPStart(context.Background(), startCh)
	if err != nil {
		t.Fatalf("waitForDirectUDPStart() error = %v", err)
	}
	if got.ExpectedBytes != 12345 {
		t.Fatalf("waitForDirectUDPStart() ExpectedBytes = %d, want 12345", got.ExpectedBytes)
	}
	if fmt.Sprint(got.SectionSizes) != fmt.Sprint([]int64{6173, 6172}) {
		t.Fatalf("waitForDirectUDPStart() SectionSizes = %v, want [6173 6172]", got.SectionSizes)
	}
	if fmt.Sprint(got.SectionAddrs) != fmt.Sprint([]string{"68.20.14.192:38183", "68.20.14.192:34375"}) {
		t.Fatalf("waitForDirectUDPStart() SectionAddrs = %v, want selected section addresses", got.SectionAddrs)
	}
	if !got.Stream {
		t.Fatal("waitForDirectUDPStart() Stream = false, want true")
	}
}

func TestWaitForDirectUDPStartAckAcceptsStartAck(t *testing.T) {
	payload, err := json.Marshal(envelope{Type: envelopeDirectUDPStartAck})
	if err != nil {
		t.Fatal(err)
	}
	startAckCh := make(chan derpbind.Packet, 1)
	startAckCh <- derpbind.Packet{
		From:    key.NodePublic{},
		Payload: payload,
	}

	if err := waitForDirectUDPStartAck(context.Background(), startAckCh); err != nil {
		t.Fatalf("waitForDirectUDPStartAck() error = %v", err)
	}
	if !isDirectUDPStartAckPayload(payload) {
		t.Fatal("isDirectUDPStartAckPayload() = false, want true")
	}
}

func TestEmitExternalDirectUDPReceiveDebugIncludesExpectedAndResultBytes(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)

	emitExternalDirectUDPReceiveStartDebug(emitter, 12345)
	emitExternalDirectUDPReceiveResultDebug(emitter, probe.TransferStats{BytesReceived: 67890}, nil)

	got := buf.String()
	if !strings.Contains(got, "udp-fast-discard-expected-bytes=12345\n") {
		t.Fatalf("receive start debug = %q, want expected byte line", got)
	}
	if !strings.Contains(got, "udp-receive-bytes=67890\n") {
		t.Fatalf("receive result debug = %q, want receive byte line", got)
	}
}

func TestExternalDirectUDPSpoolDiscardLanesSplitsAndRewinds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	src := []byte("abcdefghij")
	spool, err := externalDirectUDPSpoolDiscardLanes(ctx, bytes.NewReader(src), 3, 1)
	if err != nil {
		t.Fatalf("externalDirectUDPSpoolDiscardLanes() error = %v", err)
	}
	defer spool.Close()

	if spool.TotalBytes != int64(len(src)) {
		t.Fatalf("TotalBytes = %d, want %d", spool.TotalBytes, len(src))
	}
	if got, want := spool.Sizes[0], int64(4); got != want {
		t.Fatalf("lane 0 size = %d, want %d", got, want)
	}
	if got, want := spool.Sizes[1], int64(3); got != want {
		t.Fatalf("lane 1 size = %d, want %d", got, want)
	}
	if got, want := spool.Sizes[2], int64(3); got != want {
		t.Fatalf("lane 2 size = %d, want %d", got, want)
	}
	wantChunks := [][]byte{[]byte("abcd"), []byte("efg"), []byte("hij")}
	for i, want := range wantChunks {
		got := make([]byte, len(want))
		if _, err := spool.File.ReadAt(got, spool.Offsets[i]); err != nil {
			t.Fatalf("ReadAt(lane %d) error = %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("lane %d contents = %q, want %q", i, got, want)
		}
	}
}

func TestExternalDirectUDPReceiveSectionLayoutUsesSenderSizes(t *testing.T) {
	sizes, offsets, err := externalDirectUDPReceiveSectionLayout(10, 3, []int64{7, 3})
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionLayout() error = %v", err)
	}
	if fmt.Sprint(sizes) != fmt.Sprint([]int64{7, 3}) {
		t.Fatalf("sizes = %v, want [7 3]", sizes)
	}
	if fmt.Sprint(offsets) != fmt.Sprint([]int64{0, 7}) {
		t.Fatalf("offsets = %v, want [0 7]", offsets)
	}
}

func TestExternalDirectUDPReceiveSectionTargetUsesRegularFileDirectly(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	target, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(file, 64)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionTarget() error = %v", err)
	}
	defer cleanup()
	if target != file {
		t.Fatal("externalDirectUDPReceiveSectionTarget() did not use regular file directly")
	}
	if copyToDst {
		t.Fatal("externalDirectUDPReceiveSectionTarget() copyToDst = true, want false for regular file")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64 {
		t.Fatalf("direct target size = %d, want 64", info.Size())
	}
}

func TestExternalDirectUDPReceiveSectionTargetUsesWrappedRegularFileDirectly(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	target, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(nopWriteCloser{Writer: file}, 64)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionTarget() error = %v", err)
	}
	defer cleanup()
	if target != file {
		t.Fatal("externalDirectUDPReceiveSectionTarget() did not use wrapped regular file directly")
	}
	if copyToDst {
		t.Fatal("externalDirectUDPReceiveSectionTarget() copyToDst = true, want false for wrapped regular file")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64 {
		t.Fatalf("direct target size = %d, want 64", info.Size())
	}
}

func TestExternalDirectUDPSectionWriterForTargetBypassesBufferForRegularFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffered := bufio.NewWriter(file)

	target, flush := externalDirectUDPSectionWriterForTarget(file, buffered, buffered.Flush)
	if target != file {
		t.Fatal("externalDirectUDPSectionWriterForTarget() did not use the raw regular file")
	}
	if err := flush(); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
}

func TestExternalDirectUDPSectionWriterForTargetBypassesBufferForWrappedRegularFiles(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffered := bufio.NewWriter(file)

	target, flush := externalDirectUDPSectionWriterForTarget(nopWriteCloser{Writer: file}, buffered, buffered.Flush)
	if target != file {
		t.Fatal("externalDirectUDPSectionWriterForTarget() did not use the wrapped raw regular file")
	}
	if err := flush(); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
}

func TestExternalDirectUDPReceiveSectionTargetSpoolsNonFiles(t *testing.T) {
	var dst bytes.Buffer

	target, copyToDst, cleanup, err := externalDirectUDPReceiveSectionTarget(&dst, 64)
	if err != nil {
		t.Fatalf("externalDirectUDPReceiveSectionTarget() error = %v", err)
	}
	defer cleanup()
	if target == nil {
		t.Fatal("externalDirectUDPReceiveSectionTarget() target = nil")
	}
	if !copyToDst {
		t.Fatal("externalDirectUDPReceiveSectionTarget() copyToDst = false, want true for non-file writer")
	}
}

func TestExternalDirectUDPFinishSectionTargetSeeksDirectFileToEnd(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "derpcat-section-target-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteAt([]byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	if err := externalDirectUDPFinishSectionTarget(file, false, file, 3); err != nil {
		t.Fatalf("externalDirectUDPFinishSectionTarget() error = %v", err)
	}
	if _, err := file.WriteString("d"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcd" {
		t.Fatalf("file contents = %q, want %q", got, "abcd")
	}
}

func TestExternalDirectUDPParallelCandidateStringsPreferEstablishedPeerAddr(t *testing.T) {
	peer, err := net.ResolveUDPAddr("udp", "127.0.0.1:44321")
	if err != nil {
		t.Fatal(err)
	}

	got := externalDirectUDPParallelCandidateStringsForPeer(parseCandidateStrings([]string{
		"10.0.1.254:11111",
		"10.0.1.254:22222",
		"127.0.0.1:11111",
		"127.0.0.1:22222",
	}), 2, peer)
	want := []string{"127.0.0.1:11111", "127.0.0.1:22222"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPParallelCandidateStringsForPeer() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPParallelCandidateStringsPreferLoopbackForFakeTransport(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	peer, err := net.ResolveUDPAddr("udp", "10.0.1.254:44321")
	if err != nil {
		t.Fatal(err)
	}

	got := externalDirectUDPParallelCandidateStringsForPeer(parseCandidateStrings([]string{
		"10.0.1.254:11111",
		"10.0.1.254:22222",
		"127.0.0.1:11111",
		"127.0.0.1:22222",
	}), 2, peer)
	want := []string{"127.0.0.1:11111", "127.0.0.1:22222"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPParallelCandidateStringsForPeer(fake) = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPSelectRemoteAddrsByConnLeavesUnverifiedLanesBlank(t *testing.T) {
	observedByConn := [][]net.Addr{
		parseCandidateStrings([]string{"198.51.100.1:10001"}),
		parseCandidateStrings([]string{"198.51.100.1:10001"}),
		parseCandidateStrings([]string{"198.51.100.1:10003"}),
		nil,
	}

	got := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, 4, nil)
	want := []string{"198.51.100.1:10001", "", "198.51.100.1:10003", ""}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPSelectRemoteAddrsByConn() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPFillMissingSelectedAddrsBackfillsUnusedFallback(t *testing.T) {
	selected := []string{
		"198.51.100.1:10001",
		"",
		"198.51.100.1:10003",
	}
	fallback := []string{
		"203.0.113.1:10001",
		"203.0.113.1:10002",
		"203.0.113.1:10003",
	}

	got := externalDirectUDPFillMissingSelectedAddrs(selected, fallback)
	want := []string{
		"198.51.100.1:10001",
		"203.0.113.1:10002",
		"198.51.100.1:10003",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPFillMissingSelectedAddrs() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateMbpsForLanesScalesToVerifiedLaneCount(t *testing.T) {
	tests := []struct {
		name  string
		rate  int
		lanes int
		want  int
	}{
		{name: "disabled", rate: 0, lanes: 4, want: 0},
		{name: "none", rate: externalDirectUDPMaxRateMbps, lanes: 0, want: 0},
		{name: "one", rate: externalDirectUDPMaxRateMbps, lanes: 1, want: 1250},
		{name: "four", rate: externalDirectUDPMaxRateMbps, lanes: 4, want: 5000},
		{name: "full", rate: externalDirectUDPMaxRateMbps, lanes: externalDirectUDPParallelism, want: externalDirectUDPMaxRateMbps},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectUDPRateMbpsForLanes(tt.rate, tt.lanes); got != tt.want {
				t.Fatalf("externalDirectUDPRateMbpsForLanes(%d, %d) = %d, want %d", tt.rate, tt.lanes, got, tt.want)
			}
		})
	}
}

func TestExternalDirectUDPRateProbeRatesScaleUpToMax(t *testing.T) {
	got := externalDirectUDPRateProbeRates(10_000, 1<<30)
	want := []int{8, 25, 75, 150, 350, 700, 1200, 2250, 5000, 10000}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPRateProbeRates() = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateProbeRatesCoverSlowAndTenGigabitUnknownStreams(t *testing.T) {
	got := externalDirectUDPRateProbeRates(10_000, -1)
	want := []int{8, 25, 75, 150, 350, 700, 1200, 2250, 5000, 10000}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPRateProbeRates(unknown) = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateProbeRatesSkipSmallTransfers(t *testing.T) {
	if got := externalDirectUDPRateProbeRates(10_000, 64<<20); len(got) != 0 {
		t.Fatalf("externalDirectUDPRateProbeRates(small) = %v, want none", got)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesUsesDeliveredGoodput(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 350, BytesSent: 9_000_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 18_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 350, BytesReceived: 8_500_000, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 9_000_000, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 4_000_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 350; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples() = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffAtRateCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 52_000_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 10_021_200, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffOneTierAtMidProbeLoss(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_704, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_803_000, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 47_925_152, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_704, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 22_650_544, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 11_981_288, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(mid-probe loss) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffOneTierAtMidProbeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_569_728, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_949_760, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 57_384_100, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_587_328, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_569_728, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_401_032, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 14_974_880, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 9_181_456, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(mid-probe collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffTwoTiersAtTopProbeCollapse(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_591_872, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_394_112, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_854_264, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 55_990_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_591_872, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_394_112, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_854_264, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 34_154_352, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(top-probe collapse) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffAtLossyHighThroughputKnee(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_595_200, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_590_500, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_337_500, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_971_250, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 56_230_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_595_200, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_590_500, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_337_500, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_971_250, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 44_984_750, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(lossy high-throughput knee) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesUsesCleanTopProbeObservedCeiling(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_395_496, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_968, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 40_189_976, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_602_944, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_395_496, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_968, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 40_189_976, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 1849; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(clean top probe observed ceiling) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffAtLossyTopProbeEvenWhenGoodputIsHigh(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_815_512, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 55_808_070, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_598_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_558_656, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_348_440, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_815_512, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 44_646_456, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(lossy top probe high goodput) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesUsesObservedCeilingWhenTopProbeStillGains(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_597_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_603_000, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_384_500, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 29_988_500, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 42_790_500, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_597_000, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_603_000, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_384_500, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_988_500, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 42_790_500, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 1968; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(observed ceiling) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffMarginalHighRateGain(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_600, DurationMillis: 200},
		{RateMbps: 1967, BytesSent: 43_723_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 29_971_250, DurationMillis: 200},
		{RateMbps: 1967, BytesReceived: 38_450_000, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(1967, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(marginal high-rate gain) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPSelectRateFromProbeSamplesBacksOffBelowCeilingBurst(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 150, BytesSent: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesSent: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesSent: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesSent: 45_995_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 150, BytesReceived: 3_606_400, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 8_601_600, DurationMillis: 200},
		{RateMbps: 700, BytesReceived: 17_403_400, DurationMillis: 200},
		{RateMbps: 1200, BytesReceived: 30_000_600, DurationMillis: 200},
		{RateMbps: 2250, BytesReceived: 43_695_400, DurationMillis: 200},
	}

	if got, want := externalDirectUDPSelectRateFromProbeSamples(2250, sent, received), 700; got != want {
		t.Fatalf("externalDirectUDPSelectRateFromProbeSamples(below-ceiling burst) = %d, want %d", got, want)
	}
}

func TestExternalDirectUDPFlattenCandidateSetsRoundRobinsAlternatesAcrossLanes(t *testing.T) {
	sets := make([][]string, 8)
	for i := range sets {
		port := 60000 + i
		sets[i] = []string{
			fmt.Sprintf("10.0.1.254:%d", port),
			fmt.Sprintf("127.0.0.1:%d", port),
			fmt.Sprintf("10.0.4.184:%d", port),
			fmt.Sprintf("[fd37:89f2:37b4:4af8::%x]:%d", i+1, port),
			fmt.Sprintf("[fd37:89f2:37b4:4af9::%x]:%d", i+1, port),
			fmt.Sprintf("[::1]:%d", port),
		}
	}

	got := externalDirectUDPFlattenCandidateSets(sets)
	for _, want := range []string{"127.0.0.1:60006", "127.0.0.1:60007"} {
		if !slices.Contains(got, want) {
			t.Fatalf("externalDirectUDPFlattenCandidateSets() missing %q in %v", want, got)
		}
	}
}

func TestExternalDirectUDPOrderConnsForSectionsUsesSelectedEndpoints(t *testing.T) {
	connA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	connC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer connC.Close()

	conns := []net.PacketConn{connA, connB, connC}
	ordered, err := externalDirectUDPOrderConnsForSections(conns, []string{
		"108.18.210.19:38183",
		"108.18.210.19:34375",
		"108.18.210.19:44442",
		"10.0.1.254:38183",
		"10.0.1.254:34375",
		"10.0.1.254:44442",
	}, []string{
		"68.20.14.192:44442",
		"68.20.14.192:38183",
	})
	if err != nil {
		t.Fatalf("externalDirectUDPOrderConnsForSections() error = %v", err)
	}
	if len(ordered) != 2 {
		t.Fatalf("ordered conns length = %d, want 2", len(ordered))
	}
	if ordered[0] != connC || ordered[1] != connA {
		t.Fatalf("ordered conns = [%v %v], want [%v %v]", ordered[0].LocalAddr(), ordered[1].LocalAddr(), connC.LocalAddr(), connA.LocalAddr())
	}
}

func TestExternalDirectUDPDiscardLaneRunIDLeavesZeroForProbeGeneratedRuns(t *testing.T) {
	if got := externalDirectUDPDiscardLaneRunID([16]byte{}, 2); got != ([16]byte{}) {
		t.Fatalf("externalDirectUDPDiscardLaneRunID(zero) = %x, want zero", got)
	}
}

func TestExternalDirectUDPDiscardLaneRunIDDerivesNonZeroBase(t *testing.T) {
	var runID [16]byte
	runID[15] = 0x10

	got := externalDirectUDPDiscardLaneRunID(runID, 2)
	want := externalDirectUDPLaneRunID(runID, 2)
	if got != want {
		t.Fatalf("externalDirectUDPDiscardLaneRunID(non-zero) = %x, want %x", got, want)
	}
}

func TestExternalDirectUDPDiscardParallelSendsIndependentLanes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	runID := [16]byte{0x42}
	src := bytes.Repeat([]byte("x"), 4<<20)
	receiveCh := make(chan probe.TransferStats, 1)
	errCh := make(chan error, 2)
	go func() {
		stats, err := probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, probe.ReceiveConfig{
			Blast:          true,
			Transport:      externalDirectUDPTransportLabel,
			ExpectedRunIDs: externalDirectUDPLaneRunIDs(runID, 2),
		}, 0)
		if err != nil {
			errCh <- err
			return
		}
		receiveCh <- stats
	}()

	sendStats, err := externalDirectUDPSendDiscardParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, bytes.NewReader(src), probe.SendConfig{
		Blast:          true,
		Transport:      externalDirectUDPTransportLabel,
		ChunkSize:      externalDirectUDPChunkSize,
		RateMbps:       0,
		RunID:          runID,
		RepairPayloads: true,
	})
	if err != nil {
		t.Fatalf("externalDirectUDPSendDiscardParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case receiveStats := <-receiveCh:
		if receiveStats.BytesReceived != int64(len(src)) {
			t.Fatalf("receive BytesReceived = %d, want %d", receiveStats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestExternalDirectUDPDiscardSpoolParallelSendsIndependentLanes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverA.Close()
	serverB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverB.Close()
	clientA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.Close()

	runID := [16]byte{0x43}
	src := bytes.Repeat([]byte("y"), 4<<20)
	spool, err := externalDirectUDPSpoolDiscardLanes(ctx, bytes.NewReader(src), 2, externalDirectUDPChunkSize)
	if err != nil {
		t.Fatalf("externalDirectUDPSpoolDiscardLanes() error = %v", err)
	}
	defer spool.Close()

	receiveCh := make(chan probe.TransferStats, 1)
	errCh := make(chan error, 2)
	go func() {
		stats, err := probe.ReceiveBlastParallelToWriter(ctx, []net.PacketConn{serverA, serverB}, io.Discard, probe.ReceiveConfig{
			Blast:          true,
			Transport:      externalDirectUDPTransportLabel,
			ExpectedRunIDs: externalDirectUDPLaneRunIDs(runID, 2),
		}, int64(len(src)))
		if err != nil {
			errCh <- err
			return
		}
		receiveCh <- stats
	}()

	sendStats, err := externalDirectUDPSendDiscardSpoolParallel(ctx, []net.PacketConn{clientA, clientB}, []string{serverA.LocalAddr().String(), serverB.LocalAddr().String()}, spool, probe.SendConfig{
		Blast:          true,
		Transport:      externalDirectUDPTransportLabel,
		ChunkSize:      externalDirectUDPChunkSize,
		RateMbps:       0,
		RunID:          runID,
		RepairPayloads: true,
	})
	if err != nil {
		t.Fatalf("externalDirectUDPSendDiscardSpoolParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		t.Fatalf("ReceiveBlastParallelToWriter() error = %v", err)
	case receiveStats := <-receiveCh:
		if receiveStats.BytesReceived != int64(len(src)) {
			t.Fatalf("receive BytesReceived = %d, want %d", receiveStats.BytesReceived, len(src))
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for receive: %v", ctx.Err())
	}
}

func TestExternalDirectUDPSectionSpoolRoundTripsAcrossLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const lanes = 8
	serverConns := make([]net.PacketConn, 0, lanes)
	clientConns := make([]net.PacketConn, 0, lanes)
	defer func() {
		for _, conn := range serverConns {
			_ = conn.Close()
		}
		for _, conn := range clientConns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < lanes; i++ {
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverConns = append(serverConns, server)
		client, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		clientConns = append(clientConns, client)
	}

	src := bytes.Repeat([]byte("sectioned-loopback-"), 1<<13)
	spool, err := externalDirectUDPSpoolDiscardLanes(ctx, bytes.NewReader(src), lanes, externalDirectUDPChunkSize)
	if err != nil {
		t.Fatalf("externalDirectUDPSpoolDiscardLanes() error = %v", err)
	}
	defer spool.Close()

	var got bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		_, err := externalDirectUDPReceiveSectionSpoolParallel(ctx, serverConns, &got, probe.ReceiveConfig{
			Blast:           true,
			Transport:       externalDirectUDPTransportLabel,
			RequireComplete: true,
			FECGroupSize:    externalDirectUDPFECGroupSize,
			ExpectedRunID:   [16]byte{},
			ExpectedRunIDs:  nil,
		}, int64(len(src)), spool.Sizes)
		errCh <- err
	}()

	remoteAddrs := make([]string, 0, lanes)
	for _, conn := range serverConns {
		remoteAddrs = append(remoteAddrs, conn.LocalAddr().String())
	}
	sendStats, err := externalDirectUDPSendDiscardSpoolParallel(ctx, clientConns, remoteAddrs, spool, probe.SendConfig{
		Blast:                    true,
		Transport:                externalDirectUDPTransportLabel,
		ChunkSize:                externalDirectUDPChunkSize,
		RateMbps:                 0,
		RepairPayloads:           true,
		TailReplayBytes:          externalDirectUDPTailReplayBytes,
		FECGroupSize:             externalDirectUDPFECGroupSize,
		ParallelHandshakeTimeout: externalDirectUDPHandshakeWait,
	})
	if err != nil {
		t.Fatalf("externalDirectUDPSendDiscardSpoolParallel() error = %v", err)
	}
	if sendStats.BytesSent != int64(len(src)) {
		t.Fatalf("send BytesSent = %d, want %d", sendStats.BytesSent, len(src))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("externalDirectUDPReceiveSectionSpoolParallel() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for sectioned receive: %v", ctx.Err())
	}
	if !bytes.Equal(got.Bytes(), src) {
		t.Fatalf("received bytes length=%d want=%d equal=%t", got.Len(), len(src), bytes.Equal(got.Bytes(), src))
	}
}

func TestExternalDirectUDPReceiveSectionSpoolParallelReturnsPartialStatsOnReceiveError(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type receiveResult struct {
		stats probe.TransferStats
		err   error
	}
	resultCh := make(chan receiveResult, 1)
	payload := []byte("section-partial-before-cancel")
	pending := []byte("held-pending-gap")
	totalBytes := len(payload) + 1 + len(pending)
	go func() {
		stats, err := externalDirectUDPReceiveSectionSpoolParallel(ctx, []net.PacketConn{server}, io.Discard, probe.ReceiveConfig{
			Blast:     true,
			Transport: externalDirectUDPTransportLabel,
		}, int64(totalBytes), nil)
		resultCh <- receiveResult{stats: stats, err: err}
	}()

	runID := [16]byte{0x53}
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeHello, RunID: runID})
	for {
		packet := readExternalDirectUDPProbePacket(t, client, 500*time.Millisecond)
		if packet.Type == probe.PacketTypeHelloAck {
			break
		}
	}
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeData, RunID: runID, Seq: 0, Offset: 0, Payload: payload})
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeData, RunID: runID, Seq: 2, Offset: uint64(len(payload) + 1), Payload: pending})
	writeExternalDirectUDPProbePacket(t, client, server.LocalAddr(), probe.Packet{Version: probe.ProtocolVersion, Type: probe.PacketTypeDone, RunID: runID, Seq: 3, Offset: uint64(totalBytes)})
	for {
		packet := readExternalDirectUDPProbePacket(t, client, time.Second)
		if packet.Type == probe.PacketTypeRepairRequest {
			break
		}
	}

	cancel()
	select {
	case result := <-resultCh:
		if result.err == nil {
			t.Fatal("externalDirectUDPReceiveSectionSpoolParallel() error = nil, want incomplete blast error")
		}
		if !strings.Contains(result.err.Error(), "blast incomplete") {
			t.Fatalf("externalDirectUDPReceiveSectionSpoolParallel() error = %v, want blast incomplete", result.err)
		}
		if result.stats.BytesReceived != int64(len(payload)) {
			t.Fatalf("BytesReceived = %d, want %d", result.stats.BytesReceived, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canceled section receive")
	}
}

func TestExternalDirectUDPDistributeDiscardStreamDoesNotBlockOtherLanesBehindSlowLane(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	readerA, writerA := io.Pipe()
	defer readerA.Close()
	defer writerA.Close()
	readerB, writerB := io.Pipe()
	defer readerB.Close()
	defer writerB.Close()

	errCh := make(chan error, 1)
	go func() {
		src := bytes.NewReader(bytes.Repeat([]byte("x"), 256))
		errCh <- externalDirectUDPDistributeDiscardStream(ctx, src, []*io.PipeWriter{writerA, writerB}, 1)
	}()

	readB := make(chan int, 1)
	go func() {
		buf := make([]byte, 128)
		n, _ := io.ReadFull(readerB, buf)
		readB <- n
	}()

	select {
	case got := <-readB:
		if got != 128 {
			t.Fatalf("lane B read = %d, want 128", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("lane B did not receive data while lane A was blocked")
	}

	drainA := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, readerA)
		close(drainA)
	}()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("externalDirectUDPDistributeDiscardStream() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for distributor: %v", ctx.Err())
	}
	_ = writerA.Close()
	<-drainA
}
