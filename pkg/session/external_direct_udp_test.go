package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/derpcat/pkg/telemetry"
	"tailscale.com/types/key"
)

func TestExternalDirectUDPDefaultUsesFourStripedLanesWithoutFEC(t *testing.T) {
	if got, want := externalDirectUDPParallelism, 4; got != want {
		t.Fatalf("externalDirectUDPParallelism = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPRateMbps, 2150; got != want {
		t.Fatalf("externalDirectUDPRateMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPFECGroupSize, 0; got != want {
		t.Fatalf("externalDirectUDPFECGroupSize = %d, want %d", got, want)
	}
	if !externalDirectUDPStripedBlast {
		t.Fatal("externalDirectUDPStripedBlast = false, want true")
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
