package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExternalHandoffReceiverWritesContiguousChunksInOrderAndDedupes(t *testing.T) {
	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 2<<20)

	if err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 5, Payload: []byte("world")}); err != nil {
		t.Fatal(err)
	}
	if err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 0, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	if err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 0, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}

	if got := out.String(); got != "helloworld" {
		t.Fatalf("output = %q, want %q", got, "helloworld")
	}
	if got := rx.Watermark(); got != 10 {
		t.Fatalf("watermark = %d, want 10", got)
	}
}

func TestExternalHandoffReceiverRejectsWindowOverflow(t *testing.T) {
	var out bytes.Buffer
	rx := newExternalHandoffReceiver(&out, 8)

	err := rx.AcceptChunk(externalHandoffChunk{TransferID: 7, Offset: 1024, Payload: []byte("overflow")})
	if err == nil {
		t.Fatal("AcceptChunk() error = nil, want overflow rejection")
	}
}

func TestExternalHandoffSenderReplaysFromAckedWatermark(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnopqrstuvwxyz"), 4, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	chunk, err := spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Offset != 0 || string(chunk.Payload) != "abcd" {
		t.Fatalf("chunk = {%d %q}, want {0 %q}", chunk.Offset, chunk.Payload, "abcd")
	}

	if err := spool.AckTo(4); err != nil {
		t.Fatal(err)
	}
	if err := spool.RewindTo(4); err != nil {
		t.Fatal(err)
	}

	chunk, err = spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Offset != 4 || string(chunk.Payload) != "efgh" {
		t.Fatalf("chunk = {%d %q}, want {4 %q}", chunk.Offset, chunk.Payload, "efgh")
	}
}

func TestExternalHandoffSenderBackpressuresWhenUnackedWindowExceedsLimit(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnopqrstuvwxyz"), 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := spool.NextChunk(); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.NextChunk(); !errors.Is(err, errExternalHandoffUnackedWindowFull) {
		t.Fatalf("NextChunk() error = %v, want %v", err, errExternalHandoffUnackedWindowFull)
	}
	if err := spool.AckTo(8); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.NextChunk(); err != nil {
		t.Fatal(err)
	}
}

func TestExternalHandoffSenderReturnsEOFAfterSourceDrainedAndAcked(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abc"), 8, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	chunk, err := spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if string(chunk.Payload) != "abc" {
		t.Fatalf("chunk payload = %q, want %q", chunk.Payload, "abc")
	}
	if err := spool.AckTo(3); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.NextChunk(); !errors.Is(err, io.EOF) {
		t.Fatalf("NextChunk() error = %v, want EOF", err)
	}
}

func TestExternalHandoffSenderIgnoresStaleAckWatermarks(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefgh"), 4, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := spool.NextChunk(); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.NextChunk(); err != nil {
		t.Fatal(err)
	}

	if err := spool.AckTo(8); err != nil {
		t.Fatal(err)
	}
	if err := spool.AckTo(4); err != nil {
		t.Fatalf("AckTo() stale watermark error = %v, want nil", err)
	}
	if got := spool.AckedWatermark(); got != 8 {
		t.Fatalf("AckedWatermark() = %d, want 8", got)
	}
}

func TestExternalHandoffChunkFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := externalHandoffChunk{TransferID: 42, Offset: 9, Payload: []byte("payload")}

	if err := writeExternalHandoffChunkFrame(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := readExternalHandoffChunkFrame(&buf, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got.TransferID != want.TransferID || got.Offset != want.Offset || string(got.Payload) != string(want.Payload) {
		t.Fatalf("decoded chunk = %+v, want %+v", got, want)
	}
}

func TestExternalHandoffHandoffFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeExternalHandoffHandoffFrame(&buf, 99); err != nil {
		t.Fatal(err)
	}
	got, err := readExternalHandoffChunkFrame(&buf, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got.TransferID != externalHandoffTransferIDHandoff || got.Offset != 99 || len(got.Payload) != 0 {
		t.Fatalf("decoded marker = %+v, want handoff marker at offset 99", got)
	}
}

func TestExternalHandoffCarrierStopEmitsHandoffMarkerBeforeEOF(t *testing.T) {
	spool, err := newExternalHandoffSpool(strings.NewReader("abcdefghijklmnop"), 4, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	senderConn, receiverConn := net.Pipe()
	defer senderConn.Close()
	defer receiverConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- sendExternalHandoffCarrier(ctx, senderConn, spool, stopCh)
	}()

	chunk, err := readExternalHandoffChunkFrame(receiverConn, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Offset != 0 || string(chunk.Payload) != "abcd" {
		t.Fatalf("first chunk = {%d %q}, want {0 %q}", chunk.Offset, chunk.Payload, "abcd")
	}
	if err := writeExternalHandoffWatermarkFrame(receiverConn, 4); err != nil {
		t.Fatal(err)
	}

	close(stopCh)
	for {
		frame, err := readExternalHandoffChunkFrame(receiverConn, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if frame.TransferID == externalHandoffTransferIDHandoff {
			if len(frame.Payload) != 0 {
				t.Fatalf("marker = %+v, want handoff marker with empty payload", frame)
			}
			break
		}
		if err := writeExternalHandoffWatermarkFrame(receiverConn, frame.Offset+int64(len(frame.Payload))); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestExternalHandoffCarrierStopReturnsWhenSourceReadIsBlockedAndPreservesUnreadSourceData(t *testing.T) {
	sourceReader := newBlockingSecondReadSource([]byte("abcd"), []byte("efgh"))
	spool, err := newExternalHandoffSpool(sourceReader, 4, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		sourceReader.Release()
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	senderConn, receiverConn := net.Pipe()
	defer senderConn.Close()
	defer receiverConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- sendExternalHandoffCarrier(ctx, senderConn, spool, stopCh)
	}()

	chunk, err := readExternalHandoffChunkFrame(receiverConn, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Offset != 0 || string(chunk.Payload) != "abcd" {
		t.Fatalf("first chunk = {%d %q}, want {0 %q}", chunk.Offset, chunk.Payload, "abcd")
	}
	if err := writeExternalHandoffWatermarkFrame(receiverConn, 4); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sourceReader.SecondReadStarted():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("source reader did not start blocked second read")
	}

	close(stopCh)
	stopDone := make(chan error, 1)
	go func() {
		frame, err := readExternalHandoffChunkFrame(receiverConn, 1<<20)
		if err != nil {
			stopDone <- err
			return
		}
		if frame.TransferID != externalHandoffTransferIDHandoff || len(frame.Payload) != 0 {
			stopDone <- fmt.Errorf("handoff frame = %+v, want marker with empty payload", frame)
			return
		}
		stopDone <- nil
	}()

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("receiver did not observe handoff marker promptly after stop while source is idle")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("sendExternalHandoffCarrier() did not stop promptly while source is idle")
	}

	if err := spool.RewindTo(4); err != nil {
		t.Fatal(err)
	}
	sourceReader.Release()

	chunk, err = spool.NextChunk()
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Offset != 4 || string(chunk.Payload) != "efgh" {
		t.Fatalf("next chunk = {%d %q}, want {4 %q}", chunk.Offset, chunk.Payload, "efgh")
	}
}

type blockingSecondReadSource struct {
	mu                sync.Mutex
	firstPayload      []byte
	secondPayload     []byte
	firstDone         bool
	secondDone        bool
	secondReadStarted chan struct{}
	releaseSecondRead chan struct{}
}

func newBlockingSecondReadSource(firstPayload, secondPayload []byte) *blockingSecondReadSource {
	return &blockingSecondReadSource{
		firstPayload:      append([]byte(nil), firstPayload...),
		secondPayload:     append([]byte(nil), secondPayload...),
		secondReadStarted: make(chan struct{}),
		releaseSecondRead: make(chan struct{}),
	}
}

func (s *blockingSecondReadSource) Read(p []byte) (int, error) {
	s.mu.Lock()
	if !s.firstDone {
		s.firstDone = true
		payload := append([]byte(nil), s.firstPayload...)
		s.mu.Unlock()
		return copy(p, payload), nil
	}
	if s.secondDone {
		s.mu.Unlock()
		return 0, io.EOF
	}
	s.secondDone = true
	select {
	case <-s.secondReadStarted:
	default:
		close(s.secondReadStarted)
	}
	releaseSecondRead := s.releaseSecondRead
	payload := append([]byte(nil), s.secondPayload...)
	s.mu.Unlock()

	<-releaseSecondRead
	return copy(p, payload), nil
}

func (s *blockingSecondReadSource) SecondReadStarted() <-chan struct{} {
	return s.secondReadStarted
}

func (s *blockingSecondReadSource) Release() {
	select {
	case <-s.releaseSecondRead:
	default:
		close(s.releaseSecondRead)
	}
}

func TestExternalHandoffWatermarkFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeExternalHandoffWatermarkFrame(&buf, 99); err != nil {
		t.Fatal(err)
	}
	got, err := readExternalHandoffWatermarkFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != 99 {
		t.Fatalf("watermark = %d, want 99", got)
	}
}

func TestExternalHandoffChunkFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint64(42)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.BigEndian, int64(0)); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(9)); err != nil {
		t.Fatal(err)
	}

	_, err := readExternalHandoffChunkFrame(&buf, 8)
	if err == nil {
		t.Fatal("readExternalHandoffChunkFrame() error = nil, want oversized payload rejection")
	}
}
