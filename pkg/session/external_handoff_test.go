package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
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
