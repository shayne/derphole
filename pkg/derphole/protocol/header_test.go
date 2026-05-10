// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestWriteReadHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Header{
		Version:  1,
		Kind:     KindFile,
		Name:     "README.md",
		Size:     123,
		Verify:   "7-purple-sausages",
		Metadata: []byte(`{"mode":"0644"}`),
	}

	if err := WriteHeader(&buf, want); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}

	got, err := ReadHeader(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadHeader() = %#v, want %#v", got, want)
	}
}

func TestReadHeaderRejectsBadMagic(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("not-derphole"))
	if _, err := ReadHeader(r); err == nil {
		t.Fatal("ReadHeader() error = nil, want failure")
	}
}

func TestHeaderWireSizeMatchesEncodedHeader(t *testing.T) {
	h := Header{Version: 1, Kind: KindText, Name: "note.txt", Size: 42}
	var buf bytes.Buffer
	if err := WriteHeader(&buf, h); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	got, err := HeaderWireSize(h)
	if err != nil {
		t.Fatalf("HeaderWireSize() error = %v", err)
	}
	if got != int64(buf.Len()) {
		t.Fatalf("HeaderWireSize() = %d, want %d", got, buf.Len())
	}
}

func TestHeaderSizeGuardsRejectOversizedHeaders(t *testing.T) {
	h := Header{Version: 1, Kind: KindFile, Metadata: bytes.Repeat([]byte("x"), maxHeaderSize+1)}
	if _, err := HeaderWireSize(h); err == nil || !strings.Contains(err.Error(), "header too large") {
		t.Fatalf("HeaderWireSize(oversized) error = %v, want header too large", err)
	}
	if err := WriteHeader(ioDiscard{}, h); err == nil || !strings.Contains(err.Error(), "header too large") {
		t.Fatalf("WriteHeader(oversized) error = %v, want header too large", err)
	}
}

func TestReadHeaderRejectsOversizedAndMalformedPayloads(t *testing.T) {
	var oversized bytes.Buffer
	oversized.WriteString(magic)
	if err := binary.Write(&oversized, binary.BigEndian, uint32(maxHeaderSize+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHeader(bufio.NewReader(&oversized)); err == nil || !strings.Contains(err.Error(), "header too large") {
		t.Fatalf("ReadHeader(oversized) error = %v, want header too large", err)
	}

	var malformed bytes.Buffer
	malformed.WriteString(magic)
	if err := binary.Write(&malformed, binary.BigEndian, uint32(len("{"))); err != nil {
		t.Fatal(err)
	}
	malformed.WriteString("{")
	if _, err := ReadHeader(bufio.NewReader(&malformed)); err == nil {
		t.Fatal("ReadHeader(malformed JSON) error = nil, want failure")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
