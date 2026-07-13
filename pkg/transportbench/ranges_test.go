// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func TestSplitRangesCoversEveryByteExactlyOnce(t *testing.T) {
	for _, size := range []int64{0, 1, 7, 8, 9, 1 << 20, RequiredFileSizeBytes} {
		t.Run(stringSize(size), func(t *testing.T) {
			ranges, err := SplitRanges(size, TLSLaneCount)
			if err != nil {
				t.Fatal(err)
			}
			if len(ranges) != TLSLaneCount {
				t.Fatalf("range count = %d, want %d", len(ranges), TLSLaneCount)
			}
			var offset int64
			minLength := int64(-1)
			maxLength := int64(0)
			for lane, byteRange := range ranges {
				if byteRange.Offset != offset {
					t.Fatalf("lane %d offset = %d, want %d", lane, byteRange.Offset, offset)
				}
				if byteRange.Length < 0 {
					t.Fatalf("lane %d length = %d", lane, byteRange.Length)
				}
				offset += byteRange.Length
				if minLength < 0 || byteRange.Length < minLength {
					minLength = byteRange.Length
				}
				maxLength = max(maxLength, byteRange.Length)
			}
			if offset != size {
				t.Fatalf("covered = %d, want %d", offset, size)
			}
			if maxLength-minLength > 1 {
				t.Fatalf("range spread = %d, want <= 1", maxLength-minLength)
			}
		})
	}
}

func TestSplitRangesRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		size  int64
		lanes int
	}{
		{size: -1, lanes: 8},
		{size: 1, lanes: 0},
		{size: 1, lanes: -1},
	} {
		if _, err := SplitRanges(tc.size, tc.lanes); err == nil {
			t.Fatalf("SplitRanges(%d, %d) error = nil", tc.size, tc.lanes)
		}
	}
}

func TestLaneHeaderRoundTrip(t *testing.T) {
	header := testLaneHeaders(97)[3]

	raw := EncodeLaneHeader(header)
	got, err := DecodeLaneHeader(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != header {
		t.Fatalf("decoded = %#v, want %#v", got, header)
	}
	if string(raw[:4]) != "DHTB" {
		t.Fatalf("magic = %q", raw[:4])
	}
	if raw[4] != 1 {
		t.Fatalf("version = %d, want 1", raw[4])
	}
	if !bytes.Equal(raw[5:8], []byte{0, 0, 0}) {
		t.Fatalf("reserved = %v, want zero", raw[5:8])
	}
}

func TestFramedLaneHeaderRoundTrip(t *testing.T) {
	header := testLaneHeaders(97)[3]
	header.Framed = true

	raw := EncodeLaneHeader(header)
	got, err := DecodeLaneHeader(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != header {
		t.Fatalf("decoded = %#v, want %#v", got, header)
	}
	if raw[5] != 1 || raw[6] != 0 || raw[7] != 0 {
		t.Fatalf("flags/reserved = %v, want [1 0 0]", raw[5:8])
	}
}

func TestTLSChunkHeaderRoundTrip(t *testing.T) {
	header := TLSChunkHeader{Offset: 7 << 20, Length: TLSChunkSize}
	raw := EncodeTLSChunkHeader(header)
	got, err := DecodeTLSChunkHeader(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != header {
		t.Fatalf("decoded = %#v, want %#v", got, header)
	}
	if string(raw[:4]) != "DHTC" {
		t.Fatalf("magic = %q", raw[:4])
	}
}

func TestDecodeTLSChunkHeaderRejectsMalformedInput(t *testing.T) {
	valid := EncodeTLSChunkHeader(TLSChunkHeader{Offset: 0, Length: TLSChunkSize})
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{name: "truncated", mutate: func(raw []byte) []byte { return raw[:len(raw)-1] }, want: "length"},
		{name: "magic", mutate: func(raw []byte) []byte { raw[0] ^= 0xff; return raw }, want: "magic"},
		{name: "oversize", mutate: func(raw []byte) []byte { binary.BigEndian.PutUint32(raw[12:16], TLSChunkSize+1); return raw }, want: "chunk length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append([]byte(nil), valid[:]...)
			_, err := DecodeTLSChunkHeader(tt.mutate(raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLaneRequestRoundTrip(t *testing.T) {
	request := LaneRequest{
		TransferID: [16]byte{1, 2, 3, 4},
		Lane:       3,
		Lanes:      TLSLaneCount,
	}

	raw := EncodeLaneRequest(request)
	got, err := DecodeLaneRequest(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != request {
		t.Fatalf("decoded = %#v, want %#v", got, request)
	}
	if string(raw[:4]) != "DHTR" {
		t.Fatalf("magic = %q", raw[:4])
	}
}

func TestDecodeLaneRequestRejectsMalformedInput(t *testing.T) {
	valid := EncodeLaneRequest(LaneRequest{TransferID: [16]byte{1}, Lane: 0, Lanes: TLSLaneCount})
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{name: "truncated", mutate: func(raw []byte) []byte { return raw[:len(raw)-1] }, want: "length"},
		{name: "magic", mutate: func(raw []byte) []byte { raw[0] ^= 0xff; return raw }, want: "magic"},
		{name: "version", mutate: func(raw []byte) []byte { raw[4] = 2; return raw }, want: "version"},
		{name: "reserved", mutate: func(raw []byte) []byte { raw[5] = 1; return raw }, want: "reserved"},
		{name: "lane", mutate: func(raw []byte) []byte { binary.BigEndian.PutUint16(raw[24:26], 8); return raw }, want: "lane"},
		{name: "lanes", mutate: func(raw []byte) []byte { binary.BigEndian.PutUint16(raw[26:28], 7); return raw }, want: "lane count"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append([]byte(nil), valid[:]...)
			_, err := DecodeLaneRequest(tt.mutate(raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestDecodeLaneHeaderRejectsMalformedInput(t *testing.T) {
	valid := EncodeLaneHeader(testLaneHeaders(97)[0])
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{name: "truncated", mutate: func(raw []byte) []byte { return raw[:len(raw)-1] }, want: "length"},
		{name: "magic", mutate: func(raw []byte) []byte { raw[0] ^= 0xff; return raw }, want: "magic"},
		{name: "version", mutate: func(raw []byte) []byte { raw[4] = 2; return raw }, want: "version"},
		{name: "flags", mutate: func(raw []byte) []byte { raw[5] = 2; return raw }, want: "flags"},
		{name: "reserved", mutate: func(raw []byte) []byte { raw[6] = 1; return raw }, want: "reserved"},
		{name: "lane", mutate: func(raw []byte) []byte { binary.BigEndian.PutUint16(raw[24:26], 8); return raw }, want: "lane"},
		{name: "lanes", mutate: func(raw []byte) []byte { binary.BigEndian.PutUint16(raw[26:28], 7); return raw }, want: "lane count"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append([]byte(nil), valid[:]...)
			_, err := DecodeLaneHeader(tt.mutate(raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateLaneHeadersAcceptsExactCoverage(t *testing.T) {
	if err := ValidateLaneHeaders(testLaneHeaders(RequiredFileSizeBytes)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLaneHeadersRejectsInvalidSets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]LaneHeader) []LaneHeader
		want   string
	}{
		{name: "count", mutate: func(headers []LaneHeader) []LaneHeader { return headers[:7] }, want: "eight"},
		{name: "transfer id", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].TransferID[0]++; return headers }, want: "transfer ID"},
		{name: "hash", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].SHA256[0]++; return headers }, want: "SHA-256"},
		{name: "total", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].TotalSize++; return headers }, want: "total size"},
		{name: "duplicate lane", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].Lane = 6; return headers }, want: "duplicate"},
		{name: "gap", mutate: func(headers []LaneHeader) []LaneHeader { headers[4].Offset++; headers[4].Length--; return headers }, want: "offset"},
		{name: "overlap", mutate: func(headers []LaneHeader) []LaneHeader { headers[4].Offset--; headers[4].Length++; return headers }, want: "offset"},
		{name: "overflow", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].Length++; return headers }, want: "range"},
		{name: "lane count", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].Lanes = 7; return headers }, want: "lane count"},
		{name: "framing", mutate: func(headers []LaneHeader) []LaneHeader { headers[7].Framed = true; return headers }, want: "framing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := testLaneHeaders(97)
			err := ValidateLaneHeaders(tt.mutate(headers))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func testLaneHeaders(size int64) []LaneHeader {
	ranges, err := SplitRanges(size, TLSLaneCount)
	if err != nil {
		panic(err)
	}
	transferID := [16]byte{1, 2, 3, 4}
	hash := sha256.Sum256([]byte("transport-bench"))
	headers := make([]LaneHeader, len(ranges))
	for lane, byteRange := range ranges {
		headers[lane] = LaneHeader{
			TransferID: transferID,
			Lane:       uint16(lane),
			Lanes:      TLSLaneCount,
			TotalSize:  uint64(size),
			Offset:     uint64(byteRange.Offset),
			Length:     uint64(byteRange.Length),
			SHA256:     hash,
		}
	}
	return headers
}

func stringSize(size int64) string {
	return strconv.FormatInt(size, 10)
}
