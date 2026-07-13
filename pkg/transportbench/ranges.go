// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transportbench

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	TLSLaneCount              = 8
	TLSLaneHeaderSize         = 84
	TLSLaneRequestSize        = 28
	TLSChunkHeaderSize        = 16
	TLSChunkSize       uint32 = 1 << 20
	tlsLaneVersion            = 1
)

var tlsLaneMagic = [4]byte{'D', 'H', 'T', 'B'}
var tlsLaneRequestMagic = [4]byte{'D', 'H', 'T', 'R'}
var tlsChunkMagic = [4]byte{'D', 'H', 'T', 'C'}

type ByteRange struct {
	Offset int64
	Length int64
}

type LaneHeader struct {
	TransferID [16]byte
	Lane       uint16
	Lanes      uint16
	Framed     bool
	TotalSize  uint64
	Offset     uint64
	Length     uint64
	SHA256     [32]byte
}

type TLSChunkHeader struct {
	Offset uint64
	Length uint32
}

func EncodeTLSChunkHeader(header TLSChunkHeader) [TLSChunkHeaderSize]byte {
	var raw [TLSChunkHeaderSize]byte
	copy(raw[0:4], tlsChunkMagic[:])
	binary.BigEndian.PutUint64(raw[4:12], header.Offset)
	binary.BigEndian.PutUint32(raw[12:16], header.Length)
	return raw
}

func DecodeTLSChunkHeader(raw []byte) (TLSChunkHeader, error) {
	if len(raw) != TLSChunkHeaderSize {
		return TLSChunkHeader{}, fmt.Errorf("chunk header length %d, want %d", len(raw), TLSChunkHeaderSize)
	}
	if string(raw[0:4]) != string(tlsChunkMagic[:]) {
		return TLSChunkHeader{}, errors.New("invalid chunk header magic")
	}
	header := TLSChunkHeader{
		Offset: binary.BigEndian.Uint64(raw[4:12]),
		Length: binary.BigEndian.Uint32(raw[12:16]),
	}
	if header.Length > TLSChunkSize {
		return TLSChunkHeader{}, fmt.Errorf("chunk length %d exceeds %d", header.Length, TLSChunkSize)
	}
	return header, nil
}

type LaneRequest struct {
	TransferID [16]byte
	Lane       uint16
	Lanes      uint16
}

func EncodeLaneRequest(request LaneRequest) [TLSLaneRequestSize]byte {
	var raw [TLSLaneRequestSize]byte
	copy(raw[0:4], tlsLaneRequestMagic[:])
	raw[4] = tlsLaneVersion
	copy(raw[8:24], request.TransferID[:])
	binary.BigEndian.PutUint16(raw[24:26], request.Lane)
	binary.BigEndian.PutUint16(raw[26:28], request.Lanes)
	return raw
}

func DecodeLaneRequest(raw []byte) (LaneRequest, error) {
	if len(raw) != TLSLaneRequestSize {
		return LaneRequest{}, fmt.Errorf("lane request length %d, want %d", len(raw), TLSLaneRequestSize)
	}
	if string(raw[0:4]) != string(tlsLaneRequestMagic[:]) {
		return LaneRequest{}, errors.New("invalid lane request magic")
	}
	if raw[4] != tlsLaneVersion {
		return LaneRequest{}, fmt.Errorf("unsupported lane request version %d", raw[4])
	}
	if raw[5] != 0 || raw[6] != 0 || raw[7] != 0 {
		return LaneRequest{}, errors.New("lane request reserved bytes must be zero")
	}
	var request LaneRequest
	copy(request.TransferID[:], raw[8:24])
	request.Lane = binary.BigEndian.Uint16(raw[24:26])
	request.Lanes = binary.BigEndian.Uint16(raw[26:28])
	if request.Lanes != TLSLaneCount {
		return LaneRequest{}, fmt.Errorf("lane count %d, want %d", request.Lanes, TLSLaneCount)
	}
	if request.Lane >= TLSLaneCount {
		return LaneRequest{}, fmt.Errorf("lane %d outside [0,%d)", request.Lane, TLSLaneCount)
	}
	return request, nil
}

func SplitRanges(size int64, lanes int) ([]ByteRange, error) {
	if size < 0 {
		return nil, fmt.Errorf("negative size %d", size)
	}
	if lanes <= 0 {
		return nil, fmt.Errorf("invalid lane count %d", lanes)
	}
	ranges := make([]ByteRange, lanes)
	base := size / int64(lanes)
	remainder := size % int64(lanes)
	var offset int64
	for lane := range lanes {
		length := base
		if int64(lane) < remainder {
			length++
		}
		ranges[lane] = ByteRange{Offset: offset, Length: length}
		offset += length
	}
	return ranges, nil
}

func EncodeLaneHeader(header LaneHeader) [TLSLaneHeaderSize]byte {
	var raw [TLSLaneHeaderSize]byte
	copy(raw[0:4], tlsLaneMagic[:])
	raw[4] = tlsLaneVersion
	if header.Framed {
		raw[5] = 1
	}
	copy(raw[8:24], header.TransferID[:])
	binary.BigEndian.PutUint16(raw[24:26], header.Lane)
	binary.BigEndian.PutUint16(raw[26:28], header.Lanes)
	binary.BigEndian.PutUint64(raw[28:36], header.TotalSize)
	binary.BigEndian.PutUint64(raw[36:44], header.Offset)
	binary.BigEndian.PutUint64(raw[44:52], header.Length)
	copy(raw[52:84], header.SHA256[:])
	return raw
}

func DecodeLaneHeader(raw []byte) (LaneHeader, error) {
	if len(raw) != TLSLaneHeaderSize {
		return LaneHeader{}, fmt.Errorf("lane header length %d, want %d", len(raw), TLSLaneHeaderSize)
	}
	if string(raw[0:4]) != string(tlsLaneMagic[:]) {
		return LaneHeader{}, errors.New("invalid lane header magic")
	}
	if raw[4] != tlsLaneVersion {
		return LaneHeader{}, fmt.Errorf("unsupported lane header version %d", raw[4])
	}
	if raw[5] > 1 {
		return LaneHeader{}, errors.New("lane header flags are invalid")
	}
	if raw[6] != 0 || raw[7] != 0 {
		return LaneHeader{}, errors.New("lane header reserved bytes must be zero")
	}
	var header LaneHeader
	copy(header.TransferID[:], raw[8:24])
	header.Lane = binary.BigEndian.Uint16(raw[24:26])
	header.Lanes = binary.BigEndian.Uint16(raw[26:28])
	header.Framed = raw[5] == 1
	header.TotalSize = binary.BigEndian.Uint64(raw[28:36])
	header.Offset = binary.BigEndian.Uint64(raw[36:44])
	header.Length = binary.BigEndian.Uint64(raw[44:52])
	copy(header.SHA256[:], raw[52:84])
	if header.Lanes != TLSLaneCount {
		return LaneHeader{}, fmt.Errorf("lane count %d, want %d", header.Lanes, TLSLaneCount)
	}
	if header.Lane >= TLSLaneCount {
		return LaneHeader{}, fmt.Errorf("lane %d outside [0,%d)", header.Lane, TLSLaneCount)
	}
	return header, nil
}

func ValidateLaneHeaders(headers []LaneHeader) error {
	if len(headers) != TLSLaneCount {
		return fmt.Errorf("exactly eight lane headers are required, got %d", len(headers))
	}
	first := headers[0]
	if first.TotalSize > math.MaxInt64 {
		return fmt.Errorf("total size %d exceeds supported maximum", first.TotalSize)
	}
	byLane, err := indexLaneHeaders(headers, first)
	if err != nil {
		return err
	}
	return validateLaneRanges(byLane, first.TotalSize)
}

func indexLaneHeaders(headers []LaneHeader, first LaneHeader) ([]LaneHeader, error) {
	byLane := make([]LaneHeader, TLSLaneCount)
	seen := make([]bool, TLSLaneCount)
	for _, header := range headers {
		if err := validateLaneIdentity(header, first, seen); err != nil {
			return nil, err
		}
		seen[header.Lane] = true
		byLane[header.Lane] = header
	}
	return byLane, nil
}

func validateLaneIdentity(header, first LaneHeader, seen []bool) error {
	if header.Lanes != TLSLaneCount {
		return fmt.Errorf("lane %d reports lane count %d, want %d", header.Lane, header.Lanes, TLSLaneCount)
	}
	if header.Lane >= TLSLaneCount {
		return fmt.Errorf("lane %d outside [0,%d)", header.Lane, TLSLaneCount)
	}
	if seen[header.Lane] {
		return fmt.Errorf("duplicate lane %d", header.Lane)
	}
	if header.TransferID != first.TransferID {
		return fmt.Errorf("lane %d transfer ID does not match", header.Lane)
	}
	if header.SHA256 != first.SHA256 {
		return fmt.Errorf("lane %d SHA-256 does not match", header.Lane)
	}
	if header.TotalSize != first.TotalSize {
		return fmt.Errorf("lane %d total size %d does not match %d", header.Lane, header.TotalSize, first.TotalSize)
	}
	if header.Framed != first.Framed {
		return fmt.Errorf("lane %d framing mode does not match", header.Lane)
	}
	return nil
}

func validateLaneRanges(byLane []LaneHeader, totalSize uint64) error {
	var offset uint64
	for lane, header := range byLane {
		if header.Offset != offset {
			return fmt.Errorf("lane %d offset %d, want %d", lane, header.Offset, offset)
		}
		if header.Length > totalSize-offset {
			return fmt.Errorf("lane %d range exceeds total size", lane)
		}
		offset += header.Length
	}
	if offset != totalSize {
		return fmt.Errorf("lane ranges cover %d bytes, want %d", offset, totalSize)
	}
	return nil
}
