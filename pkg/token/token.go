// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net/netip"
	"time"
)

const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityShare
	CapabilityAttach
	CapabilityStdioOffer
	CapabilityWebFile
	CapabilityDerptunTCP
)

type Token struct {
	Version         uint8
	SessionID       [16]byte
	ExpiresUnix     int64
	BootstrapRegion uint16
	DERPPublic      [32]byte
	QUICPublic      [32]byte
	BearerSecret    [32]byte
	Capabilities    uint32
	bootstrapIP     [16]byte
	bootstrapPort   uint16
	bootstrapFamily uint8
}

var (
	ErrExpired            = errors.New("token expired")
	ErrChecksum           = errors.New("token checksum mismatch")
	ErrUnsupportedVersion = errors.New("token unsupported version")
	ErrInvalidLength      = errors.New("token invalid length")
)

const (
	SupportedVersion uint8 = 4
	legacyVersion    uint8 = 3
)

const (
	bootstrapFamilyNone uint8 = 0
	bootstrapFamilyV4   uint8 = 4
	bootstrapFamilyV6   uint8 = 6
)

const (
	fixedPayloadSizeV3 = 1 + 16 + 8 + 2 + 32 + 32 + 32 + 4
	fixedPayloadSizeV4 = fixedPayloadSizeV3 + 1 + 16 + 2
)

func Encode(tok Token) (string, error) {
	var err error
	tok.Version, err = encodeVersion(tok.Version)
	if err != nil {
		return "", ErrUnsupportedVersion
	}

	payload, err := encodePayload(tok)
	if err != nil {
		return "", err
	}
	sum := crc32.ChecksumIEEE(payload.Bytes())
	if err := binary.Write(&payload, binary.BigEndian, sum); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(payload.Bytes()), nil
}

func encodeVersion(version uint8) (uint8, error) {
	if version == 0 {
		return SupportedVersion, nil
	}
	if version != legacyVersion && version != SupportedVersion {
		return 0, ErrUnsupportedVersion
	}
	return version, nil
}

type payloadWriter struct {
	bytes.Buffer
	err error
}

func encodePayload(tok Token) (bytes.Buffer, error) {
	var payload payloadWriter
	writeTokenFixedPayload(&payload, tok)
	if tok.Version >= SupportedVersion {
		writeTokenBootstrapPayload(&payload, tok)
	}
	return payload.Buffer, payload.err
}

func writeTokenFixedPayload(payload *payloadWriter, tok Token) {
	payload.write(tok.Version)
	payload.writeBytes(tok.SessionID[:])
	payload.write(tok.ExpiresUnix)
	payload.write(tok.BootstrapRegion)
	payload.writeBytes(tok.DERPPublic[:])
	payload.writeBytes(tok.QUICPublic[:])
	payload.writeBytes(tok.BearerSecret[:])
	payload.write(tok.Capabilities)
}

func writeTokenBootstrapPayload(payload *payloadWriter, tok Token) {
	payload.write(tok.bootstrapFamily)
	payload.writeBytes(tok.bootstrapIP[:])
	payload.write(tok.bootstrapPort)
}

func (w *payloadWriter) write(value any) {
	if w.err != nil {
		return
	}
	w.err = binary.Write(&w.Buffer, binary.BigEndian, value)
}

func (w *payloadWriter) writeBytes(value []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.Write(value)
}

func Decode(encoded string, now time.Time) (Token, error) {
	tok, payload, err := decodeEnvelope(encoded)
	if err != nil {
		return tok, err
	}
	if err := decodePayload(&tok, payload); err != nil {
		return tok, err
	}
	if tokenExpired(tok, now) {
		return tok, ErrExpired
	}

	return tok, nil
}

func decodeEnvelope(encoded string) (Token, []byte, error) {
	var tok Token
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return tok, nil, err
	}
	if len(raw) < 1 {
		return tok, nil, ErrInvalidLength
	}
	tok.Version = raw[0]
	wantLen, ok := tokenWireSize(tok.Version)
	if !ok {
		return tok, nil, ErrUnsupportedVersion
	}
	if len(raw) < wantLen {
		return tok, nil, ErrInvalidLength
	}
	payload := raw[:len(raw)-4]
	checksum := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if got := crc32.ChecksumIEEE(payload); got != checksum {
		return tok, nil, ErrChecksum
	}
	return tok, payload, nil
}

func tokenWireSize(version uint8) (int, bool) {
	switch version {
	case legacyVersion:
		return fixedPayloadSizeV3 + 4, true
	case SupportedVersion:
		return fixedPayloadSizeV4 + 4, true
	default:
		return 0, false
	}
}

type payloadReader struct {
	*bytes.Reader
	err error
}

func decodePayload(tok *Token, payload []byte) error {
	reader := payloadReader{Reader: bytes.NewReader(payload[1:])}
	readTokenFixedPayload(&reader, tok)
	if tok.Version >= SupportedVersion {
		readTokenBootstrapPayload(&reader, tok)
	}
	return reader.result()
}

func readTokenFixedPayload(reader *payloadReader, tok *Token) {
	reader.readBytes(tok.SessionID[:])
	reader.read(&tok.ExpiresUnix)
	reader.read(&tok.BootstrapRegion)
	reader.readBytes(tok.DERPPublic[:])
	reader.readBytes(tok.QUICPublic[:])
	reader.readBytes(tok.BearerSecret[:])
	reader.read(&tok.Capabilities)
}

func readTokenBootstrapPayload(reader *payloadReader, tok *Token) {
	reader.read(&tok.bootstrapFamily)
	reader.readBytes(tok.bootstrapIP[:])
	reader.read(&tok.bootstrapPort)
}

func (r *payloadReader) read(value any) {
	if r.err != nil {
		return
	}
	r.err = binary.Read(r.Reader, binary.BigEndian, value)
}

func (r *payloadReader) readBytes(value []byte) {
	if r.err != nil {
		return
	}
	_, r.err = io.ReadFull(r.Reader, value)
}

func (r *payloadReader) result() error {
	if r.err != nil {
		return r.err
	}
	if r.Len() != 0 {
		return ErrInvalidLength
	}
	return nil
}

func tokenExpired(tok Token, now time.Time) bool {
	return now.Unix() >= tok.ExpiresUnix
}

func (tok *Token) SetNativeTCPBootstrapAddr(addr netip.AddrPort) {
	if !addr.IsValid() {
		tok.bootstrapFamily = bootstrapFamilyNone
		tok.bootstrapIP = [16]byte{}
		tok.bootstrapPort = 0
		return
	}
	ip := addr.Addr().Unmap()
	tok.bootstrapIP = [16]byte{}
	if ip.Is4() {
		tok.bootstrapFamily = bootstrapFamilyV4
		tok.bootstrapIP = [16]byte{}
		copy(tok.bootstrapIP[:4], ip.AsSlice())
	} else {
		tok.bootstrapFamily = bootstrapFamilyV6
		tok.bootstrapIP = ip.As16()
	}
	tok.bootstrapPort = addr.Port()
}

func (tok Token) NativeTCPBootstrapAddr() (netip.AddrPort, bool) {
	switch tok.bootstrapFamily {
	case bootstrapFamilyV4:
		var raw [4]byte
		copy(raw[:], tok.bootstrapIP[:4])
		addr := netip.AddrFrom4(raw)
		if !addr.IsValid() || tok.bootstrapPort == 0 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(addr, tok.bootstrapPort), true
	case bootstrapFamilyV6:
		addr := netip.AddrFrom16(tok.bootstrapIP)
		if !addr.IsValid() || tok.bootstrapPort == 0 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(addr, tok.bootstrapPort), true
	default:
		return netip.AddrPort{}, false
	}
}
