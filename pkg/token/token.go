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
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
)

const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityShare
	CapabilityAttach
	CapabilityStdioOffer
	CapabilityWebFile
	CapabilityDerptunTCP
	_
	CapabilityTransferV2
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
	DERPRoute       derpbind.Route
}

var (
	ErrExpired            = errors.New("token expired")
	ErrChecksum           = errors.New("token checksum mismatch")
	ErrUnsupportedVersion = errors.New("token unsupported version")
	ErrInvalidLength      = errors.New("token invalid length")
)

const (
	SupportedVersion  uint8 = 5
	CustomDERPVersion uint8 = 6
)

const (
	fixedPayloadSize = 1 + 16 + 8 + 2 + 32 + 32 + 32 + 4
)

func Encode(tok Token) (string, error) {
	var err error
	tok.Version, err = encodeVersion(tok.Version, tok.DERPRoute)
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

func VersionForRoute(route derpbind.Route) uint8 {
	if route.IsCustom() {
		return CustomDERPVersion
	}
	return SupportedVersion
}

func IsSupportedVersion(version uint8) bool {
	return version == SupportedVersion || version == CustomDERPVersion
}

func encodeVersion(version uint8, route derpbind.Route) (uint8, error) {
	want := VersionForRoute(route)
	if version == 0 {
		return want, nil
	}
	if !IsSupportedVersion(version) || version != want {
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
	if payload.err != nil {
		return payload.Buffer, payload.err
	}
	if tok.Version == CustomDERPVersion {
		routeWire, err := tok.DERPRoute.AppendWire(nil)
		if err != nil {
			return payload.Buffer, err
		}
		payload.writeBytes(routeWire)
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
	wantLen, err := tokenWireSize(raw)
	if err != nil {
		return tok, nil, err
	}
	if len(raw) != wantLen {
		return tok, nil, ErrInvalidLength
	}
	payload := raw[:len(raw)-4]
	checksum := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if got := crc32.ChecksumIEEE(payload); got != checksum {
		return tok, nil, ErrChecksum
	}
	return tok, payload, nil
}

func tokenWireSize(raw []byte) (int, error) {
	version := raw[0]
	if !IsSupportedVersion(version) {
		return 0, ErrUnsupportedVersion
	}
	if version == SupportedVersion {
		return fixedPayloadSize + 4, nil
	}
	const minimumCustomWireSize = fixedPayloadSize + 1 + 4 + 4
	if len(raw) < minimumCustomWireSize {
		return 0, ErrInvalidLength
	}
	hostLen := int(raw[fixedPayloadSize])
	return fixedPayloadSize + 1 + hostLen + 4 + 4, nil
}

type payloadReader struct {
	*bytes.Reader
	err error
}

func decodePayload(tok *Token, payload []byte) error {
	reader := payloadReader{Reader: bytes.NewReader(payload[1:fixedPayloadSize])}
	readTokenFixedPayload(&reader, tok)
	if err := reader.result(); err != nil {
		return err
	}
	if tok.Version == SupportedVersion {
		return nil
	}

	extension := payload[fixedPayloadSize:]
	route, consumed, err := derpbind.ParseRouteWire(extension)
	if err != nil {
		return err
	}
	if consumed != len(extension) {
		return ErrInvalidLength
	}
	tok.DERPRoute = route
	return nil
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
