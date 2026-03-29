package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"time"
)

const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityTCP
)

type Token struct {
	Version         uint8
	SessionID       [16]byte
	ExpiresUnix     int64
	BootstrapRegion uint16
	DERPPublic      [32]byte
	WGPublic        [32]byte
	DiscoPublic     [32]byte
	BearerSecret    [32]byte
	Capabilities    uint32
}

var (
	ErrExpired  = errors.New("token expired")
	ErrChecksum = errors.New("token checksum mismatch")
)

const payloadSize = 1 + 16 + 8 + 2 + 32 + 32 + 32 + 32 + 4

func Encode(tok Token) (string, error) {
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.BigEndian, tok.Version); err != nil {
		return "", err
	}
	if _, err := payload.Write(tok.SessionID[:]); err != nil {
		return "", err
	}
	if err := binary.Write(&payload, binary.BigEndian, tok.ExpiresUnix); err != nil {
		return "", err
	}
	if err := binary.Write(&payload, binary.BigEndian, tok.BootstrapRegion); err != nil {
		return "", err
	}
	if _, err := payload.Write(tok.DERPPublic[:]); err != nil {
		return "", err
	}
	if _, err := payload.Write(tok.WGPublic[:]); err != nil {
		return "", err
	}
	if _, err := payload.Write(tok.DiscoPublic[:]); err != nil {
		return "", err
	}
	if _, err := payload.Write(tok.BearerSecret[:]); err != nil {
		return "", err
	}
	if err := binary.Write(&payload, binary.BigEndian, tok.Capabilities); err != nil {
		return "", err
	}

	sum := crc32.ChecksumIEEE(payload.Bytes())
	if err := binary.Write(&payload, binary.BigEndian, sum); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(payload.Bytes()), nil
}

func Decode(encoded string, now time.Time) (Token, error) {
	var tok Token

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return tok, err
	}
	if len(raw) != payloadSize+4 {
		return tok, errors.New("token too short")
	}

	payload := raw[:payloadSize]
	checksum := binary.BigEndian.Uint32(raw[payloadSize:])
	if got := crc32.ChecksumIEEE(payload); got != checksum {
		return tok, ErrChecksum
	}

	r := bytes.NewReader(payload)
	if err := binary.Read(r, binary.BigEndian, &tok.Version); err != nil {
		return tok, err
	}
	if _, err := r.Read(tok.SessionID[:]); err != nil {
		return tok, err
	}
	if err := binary.Read(r, binary.BigEndian, &tok.ExpiresUnix); err != nil {
		return tok, err
	}
	if err := binary.Read(r, binary.BigEndian, &tok.BootstrapRegion); err != nil {
		return tok, err
	}
	if _, err := r.Read(tok.DERPPublic[:]); err != nil {
		return tok, err
	}
	if _, err := r.Read(tok.WGPublic[:]); err != nil {
		return tok, err
	}
	if _, err := r.Read(tok.DiscoPublic[:]); err != nil {
		return tok, err
	}
	if _, err := r.Read(tok.BearerSecret[:]); err != nil {
		return tok, err
	}
	if err := binary.Read(r, binary.BigEndian, &tok.Capabilities); err != nil {
		return tok, err
	}

	if now.Unix() > tok.ExpiresUnix {
		return tok, ErrExpired
	}

	return tok, nil
}
