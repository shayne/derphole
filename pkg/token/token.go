package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
	"time"
)

const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityShare
	CapabilityAttach
	CapabilityStdioOffer
	CapabilityWebFile
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
	if tok.Version == 0 {
		tok.Version = SupportedVersion
	} else if tok.Version != legacyVersion && tok.Version != SupportedVersion {
		return "", ErrUnsupportedVersion
	}

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
	if _, err := payload.Write(tok.QUICPublic[:]); err != nil {
		return "", err
	}
	if _, err := payload.Write(tok.BearerSecret[:]); err != nil {
		return "", err
	}
	if err := binary.Write(&payload, binary.BigEndian, tok.Capabilities); err != nil {
		return "", err
	}
	if tok.Version >= SupportedVersion {
		if err := binary.Write(&payload, binary.BigEndian, tok.bootstrapFamily); err != nil {
			return "", err
		}
		if _, err := payload.Write(tok.bootstrapIP[:]); err != nil {
			return "", err
		}
		if err := binary.Write(&payload, binary.BigEndian, tok.bootstrapPort); err != nil {
			return "", err
		}
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
	if len(raw) < 1 {
		return tok, ErrInvalidLength
	}

	tok.Version = raw[0]
	if tok.Version != legacyVersion && tok.Version != SupportedVersion {
		return tok, ErrUnsupportedVersion
	}
	wantLen := fixedPayloadSizeV3 + 4
	if tok.Version >= SupportedVersion {
		wantLen = fixedPayloadSizeV4 + 4
	}
	if len(raw) < wantLen {
		return tok, ErrInvalidLength
	}

	payload := raw[:len(raw)-4]
	checksum := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if got := crc32.ChecksumIEEE(payload); got != checksum {
		return tok, ErrChecksum
	}

	r := bytes.NewReader(payload[1:])
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
	if _, err := r.Read(tok.QUICPublic[:]); err != nil {
		return tok, err
	}
	if _, err := r.Read(tok.BearerSecret[:]); err != nil {
		return tok, err
	}
	if err := binary.Read(r, binary.BigEndian, &tok.Capabilities); err != nil {
		return tok, err
	}
	if tok.Version >= SupportedVersion {
		if err := binary.Read(r, binary.BigEndian, &tok.bootstrapFamily); err != nil {
			return tok, err
		}
		if _, err := r.Read(tok.bootstrapIP[:]); err != nil {
			return tok, err
		}
		if err := binary.Read(r, binary.BigEndian, &tok.bootstrapPort); err != nil {
			return tok, err
		}
	}
	if r.Len() != 0 {
		return tok, ErrInvalidLength
	}

	if now.Unix() >= tok.ExpiresUnix {
		return tok, ErrExpired
	}

	return tok, nil
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
