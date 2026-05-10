// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

const (
	CompactInvitePrefix = "DT1"

	compactInviteRawLen     = 186
	compactInvitePayloadLen = 279
	compactInviteBase       = 41
	compactInviteVersion    = 1
	compactInviteKindTCP    = 1

	compactInviteVersionOffset = 0
	compactInviteKindOffset    = 1
	compactInviteSessionOffset = 2
	compactInviteClientOffset  = 18
	compactInviteTokenOffset   = 34
	compactInviteExpiryOffset  = 50
	compactInviteDERPOffset    = 58
	compactInviteQUICOffset    = 90
	compactInviteBearerOffset  = 122
	compactInviteProofOffset   = 154
)

var compactInviteAlphabet = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+-./:")

func EncodeClientInvite(clientToken string) (string, error) {
	cred, err := DecodeClientToken(clientToken, time.Time{})
	if err != nil {
		return "", err
	}
	if cred.ClientName != clientNameForID(cred.ClientID) {
		return "", ErrInvalidToken
	}
	proofMAC, err := hex.DecodeString(cred.ProofMAC)
	if err != nil || len(proofMAC) != 32 {
		return "", ErrInvalidToken
	}

	raw := make([]byte, compactInviteRawLen)
	raw[compactInviteVersionOffset] = compactInviteVersion
	raw[compactInviteKindOffset] = compactInviteKindTCP
	copy(raw[compactInviteSessionOffset:compactInviteClientOffset], cred.SessionID[:])
	copy(raw[compactInviteClientOffset:compactInviteTokenOffset], cred.ClientID[:])
	copy(raw[compactInviteTokenOffset:compactInviteExpiryOffset], cred.TokenID[:])
	binary.BigEndian.PutUint64(raw[compactInviteExpiryOffset:compactInviteDERPOffset], uint64(cred.ExpiresUnix))
	copy(raw[compactInviteDERPOffset:compactInviteQUICOffset], cred.DERPPublic[:])
	copy(raw[compactInviteQUICOffset:compactInviteBearerOffset], cred.QUICPublic[:])
	copy(raw[compactInviteBearerOffset:compactInviteProofOffset], cred.BearerSecret[:])
	copy(raw[compactInviteProofOffset:], proofMAC)

	return CompactInvitePrefix + compactInviteEncode(raw), nil
}

func DecodeClientInvite(invite string, now time.Time) (ClientCredential, error) {
	raw, err := compactInviteRaw(invite)
	if err != nil {
		return ClientCredential{}, ErrInvalidToken
	}
	if !validCompactInviteHeader(raw) {
		return ClientCredential{}, ErrInvalidToken
	}

	cred := compactInviteCredential(raw)
	if !validClientInviteCredential(cred) {
		return ClientCredential{}, ErrInvalidToken
	}
	if expired(now, cred.ExpiresUnix) {
		return ClientCredential{}, ErrExpired
	}
	return cred, nil
}

func compactInviteRaw(invite string) ([]byte, error) {
	if len(invite) <= len(CompactInvitePrefix) || invite[:len(CompactInvitePrefix)] != CompactInvitePrefix {
		return nil, ErrInvalidToken
	}
	encoded := invite[len(CompactInvitePrefix):]
	if len(encoded) != compactInvitePayloadLen {
		return nil, ErrInvalidToken
	}
	return compactInviteDecode(encoded)
}

func validCompactInviteHeader(raw []byte) bool {
	return len(raw) == compactInviteRawLen &&
		raw[compactInviteVersionOffset] == compactInviteVersion &&
		raw[compactInviteKindOffset] == compactInviteKindTCP
}

func compactInviteCredential(raw []byte) ClientCredential {
	cred := ClientCredential{
		Version:     TokenVersion,
		ExpiresUnix: int64(binary.BigEndian.Uint64(raw[compactInviteExpiryOffset:compactInviteDERPOffset])),
		ProofMAC:    hex.EncodeToString(raw[compactInviteProofOffset:]),
	}
	copy(cred.SessionID[:], raw[compactInviteSessionOffset:compactInviteClientOffset])
	copy(cred.ClientID[:], raw[compactInviteClientOffset:compactInviteTokenOffset])
	copy(cred.TokenID[:], raw[compactInviteTokenOffset:compactInviteExpiryOffset])
	copy(cred.DERPPublic[:], raw[compactInviteDERPOffset:compactInviteQUICOffset])
	copy(cred.QUICPublic[:], raw[compactInviteQUICOffset:compactInviteBearerOffset])
	copy(cred.BearerSecret[:], raw[compactInviteBearerOffset:compactInviteProofOffset])
	cred.ClientName = clientNameForID(cred.ClientID)
	return cred
}

func validClientInviteCredential(cred ClientCredential) bool {
	return cred.SessionID != ([16]byte{}) &&
		cred.ClientID != ([16]byte{}) &&
		cred.TokenID != ([16]byte{}) &&
		cred.DERPPublic != ([32]byte{}) &&
		cred.QUICPublic != ([32]byte{}) &&
		cred.BearerSecret != ([32]byte{}) &&
		validProofMACHex(cred.ProofMAC)
}

func compactInviteEncode(raw []byte) string {
	var out strings.Builder
	out.Grow((len(raw) / 2 * 3) + (len(raw)%2)*2)
	for i := 0; i < len(raw); {
		if i+1 < len(raw) {
			value := int(raw[i])<<8 | int(raw[i+1])
			out.WriteByte(compactInviteAlphabet[value%compactInviteBase])
			value /= compactInviteBase
			out.WriteByte(compactInviteAlphabet[value%compactInviteBase])
			value /= compactInviteBase
			out.WriteByte(compactInviteAlphabet[value])
			i += 2
			continue
		}

		value := int(raw[i])
		out.WriteByte(compactInviteAlphabet[value%compactInviteBase])
		out.WriteByte(compactInviteAlphabet[value/compactInviteBase])
		i++
	}
	return out.String()
}

func compactInviteDecode(encoded string) ([]byte, error) {
	if len(encoded)%3 == 1 {
		return nil, ErrInvalidToken
	}

	out := make([]byte, 0, len(encoded)/3*2+1)
	for i := 0; i < len(encoded); {
		remaining := len(encoded) - i
		if remaining >= 3 {
			value, err := compactInviteDecodeTriple(encoded[i], encoded[i+1], encoded[i+2])
			if err != nil {
				return nil, ErrInvalidToken
			}
			out = append(out, byte(value>>8), byte(value))
			i += 3
			continue
		}

		value, err := compactInviteDecodePair(encoded[i], encoded[i+1])
		if err != nil {
			return nil, ErrInvalidToken
		}
		out = append(out, byte(value))
		i += 2
	}
	return out, nil
}

func compactInviteDecodeTriple(a, b, c byte) (int, error) {
	c0, c1, c2, ok := compactInviteTripleValues(a, b, c)
	if !ok {
		return 0, ErrInvalidToken
	}
	value := c0 + c1*compactInviteBase + c2*compactInviteBase*compactInviteBase
	if value > 0xffff {
		return 0, ErrInvalidToken
	}
	return value, nil
}

func compactInviteTripleValues(a, b, c byte) (int, int, int, bool) {
	c0, ok := compactInviteValue(a)
	if !ok {
		return 0, 0, 0, false
	}
	c1, ok := compactInviteValue(b)
	if !ok {
		return 0, 0, 0, false
	}
	c2, ok := compactInviteValue(c)
	return c0, c1, c2, ok
}

func compactInviteDecodePair(a, b byte) (int, error) {
	c0, ok := compactInviteValue(a)
	if !ok {
		return 0, ErrInvalidToken
	}
	c1, ok := compactInviteValue(b)
	if !ok {
		return 0, ErrInvalidToken
	}
	value := c0 + c1*compactInviteBase
	if value > 0xff {
		return 0, ErrInvalidToken
	}
	return value, nil
}

func compactInviteValue(value byte) (int, bool) {
	for i, allowed := range compactInviteAlphabet {
		if value == allowed {
			return i, true
		}
	}
	return 0, false
}
