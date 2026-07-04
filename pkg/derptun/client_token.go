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
	compactClientTokenRawLen     = 186
	compactClientTokenPayloadLen = 279
	compactClientTokenBase       = 41
	compactClientTokenVersion    = 1
	compactClientTokenKindTCP    = 1

	compactClientTokenVersionOffset = 0
	compactClientTokenKindOffset    = 1
	compactClientTokenSessionOffset = 2
	compactClientTokenClientOffset  = 18
	compactClientTokenTokenOffset   = 34
	compactClientTokenExpiryOffset  = 50
	compactClientTokenDERPOffset    = 58
	compactClientTokenQUICOffset    = 90
	compactClientTokenBearerOffset  = 122
	compactClientTokenProofOffset   = 154
)

var compactClientTokenAlphabet = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+-./:")

func encodeCompactClientToken(cred ClientCredential) (string, error) {
	if cred.ClientName != clientNameForID(cred.ClientID) {
		return "", ErrInvalidToken
	}
	proofMAC, err := hex.DecodeString(cred.ProofMAC)
	if err != nil || len(proofMAC) != 32 {
		return "", ErrInvalidToken
	}

	raw := make([]byte, compactClientTokenRawLen)
	raw[compactClientTokenVersionOffset] = compactClientTokenVersion
	raw[compactClientTokenKindOffset] = compactClientTokenKindTCP
	copy(raw[compactClientTokenSessionOffset:compactClientTokenClientOffset], cred.SessionID[:])
	copy(raw[compactClientTokenClientOffset:compactClientTokenTokenOffset], cred.ClientID[:])
	copy(raw[compactClientTokenTokenOffset:compactClientTokenExpiryOffset], cred.TokenID[:])
	binary.BigEndian.PutUint64(raw[compactClientTokenExpiryOffset:compactClientTokenDERPOffset], uint64(cred.ExpiresUnix))
	copy(raw[compactClientTokenDERPOffset:compactClientTokenQUICOffset], cred.DERPPublic[:])
	copy(raw[compactClientTokenQUICOffset:compactClientTokenBearerOffset], cred.QUICPublic[:])
	copy(raw[compactClientTokenBearerOffset:compactClientTokenProofOffset], cred.BearerSecret[:])
	copy(raw[compactClientTokenProofOffset:], proofMAC)

	return ClientTokenPrefix + compactClientTokenEncode(raw), nil
}

func decodeCompactClientToken(token string, now time.Time) (ClientCredential, error) {
	raw, err := compactClientTokenRaw(token)
	if err != nil {
		return ClientCredential{}, ErrInvalidToken
	}
	if !validCompactClientTokenHeader(raw) {
		return ClientCredential{}, ErrInvalidToken
	}

	cred := compactClientTokenCredential(raw)
	if !validClientCredential(cred) {
		return ClientCredential{}, ErrInvalidToken
	}
	if expired(now, cred.ExpiresUnix) {
		return ClientCredential{}, ErrExpired
	}
	return cred, nil
}

func compactClientTokenRaw(token string) ([]byte, error) {
	if len(token) <= len(ClientTokenPrefix) || token[:len(ClientTokenPrefix)] != ClientTokenPrefix {
		return nil, ErrInvalidToken
	}
	encoded := token[len(ClientTokenPrefix):]
	if len(encoded) != compactClientTokenPayloadLen {
		return nil, ErrInvalidToken
	}
	return compactClientTokenDecode(encoded)
}

func validCompactClientTokenHeader(raw []byte) bool {
	return len(raw) == compactClientTokenRawLen &&
		raw[compactClientTokenVersionOffset] == compactClientTokenVersion &&
		raw[compactClientTokenKindOffset] == compactClientTokenKindTCP
}

func compactClientTokenCredential(raw []byte) ClientCredential {
	cred := ClientCredential{
		Version:     TokenVersion,
		ExpiresUnix: int64(binary.BigEndian.Uint64(raw[compactClientTokenExpiryOffset:compactClientTokenDERPOffset])),
		ProofMAC:    hex.EncodeToString(raw[compactClientTokenProofOffset:]),
	}
	copy(cred.SessionID[:], raw[compactClientTokenSessionOffset:compactClientTokenClientOffset])
	copy(cred.ClientID[:], raw[compactClientTokenClientOffset:compactClientTokenTokenOffset])
	copy(cred.TokenID[:], raw[compactClientTokenTokenOffset:compactClientTokenExpiryOffset])
	copy(cred.DERPPublic[:], raw[compactClientTokenDERPOffset:compactClientTokenQUICOffset])
	copy(cred.QUICPublic[:], raw[compactClientTokenQUICOffset:compactClientTokenBearerOffset])
	copy(cred.BearerSecret[:], raw[compactClientTokenBearerOffset:compactClientTokenProofOffset])
	cred.ClientName = clientNameForID(cred.ClientID)
	return cred
}

func compactClientTokenEncode(raw []byte) string {
	var out strings.Builder
	out.Grow((len(raw) / 2 * 3) + (len(raw)%2)*2)
	for i := 0; i < len(raw); {
		if i+1 < len(raw) {
			value := int(raw[i])<<8 | int(raw[i+1])
			out.WriteByte(compactClientTokenAlphabet[value%compactClientTokenBase])
			value /= compactClientTokenBase
			out.WriteByte(compactClientTokenAlphabet[value%compactClientTokenBase])
			value /= compactClientTokenBase
			out.WriteByte(compactClientTokenAlphabet[value])
			i += 2
			continue
		}

		value := int(raw[i])
		out.WriteByte(compactClientTokenAlphabet[value%compactClientTokenBase])
		out.WriteByte(compactClientTokenAlphabet[value/compactClientTokenBase])
		i++
	}
	return out.String()
}

func compactClientTokenDecode(encoded string) ([]byte, error) {
	if len(encoded)%3 == 1 {
		return nil, ErrInvalidToken
	}

	out := make([]byte, 0, len(encoded)/3*2+1)
	for i := 0; i < len(encoded); {
		remaining := len(encoded) - i
		if remaining >= 3 {
			value, err := compactClientTokenDecodeTriple(encoded[i], encoded[i+1], encoded[i+2])
			if err != nil {
				return nil, ErrInvalidToken
			}
			out = append(out, byte(value>>8), byte(value))
			i += 3
			continue
		}

		value, err := compactClientTokenDecodePair(encoded[i], encoded[i+1])
		if err != nil {
			return nil, ErrInvalidToken
		}
		out = append(out, byte(value))
		i += 2
	}
	return out, nil
}

func compactClientTokenDecodeTriple(a, b, c byte) (int, error) {
	c0, c1, c2, ok := compactClientTokenTripleValues(a, b, c)
	if !ok {
		return 0, ErrInvalidToken
	}
	value := c0 + c1*compactClientTokenBase + c2*compactClientTokenBase*compactClientTokenBase
	if value > 0xffff {
		return 0, ErrInvalidToken
	}
	return value, nil
}

func compactClientTokenTripleValues(a, b, c byte) (int, int, int, bool) {
	c0, ok := compactClientTokenValue(a)
	if !ok {
		return 0, 0, 0, false
	}
	c1, ok := compactClientTokenValue(b)
	if !ok {
		return 0, 0, 0, false
	}
	c2, ok := compactClientTokenValue(c)
	return c0, c1, c2, ok
}

func compactClientTokenDecodePair(a, b byte) (int, error) {
	c0, ok := compactClientTokenValue(a)
	if !ok {
		return 0, ErrInvalidToken
	}
	c1, ok := compactClientTokenValue(b)
	if !ok {
		return 0, ErrInvalidToken
	}
	value := c0 + c1*compactClientTokenBase
	if value > 0xff {
		return 0, ErrInvalidToken
	}
	return value, nil
}

func compactClientTokenValue(value byte) (int, bool) {
	for i, allowed := range compactClientTokenAlphabet {
		if value == allowed {
			return i, true
		}
	}
	return 0, false
}
