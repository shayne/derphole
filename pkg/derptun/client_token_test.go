// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestClientTokenRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if !strings.HasPrefix(client, ClientTokenPrefix) {
		t.Fatalf("token prefix = %q, want %q", client[:len(ClientTokenPrefix)], ClientTokenPrefix)
	}
	if strings.Contains(client, "://") || strings.Contains(client, "?") || strings.Contains(client, "&") {
		t.Fatalf("token = %q, want compact non-URL text", client)
	}
	if len(client) != len(ClientTokenPrefix)+compactClientTokenPayloadLen {
		t.Fatalf("token length = %d, want %d", len(client), len(ClientTokenPrefix)+compactClientTokenPayloadLen)
	}
	assertCompactClientTokenText(t, client)

	cred, err := DecodeClientToken(client, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if err := VerifyClientCredential(mustServerSigningSecret(t, server, now), cred, now); err != nil {
		t.Fatalf("VerifyClientCredential() error = %v", err)
	}
}

func TestCompactClientTokenTextAlphabet(t *testing.T) {
	const wantAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+-./:"
	if compactClientTokenBase != len(compactClientTokenAlphabet) {
		t.Fatalf("compactClientTokenBase = %d, alphabet length = %d", compactClientTokenBase, len(compactClientTokenAlphabet))
	}
	if string(compactClientTokenAlphabet) != wantAlphabet {
		t.Fatalf("compact client token alphabet = %q, want %q", compactClientTokenAlphabet, wantAlphabet)
	}

	now := time.Now().UTC()
	token := generateCompactClientToken(t, now)
	assertCompactClientTokenText(t, token)
}

func TestCompactClientTokenRejectsMalformedInput(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, raw := range []string{
		"",
		"dt1ABC",
		"DT2ABC",
		"DT1",
		"DT1not valid",
	} {
		if _, err := DecodeClientToken(raw, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("DecodeClientToken(%q) error = %v, want ErrInvalidToken", raw, err)
		}
	}
}

func TestCompactClientTokenRejectsMalformedPayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, raw := range []string{
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen-1),
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen+1),
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen-1) + "_",
		ClientTokenPrefix + ":::" + strings.Repeat("0", compactClientTokenPayloadLen-3),
	} {
		if _, err := DecodeClientToken(raw, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("DecodeClientToken(%q) error = %v, want ErrInvalidToken", raw, err)
		}
	}
}

func TestCompactClientTokenRejectsWrongVersionOrKind(t *testing.T) {
	now := time.Now().UTC()
	for name, mutate := range map[string]func([]byte){
		"wrong version": func(raw []byte) { raw[compactClientTokenVersionOffset] = compactClientTokenVersion + 1 },
		"wrong kind":    func(raw []byte) { raw[compactClientTokenKindOffset] = compactClientTokenKindTCP + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			raw := validCompactClientTokenRaw(t, now)
			mutate(raw)
			token := ClientTokenPrefix + compactClientTokenEncode(raw)
			if _, err := DecodeClientToken(token, now); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("DecodeClientToken(%s) error = %v, want ErrInvalidToken", name, err)
			}
		})
	}
}

func TestCompactClientTokenRejectsExpiredCredential(t *testing.T) {
	now := time.Now().UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 2})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 1})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}

	_, err = DecodeClientToken(client, now.Add(25*time.Hour))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("DecodeClientToken(expired) error = %v, want ErrExpired", err)
	}
}

func TestCompactClientTokenCodecRoundTrip(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 5, 254, 255}
	encoded := compactClientTokenEncode(raw)
	decoded, err := compactClientTokenDecode(encoded)
	if err != nil {
		t.Fatalf("compactClientTokenDecode() error = %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatalf("decoded = %v, want %v", decoded, raw)
	}
}

func TestCompactClientTokenDecodePairBoundaries(t *testing.T) {
	got, err := compactClientTokenDecodePair(compactClientTokenAlphabet[0], compactClientTokenAlphabet[0])
	if err != nil {
		t.Fatalf("compactClientTokenDecodePair(zero) error = %v", err)
	}
	if got != 0 {
		t.Fatalf("compactClientTokenDecodePair(zero) = %d, want 0", got)
	}

	got, err = compactClientTokenDecodePair(compactClientTokenAlphabet[255%compactClientTokenBase], compactClientTokenAlphabet[255/compactClientTokenBase])
	if err != nil {
		t.Fatalf("compactClientTokenDecodePair(max byte) error = %v", err)
	}
	if got != 255 {
		t.Fatalf("compactClientTokenDecodePair(max byte) = %d, want 255", got)
	}

	for _, tc := range []struct {
		name string
		a    byte
		b    byte
	}{
		{name: "invalid first", a: '_', b: compactClientTokenAlphabet[0]},
		{name: "invalid second", a: compactClientTokenAlphabet[0], b: '_'},
		{name: "overflow", a: compactClientTokenAlphabet[0], b: compactClientTokenAlphabet[256/compactClientTokenBase+1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compactClientTokenDecodePair(tc.a, tc.b); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("compactClientTokenDecodePair(%q, %q) error = %v, want ErrInvalidToken", tc.a, tc.b, err)
			}
		})
	}
}

func mustServerSigningSecret(t *testing.T, serverToken string, now time.Time) [32]byte {
	t.Helper()
	server, err := DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	return server.SigningSecret
}

func generateCompactClientToken(t *testing.T, now time.Time) string {
	t.Helper()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return client
}

func validCompactClientTokenRaw(t *testing.T, now time.Time) []byte {
	t.Helper()
	token := generateCompactClientToken(t, now)
	raw, err := compactClientTokenDecode(token[len(ClientTokenPrefix):])
	if err != nil {
		t.Fatalf("compactClientTokenDecode() error = %v", err)
	}
	return raw
}

func assertCompactClientTokenText(t *testing.T, token string) {
	t.Helper()
	if !strings.HasPrefix(token, ClientTokenPrefix) {
		t.Fatalf("token prefix = %q, want %q", token[:len(ClientTokenPrefix)], ClientTokenPrefix)
	}
	for i, r := range token {
		if unicode.IsSpace(r) {
			t.Fatalf("token[%d] = whitespace %q, want no whitespace", i, r)
		}
	}
	for i, b := range []byte(token[len(ClientTokenPrefix):]) {
		if !compactClientTokenAlphabetContains(b) {
			t.Fatalf("token payload[%d] = %q, want compact client token alphabet", i, b)
		}
	}
}

func compactClientTokenAlphabetContains(value byte) bool {
	for _, allowed := range compactClientTokenAlphabet {
		if value == allowed {
			return true
		}
	}
	return false
}
