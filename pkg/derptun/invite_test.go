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

func TestCompactInviteRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}

	invite, err := EncodeClientInvite(client)
	if err != nil {
		t.Fatalf("EncodeClientInvite() error = %v", err)
	}
	if !strings.HasPrefix(invite, CompactInvitePrefix) {
		t.Fatalf("invite prefix = %q, want %q", invite[:len(CompactInvitePrefix)], CompactInvitePrefix)
	}
	if strings.Contains(invite, "://") || strings.Contains(invite, "?") || strings.Contains(invite, "&") {
		t.Fatalf("invite = %q, want compact non-URL text", invite)
	}
	if len(invite) != len(CompactInvitePrefix)+compactInvitePayloadLen {
		t.Fatalf("invite length = %d, want %d", len(invite), len(CompactInvitePrefix)+compactInvitePayloadLen)
	}
	assertCompactInviteText(t, invite)
	if len(invite) >= len(client) {
		t.Fatalf("compact invite length = %d, client token length = %d", len(invite), len(client))
	}

	cred, err := DecodeClientInvite(invite, now)
	if err != nil {
		t.Fatalf("DecodeClientInvite() error = %v", err)
	}
	original, err := DecodeClientToken(client, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if cred != original {
		t.Fatalf("decoded compact credential differs from original\ncompact=%#v\noriginal=%#v", cred, original)
	}
}

func TestCompactInviteTextAlphabet(t *testing.T) {
	const wantAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+-./:"
	if compactInviteBase != len(compactInviteAlphabet) {
		t.Fatalf("compactInviteBase = %d, alphabet length = %d", compactInviteBase, len(compactInviteAlphabet))
	}
	if string(compactInviteAlphabet) != wantAlphabet {
		t.Fatalf("compact invite alphabet = %q, want %q", compactInviteAlphabet, wantAlphabet)
	}

	now := time.Now().UTC()
	invite := generateCompactInvite(t, now)
	assertCompactInviteText(t, invite)
}

func TestCompactInviteRejectsMalformedInput(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, raw := range []string{
		"",
		"dt1ABC",
		"DT2ABC",
		"DT1",
		"DT1not valid",
	} {
		if _, err := DecodeClientInvite(raw, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("DecodeClientInvite(%q) error = %v, want ErrInvalidToken", raw, err)
		}
	}
}

func TestCompactInviteRejectsMalformedPayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, raw := range []string{
		CompactInvitePrefix + strings.Repeat("0", compactInvitePayloadLen-1),
		CompactInvitePrefix + strings.Repeat("0", compactInvitePayloadLen+1),
		CompactInvitePrefix + strings.Repeat("0", compactInvitePayloadLen-1) + "_",
		CompactInvitePrefix + ":::" + strings.Repeat("0", compactInvitePayloadLen-3),
	} {
		if _, err := DecodeClientInvite(raw, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("DecodeClientInvite(%q) error = %v, want ErrInvalidToken", raw, err)
		}
	}
}

func TestCompactInviteRejectsWrongVersionOrKind(t *testing.T) {
	now := time.Now().UTC()
	for name, mutate := range map[string]func([]byte){
		"wrong version": func(raw []byte) { raw[compactInviteVersionOffset] = compactInviteVersion + 1 },
		"wrong kind":    func(raw []byte) { raw[compactInviteKindOffset] = compactInviteKindTCP + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			raw := validCompactInviteRaw(t, now)
			mutate(raw)
			invite := CompactInvitePrefix + compactInviteEncode(raw)
			if _, err := DecodeClientInvite(invite, now); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("DecodeClientInvite(%s) error = %v, want ErrInvalidToken", name, err)
			}
		})
	}
}

func TestCompactInviteRejectsExpiredCredential(t *testing.T) {
	now := time.Now().UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 2})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 1})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	invite, err := EncodeClientInvite(client)
	if err != nil {
		t.Fatalf("EncodeClientInvite() error = %v", err)
	}

	_, err = DecodeClientInvite(invite, now.Add(25*time.Hour))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("DecodeClientInvite(expired) error = %v, want ErrExpired", err)
	}
}

func TestCompactInviteCodecRoundTrip(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 5, 254, 255}
	encoded := compactInviteEncode(raw)
	decoded, err := compactInviteDecode(encoded)
	if err != nil {
		t.Fatalf("compactInviteDecode() error = %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatalf("decoded = %v, want %v", decoded, raw)
	}
}

func generateCompactInvite(t *testing.T, now time.Time) string {
	t.Helper()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	invite, err := EncodeClientInvite(client)
	if err != nil {
		t.Fatalf("EncodeClientInvite() error = %v", err)
	}
	return invite
}

func validCompactInviteRaw(t *testing.T, now time.Time) []byte {
	t.Helper()
	invite := generateCompactInvite(t, now)
	raw, err := compactInviteDecode(invite[len(CompactInvitePrefix):])
	if err != nil {
		t.Fatalf("compactInviteDecode() error = %v", err)
	}
	return raw
}

func assertCompactInviteText(t *testing.T, invite string) {
	t.Helper()
	if !strings.HasPrefix(invite, CompactInvitePrefix) {
		t.Fatalf("invite prefix = %q, want %q", invite[:len(CompactInvitePrefix)], CompactInvitePrefix)
	}
	for i, r := range invite {
		if unicode.IsSpace(r) {
			t.Fatalf("invite[%d] = whitespace %q, want no whitespace", i, r)
		}
	}
	for i, b := range []byte(invite[len(CompactInvitePrefix):]) {
		if !compactInviteAlphabetContains(b) {
			t.Fatalf("invite payload[%d] = %q, want compact invite alphabet", i, b)
		}
	}
}

func compactInviteAlphabetContains(value byte) bool {
	for _, allowed := range compactInviteAlphabet {
		if value == allowed {
			return true
		}
	}
	return false
}
