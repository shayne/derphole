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

	"github.com/shayne/derphole/pkg/derpbind"
)

const publicClientGolden = "DT1B60A60000000000000000000000KC0000000000000000000000T21000000000000000000000000000RHFWS+UI0000000000000000000000000000000000000000000000:O00000000000000000000000000000000000000000000009V0000000000000000000000000000000000000000000000P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0P-0"

func TestPublicClientCredentialGolden(t *testing.T) {
	cred := ClientCredential{
		Version:      TokenVersion,
		ClientName:   "client-02000000",
		ExpiresUnix:  1_700_000_000,
		DERPPublic:   [32]byte{3},
		QUICPublic:   [32]byte{4},
		BearerSecret: [32]byte{5},
		ProofMAC:     strings.Repeat("06", 32),
	}
	cred.SessionID[0] = 1
	cred.ClientID[0] = 2
	cred.TokenID[0] = 7

	got, err := EncodeClientCredential(cred)
	if err != nil {
		t.Fatalf("EncodeClientCredential() error = %v", err)
	}
	if got != publicClientGolden {
		t.Fatalf("EncodeClientCredential() = %q, want literal public golden %q", got, publicClientGolden)
	}
}

func TestCompactClientTokenRequiresMatchingPrefixVersionAndRoute(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	raw := validCompactClientTokenRaw(t, now)
	raw[compactClientTokenVersionOffset] = CustomTokenVersion

	for name, token := range map[string]string{
		"DT1 with v2 bytes":     ClientTokenPrefix + compactClientTokenEncode(raw),
		"DT2 without route":     CustomClientTokenPrefix + compactClientTokenEncode(raw),
		"unknown client prefix": "DT3" + compactClientTokenEncode(raw),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeClientToken(token, now); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("DecodeClientToken() error = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestCustomClientProofBindsCanonicalRouteWire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	route, err := derpbind.NewCustomRoute("derp.example.com", 8443, 3478)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7, DERPRoute: route})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	server, err := DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientToken, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: serverToken, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	raw, err := compactClientTokenDecode(clientToken[len(CustomClientTokenPrefix):])
	if err != nil {
		t.Fatalf("compactClientTokenDecode() error = %v", err)
	}
	if len(raw) <= compactClientTokenRawLen+1 {
		t.Fatalf("custom raw length = %d, want route extension", len(raw))
	}
	raw[compactClientTokenRawLen+1] = 'x'
	tamperedToken := CustomClientTokenPrefix + compactClientTokenEncode(raw)
	tampered, err := DecodeClientToken(tamperedToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken(tampered canonical route) error = %v", err)
	}
	if err := VerifyClientCredential(server.SigningSecret, tampered, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyClientCredential(tampered route) error = %v, want ErrInvalidToken", err)
	}
}

func TestCustomClientTokenMaximumHostRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	maxHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(maxHost) != 253 {
		t.Fatalf("maximum host fixture length = %d, want 253", len(maxHost))
	}
	route, err := derpbind.NewCustomRoute(maxHost, 443, 3478)
	if err != nil {
		t.Fatalf("NewCustomRoute(maximum host) error = %v", err)
	}
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7, DERPRoute: route})
	if err != nil {
		t.Fatalf("GenerateServerToken(maximum host) error = %v", err)
	}
	clientToken, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: serverToken, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken(maximum host) error = %v", err)
	}
	client, err := DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken(maximum host) error = %v", err)
	}
	if client.DERPRoute == nil || client.DERPRoute.Host != maxHost {
		t.Fatalf("DERPRoute = %+v, want maximum host", client.DERPRoute)
	}

	tooLongRoute := derpbind.Route{Host: maxHost + "e", DERPPort: 443, STUNPort: 3478}
	if token, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7, DERPRoute: tooLongRoute}); err == nil || token != "" {
		t.Fatalf("GenerateServerToken(254-byte host) = %q, %v; want empty token and error", token, err)
	}
}

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
		"DT200",
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

func TestCompactCustomClientTokenPayloadLengthBounds(t *testing.T) {
	const (
		minimumRouteWireLength = 1 + 1 + 2 + 2
		maximumRouteWireLength = 1 + 253 + 2 + 2
		minimumPayloadLength   = (compactClientTokenRawLen + minimumRouteWireLength) / 2 * 3
		maximumPayloadLength   = (compactClientTokenRawLen + maximumRouteWireLength) / 2 * 3
	)

	for _, tt := range []struct {
		name   string
		length int
		want   bool
	}{
		{name: "below minimum", length: minimumPayloadLength - 1},
		{name: "minimum", length: minimumPayloadLength, want: true},
		{name: "maximum", length: maximumPayloadLength, want: true},
		{name: "oversized", length: maximumPayloadLength + 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := validCompactCustomClientTokenPayloadLength(tt.length); got != tt.want {
				t.Fatalf("validCompactCustomClientTokenPayloadLength(%d) = %t, want %t", tt.length, got, tt.want)
			}
		})
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
