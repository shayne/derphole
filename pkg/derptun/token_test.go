// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sessiontoken "github.com/shayne/derphole/pkg/token"
)

func TestGenerateServerTokenDefaultsToSixMonths(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	encoded, err := GenerateServerToken(ServerTokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	if got := encoded[:len(ServerTokenPrefix)]; got != ServerTokenPrefix {
		t.Fatalf("prefix = %q, want %q", got, ServerTokenPrefix)
	}
	cred, err := DecodeServerToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	if got, want := time.Unix(cred.ExpiresUnix, 0).UTC(), now.Add(180*24*time.Hour); !got.Equal(want) {
		t.Fatalf("expiry = %s, want %s", got, want)
	}
}

func TestGenerateClientTokenDefaultsToNinetyDays(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := GenerateClientToken(ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	clientCred, err := DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if got, want := time.Unix(clientCred.ExpiresUnix, 0).UTC(), now.Add(90*24*time.Hour); !got.Equal(want) {
		t.Fatalf("client expiry = %s, want %s", got, want)
	}
}

func TestGenerateClientTokenFromServerToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := GenerateClientToken(ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if got := clientToken[:len(ClientTokenPrefix)]; got != ClientTokenPrefix {
		t.Fatalf("prefix = %q, want %q", got, ClientTokenPrefix)
	}
	clientCred, err := DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if clientCred.ClientName == "" {
		t.Fatalf("ClientName = empty, want generated name")
	}
	payload := decodeTokenPayload(t, ClientTokenPrefix, clientToken)
	for _, field := range []string{"derp_private", "quic_private", "signing_secret"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("client token exposed private field %q", field)
		}
	}
	if got, want := time.Unix(clientCred.ExpiresUnix, 0).UTC(), now.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("client expiry = %s, want %s", got, want)
	}
}

func TestDecodeClientTokenRejectsMalformedProofMAC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := GenerateClientToken(ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	payload := decodeTokenPayload(t, ClientTokenPrefix, clientToken)
	payload["proof_mac"] = "not-hex"
	tampered := encodeTokenPayload(t, ClientTokenPrefix, payload)

	if _, err := DecodeClientToken(tampered, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("DecodeClientToken(tampered) error = %v, want ErrInvalidToken", err)
	}
}

func TestClientTokenCannotOutliveServerToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	_, err = GenerateClientToken(ClientTokenOptions{
		Now:         now,
		ServerToken: server,
		Days:        2,
	})
	if err == nil || err.Error() != "client expiry exceeds server expiry" {
		t.Fatalf("GenerateClientToken() error = %v, want client expiry exceeds server expiry", err)
	}
}

func TestDecodeRejectsWrongTokenRole(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if _, err := DecodeClientToken(server, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("DecodeClientToken(server) error = %v, want ErrInvalidToken", err)
	}
	if _, err := DecodeServerToken(client, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("DecodeServerToken(client) error = %v, want ErrInvalidToken", err)
	}
	if _, err := DecodeServerToken("dt1_legacy", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("DecodeServerToken(legacy) error = %v, want ErrInvalidToken", err)
	}
}

func TestServerAndClientSessionTokensShareServerIdentity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	serverCred, err := DecodeServerToken(server, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	clientCred, err := DecodeClientToken(client, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	serverTok, err := serverCred.SessionToken()
	if err != nil {
		t.Fatalf("server SessionToken() error = %v", err)
	}
	clientTok, err := clientCred.SessionToken()
	if err != nil {
		t.Fatalf("client SessionToken() error = %v", err)
	}
	if serverTok.SessionID != clientTok.SessionID {
		t.Fatalf("session mismatch")
	}
	if serverTok.DERPPublic != clientTok.DERPPublic {
		t.Fatalf("DERP public mismatch")
	}
	if serverTok.QUICPublic != clientTok.QUICPublic {
		t.Fatalf("QUIC public mismatch")
	}
	if clientTok.Capabilities&sessiontoken.CapabilityDerptunTCP == 0 {
		t.Fatalf("client capabilities = %b, want derptun tcp bit", clientTok.Capabilities)
	}
}

func decodeTokenPayload(t *testing.T, prefix, encoded string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded[len(prefix):])
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return payload
}

func encodeTokenPayload(t *testing.T, prefix string, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}
