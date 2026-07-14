// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	sessiontoken "github.com/shayne/derphole/pkg/token"
)

const publicServerGolden = "dts1_eyJ2ZXJzaW9uIjoxLCJzZXNzaW9uX2lkIjpbMSwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMF0sImV4cGlyZXNfdW5peCI6MTcwMDAwMDAwMCwiZGVycF9wcml2YXRlIjoicHJpdmtleTpnb2xkZW4iLCJxdWljX3ByaXZhdGUiOiJBZ009Iiwic2lnbmluZ19zZWNyZXQiOls0LDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDBdfQ"

func TestPublicServerCredentialGolden(t *testing.T) {
	cred := ServerCredential{
		Version:       TokenVersion,
		ExpiresUnix:   1_700_000_000,
		DERPPrivate:   "privkey:golden",
		QUICPrivate:   []byte{2, 3},
		SigningSecret: [32]byte{4},
	}
	cred.SessionID[0] = 1

	got, err := encodeJSONToken(ServerTokenPrefix, cred)
	if err != nil {
		t.Fatalf("encodeJSONToken() error = %v", err)
	}
	if got != publicServerGolden {
		t.Fatalf("encodeJSONToken() = %q, want literal public golden %q", got, publicServerGolden)
	}
}

func TestCustomDERPCredentialFlowIgnoresDerivationEnvironment(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	route, err := derpbind.NewCustomRoute("derp.example.com", 8443, 3478)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30, DERPRoute: route})
	if err != nil {
		t.Fatalf("GenerateServerToken(custom) error = %v", err)
	}
	if !strings.HasPrefix(serverToken, CustomServerTokenPrefix) {
		t.Fatalf("server token = %q, want %s prefix", serverToken, CustomServerTokenPrefix)
	}
	server, err := DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken(custom) error = %v", err)
	}
	if server.Version != CustomTokenVersion || server.DERPRoute == nil || *server.DERPRoute != route {
		t.Fatalf("server credential = %+v, want version %d route %+v", server, CustomTokenVersion, route)
	}

	t.Setenv(derpbind.CustomDERPServerEnv, "https://conflict.invalid")
	clientToken, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: serverToken, Days: 7})
	if err != nil {
		t.Fatalf("GenerateClientToken(custom) error = %v", err)
	}
	if !strings.HasPrefix(clientToken, CustomClientTokenPrefix) {
		t.Fatalf("client token = %q, want %s prefix", clientToken, CustomClientTokenPrefix)
	}
	client, err := DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken(custom) error = %v", err)
	}
	if client.Version != CustomTokenVersion || client.DERPRoute == nil || *client.DERPRoute != route {
		t.Fatalf("client credential = %+v, want version %d route %+v", client, CustomTokenVersion, route)
	}

	serverSession, err := server.SessionToken()
	if err != nil {
		t.Fatalf("server SessionToken() error = %v", err)
	}
	clientSession, err := client.SessionToken()
	if err != nil {
		t.Fatalf("client SessionToken() error = %v", err)
	}
	for name, tok := range map[string]sessiontoken.Token{"server": serverSession, "client": clientSession} {
		if tok.Version != sessiontoken.CustomDERPVersion || tok.DERPRoute != route {
			t.Fatalf("%s session token = %+v, want version %d route %+v", name, tok, sessiontoken.CustomDERPVersion, route)
		}
	}

	publicServerToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken(public) error = %v", err)
	}
	publicServer, err := DecodeServerToken(publicServerToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken(public) error = %v", err)
	}
	publicClientToken, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: publicServerToken, Days: 7})
	if err != nil {
		t.Fatalf("GenerateClientToken(public) error = %v", err)
	}
	publicClient, err := DecodeClientToken(publicClientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken(public) error = %v", err)
	}
	publicServerSession, err := publicServer.SessionToken()
	if err != nil {
		t.Fatalf("public server SessionToken() error = %v", err)
	}
	publicClientSession, err := publicClient.SessionToken()
	if err != nil {
		t.Fatalf("public client SessionToken() error = %v", err)
	}
	if publicServerSession.Version != sessiontoken.SupportedVersion || publicClientSession.Version != sessiontoken.SupportedVersion {
		t.Fatalf("public session versions = %d/%d, want %d", publicServerSession.Version, publicClientSession.Version, sessiontoken.SupportedVersion)
	}
	if publicServerSession.DERPRoute.IsCustom() || publicClientSession.DERPRoute.IsCustom() {
		t.Fatalf("public session routes = %+v/%+v, want public", publicServerSession.DERPRoute, publicClientSession.DERPRoute)
	}
}

func TestGenerateServerTokenFromEnvironment(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	t.Setenv(derpbind.CustomDERPServerEnv, "https://derp.example.com:8443/derp")
	token, err := GenerateServerTokenFromEnvironment(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerTokenFromEnvironment() error = %v", err)
	}
	cred, err := DecodeServerToken(token, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	if cred.DERPRoute == nil || cred.DERPRoute.Host != "derp.example.com" || cred.DERPRoute.DERPPort != 8443 {
		t.Fatalf("DERPRoute = %+v, want environment route", cred.DERPRoute)
	}
}

func TestDecodeServerTokenRequiresMatchingPrefixVersionAndRoute(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	publicToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken(public) error = %v", err)
	}
	publicPayload := decodeTokenPayload(t, ServerTokenPrefix, publicToken)

	v2WithPublicPrefix := cloneTokenPayload(publicPayload)
	v2WithPublicPrefix["version"] = float64(CustomTokenVersion)
	v2WithPublicPrefix["derp_route"] = map[string]any{"host": "derp.example.com", "derp_port": float64(8443), "stun_port": float64(3478)}

	v1WithCustomPrefix := cloneTokenPayload(publicPayload)

	for name, token := range map[string]string{
		"dts1 with v2 route":  encodeTokenPayload(t, ServerTokenPrefix, v2WithPublicPrefix),
		"dts2 with v1 public": encodeTokenPayload(t, CustomServerTokenPrefix, v1WithCustomPrefix),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeServerToken(token, now); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("DecodeServerToken() error = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestCredentialPrefixRecognitionIsExact(t *testing.T) {
	for _, tt := range []struct {
		value  string
		server bool
		client bool
	}{
		{value: ServerTokenPrefix + "payload", server: true},
		{value: CustomServerTokenPrefix + "payload", server: true},
		{value: ClientTokenPrefix + "payload", client: true},
		{value: CustomClientTokenPrefix + "payload", client: true},
		{value: "dts3_payload"},
		{value: "DT3payload"},
		{value: "prefix" + ServerTokenPrefix},
		{value: "prefix" + ClientTokenPrefix},
	} {
		if got := HasServerTokenPrefix(tt.value); got != tt.server {
			t.Errorf("HasServerTokenPrefix(%q) = %t, want %t", tt.value, got, tt.server)
		}
		if got := HasClientTokenPrefix(tt.value); got != tt.client {
			t.Errorf("HasClientTokenPrefix(%q) = %t, want %t", tt.value, got, tt.client)
		}
	}
}

func cloneTokenPayload(payload map[string]any) map[string]any {
	clone := make(map[string]any, len(payload))
	for key, value := range payload {
		clone[key] = value
	}
	return clone
}

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
	if !strings.HasPrefix(clientToken, ClientTokenPrefix) {
		t.Fatalf("client token = %q, want %s prefix", clientToken, ClientTokenPrefix)
	}
	if strings.HasPrefix(clientToken, "dtc1_") {
		t.Fatalf("client token = %q, want removed format to be unused", clientToken)
	}
	clientCred, err := DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if clientCred.ClientName == "" {
		t.Fatalf("ClientName = empty, want generated name")
	}
	if got, want := time.Unix(clientCred.ExpiresUnix, 0).UTC(), now.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("client expiry = %s, want %s", got, want)
	}
}

func TestDecodeClientTokenRejectsMalformedInput(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, raw := range []string{
		"",
		"dtc1_legacy",
		"DT2ABC",
		"DT1",
		"DT1not valid",
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen-1),
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen+1),
	} {
		if _, err := DecodeClientToken(raw, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("DecodeClientToken(%q) error = %v, want ErrInvalidToken", raw, err)
		}
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

func TestVerifyClientCredentialChecksBearerProofAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	serverCred, err := DecodeServerToken(server, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 7})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	clientCred, err := DecodeClientToken(client, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if err := VerifyClientCredential(serverCred.SigningSecret, clientCred, now); err != nil {
		t.Fatalf("VerifyClientCredential(valid) error = %v", err)
	}
	if got := DeriveClientBearerSecretForClaim(serverCred.SigningSecret, clientCred.ClientID); got != clientCred.BearerSecret {
		t.Fatal("DeriveClientBearerSecretForClaim() did not match client bearer secret")
	}

	badBearer := clientCred
	badBearer.BearerSecret[0] ^= 0xff
	if err := VerifyClientCredential(serverCred.SigningSecret, badBearer, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyClientCredential(bad bearer) error = %v, want ErrInvalidToken", err)
	}

	badProof := clientCred
	badProof.ProofMAC = "00" + badProof.ProofMAC[2:]
	if err := VerifyClientCredential(serverCred.SigningSecret, badProof, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyClientCredential(bad proof) error = %v, want ErrInvalidToken", err)
	}
	if err := VerifyClientCredential(serverCred.SigningSecret, clientCred, now.Add(8*24*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("VerifyClientCredential(expired) error = %v, want ErrExpired", err)
	}
}

func TestEncodeClientCredentialAndDecodeServerValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 7})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	clientCred, err := DecodeClientToken(client, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	encoded, err := EncodeClientCredential(clientCred)
	if err != nil {
		t.Fatalf("EncodeClientCredential() error = %v", err)
	}
	if !strings.HasPrefix(encoded, ClientTokenPrefix) {
		t.Fatalf("EncodeClientCredential() = %q, want %s prefix", encoded, ClientTokenPrefix)
	}
	roundTrip, err := DecodeClientToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeClientToken(encoded credential) error = %v", err)
	}
	if roundTrip.ClientID != clientCred.ClientID || roundTrip.ProofMAC != clientCred.ProofMAC {
		t.Fatal("encoded client credential did not round-trip")
	}

	payload := decodeTokenPayload(t, ServerTokenPrefix, server)
	payload["derp_private"] = "not-a-node-key"
	tampered := encodeTokenPayload(t, ServerTokenPrefix, payload)
	if _, err := DecodeServerToken(tampered, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("DecodeServerToken(bad derp key) error = %v, want ErrInvalidToken", err)
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
