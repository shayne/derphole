package derptun

import (
	"crypto/ed25519"
	"testing"
	"time"

	sessiontoken "github.com/shayne/derphole/pkg/token"
)

func TestGenerateTokenDefaultsToSevenDays(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}
	if got, want := time.Unix(cred.ExpiresUnix, 0).UTC(), now.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("expiry = %s, want %s", got, want)
	}
}

func TestGenerateTokenUsesAbsoluteExpiry(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	expires := now.Add(36 * time.Hour)
	encoded, err := GenerateToken(TokenOptions{Now: now, Expires: expires})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}
	if got := time.Unix(cred.ExpiresUnix, 0).UTC(); !got.Equal(expires) {
		t.Fatalf("expiry = %s, want %s", got, expires)
	}
}

func TestDecodeTokenRejectsExpired(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	_, err = DecodeToken(encoded, now.Add(25*time.Hour))
	if err != ErrExpired {
		t.Fatalf("DecodeToken() error = %v, want %v", err, ErrExpired)
	}
}

func TestTokenSessionTokenUsesDerptunCapability(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}
	tok, err := cred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	if tok.Capabilities&sessiontoken.CapabilityDerptunTCP == 0 {
		t.Fatalf("capabilities = %b, want derptun tcp bit", tok.Capabilities)
	}
	if tok.Capabilities&sessiontoken.CapabilityShare != 0 {
		t.Fatalf("capabilities = %b, must not include share bit", tok.Capabilities)
	}
}

func TestTokenStableIdentityMaterialRoundTrips(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	first, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken(first) error = %v", err)
	}
	second, err := DecodeToken(encoded, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("DecodeToken(second) error = %v", err)
	}
	if first.DERPPrivate != second.DERPPrivate {
		t.Fatal("DERP private key changed across decode")
	}
	if string(first.QUICPrivate) != string(second.QUICPrivate) {
		t.Fatal("QUIC private key changed across decode")
	}
	if len(first.QUICPrivate) != ed25519.PrivateKeySize {
		t.Fatalf("QUIC private key length = %d, want %d", len(first.QUICPrivate), ed25519.PrivateKeySize)
	}
}

func TestDecodeTokenRejectsInvalidDERPPrivateKey(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken(valid) error = %v", err)
	}
	cred.DERPPrivate = "not-a-node-private-key"
	encoded, err = EncodeCredential(cred)
	if err != nil {
		t.Fatalf("EncodeCredential() error = %v", err)
	}
	_, err = DecodeToken(encoded, now)
	if err != ErrInvalidToken {
		t.Fatalf("DecodeToken() error = %v, want %v", err, ErrInvalidToken)
	}
}
