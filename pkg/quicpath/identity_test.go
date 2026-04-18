package quicpath

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateSessionIdentityMatchesCertificatePublicKey(t *testing.T) {
	identity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity() error = %v", err)
	}

	if len(identity.Certificate.Certificate) != 1 {
		t.Fatalf("certificate chain length = %d, want 1", len(identity.Certificate.Certificate))
	}
	cert, err := x509.ParseCertificate(identity.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want ed25519.PublicKey", cert.PublicKey)
	}
	var want [32]byte
	copy(want[:], pub)
	if identity.Public != want {
		t.Fatalf("identity public = %x, want %x", identity.Public, want)
	}
}

func TestPinnedClientTLSConfigRejectsUnexpectedPeer(t *testing.T) {
	serverIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}
	wrongPeer, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(wrong) error = %v", err)
	}

	cfg := ClientTLSConfig(clientIdentity, wrongPeer.Public)
	if err := cfg.VerifyPeerCertificate(serverIdentity.Certificate.Certificate, nil); err == nil {
		t.Fatal("VerifyPeerCertificate() error = nil, want mismatch failure")
	}
}

func TestPinnedServerTLSConfigRequiresExpectedClient(t *testing.T) {
	serverIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}
	wrongPeer, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(wrong) error = %v", err)
	}

	cfg := ServerTLSConfig(serverIdentity, wrongPeer.Public)
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("ClientAuth = %v, want %v", cfg.ClientAuth, tls.RequireAnyClientCert)
	}
	if err := cfg.VerifyPeerCertificate(clientIdentity.Certificate.Certificate, nil); err == nil {
		t.Fatal("VerifyPeerCertificate() error = nil, want mismatch failure")
	}
}

func TestSessionIdentityFromEd25519PrivateKeyIsStable(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)

	first, err := SessionIdentityFromEd25519PrivateKey(priv, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("SessionIdentityFromEd25519PrivateKey(first) error = %v", err)
	}
	second, err := SessionIdentityFromEd25519PrivateKey(priv, time.Unix(200, 0))
	if err != nil {
		t.Fatalf("SessionIdentityFromEd25519PrivateKey(second) error = %v", err)
	}

	var want [32]byte
	copy(want[:], priv.Public().(ed25519.PublicKey))
	if first.Public != want {
		t.Fatalf("first.Public = %x, want %x", first.Public, want)
	}
	if second.Public != want {
		t.Fatalf("second.Public = %x, want %x", second.Public, want)
	}
	if len(first.Certificate.Certificate) == 0 || len(second.Certificate.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
}

func TestSessionIdentityFromEd25519PrivateKeyRejectsWrongLength(t *testing.T) {
	_, err := SessionIdentityFromEd25519PrivateKey(ed25519.PrivateKey(bytes.Repeat([]byte{1}, 12)), time.Now())
	if err == nil {
		t.Fatal("SessionIdentityFromEd25519PrivateKey() error = nil, want error")
	}
}
