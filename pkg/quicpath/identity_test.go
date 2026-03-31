package quicpath

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"testing"
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
