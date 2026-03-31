package quicpath

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	quic "github.com/quic-go/quic-go"
)

const ALPN = "derpcat-quic/1"
const ServerName = "derpcat"
const MaxIncomingStreams = 64

var ErrPeerIdentityMismatch = errors.New("quic peer identity mismatch")

type SessionIdentity struct {
	Certificate tls.Certificate
	Public      [32]byte
}

func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:       5 * time.Second,
		MaxIdleTimeout:        30 * time.Second,
		HandshakeIdleTimeout:  10 * time.Second,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       false,
	}
}

func DefaultTLSConfig(cert tls.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
	}
}

func DefaultClientTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		ServerName:         ServerName,
		InsecureSkipVerify: true,
	}
}

func ClientTLSConfig(identity SessionIdentity, expectedPeer [32]byte) *tls.Config {
	cfg := DefaultClientTLSConfig()
	cfg.Certificates = []tls.Certificate{identity.Certificate}
	cfg.VerifyPeerCertificate = verifyPinnedPeer(expectedPeer)
	return cfg
}

func ServerTLSConfig(identity SessionIdentity, expectedPeer [32]byte) *tls.Config {
	cfg := DefaultTLSConfig(identity.Certificate, ServerName)
	cfg.ClientAuth = tls.RequireAnyClientCert
	cfg.VerifyPeerCertificate = verifyPinnedPeer(expectedPeer)
	return cfg
}

func GenerateSessionIdentity() (SessionIdentity, error) {
	cert, pub, err := generateSelfSignedCertificate()
	if err != nil {
		return SessionIdentity{}, err
	}
	return SessionIdentity{
		Certificate: cert,
		Public:      pub,
	}, nil
}

func GenerateSelfSignedCertificate() (tls.Certificate, error) {
	cert, _, err := generateSelfSignedCertificate()
	return cert, err
}

func generateSelfSignedCertificate() (tls.Certificate, [32]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	var public [32]byte
	copy(public[:], priv.Public().(ed25519.PublicKey))

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: ServerName,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{ServerName},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	return cert, public, nil
}

func verifyPinnedPeer(expected [32]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return ErrPeerIdentityMismatch
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || len(pub) != len(expected) {
			return ErrPeerIdentityMismatch
		}
		var got [32]byte
		copy(got[:], pub)
		if got != expected {
			return ErrPeerIdentityMismatch
		}
		return nil
	}
}
