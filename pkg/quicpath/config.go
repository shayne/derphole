package quicpath

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const ALPN = "derphole-quic/1"
const ServerName = "derphole"
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
		InitialPacketSize:     1200,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       false,
		Tracer:                tracerFromEnv(),
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
	identity, err := SessionIdentityFromEd25519PrivateKey(priv, time.Now())
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	return identity.Certificate, identity.Public, nil
}

func SessionIdentityFromEd25519PrivateKey(priv ed25519.PrivateKey, now time.Time) (SessionIdentity, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SessionIdentity{}, fmt.Errorf("ed25519 private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return SessionIdentity{}, ErrPeerIdentityMismatch
	}
	var public [32]byte
	copy(public[:], pub)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return SessionIdentity{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: ServerName,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{ServerName},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return SessionIdentity{}, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return SessionIdentity{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return SessionIdentity{}, err
	}
	return SessionIdentity{Certificate: cert, Public: public}, nil
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

func qlogTracerFromEnv() func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	dir := os.Getenv("DERPHOLE_QLOG_DIR")
	if dir == "" {
		return nil
	}
	return func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		perspective := "server"
		if isClient {
			perspective = "client"
		}
		path := filepath.Join(dir, fmt.Sprintf("derphole-%s-%s.qlog", connID, perspective))
		f, err := os.Create(path)
		if err != nil {
			return nil
		}
		trace := qlogwriter.NewConnectionFileSeq(f, isClient, connID, []string{qlog.EventSchema})
		go trace.Run()
		return trace
	}
}

func tracerFromEnv() func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	if trace := metricsTracerFromEnv(); trace != nil {
		return trace
	}
	return qlogTracerFromEnv()
}
