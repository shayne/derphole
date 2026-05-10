// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"crypto/x509"
	"testing"
)

func TestDefaultQUICConfigUsesConservativeInitialPacketSize(t *testing.T) {
	cfg := DefaultQUICConfig()
	if got, want := cfg.InitialPacketSize, uint16(1200); got != want {
		t.Fatalf("InitialPacketSize = %d, want %d", got, want)
	}
}

func TestDefaultQUICConfigKeepsPathMTUDiscoveryEnabled(t *testing.T) {
	cfg := DefaultQUICConfig()
	if cfg.DisablePathMTUDiscovery {
		t.Fatal("DisablePathMTUDiscovery = true, want false")
	}
}

func TestDefaultQUICConfigEnablesQlogTracerFromEnv(t *testing.T) {
	t.Setenv("DERPHOLE_QLOG_DIR", t.TempDir())

	cfg := DefaultQUICConfig()
	if cfg.Tracer == nil {
		t.Fatal("Tracer = nil, want qlog tracer from DERPHOLE_QLOG_DIR")
	}
}

func TestDefaultQUICConfigEnablesMetricsTracerFromEnv(t *testing.T) {
	t.Setenv("DERPHOLE_QUIC_METRICS_DIR", t.TempDir())

	cfg := DefaultQUICConfig()
	if cfg.Tracer == nil {
		t.Fatal("Tracer = nil, want metrics tracer from DERPHOLE_QUIC_METRICS_DIR")
	}
}

func TestGenerateSelfSignedCertificateReturnsUsableCertificate(t *testing.T) {
	cert, err := GenerateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertificate() error = %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if parsed.Subject.CommonName != ServerName {
		t.Fatalf("CommonName = %q, want %q", parsed.Subject.CommonName, ServerName)
	}
}
