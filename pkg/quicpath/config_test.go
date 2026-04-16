package quicpath

import "testing"

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
