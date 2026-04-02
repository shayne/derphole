package quicpath

import "testing"

func TestDefaultQUICConfigUsesConservativeInitialPacketSize(t *testing.T) {
	cfg := DefaultQUICConfig()
	if got, want := cfg.InitialPacketSize, uint16(1200); got != want {
		t.Fatalf("InitialPacketSize = %d, want %d", got, want)
	}
}
