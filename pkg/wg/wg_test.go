package wg

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestDeriveAddressesIsDeterministic(t *testing.T) {
	var sessionID [16]byte
	sessionID[0] = 7

	aPrefix, aListener, aSender := DeriveAddresses(sessionID)
	bPrefix, bListener, bSender := DeriveAddresses(sessionID)

	if aPrefix != bPrefix || aListener != bListener || aSender != bSender {
		t.Fatalf("DeriveAddresses() is not deterministic: %v %v %v vs %v %v %v", aPrefix, aListener, aSender, bPrefix, bListener, bSender)
	}
	if aPrefix.Bits() != 64 {
		t.Fatalf("prefix bits = %d, want 64", aPrefix.Bits())
	}
	if got := aPrefix.Addr().As16()[0]; got != 0xfd {
		t.Fatalf("prefix first byte = 0x%x, want fd", got)
	}
	if !aPrefix.Contains(aListener) || !aPrefix.Contains(aSender) {
		t.Fatalf("derived addresses %v %v not in prefix %v", aListener, aSender, aPrefix)
	}
	if aListener == aSender {
		t.Fatal("listener and sender addresses are identical")
	}

	var otherSessionID [16]byte
	otherSessionID[0] = 8
	otherPrefix, otherListener, otherSender := DeriveAddresses(otherSessionID)
	if aPrefix == otherPrefix && aListener == otherListener && aSender == otherSender {
		t.Fatal("different session IDs derived identical addresses")
	}
}

func TestMemoryTransportExchangesPackets(t *testing.T) {
	a, b := NewMemoryTransportPair()

	if err := a.Send([]byte("ping")); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := b.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("Receive() = %q, want ping", got)
	}
}

func TestMemoryTransportReceiveRespectsContext(t *testing.T) {
	_, b := NewMemoryTransportPair()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.Receive(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive() error = %v, want context.Canceled", err)
	}
}

func TestNewNodeStoresConfig(t *testing.T) {
	cfg := NodeConfig{
		ListenAddr: netip.MustParseAddr("fd00::1"),
		PeerAddr:   netip.MustParseAddr("fd00::2"),
	}

	node := NewNode(cfg)
	if node == nil {
		t.Fatal("NewNode() = nil, want node")
	}
	if node.Config != cfg {
		t.Fatalf("node.Config = %+v, want %+v", node.Config, cfg)
	}
}
