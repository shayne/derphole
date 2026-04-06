package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestPunchDirectLoopback(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := PunchDirect(ctx, a, b.LocalAddr().String(), b, a.LocalAddr().String())
	if err != nil {
		t.Fatalf("PunchDirect() error = %v", err)
	}
	if !got.Direct {
		t.Fatal("PunchDirect() direct = false, want true")
	}
}

func TestDiscoverCandidatesIncludesLocalAndTraversalCandidates(t *testing.T) {
	oldFetch := fetchDERPMap
	oldGather := gatherTraversalPackets
	oldInterfaces := interfaceAddrs
	defer func() {
		fetchDERPMap = oldFetch
		gatherTraversalPackets = oldGather
		interfaceAddrs = oldInterfaces
	}()

	fetchDERPMap = func(ctx context.Context, url string) (*tailcfg.DERPMap, error) {
		return &tailcfg.DERPMap{}, nil
	}
	gatherTraversalPackets = func(ctx context.Context, conn net.PacketConn, dm *tailcfg.DERPMap, mapped func() (netip.AddrPort, bool)) ([]string, error) {
		return []string{"203.0.113.7:4242"}, nil
	}
	interfaceAddrs = func() ([]net.Addr, error) {
		return nil, nil
	}

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := DiscoverCandidates(ctx, conn)
	if err != nil {
		t.Fatalf("DiscoverCandidates() error = %v", err)
	}

	gotStrings := CandidateStrings(got)
	if len(gotStrings) != 2 {
		t.Fatalf("DiscoverCandidates() = %v, want 2 candidates", gotStrings)
	}
	wantLocal := fmt.Sprintf("127.0.0.1:%d", conn.LocalAddr().(*net.UDPAddr).Port)
	if gotStrings[0] != wantLocal && gotStrings[1] != wantLocal {
		t.Fatalf("DiscoverCandidates() = %v, want local candidate %q", gotStrings, wantLocal)
	}
	if gotStrings[0] != "203.0.113.7:4242" && gotStrings[1] != "203.0.113.7:4242" {
		t.Fatalf("DiscoverCandidates() = %v, want traversal candidate", gotStrings)
	}
}
