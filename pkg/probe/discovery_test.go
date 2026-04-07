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

func TestObservePunchAddrsReturnsPacketSources(t *testing.T) {
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

	if _, err := b.WriteTo([]byte(defaultPunchPayload), a.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := ObservePunchAddrs(ctx, []net.PacketConn{a}, 100*time.Millisecond)
	gotStrings := CandidateStrings(got)
	if len(gotStrings) != 1 || gotStrings[0] != b.LocalAddr().String() {
		t.Fatalf("ObservePunchAddrs() = %v, want %s", gotStrings, b.LocalAddr())
	}
}

func TestObservePunchAddrsByConnPreservesSocketAssociation(t *testing.T) {
	receivers := make([]net.PacketConn, 2)
	for i := range receivers {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		receivers[i] = conn
	}
	senders := make([]net.PacketConn, 2)
	for i := range senders {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		senders[i] = conn
		if _, err := conn.WriteTo([]byte(defaultPunchPayload), receivers[i].LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := ObservePunchAddrsByConn(ctx, receivers, 100*time.Millisecond)
	if len(got) != len(receivers) {
		t.Fatalf("len(ObservePunchAddrsByConn()) = %d, want %d", len(got), len(receivers))
	}
	for i := range got {
		gotStrings := CandidateStrings(got[i])
		if len(gotStrings) != 1 || gotStrings[0] != senders[i].LocalAddr().String() {
			t.Fatalf("ObservePunchAddrsByConn()[%d] = %v, want %s", i, gotStrings, senders[i].LocalAddr())
		}
	}
}

func TestObservePunchAddrsByConnReturnsAfterAllConnsObserved(t *testing.T) {
	receivers := make([]net.PacketConn, 2)
	for i := range receivers {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		receivers[i] = conn
	}
	senders := make([]net.PacketConn, 2)
	for i := range senders {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		senders[i] = conn
		if _, err := conn.WriteTo([]byte(defaultPunchPayload), receivers[i].LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}

	startedAt := time.Now()
	got := ObservePunchAddrsByConn(context.Background(), receivers, 500*time.Millisecond)
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("ObservePunchAddrsByConn() took %s after all conns were observed", elapsed)
	}
	if len(got) != len(receivers) {
		t.Fatalf("len(ObservePunchAddrsByConn()) = %d, want %d", len(got), len(receivers))
	}
}

func TestCandidateStringsInOrderPreservesInputOrder(t *testing.T) {
	raw := []net.Addr{
		&net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 2000},
		&net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1000},
		&net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 2000},
	}
	got := CandidateStringsInOrder(raw)
	want := []string{"203.0.113.2:2000", "203.0.113.1:1000"}
	if len(got) != len(want) {
		t.Fatalf("CandidateStringsInOrder() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CandidateStringsInOrder() = %v, want %v", got, want)
		}
	}
}
