package traversal

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
)

func TestProbePromotesDirectPath(t *testing.T) {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := ProbeDirect(ctx, a, b.LocalAddr().String(), b, a.LocalAddr().String())
	if err != nil {
		t.Fatalf("ProbeDirect() error = %v", err)
	}
	if !result.Direct {
		t.Fatalf("Direct = false, want true")
	}
}

func TestProbeFallsBackWhenNoPeerResponds(t *testing.T) {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	result, err := ProbeDirect(ctx, a, "127.0.0.1:9", nil, "")
	if err != nil {
		t.Fatalf("ProbeDirect() error = %v", err)
	}
	if result.Direct {
		t.Fatalf("Direct = true, want false")
	}
}

func TestGatherCandidatesRejectsNilDERPMap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := GatherCandidates(ctx, nil, nil, nil); err == nil {
		t.Fatal("GatherCandidates() error = nil, want non-nil")
	}
}

func TestGatherCandidatesUsesProvidedProbeConnPort(t *testing.T) {
	stunAddr, cleanup := stuntest.Serve(t)
	defer cleanup()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := GatherCandidates(ctx, conn, stuntest.DERPMapOf(stunAddr.String()), nil)
	if err != nil {
		t.Fatalf("GatherCandidates() error = %v", err)
	}

	want := conn.LocalAddr().String()
	if !containsCandidate(got, want) {
		t.Fatalf("GatherCandidates() = %v, want candidate %q from provided probe conn", got, want)
	}
}

func TestGatherCandidatesFromSTUNPacketsUsesInjectedPackets(t *testing.T) {
	stunAddr, cleanup := stuntest.Serve(t)
	defer cleanup()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()

	packetCh := make(chan STUNPacket, 32)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64<<10)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				return
			}
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if !stun.Is(buf[:n]) {
				continue
			}
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			addrIP, ok := netip.AddrFromSlice(udpAddr.IP)
			if !ok {
				continue
			}
			packetCh <- STUNPacket{
				Payload: append([]byte(nil), buf[:n]...),
				Addr:    netip.AddrPortFrom(addrIP.Unmap(), uint16(udpAddr.Port)),
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := GatherCandidatesFromSTUNPackets(ctx, conn, stuntest.DERPMapOf(stunAddr.String()), nil, packetCh)
	if err != nil {
		t.Fatalf("GatherCandidatesFromSTUNPackets() error = %v", err)
	}

	want := conn.LocalAddr().String()
	if !containsCandidate(got, want) {
		t.Fatalf("GatherCandidatesFromSTUNPackets() = %v, want candidate %q from provided probe conn", got, want)
	}

	_ = conn.Close()
	<-readDone
}

func TestGatherCandidatesMergesMappedEndpoint(t *testing.T) {
	got := gatherCandidates(
		[]netip.AddrPort{netip.MustParseAddrPort("100.64.0.10:1000")},
		[]netip.AddrPort{netip.MustParseAddrPort("[fd7a:115c:a1e0::1]:2000")},
		func() (netip.AddrPort, bool) {
			return netip.MustParseAddrPort("100.64.0.11:4242"), true
		},
	)

	want := []string{"100.64.0.10:1000", "[fd7a:115c:a1e0::1]:2000", "100.64.0.11:4242"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGatherCandidatesSkipsDuplicateMappedEndpoint(t *testing.T) {
	got := gatherCandidates(
		[]netip.AddrPort{netip.MustParseAddrPort("100.64.0.10:4242")},
		nil,
		func() (netip.AddrPort, bool) {
			return netip.MustParseAddrPort("100.64.0.10:4242"), true
		},
	)

	want := []string{"100.64.0.10:4242"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAppendMappedCandidateRejectsInvalidEndpoint(t *testing.T) {
	candidates := []string{"100.64.0.10:4242"}
	got := appendMappedCandidate(candidates, netip.AddrPort{}, true)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
}

func containsCandidate(candidates []string, want string) bool {
	for _, candidate := range candidates {
		if candidate == want {
			return true
		}
	}
	return false
}
