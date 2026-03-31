package transport

import (
	"net"
	"testing"
)

func TestParseCandidateAddrsCapsOversizedInput(t *testing.T) {
	raw := make([]string, maxControlCandidates+5)
	for i := range raw {
		raw[i] = "127.0.0.1:1234"
	}

	addrs := parseCandidateAddrs(raw)
	if got, want := len(addrs), maxControlCandidates; got != want {
		t.Fatalf("len(addrs) = %d, want %d", got, want)
	}
}

func TestStringifyCandidatesCapsAndSkipsOversized(t *testing.T) {
	addrs := make([]net.Addr, 0, maxControlCandidates+2)
	for i := 0; i < maxControlCandidates+1; i++ {
		addrs = append(addrs, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + i})
	}
	addrs = append(addrs, oversizedAddr("x"))

	raw := stringifyCandidates(addrs)
	if got, want := len(raw), maxControlCandidates; got != want {
		t.Fatalf("len(raw) = %d, want %d", got, want)
	}
	for _, candidate := range raw {
		if len(candidate) > maxControlCandidateLength {
			t.Fatalf("candidate %q exceeds max length %d", candidate, maxControlCandidateLength)
		}
	}
}

type oversizedAddr string

func (a oversizedAddr) Network() string { return "udp" }

func (a oversizedAddr) String() string {
	buf := make([]byte, maxControlCandidateLength+1)
	for i := range buf {
		buf[i] = 'a'
	}
	return string(buf)
}
