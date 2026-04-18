# Rendezvous Candidate Validation Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make peer-provided rendezvous and transport candidates parseable, bounded, deduplicated, and class-filtered before they can be accepted or probed.

**Architecture:** Add a small reusable `pkg/candidate` policy package. Use it fail-closed at signed rendezvous claim validation, defensively in session candidate seeding, and entry-filtered in transport control messages so malformed controls do not clear healthy endpoints. Keep local candidate generation and native TCP bind overrides separate from peer-candidate policy.

**Tech Stack:** Go 1.26, `net/netip`, existing `pkg/rendezvous`, `pkg/session`, `pkg/transport`, `mise`.

---

## Policy Choices

- Candidate wire format is canonical `netip.AddrPort.String()`: `203.0.113.10:12345` or `[2001:db8::10]:12345`.
- Reject legacy `udp4:` and `udp6:` prefixes at the claim boundary.
- Maximum count stays `32`; maximum string length stays `128`.
- Reject empty, overlong, unparsable, non-canonical, duplicate, port-zero, unspecified, multicast, IPv6-zone, and loopback peer candidates.
- Allow public, RFC1918, CGNAT, ULA, and link-local non-loopback addresses. Tailscale candidate enablement remains a local advertisement policy, not an inbound parse policy.
- `DERPHOLE_FAKE_TRANSPORT=1` may allow loopback only in local test/fake transport parsing, never by default.
- Rendezvous claims reject the whole claim on any invalid candidate with `RejectClaimMalformed`.
- Ongoing transport control candidate updates drop invalid entries. If a non-empty update contains no valid candidates, ignore it rather than clearing existing endpoints.

## File Structure

- Create: `pkg/candidate/policy.go`
- Create: `pkg/candidate/policy_test.go`
- Modify: `pkg/rendezvous/state.go`
- Modify: `pkg/rendezvous/rendezvous_test.go`
- Modify: `pkg/rendezvous/durable_gate_test.go`
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_native_tcp.go`
- Modify: `pkg/session/session_test.go`
- Modify: `pkg/session/derptun_test.go`
- Modify: `pkg/transport/control.go`
- Modify: `pkg/transport/control_test.go`
- Modify: `pkg/transport/manager_test.go`

---

### Task 1: Shared Candidate Policy

**Files:**
- Create: `pkg/candidate/policy.go`
- Create: `pkg/candidate/policy_test.go`

- [ ] **Step 1: Add failing policy tests**

Create `pkg/candidate/policy_test.go`:

```go
package candidate

import (
	"net"
	"testing"
)

func TestValidateClaimStringsRejectsMalformedAndUnsafeCandidates(t *testing.T) {
	for _, value := range []string{
		"",
		"udp4:203.0.113.10:12345",
		"127.0.0.1:12345",
		"0.0.0.0:12345",
		"224.0.0.1:12345",
		"203.0.113.10:0",
		"203.0.113.10",
		"203.0.113.10:12345 ",
	} {
		if err := ValidateClaimStrings([]string{value}); err == nil {
			t.Fatalf("ValidateClaimStrings(%q) error = nil, want rejection", value)
		}
	}
}

func TestValidateClaimStringsRejectsDuplicateCanonicalEndpoint(t *testing.T) {
	if err := ValidateClaimStrings([]string{"203.0.113.10:12345", "203.0.113.10:12345"}); err == nil {
		t.Fatal("ValidateClaimStrings(duplicate) error = nil, want rejection")
	}
}

func TestParsePeerAddrsDropsInvalidUnsafeAndDuplicateCandidates(t *testing.T) {
	addrs := ParsePeerAddrs([]string{
		"127.0.0.1:1",
		"203.0.113.10:12345",
		"203.0.113.10:12345",
		"[fd7a:115c:a1e0::1]:41641",
		"bad",
	})
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2 (%v)", len(addrs), addrs)
	}
	if addrs[0].String() != "203.0.113.10:12345" {
		t.Fatalf("addrs[0] = %v, want 203.0.113.10:12345", addrs[0])
	}
	if addrs[1].String() != "[fd7a:115c:a1e0::1]:41641" {
		t.Fatalf("addrs[1] = %v, want fd7a ULA", addrs[1])
	}
}

func TestStringifyLocalAddrsCapsDeduplicatesAndSkipsUnsafe(t *testing.T) {
	input := make([]net.Addr, 0, MaxCount+2)
	input = append(input, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	for i := 0; i < MaxCount+1; i++ {
		input = append(input, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 10000 + i})
	}
	got := StringifyLocalAddrs(input)
	if len(got) != MaxCount {
		t.Fatalf("len(got) = %d, want %d", len(got), MaxCount)
	}
	if got[0] != "203.0.113.10:10000" {
		t.Fatalf("got[0] = %q, want canonical addr", got[0])
	}
}
```

- [ ] **Step 2: Run red policy tests**

Run:

```bash
go test ./pkg/candidate -run 'TestValidateClaimStrings|TestParsePeerAddrs|TestStringifyLocalAddrs' -count=1
```

Expected: FAIL because `pkg/candidate` does not exist.

- [ ] **Step 3: Implement policy package**

Create `pkg/candidate/policy.go`:

```go
package candidate

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

const MaxCount = 32
const MaxLength = 128

var ErrInvalid = errors.New("invalid candidate")

func ValidateClaimStrings(values []string) error {
	if len(values) > MaxCount {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ap, ok := parsePeerAddrPort(value)
		if !ok {
			return ErrInvalid
		}
		canonical := ap.String()
		if _, exists := seen[canonical]; exists {
			return ErrInvalid
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func ParsePeerAddrs(values []string) []net.Addr {
	return parseAddrs(values, parsePeerAddrPort)
}

func ParseLocalAddrs(values []string) []net.Addr {
	return parseAddrs(values, parseLocalAddrPort)
}

func StringifyLocalAddrs(addrs []net.Addr) []string {
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		ap, ok := addrPortFromNetAddr(addr)
		if !ok || !validLocalAddrPort(ap) {
			continue
		}
		canonical := ap.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
		if len(out) == MaxCount {
			break
		}
	}
	return out
}
```

Add unexported helpers in the same file:

```go
func parseAddrs(values []string, parse func(string) (netip.AddrPort, bool)) []net.Addr {
	out := make([]net.Addr, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ap, ok := parse(value)
		if !ok {
			continue
		}
		canonical := ap.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, net.UDPAddrFromAddrPort(ap))
		if len(out) == MaxCount {
			break
		}
	}
	return out
}

func parsePeerAddrPort(value string) (netip.AddrPort, bool) {
	if len(value) == 0 || len(value) > MaxLength {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil || ap.String() != value || !validPeerAddrPort(ap) {
		return netip.AddrPort{}, false
	}
	return ap, true
}

func parseLocalAddrPort(value string) (netip.AddrPort, bool) {
	if len(value) == 0 || len(value) > MaxLength {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil || ap.String() != value || !validLocalAddrPort(ap) {
		return netip.AddrPort{}, false
	}
	return ap, true
}

func validPeerAddrPort(ap netip.AddrPort) bool {
	addr := ap.Addr()
	return ap.Port() != 0 &&
		addr.IsValid() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast() &&
		!addr.IsLoopback()
}

func validLocalAddrPort(ap netip.AddrPort) bool {
	addr := ap.Addr()
	return ap.Port() != 0 &&
		addr.IsValid() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast() &&
		!addr.IsLoopback()
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort(), a.Port != 0 && a.IP != nil
	case *net.TCPAddr:
		return a.AddrPort(), a.Port != 0 && a.IP != nil
	default:
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return netip.AddrPort{}, false
		}
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ip, uint16(parsedPort)), true
	}
}
```

- [ ] **Step 4: Verify green**

Run:

```bash
go test ./pkg/candidate -count=1
```

Expected: PASS.

### Task 2: Rendezvous Claim Validation

**Files:**
- Modify: `pkg/rendezvous/state.go`
- Modify: `pkg/rendezvous/rendezvous_test.go`
- Modify: `pkg/rendezvous/durable_gate_test.go`

- [ ] **Step 1: Update fixtures and add red rendezvous tests**

In `pkg/rendezvous/rendezvous_test.go`, change `testClaim` candidates to:

```go
Candidates: []string{"203.0.113.10:12345", "[2001:db8::10]:12345"},
```

Append:

```go
func TestGateRejectsMalformedCandidateStrings(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)
	claim := testClaim(tok)
	claim.Candidates = []string{"udp4:203.0.113.10:12345"}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectClaimMalformed {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectClaimMalformed)
	}
}

func TestGateRejectsDuplicateCandidates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := testToken(now)
	gate := NewGate(tok)
	claim := testClaim(tok)
	claim.Candidates = []string{"203.0.113.10:12345", "203.0.113.10:12345"}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)

	decision, err := gate.Accept(now, claim)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Accept() error = %v, want ErrDenied", err)
	}
	if decision.Reject == nil || decision.Reject.Code != RejectClaimMalformed {
		t.Fatalf("Reject = %+v, want %q", decision.Reject, RejectClaimMalformed)
	}
}
```

In `pkg/rendezvous/durable_gate_test.go`, update any `udp4:` fixture candidates to canonical `203.0.113.10:12345`.

- [ ] **Step 2: Run red rendezvous tests**

Run:

```bash
go test ./pkg/rendezvous -run 'TestGateRejects.*Candidate|TestDurableGateRejects.*Candidate' -count=1
```

Expected: FAIL because current `validCandidates` only checks count, empty string, and length.

- [ ] **Step 3: Use shared claim validator**

Modify `pkg/rendezvous/state.go`:

```go
import "github.com/shayne/derphole/pkg/candidate"

const MaxClaimCandidates = candidate.MaxCount
const MaxCandidateLength = candidate.MaxLength

func validCandidates(candidates []string) bool {
	return candidate.ValidateClaimStrings(candidates) == nil
}
```

Keep existing MAC-first order in `validateClaimForToken`.

- [ ] **Step 4: Verify rendezvous green**

Run:

```bash
go test ./pkg/rendezvous -count=1
```

Expected: PASS.

### Task 3: Session Candidate Parsing And Seeding

**Files:**
- Modify: `pkg/session/external.go`
- Modify: `pkg/session/external_native_tcp.go`
- Modify: `pkg/session/session_test.go`
- Modify: `pkg/session/derptun_test.go`

- [ ] **Step 1: Add failing session tests**

Add tests in `pkg/session/session_test.go` for:

```go
func TestSeedAcceptedDecisionCandidatesFiltersUnsafeCandidates(t *testing.T)
func TestSeedAcceptedClaimCandidatesFiltersUnsafeCandidates(t *testing.T)
func TestParseRemoteCandidateStringsRejectsLoopbackWithoutFakeTransport(t *testing.T)
func TestParseRemoteCandidateStringsAllowsLoopbackForFakeTransport(t *testing.T)
```

Use decisions/claims with candidates:

```go
[]string{"127.0.0.1:1", "203.0.113.10:12345", "203.0.113.10:12345", "bad"}
```

Assert only `203.0.113.10:12345` is seeded or parsed without fake transport. In the fake-transport test, set `DERPHOLE_FAKE_TRANSPORT=1` and assert loopback is accepted only in the local/fake parser.

In `pkg/session/derptun_test.go`, change `derptunTestClaim` and `derptunClaimForClient` fixture candidates from `udp4:203.0.113.10:12345` to `203.0.113.10:12345`.

- [ ] **Step 2: Run red session tests**

Run:

```bash
go test ./pkg/session -run 'TestSeedAccepted.*Candidates|TestParseRemoteCandidateStrings|TestDerptun.*Claim|TestHandleDerptunServeClaim' -count=1
```

Expected: FAIL because current `parseCandidateStrings` has no peer/local policy split.

- [ ] **Step 3: Split local and peer parsing**

Modify `pkg/session/external.go`:

```go
func parseCandidateStrings(values []string) []net.Addr {
	return candidate.ParseLocalAddrs(values)
}

func parseRemoteCandidateStrings(values []string) []net.Addr {
	return candidate.ParsePeerAddrs(values)
}
```

Change `seedAcceptedDecisionCandidates` and `seedAcceptedClaimCandidates` to call `parseRemoteCandidateStrings`.

Change direct UDP remote candidate parsing from `decision.Accept.Candidates` and `env.Claim.Candidates` to use `parseRemoteCandidateStrings`.

Modify `pkg/session/external_native_tcp.go` so `externalNativeTCPEnvAddrs` keeps local parsing. Explicit local test binds such as `127.0.0.1:8321` must continue to work.

- [ ] **Step 4: Verify session green**

Run:

```bash
go test ./pkg/session -run 'TestSeedAccepted.*Candidates|TestParseRemoteCandidateStrings|TestPublicProbeCandidateAllowed|TestPublicInitialProbeCandidates|TestListenExternalNativeTCPOnCandidates|TestDerptun' -count=1
```

Expected: PASS.

### Task 4: Transport Control Candidate Use

**Files:**
- Modify: `pkg/transport/control.go`
- Modify: `pkg/transport/control_test.go`
- Modify: `pkg/transport/manager_test.go`

- [ ] **Step 1: Add failing transport tests**

Modify `pkg/transport/control_test.go`:

```go
func TestParseCandidateAddrsDropsUnsafeAndDeduplicates(t *testing.T) {
	addrs := parseCandidateAddrs([]string{
		"127.0.0.1:1",
		"100.64.0.10:1234",
		"100.64.0.10:1234",
		"bad",
	})
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1 (%v)", len(addrs), addrs)
	}
	if addrs[0].String() != "100.64.0.10:1234" {
		t.Fatalf("addr = %v, want 100.64.0.10:1234", addrs[0])
	}
}
```

Modify `pkg/transport/manager_test.go` to add:

```go
func TestManagerIgnoresInvalidOnlyCandidateControlWithoutClearingEndpoint(t *testing.T)
func TestManagerDropsUnsafePeerCandidateControl(t *testing.T)
```

Set up a manager with an existing direct endpoint, deliver `ControlCandidates{Candidates: []string{"bad", "127.0.0.1:1"}}`, and assert the existing endpoint remains unchanged.

- [ ] **Step 2: Run red transport tests**

Run:

```bash
go test ./pkg/transport -run 'TestParseCandidateAddrs|TestManager.*Candidate' -count=1
```

Expected: FAIL because invalid-only controls currently parse to an empty slice and can clear endpoint state.

- [ ] **Step 3: Apply peer policy in transport controls**

Modify `pkg/transport/control.go`:

```go
func parseCandidateAddrs(values []string) []net.Addr {
	return candidate.ParsePeerAddrs(values)
}

func stringifyCandidates(addrs []net.Addr) []string {
	return candidate.StringifyLocalAddrs(addrs)
}
```

In `handleControl`, ignore non-empty `ControlCandidates` messages when parsing returns zero valid addresses. Keep empty candidate controls meaningful only when the raw candidate list is empty.

- [ ] **Step 4: Verify transport green**

Run:

```bash
go test ./pkg/transport -count=1
```

Expected: PASS.

### Task 5: Full Verification And Live Smoke

**Files:**
- Test: `pkg/candidate`
- Test: `pkg/rendezvous`
- Test: `pkg/session`
- Test: `pkg/transport`

- [ ] **Step 1: Run focused package suite**

Run:

```bash
go test ./pkg/candidate ./pkg/rendezvous ./pkg/session ./pkg/transport -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full local verification**

Run:

```bash
mise run test
mise run vet
```

Expected: both pass.

- [ ] **Step 3: Run live no-Tailscale smoke**

Run:

```bash
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote
REMOTE_HOST=ktzlxc DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 mise run smoke-remote-share
REMOTE_HOST=ktzlxc mise run smoke-remote-derptun
```

Expected: all pass with `connected-direct` evidence.

- [ ] **Step 4: Final repository gate**

Run:

```bash
mise run check
```

Expected: PASS.
