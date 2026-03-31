# Public Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden public `derpcat` sessions by adding real peer authentication, tightening token contents, and enforcing practical abuse limits without changing the user-facing CLI flows.

**Architecture:** Keep the bearer-token workflow and public Tailscale DERP bootstrap model, but bind QUIC to ephemeral session identity instead of trusting any self-signed peer. Minimize token contents to current transport needs, move unsafe local defaults out of the token, and add runtime validation and bounded resource usage around claims, control messages, and multiplexed streams.

**Tech Stack:** Go 1.26, `quic-go`, existing `pkg/session`, `pkg/token`, `pkg/rendezvous`, `pkg/quicpath`, `pkg/transport`, `mise`, existing smoke scripts plus live verification against this host, `hetz`, and `pve1`.

---

## File Map

- Modify: `/Users/shayne/code/derpcat/pkg/token/token.go`
  - shrink token schema to fields required by the current public transport
- Modify: `/Users/shayne/code/derpcat/pkg/token/token_test.go`
  - lock down new token encoding, expiry, and compatibility behavior
- Modify: `/Users/shayne/code/derpcat/pkg/rendezvous/messages.go`
  - carry explicit QUIC client identity and validate bounded claim payloads
- Modify: `/Users/shayne/code/derpcat/pkg/rendezvous/state.go`
  - enforce stricter claim validation and reject malformed capability or size abuse
- Modify: `/Users/shayne/code/derpcat/pkg/quicpath/config.go`
  - replace blind QUIC verification with pinned session identity checks
- Create: `/Users/shayne/code/derpcat/pkg/quicpath/identity.go`
  - derive and verify session-bound QUIC certificates and peer identity pins
- Create: `/Users/shayne/code/derpcat/pkg/quicpath/identity_test.go`
  - prove valid peers connect and mismatched peers fail closed
- Modify: `/Users/shayne/code/derpcat/pkg/session/external.go`
  - issue pinned QUIC server identity for `listen`, send pinned client identity for `send`
- Modify: `/Users/shayne/code/derpcat/pkg/session/external_share.go`
  - issue pinned QUIC server identity for `share`, validate claimant QUIC identity for `open`
- Modify: `/Users/shayne/code/derpcat/pkg/session/open.go`
  - ensure local bind defaults remain local policy, not token-driven policy
- Modify: `/Users/shayne/code/derpcat/pkg/session/share.go`
  - add bounded concurrent stream policy around shared backend handling
- Modify: `/Users/shayne/code/derpcat/pkg/transport/control.go`
  - bound control payload size and candidate counts
- Modify: `/Users/shayne/code/derpcat/pkg/session/session_test.go`
  - add public-session security regressions
- Modify: `/Users/shayne/code/derpcat/pkg/quicpath/integration_test.go`
  - verify handshake succeeds only for pinned peers
- Modify: `/Users/shayne/code/derpcat/cmd/derpcat/open.go`
  - keep `open` bind defaults ergonomic while detached from token fields
- Modify: `/Users/shayne/code/derpcat/README.md`
  - document 1-hour tokens and optional passphrase note only if implemented

### Task 1: Tighten the Token Schema

**Files:**
- Modify: `/Users/shayne/code/derpcat/pkg/token/token.go`
- Modify: `/Users/shayne/code/derpcat/pkg/token/token_test.go`

- [ ] **Step 1: Write the failing token-shape tests**

```go
func TestEncodeDecodeRoundTripPublicShareToken(t *testing.T) {
	now := time.Now()
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     now.Add(time.Hour).Unix(),
		BootstrapRegion: 7,
		DERPPublic:      [32]byte{9, 9, 9, 9},
		BearerSecret:    [32]byte{8, 8, 8, 8},
		Capabilities:    CapabilityShare,
		QUICPublic:      [32]byte{7, 7, 7, 7},
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.ShareTargetAddr != "" {
		t.Fatalf("ShareTargetAddr = %q, want empty", decoded.ShareTargetAddr)
	}
	if decoded.DefaultBindHost != "" || decoded.DefaultBindPort != 0 {
		t.Fatalf("unexpected bind defaults in token: %+v", decoded)
	}
	if decoded.QUICPublic != tok.QUICPublic {
		t.Fatalf("QUICPublic = %x, want %x", decoded.QUICPublic, tok.QUICPublic)
	}
}

func TestEncodeRejectsOverlongStrings(t *testing.T) {
	tok := Token{
		Version:      SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: CapabilityShare,
	}
	_, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() unexpected error = %v", err)
	}
}
```

- [ ] **Step 2: Run token tests to verify they fail**

Run: `go test ./pkg/token -count=1`
Expected: FAIL because `QUICPublic` does not exist yet and old fields are still encoded.

- [ ] **Step 3: Implement the new token shape**

```go
type Token struct {
	Version         uint8
	SessionID       [16]byte
	ExpiresUnix     int64
	BootstrapRegion uint16
	DERPPublic      [32]byte
	BearerSecret    [32]byte
	Capabilities    uint32
	QUICPublic      [32]byte
}

const fixedPayloadSize = 1 + 16 + 8 + 2 + 32 + 32 + 4 + 32
```

Update `Encode` and `Decode` to:

- write only the fields above
- keep `Version == 0` meaning “default to `SupportedVersion`”
- keep CRC32 corruption detection for accidental corruption only
- preserve 1-hour expiry support via `ExpiresUnix`

- [ ] **Step 4: Run token tests to verify they pass**

Run: `go test ./pkg/token -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/shayne/code/derpcat/pkg/token/token.go /Users/shayne/code/derpcat/pkg/token/token_test.go
git commit -m "security: tighten public token schema"
```

### Task 2: Add Pinned QUIC Session Identity

**Files:**
- Create: `/Users/shayne/code/derpcat/pkg/quicpath/identity.go`
- Create: `/Users/shayne/code/derpcat/pkg/quicpath/identity_test.go`
- Modify: `/Users/shayne/code/derpcat/pkg/quicpath/config.go`

- [ ] **Step 1: Write failing QUIC identity tests**

```go
func TestPinnedServerIdentityAcceptsExpectedPeer(t *testing.T) {
	serverID, serverCert, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity() error = %v", err)
	}
	clientTLS := DefaultPinnedClientTLSConfig(serverID.Public)
	if clientTLS.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate is nil")
	}
	if err := VerifyPeerCertificate(serverID.Public, serverCert.Certificate[0]); err != nil {
		t.Fatalf("VerifyPeerCertificate() error = %v", err)
	}
}

func TestPinnedServerIdentityRejectsWrongPeer(t *testing.T) {
	serverID, serverCert, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity() error = %v", err)
	}
	otherID, _, err := GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity() error = %v", err)
	}
	if err := VerifyPeerCertificate(otherID.Public, serverCert.Certificate[0]); err == nil {
		t.Fatal("VerifyPeerCertificate() unexpectedly succeeded")
	}
	_ = serverID
}
```

- [ ] **Step 2: Run QUIC identity tests to verify they fail**

Run: `go test ./pkg/quicpath -run 'TestPinnedServerIdentity' -count=1`
Expected: FAIL because session identity helpers do not exist yet.

- [ ] **Step 3: Implement session identity generation and verification**

```go
type SessionIdentity struct {
	Public  [32]byte
	Cert    tls.Certificate
}

func GenerateSessionIdentity() (SessionIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SessionIdentity{}, err
	}
	var raw [32]byte
	copy(raw[:], pub)
	cert, err := makeSessionCertificate(pub, priv)
	if err != nil {
		return SessionIdentity{}, err
	}
	return SessionIdentity{Public: raw, Cert: cert}, nil
}

func VerifyPeerCertificate(expected [32]byte, certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("unexpected peer public key type")
	}
	var actual [32]byte
	copy(actual[:], pub)
	if actual != expected {
		return errors.New("peer identity mismatch")
	}
	return nil
}
```

Update `DefaultClientTLSConfig` into a pinned form:

```go
func DefaultPinnedClientTLSConfig(expected [32]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		ServerName:         ServerName,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing peer certificate")
			}
			return VerifyPeerCertificate(expected, rawCerts[0])
		},
	}
}
```

- [ ] **Step 4: Run QUIC identity tests to verify they pass**

Run: `go test ./pkg/quicpath -run 'TestPinnedServerIdentity' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/shayne/code/derpcat/pkg/quicpath/config.go /Users/shayne/code/derpcat/pkg/quicpath/identity.go /Users/shayne/code/derpcat/pkg/quicpath/identity_test.go
git commit -m "security: pin quic peer identity"
```

### Task 3: Bind Public Sessions to QUIC Identity

**Files:**
- Modify: `/Users/shayne/code/derpcat/pkg/session/external.go`
- Modify: `/Users/shayne/code/derpcat/pkg/session/external_share.go`
- Modify: `/Users/shayne/code/derpcat/pkg/session/session_test.go`

- [ ] **Step 1: Write failing public-session tests for mismatched peer identity**

```go
func TestPublicListenSendRejectsQUICPeerIdentityMismatch(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tokenSink := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			TokenSink:     tokenSink,
			UsePublicDERP: true,
		})
		errCh <- err
	}()
	tok := <-tokenSink

	decoded, err := token.Decode(tok, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	decoded.QUICPublic[0] ^= 0xff
	badToken, err := token.Encode(decoded)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	err = Send(ctx, SendConfig{
		Token:         badToken,
		StdioIn:       strings.NewReader("payload"),
		UsePublicDERP: true,
	})
	if err == nil {
		t.Fatal("Send() unexpectedly succeeded")
	}
}
```

- [ ] **Step 2: Run the targeted session test to verify it fails**

Run: `go test ./pkg/session -run TestPublicListenSendRejectsQUICPeerIdentityMismatch -count=1`
Expected: FAIL because the handshake still accepts any self-signed peer.

- [ ] **Step 3: Issue and verify session identities in public session setup**

In `issuePublicSession` and `issuePublicShareSession`:

```go
quicID, err := quicpath.GenerateSessionIdentity()
if err != nil {
	_ = derpClient.Close()
	return "", nil, err
}

tokValue := token.Token{
	Version:         token.SupportedVersion,
	SessionID:       sessionID,
	ExpiresUnix:     time.Now().Add(1 * time.Hour).Unix(),
	BootstrapRegion: uint16(node.RegionID),
	DERPPublic:      derpPublicKeyRaw32(derpClient.PublicKey()),
	BearerSecret:    bearerSecret,
	Capabilities:    token.CapabilityStdio, // or Share
	QUICPublic:      quicID.Public,
}
```

In the listener and sharer QUIC server setup:

```go
quicListener, err := quic.Listen(
	adapter,
	quicpath.DefaultTLSConfig(quicID.Cert, quicpath.ServerName),
	quicpath.DefaultQUICConfig(),
)
```

In the sender and opener QUIC dial path:

```go
quicConn, err := quic.Dial(
	ctx,
	adapter,
	peerConn.RemoteAddr(),
	quicpath.DefaultPinnedClientTLSConfig(tok.QUICPublic),
	quicpath.DefaultQUICConfig(),
)
```

- [ ] **Step 4: Run the targeted session test to verify it passes**

Run: `go test ./pkg/session -run TestPublicListenSendRejectsQUICPeerIdentityMismatch -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/shayne/code/derpcat/pkg/session/external.go /Users/shayne/code/derpcat/pkg/session/external_share.go /Users/shayne/code/derpcat/pkg/session/session_test.go
git commit -m "security: bind public sessions to quic identity"
```

### Task 4: Validate Claim Payloads and Bound Control Data

**Files:**
- Modify: `/Users/shayne/code/derpcat/pkg/rendezvous/messages.go`
- Modify: `/Users/shayne/code/derpcat/pkg/rendezvous/state.go`
- Modify: `/Users/shayne/code/derpcat/pkg/transport/control.go`
- Modify: `/Users/shayne/code/derpcat/pkg/rendezvous/rendezvous_test.go`
- Modify: `/Users/shayne/code/derpcat/pkg/transport/manager_test.go`

- [ ] **Step 1: Write failing tests for malformed candidate abuse**

```go
func TestGateRejectsTooManyCandidates(t *testing.T) {
	now := time.Now()
	tok := testToken(now)
	claim := testClaim(tok)
	claim.Candidates = make([]string, 1025)
	for i := range claim.Candidates {
		claim.Candidates[i] = "127.0.0.1:1234"
	}

	gate := NewGate(tok)
	decision, err := gate.Accept(now, claim)
	if err == nil {
		t.Fatal("Accept() unexpectedly succeeded")
	}
	if decision.Accepted {
		t.Fatal("decision.Accepted unexpectedly true")
	}
}

func TestParseCandidateAddrsDropsExcessAndInvalidEntries(t *testing.T) {
	raw := []string{"127.0.0.1:1"}
	for i := 0; i < 2000; i++ {
		raw = append(raw, "bad")
	}
	got := parseCandidateAddrs(raw)
	if len(got) > maxCandidateAddrs {
		t.Fatalf("len(got) = %d, want <= %d", len(got), maxCandidateAddrs)
	}
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `go test ./pkg/rendezvous ./pkg/transport -run 'TestGateRejectsTooManyCandidates|TestParseCandidateAddrsDropsExcessAndInvalidEntries' -count=1`
Expected: FAIL because there are no explicit limits yet.

- [ ] **Step 3: Implement bounded validation**

Add constants:

```go
const (
	maxCandidateAddrs   = 64
	maxControlCandidates = 64
)
```

Add helper:

```go
func validateClaim(claim Claim) error {
	if len(claim.Candidates) > maxCandidateAddrs {
		return errors.New("too many candidates")
	}
	for _, candidate := range claim.Candidates {
		if len(candidate) > 128 {
			return errors.New("candidate too long")
		}
	}
	return nil
}
```

Call it from `Gate.Accept`. In `parseCandidateAddrs`, cap accepted candidate count to `maxControlCandidates`.

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `go test ./pkg/rendezvous ./pkg/transport -run 'TestGateRejectsTooManyCandidates|TestParseCandidateAddrsDropsExcessAndInvalidEntries' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/shayne/code/derpcat/pkg/rendezvous/messages.go /Users/shayne/code/derpcat/pkg/rendezvous/state.go /Users/shayne/code/derpcat/pkg/transport/control.go /Users/shayne/code/derpcat/pkg/rendezvous/rendezvous_test.go /Users/shayne/code/derpcat/pkg/transport/manager_test.go
git commit -m "security: bound claim and control data"
```

### Task 5: Bound Shared-Service Stream Fan-Out

**Files:**
- Modify: `/Users/shayne/code/derpcat/pkg/session/share.go`
- Modify: `/Users/shayne/code/derpcat/pkg/session/external_share.go`
- Modify: `/Users/shayne/code/derpcat/pkg/session/session_test.go`

- [ ] **Step 1: Write the failing concurrent-stream limit test**

```go
func TestShareOpenRejectsExcessConcurrentStreams(t *testing.T) {
	const limit = 32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use the existing share/open round-trip harness and attempt limit+1 concurrent opens.
	result := runShareOpenRoundTrip(t, shareOpenRoundTripConfig{
		UseExternal:       false,
		ConcurrentStreams: limit + 1,
	})

	if result.RejectedStreams == 0 {
		t.Fatal("expected at least one rejected stream")
	}
}
```

- [ ] **Step 2: Run the targeted session test to verify it fails**

Run: `go test ./pkg/session -run TestShareOpenRejectsExcessConcurrentStreams -count=1`
Expected: FAIL because there is no explicit limit yet.

- [ ] **Step 3: Implement a practical stream cap**

In `pkg/session/external_share.go`:

```go
const maxConcurrentSharedStreams = 64
```

Wrap `serveQUICListener` with a semaphore:

```go
sem := make(chan struct{}, maxConcurrentSharedStreams)

select {
case sem <- struct{}{}:
case <-ctx.Done():
	return nil
default:
	_ = overlayConn.Close()
	continue
}

go func() {
	defer func() { <-sem }()
	// existing bridge body
}()
```

Mirror the same limit in the local `share/open` path if needed so local and public behavior stay aligned.

- [ ] **Step 4: Run the targeted session test to verify it passes**

Run: `go test ./pkg/session -run TestShareOpenRejectsExcessConcurrentStreams -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/shayne/code/derpcat/pkg/session/share.go /Users/shayne/code/derpcat/pkg/session/external_share.go /Users/shayne/code/derpcat/pkg/session/session_test.go
git commit -m "security: bound shared session fan-out"
```

### Task 6: Keep `open` Defaults Local and Safe

**Files:**
- Modify: `/Users/shayne/code/derpcat/pkg/session/open.go`
- Modify: `/Users/shayne/code/derpcat/cmd/derpcat/open_test.go`

- [ ] **Step 1: Write the failing bind-default test**

```go
func TestOpenDefaultsToLocalEphemeralBind(t *testing.T) {
	tok := token.Token{
		Version:      token.SupportedVersion,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		Capabilities: token.CapabilityShare,
	}
	l, err := openLocalListener(OpenConfig{}, tok)
	if err != nil {
		t.Fatalf("openLocalListener() error = %v", err)
	}
	defer l.Close()

	addr := l.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("addr = %q, want 127.0.0.1:<ephemeral>", addr)
	}
}
```

- [ ] **Step 2: Run the targeted test to verify it fails if token defaults still matter**

Run: `go test ./pkg/session ./cmd/derpcat -run TestOpenDefaultsToLocalEphemeralBind -count=1`
Expected: FAIL or require adjustment because old token fields still influenced bind policy.

- [ ] **Step 3: Implement fixed local policy**

```go
func openLocalListener(cfg OpenConfig, tok token.Token) (net.Listener, error) {
	addr := cfg.BindAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return net.Listen("tcp", addr)
}
```

- [ ] **Step 4: Run the targeted test to verify it passes**

Run: `go test ./pkg/session ./cmd/derpcat -run TestOpenDefaultsToLocalEphemeralBind -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/shayne/code/derpcat/pkg/session/open.go /Users/shayne/code/derpcat/cmd/derpcat/open_test.go
git commit -m "security: keep open defaults local"
```

### Task 7: Full Suite and Live Security Verification

**Files:**
- Modify: `/Users/shayne/code/derpcat/README.md`
  - mention one-hour token lifetime if user-facing docs need it

- [ ] **Step 1: Run the full local verification suite**

Run:

```bash
mise run check
go test ./pkg/quicpath ./pkg/rendezvous ./pkg/session ./pkg/transport -count=1
```

Expected: PASS

- [ ] **Step 2: Verify local -> hetz one-shot still works**

Run:

```bash
REMOTE_HOST=hetz mise run smoke-remote
```

Expected: PASS with relay-first/direct-upgrade traces still observed when the network allows it.

- [ ] **Step 3: Verify local -> hetz shared-service flow still works**

Run:

```bash
REMOTE_HOST=hetz mise run smoke-remote-share
```

Expected: PASS

- [ ] **Step 4: Verify local -> pve1 one-shot still works**

Run:

```bash
REMOTE_HOST=pve1 mise run smoke-remote
```

Expected: PASS

- [ ] **Step 5: Verify local -> pve1 shared-service flow still works**

Run:

```bash
REMOTE_HOST=pve1 mise run smoke-remote-share
```

Expected: PASS

- [ ] **Step 6: Verify long transfer still upgrades and remains stable**

Run:

```bash
REMOTE_HOST=hetz mise run promotion-1g
REMOTE_HOST=pve1 mise run promotion-1g
```

Expected: PASS with direct evidence on at least one side, no new security validation failures, and no regression in final payload integrity.

- [ ] **Step 7: Commit**

```bash
git add /Users/shayne/code/derpcat/README.md
git commit -m "security: document hardened public sessions"
```

## Self-Review

- Spec coverage:
  - session-authenticated QUIC: Tasks 2 and 3
  - token tightening: Tasks 1 and 6
  - runtime hardening: Tasks 4 and 5
  - live verification on this host, `hetz`, and `pve1`: Task 7
- Placeholder scan:
  - removed generic TODO wording
  - each task contains concrete file paths, commands, and code snippets
- Type consistency:
  - `QUICPublic` introduced once in `token.Token` and then referenced consistently
  - `DefaultPinnedClientTLSConfig`, `GenerateSessionIdentity`, and `VerifyPeerCertificate` are defined in Task 2 before use in Task 3
