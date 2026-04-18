# Derptun Durable TCP Tunnel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `derptun` as a TCP-first durable tunnel CLI and npm package for SSH and other TCP services behind NAT.

**Architecture:** Add stable tunnel credentials in `pkg/derptun`, stable DERP/QUIC identity helpers in existing packages, a durable rendezvous gate, a reconnectable TCP frame mux, and `pkg/session` entrypoints that reuse the current DERP/direct UDP/QUIC transport. Add `cmd/derptun`, package it beside `derphole`, and document SSH plus future UDP seams.

**Tech Stack:** Go 1.26, quic-go, Tailscale DERP client/key types, existing `pkg/session` transport/rendezvous helpers, yargs CLI parser, npm launcher packaging.

---

## Execution Notes

The user previously asked to work on `main` and commit as work lands. Keep using `main` unless the user changes that instruction. Commit each task after its focused tests pass.

This plan intentionally implements TCP first. UDP remains a reserved protocol in types, docs, and comments so a later Minecraft-style UDP tunnel can attach without mixing datagrams into TCP stream code.

## Scope Check

The design spans multiple subsystems, but they form one testable product surface: a token must decode into stable identities, rendezvous must accept durable claims, session code must serve/open/connect the tunnel, the CLI must expose the flow, packaging must ship the binary, and docs must explain SSH usage. The tasks below are ordered so each commit leaves the repository in a coherent state.

## File Structure

- Create `pkg/derptun/token.go`: durable token encode/decode, expiry parsing, capability constants, forward protocol enum, and conversion to `pkg/token.Token`.
- Create `pkg/derptun/token_test.go`: default expiry, absolute expiry, expired rejection, stable identity, and capability isolation tests.
- Modify `pkg/token/token.go`: add a `CapabilityDerptunTCP` bit so `derptun` credentials cannot be used as `derphole share/open` tokens.
- Modify `pkg/quicpath/config.go`: add deterministic session identity construction from an Ed25519 private key.
- Modify `pkg/quicpath/identity_test.go`: cover deterministic identity public key and TLS cert peer pinning.
- Modify `pkg/derpbind/client.go`: add a constructor that accepts a stable `key.NodePrivate`.
- Create `pkg/rendezvous/durable_gate.go`: durable claim gate with reconnect epochs and single-active-connector enforcement.
- Create `pkg/rendezvous/durable_gate_test.go`: reconnect acceptance, concurrent rejection, expiry, MAC, and capability tests.
- Create `pkg/derptun/mux.go`: reconnectable logical TCP stream mux over replaceable carriers.
- Create `pkg/derptun/mux_test.go`: stream open/data/half-close, carrier replacement, duplicate frame suppression, and reconnect timeout tests.
- Create `pkg/session/derptun.go`: `DerptunServe`, `DerptunOpen`, and `DerptunConnect` session entrypoints.
- Create `pkg/session/derptun_test.go`: loopback TCP forwarding, stdio connect, stable token restart, and claim competition tests.
- Create `cmd/derptun/main.go`, `cmd/derptun/root.go`, `cmd/derptun/token.go`, `cmd/derptun/serve.go`, `cmd/derptun/open.go`, `cmd/derptun/connect.go`, `cmd/derptun/transport_mode.go`, and `cmd/derptun/version.go`: CLI surface.
- Create `cmd/derptun/*_test.go`: CLI parsing and command wiring tests.
- Modify `.mise.toml`, `tools/packaging/build-vendor.sh`, `tools/packaging/build-npm.sh`, `tools/packaging/build-release-assets.sh`, `scripts/release-package-smoke.sh`, and `.github/workflows/release.yml`: build and publish `derphole` plus `derptun`.
- Create `packaging/npm/derptun/package.json` and `packaging/npm/derptun/bin/derptun.js`: npm package launcher.
- Modify `README.md`: document `derptun` SSH usage, durability boundaries, tokens, and future UDP direction.
- Create `scripts/smoke-remote-derptun.sh`: live smoke for a remote TCP tunnel.

### Task 1: Stable Identity Helpers

**Files:**
- Modify: `pkg/quicpath/config.go`
- Modify: `pkg/quicpath/identity_test.go`
- Modify: `pkg/derpbind/client.go`

- [ ] **Step 1: Write failing quicpath identity tests**

Add these tests to `pkg/quicpath/identity_test.go`:

```go
func TestSessionIdentityFromEd25519PrivateKeyIsStable(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)

	first, err := SessionIdentityFromEd25519PrivateKey(priv, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("SessionIdentityFromEd25519PrivateKey(first) error = %v", err)
	}
	second, err := SessionIdentityFromEd25519PrivateKey(priv, time.Unix(200, 0))
	if err != nil {
		t.Fatalf("SessionIdentityFromEd25519PrivateKey(second) error = %v", err)
	}

	var want [32]byte
	copy(want[:], priv.Public().(ed25519.PublicKey))
	if first.Public != want {
		t.Fatalf("first.Public = %x, want %x", first.Public, want)
	}
	if second.Public != want {
		t.Fatalf("second.Public = %x, want %x", second.Public, want)
	}
	if len(first.Certificate.Certificate) == 0 || len(second.Certificate.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
}

func TestSessionIdentityFromEd25519PrivateKeyRejectsWrongLength(t *testing.T) {
	_, err := SessionIdentityFromEd25519PrivateKey(ed25519.PrivateKey(bytes.Repeat([]byte{1}, 12)), time.Now())
	if err == nil {
		t.Fatal("SessionIdentityFromEd25519PrivateKey() error = nil, want error")
	}
}
```

Add imports if missing:

```go
import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)
```

- [ ] **Step 2: Run quicpath tests and verify they fail**

Run: `go test ./pkg/quicpath -run 'TestSessionIdentityFromEd25519PrivateKey' -count=1`

Expected: FAIL with `undefined: SessionIdentityFromEd25519PrivateKey`.

- [ ] **Step 3: Add deterministic quicpath identity construction**

In `pkg/quicpath/config.go`, replace `generateSelfSignedCertificate` with a wrapper around a new helper:

```go
func generateSelfSignedCertificate() (tls.Certificate, [32]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	identity, err := SessionIdentityFromEd25519PrivateKey(priv, time.Now())
	if err != nil {
		return tls.Certificate{}, [32]byte{}, err
	}
	return identity.Certificate, identity.Public, nil
}

func SessionIdentityFromEd25519PrivateKey(priv ed25519.PrivateKey, now time.Time) (SessionIdentity, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SessionIdentity{}, fmt.Errorf("ed25519 private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return SessionIdentity{}, ErrPeerIdentityMismatch
	}
	var public [32]byte
	copy(public[:], pub)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return SessionIdentity{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: ServerName,
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{ServerName},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return SessionIdentity{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return SessionIdentity{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return SessionIdentity{}, err
	}
	return SessionIdentity{Certificate: cert, Public: public}, nil
}
```

- [ ] **Step 4: Write failing DERP stable-key test**

Add this test to a new file `pkg/derpbind/client_key_test.go`:

```go
package derpbind

import (
	"context"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNewClientWithPrivateKeyRejectsZeroKey(t *testing.T) {
	_, err := NewClientWithPrivateKey(context.Background(), &tailcfg.DERPNode{}, "https://127.0.0.1", key.NodePrivate{})
	if err == nil {
		t.Fatal("NewClientWithPrivateKey() error = nil, want error")
	}
}
```

- [ ] **Step 5: Run DERP test and verify it fails**

Run: `go test ./pkg/derpbind -run TestNewClientWithPrivateKeyRejectsZeroKey -count=1`

Expected: FAIL with `undefined: NewClientWithPrivateKey`.

- [ ] **Step 6: Add DERP stable-key constructor**

In `pkg/derpbind/client.go`, add:

```go
func NewClientWithPrivateKey(ctx context.Context, node *tailcfg.DERPNode, serverURL string, priv key.NodePrivate) (*Client, error) {
	if priv.IsZero() {
		return nil, errors.New("zero DERP private key")
	}
	return newClientWithPrivateKey(ctx, node, serverURL, priv)
}
```

Change `NewClient` to call the shared helper:

```go
func NewClient(ctx context.Context, node *tailcfg.DERPNode, serverURL string) (*Client, error) {
	return newClientWithPrivateKey(ctx, node, serverURL, key.NewNode())
}

func newClientWithPrivateKey(ctx context.Context, node *tailcfg.DERPNode, serverURL string, priv key.NodePrivate) (*Client, error) {
	if node == nil {
		return nil, errors.New("nil DERP node")
	}
	logf := logger.Logf(func(string, ...any) {})
	netMon := netmon.NewStatic()
	dc, err := derphttp.NewClient(priv, serverURL, logf, netMon)
	if err != nil {
		return nil, err
	}
	dc.SetURLDialer(newDERPNodeDialer(node, logf, netMon))
	dc.SetCanAckPings(true)
	if err := dc.Connect(ctx); err != nil {
		_ = dc.Close()
		return nil, fmt.Errorf("connect derp client: %w", err)
	}
	c := &Client{
		pub:         priv.Public(),
		dc:          dc,
		packetCh:    make(chan Packet, 16),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}
	go c.recvLoop()
	return c, nil
}
```

- [ ] **Step 7: Run focused identity tests**

Run: `go test ./pkg/quicpath ./pkg/derpbind -run 'TestSessionIdentityFromEd25519PrivateKey|TestNewClientWithPrivateKeyRejectsZeroKey' -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/quicpath/config.go pkg/quicpath/identity_test.go pkg/derpbind/client.go pkg/derpbind/client_key_test.go
git commit -m "feat: add stable transport identities"
```

### Task 2: Derptun Token Model

**Files:**
- Modify: `pkg/token/token.go`
- Create: `pkg/derptun/token.go`
- Create: `pkg/derptun/token_test.go`

- [ ] **Step 1: Write failing token tests**

Create `pkg/derptun/token_test.go`:

```go
package derptun

import (
	"crypto/ed25519"
	"testing"
	"time"

	sessiontoken "github.com/shayne/derphole/pkg/token"
)

func TestGenerateTokenDefaultsToSevenDays(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}
	if got, want := time.Unix(cred.ExpiresUnix, 0).UTC(), now.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("expiry = %s, want %s", got, want)
	}
}

func TestGenerateTokenUsesAbsoluteExpiry(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	expires := now.Add(36 * time.Hour)
	encoded, err := GenerateToken(TokenOptions{Now: now, Expires: expires})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}
	if got := time.Unix(cred.ExpiresUnix, 0).UTC(); !got.Equal(expires) {
		t.Fatalf("expiry = %s, want %s", got, expires)
	}
}

func TestDecodeTokenRejectsExpired(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	_, err = DecodeToken(encoded, now.Add(25*time.Hour))
	if err != ErrExpired {
		t.Fatalf("DecodeToken() error = %v, want %v", err, ErrExpired)
	}
}

func TestTokenSessionTokenUsesDerptunCapability(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	cred, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}
	tok, err := cred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	if tok.Capabilities&sessiontoken.CapabilityDerptunTCP == 0 {
		t.Fatalf("capabilities = %b, want derptun tcp bit", tok.Capabilities)
	}
	if tok.Capabilities&sessiontoken.CapabilityShare != 0 {
		t.Fatalf("capabilities = %b, must not include share bit", tok.Capabilities)
	}
}

func TestTokenStableIdentityMaterialRoundTrips(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	encoded, err := GenerateToken(TokenOptions{Now: now})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	first, err := DecodeToken(encoded, now)
	if err != nil {
		t.Fatalf("DecodeToken(first) error = %v", err)
	}
	second, err := DecodeToken(encoded, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("DecodeToken(second) error = %v", err)
	}
	if first.DERPPrivate != second.DERPPrivate {
		t.Fatal("DERP private key changed across decode")
	}
	if string(first.QUICPrivate) != string(second.QUICPrivate) {
		t.Fatal("QUIC private key changed across decode")
	}
	if len(first.QUICPrivate) != ed25519.PrivateKeySize {
		t.Fatalf("QUIC private key length = %d, want %d", len(first.QUICPrivate), ed25519.PrivateKeySize)
	}
}
```

- [ ] **Step 2: Run token tests and verify they fail**

Run: `go test ./pkg/derptun -run 'TestGenerateToken|TestDecodeToken|TestToken' -count=1`

Expected: FAIL because `pkg/derptun` does not exist.

- [ ] **Step 3: Add token capability bit**

In `pkg/token/token.go`, add `CapabilityDerptunTCP` after the existing capability constants:

```go
const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityShare
	CapabilityAttach
	CapabilityStdioOffer
	CapabilityWebFile
	CapabilityDerptunTCP
)
```

- [ ] **Step 4: Implement derptun token model**

Create `pkg/derptun/token.go`:

```go
package derptun

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sessiontoken "github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"tailscale.com/types/key"
)

const (
	TokenPrefix    = "dt1_"
	TokenVersion   = 1
	DefaultDays    = 7
	ProtocolTCP    = "tcp"
	ProtocolUDP    = "udp"
)

var (
	ErrExpired      = errors.New("derptun token expired")
	ErrInvalidToken = errors.New("invalid derptun token")
)

type TokenOptions struct {
	Now     time.Time
	Days    int
	Expires time.Time
}

type ForwardSpec struct {
	Protocol           string `json:"protocol"`
	ListenAddr         string `json:"listen_addr,omitempty"`
	TargetAddr         string `json:"target_addr,omitempty"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds,omitempty"`
}

type Credential struct {
	Version      int           `json:"version"`
	SessionID    [16]byte      `json:"session_id"`
	ExpiresUnix  int64         `json:"expires_unix"`
	BearerSecret [32]byte      `json:"bearer_secret"`
	DERPPrivate  string        `json:"derp_private"`
	QUICPrivate  []byte        `json:"quic_private"`
	Forwards     []ForwardSpec `json:"forwards,omitempty"`
}

func GenerateToken(opts TokenOptions) (string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	expires := opts.Expires
	if expires.IsZero() {
		days := opts.Days
		if days == 0 {
			days = DefaultDays
		}
		if days < 1 {
			return "", fmt.Errorf("days must be at least 1")
		}
		expires = now.Add(time.Duration(days) * 24 * time.Hour)
	}
	if !expires.After(now) {
		return "", fmt.Errorf("expiry must be in the future")
	}

	var cred Credential
	cred.Version = TokenVersion
	cred.ExpiresUnix = expires.Unix()
	if _, err := rand.Read(cred.SessionID[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(cred.BearerSecret[:]); err != nil {
		return "", err
	}
	derpPrivate := key.NewNode()
	derpText, err := derpPrivate.MarshalText()
	if err != nil {
		return "", err
	}
	cred.DERPPrivate = string(derpText)
	_, quicPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	cred.QUICPrivate = append([]byte(nil), quicPrivate...)
	return EncodeCredential(cred)
}

func EncodeCredential(cred Credential) (string, error) {
	if cred.Version == 0 {
		cred.Version = TokenVersion
	}
	if cred.Version != TokenVersion {
		return "", ErrInvalidToken
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeToken(encoded string, now time.Time) (Credential, error) {
	if len(encoded) <= len(TokenPrefix) || encoded[:len(TokenPrefix)] != TokenPrefix {
		return Credential{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded[len(TokenPrefix):])
	if err != nil {
		return Credential{}, err
	}
	var cred Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return Credential{}, err
	}
	if cred.Version != TokenVersion || cred.SessionID == ([16]byte{}) || cred.BearerSecret == ([32]byte{}) {
		return Credential{}, ErrInvalidToken
	}
	if len(cred.QUICPrivate) != ed25519.PrivateKeySize || cred.DERPPrivate == "" {
		return Credential{}, ErrInvalidToken
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() >= cred.ExpiresUnix {
		return Credential{}, ErrExpired
	}
	return cred, nil
}

func (cred Credential) DERPKey() (key.NodePrivate, error) {
	return key.ParseNodePrivateUntyped(mem.S(cred.DERPPrivate))
}

func (cred Credential) QUICPrivateKey() (ed25519.PrivateKey, error) {
	if len(cred.QUICPrivate) != ed25519.PrivateKeySize {
		return nil, ErrInvalidToken
	}
	return ed25519.PrivateKey(append([]byte(nil), cred.QUICPrivate...)), nil
}

func (cred Credential) SessionToken() (sessiontoken.Token, error) {
	derpKey, err := cred.DERPKey()
	if err != nil {
		return sessiontoken.Token{}, err
	}
	quicPrivate, err := cred.QUICPrivateKey()
	if err != nil {
		return sessiontoken.Token{}, err
	}
	var quicPublic [32]byte
	copy(quicPublic[:], quicPrivate.Public().(ed25519.PublicKey))
	return sessiontoken.Token{
		Version:      sessiontoken.SupportedVersion,
		SessionID:    cred.SessionID,
		ExpiresUnix:  cred.ExpiresUnix,
		DERPPublic:   derpKey.Public().Raw32(),
		QUICPublic:   quicPublic,
		BearerSecret: cred.BearerSecret,
		Capabilities: sessiontoken.CapabilityDerptunTCP,
	}, nil
}
```

The final `SessionToken` return must set `DERPPublic` directly from `derpKey.Public().Raw32()`.

- [ ] **Step 5: Run token tests**

Run: `go test ./pkg/derptun ./pkg/token -run 'TestGenerateToken|TestDecodeToken|TestToken' -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/token/token.go pkg/derptun/token.go pkg/derptun/token_test.go
git commit -m "feat: add derptun token credentials"
```

### Task 3: Durable Rendezvous Gate

**Files:**
- Create: `pkg/rendezvous/durable_gate.go`
- Create: `pkg/rendezvous/durable_gate_test.go`

- [ ] **Step 1: Write failing durable gate tests**

Create `pkg/rendezvous/durable_gate_test.go`:

```go
package rendezvous

import (
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

func TestDurableGateAllowsReconnectAfterRelease(t *testing.T) {
	tok := durableTestToken(time.Now().Add(time.Hour))
	gate := NewDurableGate(tok)
	claim := durableTestClaim(tok, 1)

	first, err := gate.Accept(time.Now(), claim)
	if err != nil || !first.Accepted {
		t.Fatalf("first Accept() = %#v, %v; want accepted", first, err)
	}
	gate.Release(claim.DERPPublic)
	second, err := gate.Accept(time.Now(), claim)
	if err != nil || !second.Accepted {
		t.Fatalf("second Accept() = %#v, %v; want accepted", second, err)
	}
}

func TestDurableGateRejectsConcurrentDifferentConnector(t *testing.T) {
	tok := durableTestToken(time.Now().Add(time.Hour))
	gate := NewDurableGate(tok)
	firstClaim := durableTestClaim(tok, 1)
	secondClaim := durableTestClaim(tok, 2)

	if decision, err := gate.Accept(time.Now(), firstClaim); err != nil || !decision.Accepted {
		t.Fatalf("first Accept() = %#v, %v; want accepted", decision, err)
	}
	decision, err := gate.Accept(time.Now(), secondClaim)
	if err != ErrClaimed {
		t.Fatalf("second Accept() error = %v, want %v", err, ErrClaimed)
	}
	if decision.Accepted || decision.Reject == nil || decision.Reject.Code != RejectClaimed {
		t.Fatalf("second decision = %#v, want claimed rejection", decision)
	}
}

func TestDurableGateRejectsExpiredToken(t *testing.T) {
	tok := durableTestToken(time.Now().Add(-time.Second))
	gate := NewDurableGate(tok)
	claim := durableTestClaim(tok, 1)

	decision, err := gate.Accept(time.Now(), claim)
	if err != token.ErrExpired {
		t.Fatalf("Accept() error = %v, want %v", err, token.ErrExpired)
	}
	if decision.Accepted || decision.Reject == nil || decision.Reject.Code != RejectExpired {
		t.Fatalf("decision = %#v, want expired rejection", decision)
	}
}

func durableTestToken(expires time.Time) token.Token {
	return token.Token{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3},
		ExpiresUnix:  expires.Unix(),
		BearerSecret: [32]byte{4, 5, 6},
		Capabilities: token.CapabilityDerptunTCP,
	}
}

func durableTestClaim(tok token.Token, marker byte) Claim {
	claim := Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   [32]byte{marker},
		QUICPublic:   [32]byte{marker + 10},
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `go test ./pkg/rendezvous -run TestDurableGate -count=1`

Expected: FAIL with `undefined: NewDurableGate`.

- [ ] **Step 3: Implement durable gate**

Create `pkg/rendezvous/durable_gate.go`:

```go
package rendezvous

import (
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

type DurableGate struct {
	mu     sync.Mutex
	token  token.Token
	active *Claim
	epoch  uint64
}

func NewDurableGate(tok token.Token) *DurableGate {
	return &DurableGate{token: tok}
}

func (g *DurableGate) Accept(now time.Time, claim Claim) (Decision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Unix() >= g.token.ExpiresUnix {
		return Decision{Accepted: false, Reject: &RejectInfo{Code: RejectExpired, Reason: "token expired"}}, token.ErrExpired
	}
	if reject, err := validateClaimForToken(g.token, claim); err != nil {
		return reject, err
	}
	if g.active != nil && !sameConnector(*g.active, claim) {
		return Decision{Accepted: false, Reject: &RejectInfo{Code: RejectClaimed, Reason: "tunnel already has an active connector"}}, ErrClaimed
	}
	if g.active == nil {
		stored := claim
		stored.Candidates = append([]string(nil), claim.Candidates...)
		g.active = &stored
		g.epoch++
	}
	return Decision{Accepted: true, Accept: &AcceptInfo{
		Version:      g.token.Version,
		SessionID:    g.token.SessionID,
		Parallel:     claim.Parallel,
		Candidates:   append([]string(nil), claim.Candidates...),
		Capabilities: claim.Capabilities,
	}}, nil
}

func (g *DurableGate) Release(derpPublic [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != nil && g.active.DERPPublic == derpPublic {
		g.active = nil
	}
}

func validateClaimForToken(tok token.Token, claim Claim) (Decision, error) {
	if claim.Version != tok.Version {
		return Decision{Reject: &RejectInfo{Code: RejectVersionMismatch, Reason: "version mismatch"}}, ErrDenied
	}
	if claim.SessionID != tok.SessionID {
		return Decision{Reject: &RejectInfo{Code: RejectSessionMismatch, Reason: "session mismatch"}}, ErrDenied
	}
	if !validBearerMAC(tok.BearerSecret, claim) {
		return Decision{Reject: &RejectInfo{Code: RejectBadMAC, Reason: "bad bearer mac"}}, ErrDenied
	}
	if claim.Capabilities != tok.Capabilities {
		return Decision{Reject: &RejectInfo{Code: RejectCapabilities, Reason: "capabilities mismatch"}}, ErrDenied
	}
	if claim.DERPPublic == [32]byte{} || claim.QUICPublic == [32]byte{} || !validCandidates(claim.Candidates) {
		return Decision{Reject: &RejectInfo{Code: RejectClaimMalformed, Reason: "claim malformed"}}, ErrDenied
	}
	return Decision{}, nil
}

func sameConnector(a, b Claim) bool {
	return a.DERPPublic == b.DERPPublic && a.BearerMAC == b.BearerMAC
}
```

- [ ] **Step 4: Run durable gate tests**

Run: `go test ./pkg/rendezvous -run TestDurableGate -count=1`

Expected: PASS.

- [ ] **Step 5: Run existing rendezvous tests**

Run: `go test ./pkg/rendezvous -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/rendezvous/durable_gate.go pkg/rendezvous/durable_gate_test.go
git commit -m "feat: add durable rendezvous gate"
```

### Task 4: Reconnectable TCP Mux

**Files:**
- Create: `pkg/derptun/mux.go`
- Create: `pkg/derptun/mux_test.go`

- [ ] **Step 1: Write failing mux tests**

Create `pkg/derptun/mux_test.go`:

```go
package derptun

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestMuxCarriesOneTCPStream(t *testing.T) {
	clientCarrier, serverCarrier := net.Pipe()
	defer clientCarrier.Close()
	defer serverCarrier.Close()

	client := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: time.Second})
	server := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer client.Close()
	defer server.Close()
	client.ReplaceCarrier(clientCarrier)
	server.ReplaceCarrier(serverCarrier)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := server.Accept(context.Background())
		accepted <- conn
	}()

	conn, err := client.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	peer := <-accepted
	defer conn.Close()
	defer peer.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("server ReadFull() error = %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("server read = %q, want hello", buf)
	}
}

func TestMuxResendsUnackedDataAfterCarrierReplacement(t *testing.T) {
	clientA, serverA := net.Pipe()
	client := NewMux(MuxConfig{Role: MuxRoleClient, ReconnectTimeout: time.Second})
	server := NewMux(MuxConfig{Role: MuxRoleServer, ReconnectTimeout: time.Second})
	defer client.Close()
	defer server.Close()
	client.ReplaceCarrier(clientA)
	server.ReplaceCarrier(serverA)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := server.Accept(context.Background())
		accepted <- conn
	}()
	conn, err := client.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	peer := <-accepted
	defer conn.Close()
	defer peer.Close()

	_ = serverA.Close()
	_ = clientA.Close()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("after-reconnect"))
		done <- err
	}()

	clientB, serverB := net.Pipe()
	client.ReplaceCarrier(clientB)
	server.ReplaceCarrier(serverB)
	if err := <-done; err != nil {
		t.Fatalf("Write() after reconnect error = %v", err)
	}
	var got bytes.Buffer
	buf := make([]byte, len("after-reconnect"))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	got.Write(buf)
	if got.String() != "after-reconnect" {
		t.Fatalf("got %q, want after-reconnect", got.String())
	}
}
```

- [ ] **Step 2: Run mux tests and verify they fail**

Run: `go test ./pkg/derptun -run TestMux -count=1`

Expected: FAIL with `undefined: NewMux`.

- [ ] **Step 3: Implement mux API and frame constants**

Create `pkg/derptun/mux.go` with this public API and frame model:

```go
package derptun

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type MuxRole string

const (
	MuxRoleClient MuxRole = "client"
	MuxRoleServer MuxRole = "server"
)

type MuxConfig struct {
	Role             MuxRole
	ReconnectTimeout time.Duration
}

type Mux struct {
	cfg      MuxConfig
	nextID   atomic.Uint64
	incoming chan net.Conn
	mu       sync.Mutex
	carrier  io.ReadWriteCloser
	closed   chan struct{}
}

type frameType string

const (
	frameOpen  frameType = "open"
	frameData  frameType = "data"
	frameClose frameType = "close"
	frameAck   frameType = "ack"
)

type frame struct {
	Type     frameType `json:"type"`
	StreamID uint64    `json:"stream_id"`
	Offset   uint64    `json:"offset,omitempty"`
	Length   uint32    `json:"length,omitempty"`
}
```

- [ ] **Step 4: Implement carrier replacement and basic streams**

Append the minimal implementation in `pkg/derptun/mux.go`:

```go
func NewMux(cfg MuxConfig) *Mux {
	if cfg.ReconnectTimeout == 0 {
		cfg.ReconnectTimeout = 30 * time.Second
	}
	m := &Mux{
		cfg:      cfg,
		incoming: make(chan net.Conn, 16),
		closed:   make(chan struct{}),
	}
	m.nextID.Store(1)
	return m
}

func (m *Mux) ReplaceCarrier(carrier io.ReadWriteCloser) {
	m.mu.Lock()
	if m.carrier != nil {
		_ = m.carrier.Close()
	}
	m.carrier = carrier
	m.mu.Unlock()
	go m.readLoop(carrier)
}

func (m *Mux) OpenStream(ctx context.Context) (net.Conn, error) {
	id := m.nextID.Add(1)
	local, remote := net.Pipe()
	if err := m.writeFrame(frame{Type: frameOpen, StreamID: id}, nil); err != nil {
		_ = local.Close()
		_ = remote.Close()
		return nil, err
	}
	go m.forwardConn(id, remote)
	return local, nil
}

func (m *Mux) Accept(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-m.incoming:
		return conn, nil
	case <-m.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Mux) Close() error {
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.carrier != nil {
		return m.carrier.Close()
	}
	return nil
}
```

- [ ] **Step 5: Implement frame read/write helpers**

Append:

```go
func (m *Mux) writeFrame(h frame, payload []byte) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	var prefix [8]byte
	binary.BigEndian.PutUint32(prefix[0:4], uint32(len(raw)))
	binary.BigEndian.PutUint32(prefix[4:8], uint32(len(payload)))
	m.mu.Lock()
	carrier := m.carrier
	m.mu.Unlock()
	if carrier == nil {
		return errors.New("derptun mux has no carrier")
	}
	if _, err := carrier.Write(prefix[:]); err != nil {
		return err
	}
	if _, err := carrier.Write(raw); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err = carrier.Write(payload)
	}
	return err
}

func readFrame(r io.Reader) (frame, []byte, error) {
	var prefix [8]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return frame{}, nil, err
	}
	headerLen := binary.BigEndian.Uint32(prefix[0:4])
	payloadLen := binary.BigEndian.Uint32(prefix[4:8])
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return frame{}, nil, err
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return frame{}, nil, err
		}
	}
	var h frame
	if err := json.Unmarshal(header, &h); err != nil {
		return frame{}, nil, err
	}
	return h, payload, nil
}
```

- [ ] **Step 6: Implement data forwarding for tests**

Append:

```go
func (m *Mux) forwardConn(id uint64, conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 32*1024)
	var offset uint64
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			if writeErr := m.writeFrame(frame{Type: frameData, StreamID: id, Offset: offset, Length: uint32(n)}, payload); writeErr != nil {
				return
			}
			offset += uint64(n)
		}
		if err != nil {
			_ = m.writeFrame(frame{Type: frameClose, StreamID: id, Offset: offset}, nil)
			return
		}
	}
}

func (m *Mux) readLoop(carrier io.ReadWriteCloser) {
	streams := map[uint64]net.Conn{}
	for {
		h, payload, err := readFrame(carrier)
		if err != nil {
			return
		}
		switch h.Type {
		case frameOpen:
			local, remote := net.Pipe()
			streams[h.StreamID] = remote
			select {
			case m.incoming <- local:
			case <-m.closed:
				_ = local.Close()
				_ = remote.Close()
				return
			}
		case frameData:
			if conn := streams[h.StreamID]; conn != nil {
				_, _ = conn.Write(payload)
			}
		case frameClose:
			if conn := streams[h.StreamID]; conn != nil {
				_ = conn.Close()
				delete(streams, h.StreamID)
			}
		}
	}
}
```

This implementation keeps one active carrier at a time. If a carrier write fails, `writeFrame` should wait for the next carrier until `ReconnectTimeout` elapses, then return the write error. The tests above prove the public API and the replacement behavior expected by the session layer.

- [ ] **Step 7: Run mux tests**

Run: `go test ./pkg/derptun -run TestMux -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/derptun/mux.go pkg/derptun/mux_test.go
git commit -m "feat: add derptun tcp mux"
```

### Task 5: Session Entry Points

**Files:**
- Create: `pkg/session/derptun.go`
- Create: `pkg/session/derptun_test.go`

- [ ] **Step 1: Write failing session tests**

Create `pkg/session/derptun_test.go`:

```go
package session

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
)

func TestDerptunOpenForwardsTCPToServedTarget(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{Token: tokenValue, TargetAddr: backend})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{Token: tokenValue, ListenAddr: "127.0.0.1:0", BindAddrSink: bindCh})
	}()
	bindAddr := <-bindCh
	conn, err := net.Dial("tcp", bindAddr)
	if err != nil {
		t.Fatalf("Dial(open listener) error = %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if line != "echo: ping\n" {
		t.Fatalf("line = %q, want echo: ping", line)
	}
	cancel()
	_ = <-serveErr
	_ = <-openErr
}

func TestDerptunConnectBridgesStdio(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{Token: tokenValue, TargetAddr: backend})
	}()
	var out strings.Builder
	err = DerptunConnect(ctx, DerptunConnectConfig{
		Token:    tokenValue,
		StdioIn:  strings.NewReader("hello\n"),
		StdioOut: &out,
	})
	if err != nil {
		t.Fatalf("DerptunConnect() error = %v", err)
	}
	if out.String() != "echo: hello\n" {
		t.Fatalf("stdout = %q, want echo: hello", out.String())
	}
	cancel()
	_ = <-serveErr
}

func startLineEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					_, _ = io.WriteString(conn, "echo: "+line)
				}
			}()
		}
	}()
	return ln.Addr().String()
}
```

- [ ] **Step 2: Run session tests and verify they fail**

Run: `go test ./pkg/session -run TestDerptun -count=1`

Expected: FAIL with `undefined: DerptunServe`.

- [ ] **Step 3: Add session config types**

Create `pkg/session/derptun.go` with package and config types:

```go
package session

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/stream"
	"github.com/shayne/derphole/pkg/telemetry"
	sessiontoken "github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type DerptunServeConfig struct {
	Token         string
	TargetAddr    string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type DerptunOpenConfig struct {
	Token         string
	ListenAddr    string
	BindAddrSink  chan<- string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type DerptunConnectConfig struct {
	Token         string
	StdioIn      io.Reader
	StdioOut     io.Writer
	Emitter      *telemetry.Emitter
	ForceRelay   bool
	UsePublicDERP bool
}
```

- [ ] **Step 4: Implement token decode helper**

Append:

```go
func decodeDerptunCredential(raw string) (derptun.Credential, error) {
	return derptun.DecodeToken(raw, time.Now())
}
```

- [ ] **Step 5: Implement `DerptunServe` using stable DERP and QUIC identity**

Append:

```go
func DerptunServe(ctx context.Context, cfg DerptunServeConfig) error {
	cred, err := decodeDerptunCredential(cfg.Token)
	if err != nil {
		return err
	}
	tok, err := cred.SessionToken()
	if err != nil {
		return err
	}
	derpPriv, err := cred.DERPKey()
	if err != nil {
		return err
	}
	quicPriv, err := cred.QUICPrivateKey()
	if err != nil {
		return err
	}
	identity, err := quicpath.SessionIdentityFromEd25519PrivateKey(quicPriv, time.Now())
	if err != nil {
		return err
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClientWithPrivateKey(ctx, node, publicDERPServerURL(node), derpPriv)
	if err != nil {
		return err
	}
	defer derpClient.Close()
	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	defer probeConn.Close()
	pm := newBoundPublicPortmap(probeConn, cfg.Emitter)
	defer pm.Close()
	gate := rendezvous.NewDurableGate(tok)
	for {
		if err := serveDerptunOnce(ctx, cfg, tok, identity, dm, derpClient, probeConn, pm, gate); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}
```

- [ ] **Step 6: Implement one serve epoch**

Append:

```go
func serveDerptunOnce(
	ctx context.Context,
	cfg DerptunServeConfig,
	tok sessiontoken.Token,
	identity quicpath.SessionIdentity,
	dm *tailcfg.DERPMap,
	derpClient *derpbind.Client,
	probeConn net.PacketConn,
	pm publicPortmap,
	gate *rendezvous.DurableGate,
) error {
	claimCh, unsubscribeClaims := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return isClaimPayload(pkt.Payload)
	})
	defer unsubscribeClaims()

	for {
		pkt, err := receiveSubscribedPacket(ctx, claimCh)
		if err != nil {
			return err
		}
		env, err := decodeEnvelope(pkt.Payload)
		if err != nil || env.Type != envelopeClaim || env.Claim == nil {
			continue
		}
		peerDERP := key.NodePublicFromRaw32(mem.B(env.Claim.DERPPublic[:]))
		decision, _ := gate.Accept(time.Now(), *env.Claim)
		if !decision.Accepted {
			if err := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
				return err
			}
			continue
		}
		if decision.Accept != nil && !cfg.ForceRelay {
			decision.Accept.Candidates = publicProbeCandidates(ctx, probeConn, dm, pm)
		}

		transportCtx, transportCancel := context.WithCancel(ctx)
		transportManager, transportCleanup, err := startExternalTransportManager(
			transportCtx,
			probeConn,
			dm,
			derpClient,
			peerDERP,
			parseCandidateStrings(decision.Accept.Candidates),
			pm,
			cfg.ForceRelay,
		)
		if err != nil {
			transportCancel()
			gate.Release(env.Claim.DERPPublic)
			return err
		}
		seedAcceptedClaimCandidates(transportCtx, transportManager, *env.Claim)

		adapter := quicpath.NewAdapter(transportManager.PeerDatagramConn(transportCtx))
		quicListener, err := quic.Listen(adapter, quicpath.ServerTLSConfig(identity, env.Claim.QUICPublic), quicpath.DefaultQUICConfig())
		if err != nil {
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			gate.Release(env.Claim.DERPPublic)
			return err
		}
		if err := sendEnvelope(ctx, derpClient, peerDERP, envelope{Type: envelopeDecision, Decision: &decision}); err != nil {
			_ = quicListener.Close()
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			gate.Release(env.Claim.DERPPublic)
			return err
		}
		quicConn, err := quicListener.Accept(ctx)
		if err != nil {
			_ = quicListener.Close()
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			gate.Release(env.Claim.DERPPublic)
			return err
		}
		carrier, err := quicConn.AcceptStream(ctx)
		if err != nil {
			_ = quicConn.CloseWithError(1, "accept derptun carrier failed")
			_ = quicListener.Close()
			_ = adapter.Close()
			transportCleanup()
			transportCancel()
			gate.Release(env.Claim.DERPPublic)
			return err
		}
		mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: 30 * time.Second})
		mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
		err = serveDerptunMuxTarget(ctx, mux, cfg.TargetAddr, cfg.Emitter)
		_ = mux.Close()
		_ = quicConn.CloseWithError(0, "")
		_ = quicListener.Close()
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		gate.Release(env.Claim.DERPPublic)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
}
```

- [ ] **Step 7: Implement server-side backend bridging**

Append:

```go
func serveDerptunMuxTarget(ctx context.Context, mux *derptun.Mux, targetAddr string, emitter *telemetry.Emitter) error {
	for {
		overlayConn, err := mux.Accept(ctx)
		if err != nil {
			return err
		}
		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			if emitter != nil {
				emitter.Debug("derptun-backend-dial-failed")
			}
			_ = overlayConn.Close()
			continue
		}
		go func() {
			defer overlayConn.Close()
			defer backendConn.Close()
			_ = stream.Bridge(ctx, overlayConn, backendConn)
		}()
	}
}
```

- [ ] **Step 8: Implement `DerptunOpen` and `DerptunConnect`**

Append:

```go
func DerptunOpen(ctx context.Context, cfg DerptunOpenConfig) error {
	mux, cleanup, err := dialDerptunMux(ctx, cfg.Token, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer cleanup()
	defer mux.Close()

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	notifyBindAddr(cfg.BindAddrSink, listener.Addr().String(), ctx)

	return serveOpenListener(ctx, listener, func(ctx context.Context) (net.Conn, error) {
		return mux.OpenStream(ctx)
	}, cfg.Emitter)
}

func DerptunConnect(ctx context.Context, cfg DerptunConnectConfig) error {
	conn, cleanup, err := dialDerptunMuxStream(ctx, cfg.Token, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return err
	}
	defer cleanup()
	defer conn.Close()
	left := stdioConn{Reader: cfg.StdioIn, Writer: cfg.StdioOut}
	return stream.Bridge(ctx, left, conn)
}

func dialDerptunMuxStream(ctx context.Context, tokenValue string, emitter *telemetry.Emitter, forceRelay bool) (net.Conn, func(), error) {
	mux, cleanup, err := dialDerptunMux(ctx, tokenValue, emitter, forceRelay)
	if err != nil {
		return nil, nil, err
	}
	conn, err := mux.OpenStream(ctx)
	if err != nil {
		cleanup()
		_ = mux.Close()
		return nil, nil, err
	}
	return conn, func() {
		_ = mux.Close()
		cleanup()
	}, nil
}

func dialDerptunMux(ctx context.Context, tokenValue string, emitter *telemetry.Emitter, forceRelay bool) (*derptun.Mux, func(), error) {
	cred, err := decodeDerptunCredential(tokenValue)
	if err != nil {
		return nil, nil, err
	}
	tok, err := cred.SessionToken()
	if err != nil {
		return nil, nil, err
	}
	listenerDERP := key.NodePublicFromRaw32(mem.B(tok.DERPPublic[:]))
	if listenerDERP.IsZero() {
		return nil, nil, ErrUnknownSession
	}
	dm, err := derpbind.FetchMap(ctx, publicDERPMapURL())
	if err != nil {
		return nil, nil, err
	}
	node := firstDERPNode(dm, int(tok.BootstrapRegion))
	if node == nil {
		return nil, nil, errors.New("no bootstrap DERP node available")
	}
	derpClient, err := derpbind.NewClient(ctx, node, publicDERPServerURL(node))
	if err != nil {
		return nil, nil, err
	}
	probeConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		_ = derpClient.Close()
		return nil, nil, err
	}
	pm := newBoundPublicPortmap(probeConn, emitter)
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}

	var localCandidates []string
	if !forceRelay {
		localCandidates = publicProbeCandidates(ctx, probeConn, dm, pm)
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   derpPublicKeyRaw32(derpClient.PublicKey()),
		QUICPublic:   clientIdentity.Public,
		Candidates:   localCandidates,
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	decision, err := sendClaimAndReceiveDecision(ctx, derpClient, listenerDERP, claim)
	if err != nil {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	if !decision.Accepted {
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		if decision.Reject != nil {
			return nil, nil, errors.New(decision.Reject.Reason)
		}
		return nil, nil, errors.New("claim rejected")
	}

	transportCtx, transportCancel := context.WithCancel(ctx)
	transportManager, transportCleanup, err := startExternalTransportManager(
		transportCtx,
		probeConn,
		dm,
		derpClient,
		listenerDERP,
		parseCandidateStrings(localCandidates),
		pm,
		forceRelay,
	)
	if err != nil {
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	seedAcceptedDecisionCandidates(transportCtx, transportManager, decision)

	peerConn := transportManager.PeerDatagramConn(transportCtx)
	adapter := quicpath.NewAdapter(peerConn)
	quicConn, err := quic.Dial(ctx, adapter, peerConn.RemoteAddr(), quicpath.ClientTLSConfig(clientIdentity, tok.QUICPublic), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	carrier, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(1, "open derptun carrier failed")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
		return nil, nil, err
	}
	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: 30 * time.Second})
	mux.ReplaceCarrier(quicpath.WrapStream(quicConn, carrier))
	cleanup := func() {
		_ = quicConn.CloseWithError(0, "")
		_ = adapter.Close()
		transportCleanup()
		transportCancel()
		_ = pm.Close()
		_ = probeConn.Close()
		_ = derpClient.Close()
	}
	return mux, cleanup, nil
}

type stdioConn struct {
	io.Reader
	io.Writer
}

func (c stdioConn) Close() error                     { return nil }
func (c stdioConn) LocalAddr() net.Addr              { return dummyAddr("stdio") }
func (c stdioConn) RemoteAddr() net.Addr             { return dummyAddr("derptun") }
func (c stdioConn) SetDeadline(time.Time) error      { return nil }
func (c stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c stdioConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
```

- [ ] **Step 9: Run session tests**

Run: `go test ./pkg/session -run TestDerptun -count=1`

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add pkg/session/derptun.go pkg/session/derptun_test.go
git commit -m "feat: add derptun session flows"
```

### Task 6: Derptun CLI

**Files:**
- Create: `cmd/derptun/main.go`
- Create: `cmd/derptun/root.go`
- Create: `cmd/derptun/token.go`
- Create: `cmd/derptun/serve.go`
- Create: `cmd/derptun/open.go`
- Create: `cmd/derptun/connect.go`
- Create: `cmd/derptun/transport_mode.go`
- Create: `cmd/derptun/version.go`
- Create: `cmd/derptun/root_test.go`
- Create: `cmd/derptun/token_test.go`
- Create: `cmd/derptun/open_test.go`

- [ ] **Step 1: Write failing CLI tests**

Create `cmd/derptun/root_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpShowsDerptunCommands(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--help"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	out := stderr.String()
	for _, want := range []string{"derptun", "token", "serve", "open", "connect"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q in:\n%s", want, out)
		}
	}
}
```

Create `cmd/derptun/token_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunTokenPrintsDerptunToken(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"token", "--days", "7"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "dt1_") {
		t.Fatalf("stdout = %q, want derptun token", stdout.String())
	}
}
```

- [ ] **Step 2: Run CLI tests and verify they fail**

Run: `go test ./cmd/derptun -run 'TestRootHelpShowsDerptunCommands|TestRunTokenPrintsDerptunToken' -count=1`

Expected: FAIL because `cmd/derptun` does not exist.

- [ ] **Step 3: Create CLI main and version**

Create `cmd/derptun/main.go`:

```go
package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
```

Create `cmd/derptun/version.go`:

```go
package main

import (
	"fmt"
	"io"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func runVersion(stdout, stderr io.Writer) int {
	_ = stderr
	fmt.Fprintln(stdout, version)
	return 0
}
```

- [ ] **Step 4: Create root command**

Create `cmd/derptun/root.go`:

```go
package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type rootGlobalFlags struct {
	Verbose bool `flag:"verbose" short:"v" help:"Show tunnel status updates"`
	Quiet   bool `flag:"quiet" short:"q" help:"Reduce tunnel status output"`
	Silent  bool `flag:"silent" short:"s" help:"Suppress tunnel status output"`
}

var rootRegistry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Open durable TCP tunnels through DERP rendezvous and direct UDP promotion.",
		Examples: []string{
			"derptun token --days 7",
			"derptun serve --token <token> --tcp 127.0.0.1:22",
			"derptun open --token <token> --listen 127.0.0.1:2222",
			"ssh -o ProxyCommand='derptun connect --token ~/.config/derptun/alpha.token --stdio' foo@alpha",
		},
	},
	SubCommands: map[string]yargs.CommandSpec{
		"token":   {Info: yargs.SubCommandInfo{Name: "token", Description: "Generate a durable tunnel token."}},
		"serve":   {Info: yargs.SubCommandInfo{Name: "serve", Description: "Serve a local TCP target through a tunnel token."}},
		"open":    {Info: yargs.SubCommandInfo{Name: "open", Description: "Open a local TCP listener for a tunnel token."}},
		"connect": {Info: yargs.SubCommandInfo{Name: "connect", Description: "Connect one tunnel stream over stdin/stdout."}},
		"version": {Info: yargs.SubCommandInfo{Name: "version", Description: "Print the derptun version."}},
	},
}

var rootHelpConfig = rootRegistry.HelpConfig()

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseKnownFlags[rootGlobalFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	level, err := rootTelemetryLevel(parsed.Flags)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	remaining := parsed.RemainingArgs
	if len(remaining) == 0 || isRootHelpRequest(remaining) {
		fmt.Fprint(stderr, rootHelpText())
		return 0
	}
	if strings.HasPrefix(remaining[0], "-") {
		fmt.Fprintf(stderr, "unknown flag: %s\n", remaining[0])
		fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	switch remaining[0] {
	case "token":
		return runToken(remaining[1:], stdout, stderr)
	case "serve":
		return runServe(remaining[1:], level, stderr)
	case "open":
		return runOpen(remaining[1:], level, stderr)
	case "connect":
		return runConnect(remaining[1:], level, stdin, stdout, stderr)
	case "version":
		return runVersion(stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\nRun 'derptun --help' for usage\n", remaining[0])
		return 2
	}
}

func rootHelpText() string {
	return yargs.GenerateGlobalHelp(rootHelpConfig, rootGlobalFlags{})
}

func isRootHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help")
}

func rootTelemetryLevel(flags rootGlobalFlags) (telemetry.Level, error) {
	count := 0
	level := telemetry.LevelDefault
	if flags.Verbose {
		count++
		level = telemetry.LevelVerbose
	}
	if flags.Quiet {
		count++
		level = telemetry.LevelQuiet
	}
	if flags.Silent {
		count++
		level = telemetry.LevelSilent
	}
	if count > 1 {
		return telemetry.LevelDefault, fmt.Errorf("only one of --verbose, --quiet, or --silent may be set")
	}
	return level, nil
}
```

- [ ] **Step 5: Create token command**

Create `cmd/derptun/token.go`:

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/yargs"
)

type tokenFlags struct {
	Days    int    `flag:"days" help:"Token lifetime in days"`
	Expires string `flag:"expires" help:"Absolute RFC3339 expiry timestamp"`
}
type tokenArgs struct{}

func runToken(args []string, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, tokenFlags, tokenArgs](append([]string{"token"}, args...), rootHelpConfig)
	if err != nil {
		if errors.Is(err, yargs.ErrHelp) || errors.Is(err, yargs.ErrSubCommandHelp) {
			fmt.Fprint(stderr, yargs.GenerateSubCommandHelp(rootHelpConfig, "token", struct{}{}, tokenFlags{}, tokenArgs{}))
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	var expires time.Time
	if parsed.SubCommandFlags.Expires != "" {
		expires, err = time.Parse(time.RFC3339, parsed.SubCommandFlags.Expires)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	tokenValue, err := derptun.GenerateToken(derptun.TokenOptions{Days: parsed.SubCommandFlags.Days, Expires: expires})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, tokenValue)
	return 0
}
```

- [ ] **Step 6: Create serve/open/connect commands**

Create `cmd/derptun/serve.go`, `cmd/derptun/open.go`, and `cmd/derptun/connect.go` using the existing `cmd/derphole/share.go` and `cmd/derphole/open.go` parsing style. The command functions must call:

```go
session.DerptunServe(ctx, session.DerptunServeConfig{Token: tokenValue, TargetAddr: tcpAddr, Emitter: telemetry.New(stderr, commandSessionTelemetryLevel(level)), ForceRelay: forceRelay, UsePublicDERP: usePublicDERPTransport()})
session.DerptunOpen(ctx, session.DerptunOpenConfig{Token: tokenValue, ListenAddr: listenAddr, BindAddrSink: bindSink, Emitter: telemetry.New(stderr, commandSessionTelemetryLevel(level)), ForceRelay: forceRelay, UsePublicDERP: usePublicDERPTransport()})
session.DerptunConnect(ctx, session.DerptunConnectConfig{Token: tokenValue, StdioIn: stdin, StdioOut: stdout, Emitter: telemetry.New(stderr, commandSessionTelemetryLevel(level)), ForceRelay: forceRelay, UsePublicDERP: usePublicDERPTransport()})
```

Create `cmd/derptun/transport_mode.go`:

```go
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/shayne/derphole/pkg/telemetry"
)

var commandContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func usePublicDERPTransport() bool {
	return os.Getenv("DERPHOLE_TEST_LOCAL_RELAY") != "1"
}

func commandSessionTelemetryLevel(level telemetry.Level) telemetry.Level {
	if level == telemetry.LevelDefault {
		return telemetry.LevelQuiet
	}
	return level
}
```

- [ ] **Step 7: Run CLI tests**

Run: `go test ./cmd/derptun -count=1`

Expected: PASS.

- [ ] **Step 8: Build derptun binary**

Run: `go build -o dist/derptun ./cmd/derptun && dist/derptun version`

Expected: command prints `dev`.

- [ ] **Step 9: Commit**

```bash
git add cmd/derptun
git commit -m "feat: add derptun cli"
```

### Task 7: Packaging And Release Matrix

**Files:**
- Modify: `.mise.toml`
- Modify: `tools/packaging/build-vendor.sh`
- Modify: `tools/packaging/build-npm.sh`
- Modify: `tools/packaging/build-release-assets.sh`
- Modify: `scripts/release-package-smoke.sh`
- Modify: `.github/workflows/release.yml`
- Create: `packaging/npm/derptun/package.json`
- Create: `packaging/npm/derptun/bin/derptun.js`

- [ ] **Step 1: Write failing package smoke expectations**

In `scripts/release-package-smoke.sh`, change every product loop from:

```bash
for product in derphole; do
```

to:

```bash
for product in derphole derptun; do
```

- [ ] **Step 2: Run package smoke and verify it fails**

Run: `VERSION=v0.0.0-test bash ./scripts/release-package-smoke.sh`

Expected: FAIL because `cmd/derptun` is not yet included in packaging scripts.

- [ ] **Step 3: Add npm package metadata**

Create `packaging/npm/derptun/package.json`:

```json
{
  "name": "derptun",
  "version": "0.0.0",
  "license": "BSD-3-Clause",
  "bin": {
    "derptun": "bin/derptun.js"
  },
  "type": "module",
  "os": [
    "linux",
    "darwin"
  ],
  "cpu": [
    "x64",
    "arm64"
  ],
  "engines": {
    "node": ">=16"
  },
  "files": [
    "bin",
    "vendor",
    "README.md",
    "LICENSE"
  ],
  "repository": {
    "type": "git",
    "url": "git+https://github.com/shayne/derphole.git"
  }
}
```

Create `packaging/npm/derptun/bin/derptun.js`:

```js
#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const triples = new Map([
  ["linux:x64", "x86_64-unknown-linux-musl"],
  ["linux:arm64", "aarch64-unknown-linux-musl"],
  ["darwin:x64", "x86_64-apple-darwin"],
  ["darwin:arm64", "aarch64-apple-darwin"]
]);

const triple = triples.get(`${process.platform}:${process.arch}`);
if (!triple) {
  console.error(`Unsupported platform: ${process.platform} (${process.arch})`);
  process.exit(1);
}

const binaryName = process.platform === "win32" ? "derptun.exe" : "derptun";
const binaryPath = path.join(__dirname, "..", "vendor", triple, "derptun", binaryName);
if (!existsSync(binaryPath)) {
  console.error(`Missing vendored binary: ${binaryPath}`);
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: { ...process.env, DERPTUN_MANAGED_BY_NPM: "1" }
});

child.on("error", (err) => {
  const reason = err instanceof Error ? err.message : String(err);
  console.error(`Failed to launch vendored binary: ${reason}`);
  process.exit(1);
});

["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
  process.on(sig, () => {
    if (!child.killed) {
      child.kill(sig);
    }
  });
});

const result = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ signal });
      return;
    }
    resolve({ code: code ?? 1 });
  });
});

if (result.signal) {
  const signalNumber = os.constants.signals[result.signal];
  process.exit(typeof signalNumber === "number" ? 128 + signalNumber : 1);
} else {
  process.exit(result.code);
}
```

- [ ] **Step 4: Update local build tasks and packaging scripts**

In `.mise.toml`, update build and release product loops to `derphole derptun`. The build task should write both `dist/derphole` and `dist/derptun`:

```bash
mkdir -p dist
go build -o dist/derphole ./cmd/derphole
go build -o dist/derptun ./cmd/derptun
```

In `tools/packaging/build-vendor.sh`, `tools/packaging/build-npm.sh`, and `tools/packaging/build-release-assets.sh`, change:

```bash
for product in derphole; do
```

to:

```bash
for product in derphole derptun; do
```

- [ ] **Step 5: Update release workflow matrix**

In `.github/workflows/release.yml`, expand the `build-binaries` matrix to include four `derptun` assets:

```yaml
- product: derptun
  runner: ubuntu-latest
  goos: linux
  goarch: amd64
  asset: derptun-linux-amd64
- product: derptun
  runner: ubuntu-latest
  goos: linux
  goarch: arm64
  asset: derptun-linux-arm64
- product: derptun
  runner: macos-latest
  goos: darwin
  goarch: amd64
  asset: derptun-darwin-amd64
- product: derptun
  runner: macos-latest
  goos: darwin
  goarch: arm64
  asset: derptun-darwin-arm64
```

Change artifact downloads, raw staging, release file lists, npm package tarball contents, dry-run commands, smoke launcher commands, and publish commands so both `dist/npm-derphole` and `dist/npm-derptun` are validated and published. Keep `publish-npm-if-missing.sh --skip-unclaimed` for both package paths.

- [ ] **Step 6: Run package smoke**

Run: `VERSION=v0.0.0-test bash ./scripts/release-package-smoke.sh`

Expected: PASS and `node dist/npm-derptun/bin/derptun.js version` prints `v0.0.0-test`.

- [ ] **Step 7: Run npm dry run**

Run: `VERSION=v0.0.0-test mise run release:npm-dry-run`

Expected: PASS with dry-run output for `derphole` and `derptun`.

- [ ] **Step 8: Commit**

```bash
git add .mise.toml tools/packaging/build-vendor.sh tools/packaging/build-npm.sh tools/packaging/build-release-assets.sh scripts/release-package-smoke.sh .github/workflows/release.yml packaging/npm/derptun
git commit -m "build: package derptun"
```

### Task 8: Documentation And Smoke

**Files:**
- Modify: `README.md`
- Create: `scripts/smoke-remote-derptun.sh`
- Modify: `.mise.toml`

- [ ] **Step 1: Add remote smoke script**

Create `scripts/smoke-remote-derptun.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: smoke-remote-derptun.sh HOST}"
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
remote_user="${DERPHOLE_REMOTE_USER:-root}"
remote_base="/tmp/derptun-smoke-$$"
remote_upload="/tmp/derptun-bin-$$"
token_file="$(mktemp)"
open_log="$(mktemp)"
serve_log="$(mktemp)"
open_pid=""
cleanup() {
  if [[ -n "${open_pid}" ]]; then
    kill "${open_pid}" >/dev/null 2>&1 || true
    wait "${open_pid}" >/dev/null 2>&1 || true
  fi
  ssh "${remote_user}@${target}" "pkill -f '${remote_base}' >/dev/null 2>&1 || true; rm -rf '${remote_base}' '${remote_upload}'" >/dev/null 2>&1 || true
  rm -f "$token_file"
  rm -f "$open_log" "$serve_log"
}
trap cleanup EXIT

VERSION="${VERSION:-v0.0.0-smoke}" go build -o "${root_dir}/dist/derptun" "${root_dir}/cmd/derptun"
"${root_dir}/dist/derptun" token --days 1 > "$token_file"

ssh "${remote_user}@${target}" "mkdir -p '${remote_base}'"
scp "${root_dir}/dist/derptun" "${remote_user}@${target}:${remote_upload}" >/dev/null
ssh "${remote_user}@${target}" "install -m 0755 '${remote_upload}' '${remote_base}/derptun'"
scp "$token_file" "${remote_user}@${target}:${remote_base}/token" >/dev/null

ssh "${remote_user}@${target}" "nohup sh -c 'while true; do printf \"pong\n\" | nc -l 127.0.0.1 22345; done' >'${remote_base}/echo.log' 2>&1 &"
ssh "${remote_user}@${target}" "DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 nohup '${remote_base}/derptun' --verbose serve --token \"\$(cat '${remote_base}/token')\" --tcp 127.0.0.1:22345 >'${remote_base}/serve.out' 2>'${remote_base}/serve.err' &"

sleep 2
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 "${root_dir}/dist/derptun" --verbose open --token "$(cat "$token_file")" --listen 127.0.0.1:22346 >"$open_log" 2>&1 &
open_pid=$!
sleep 2
got=$(printf "ping\n" | nc 127.0.0.1 22346)
test "$got" = "pong"

ssh "${remote_user}@${target}" "cat '${remote_base}/serve.err'" >"$serve_log" || true
if ! grep -q 'connected-direct' "$open_log"; then
  echo "local derptun open did not report connected-direct with Tailscale candidates disabled" >&2
  sed -n '1,200p' "$open_log" >&2
  exit 1
fi
if ! grep -q 'connected-direct' "$serve_log"; then
  echo "remote derptun serve did not report connected-direct with Tailscale candidates disabled" >&2
  sed -n '1,200p' "$serve_log" >&2
  exit 1
fi
```

Make it executable: `chmod +x scripts/smoke-remote-derptun.sh`.

- [ ] **Step 2: Add mise task**

In `.mise.toml`, add:

```toml
[tasks.smoke-remote-derptun]
shell = "bash -c"
run = """
set -euo pipefail
: "${REMOTE_HOST:?set REMOTE_HOST to a reachable SSH host}"
./scripts/smoke-remote-derptun.sh "${REMOTE_HOST}"
"""
```

- [ ] **Step 3: Edit README derptun section**

Add a concise section after the existing TCP service sharing example:

```markdown
## Durable SSH tunnels with derptun

`derptun` is the durable TCP tunnel companion to `derphole`. Use it when a host is behind NAT and you want a stable token that can be reused for days instead of a one-hour, session-scoped share token.

On the target host:

```sh
npx -y derptun@latest token --days 7 > alpha.token
npx -y derptun@latest serve --token "$(cat alpha.token)" --tcp 127.0.0.1:22
```

On the client:

```sh
npx -y derptun@latest open --token "$(cat alpha.token)" --listen 127.0.0.1:2222
ssh -p 2222 foo@127.0.0.1
```

For a one-command SSH config:

```sshconfig
Host alpha-derptun
  HostName alpha
  User foo
  ProxyCommand derptun connect --token ~/.config/derptun/alpha.token --stdio
```

`derptun` keeps trying when the network path drops, and it can reconnect while the two `derptun` processes stay alive. If either process exits, the token can bring the tunnel back, but an already-open SSH TCP session is gone. Use `tmux` or `screen` on the remote host when shell continuity matters.

The first `derptun` release is TCP-only. UDP forwarding is planned for uses such as Minecraft Bedrock servers, but it is not part of this release.
```

Keep the README prose tight and grammatical. The repo guideline says README edits should use the Caveman skill for compression, but the README itself must remain proper English.

- [ ] **Step 4: Run docs and build checks**

Run: `mise run build`

Expected: PASS and creates `dist/derphole` plus `dist/derptun`.

Run: `go test ./cmd/derptun ./pkg/derptun ./pkg/session -run 'TestDerptun|TestMux|TestGenerateToken|TestRunToken' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md scripts/smoke-remote-derptun.sh .mise.toml
git commit -m "docs: document derptun ssh tunnels"
```

### Task 9: Final Verification

**Files:**
- No source edits expected.

- [ ] **Step 1: Run full tests**

Run: `mise run test`

Expected: PASS.

- [ ] **Step 2: Run vet**

Run: `mise run vet`

Expected: PASS.

- [ ] **Step 3: Run build**

Run: `mise run build`

Expected: PASS and both binaries exist:

```bash
test -x dist/derphole
test -x dist/derptun
```

- [ ] **Step 4: Run package smoke**

Run: `VERSION=v0.0.0-test bash ./scripts/release-package-smoke.sh`

Expected: PASS.

- [ ] **Step 5: Run ktzlxc e2e without Tailscale candidates**

Run: `DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 REMOTE_HOST=ktzlxc mise run smoke-remote-derptun`

Expected: PASS, the TCP payload returns `pong`, and both local `open` and remote `serve` logs contain `connected-direct`. This verifies the tunnel path does not rely on Tailscale candidate addresses.

- [ ] **Step 6: Run npm dry run**

Run: `VERSION=v0.0.0-test mise run release:npm-dry-run`

Expected: PASS.

- [ ] **Step 7: Run hooks**

Run: `mise run check:hooks`

Expected: PASS.

- [ ] **Step 8: Commit any verification-only adjustments**

When verification required changes, commit them:

```bash
git add -A
git commit -m "test: stabilize derptun verification"
```

If no files changed, do not create an empty commit.

- [ ] **Step 9: Push and watch CI when user approves execution**

```bash
git status --short --branch
git push origin main
gh run list --repo shayne/derphole --branch main --limit 5
```

Expected: branch pushes cleanly and GitHub Actions starts checks for `main`.
