# derpcat Share/Open Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current one-shot TCP bridge with persistent `share` / `open` service forwarding while keeping `listen` / `send` as one-shot stdio commands.

**Architecture:** Keep the current DERP bootstrap, rendezvous, relay fallback, and userspace WireGuard underlay. Add a new long-lived service-sharing layer that promotes the existing overlay TCP listener into a multi-connection forwarder: `share` listens on the overlay and bridges each forwarded connection to the target service, while `open` accepts local TCP connections and dials the overlay repeatedly over the same claimed peer session.

**Tech Stack:** Go 1.26, `github.com/shayne/yargs`, existing `pkg/session`, `pkg/token`, `pkg/wg`, `pkg/stream`, `mise`, pre-commit, existing smoke scripts plus new share/open smoke coverage.

---

## File Structure

- `cmd/derpcat/root.go`
  Register `share` and `open`, remove TCP flags from `listen` / `send`, keep root help coherent.
- `cmd/derpcat/share.go`
  Parse `share <target-addr>` and call `session.Share`.
- `cmd/derpcat/open.go`
  Parse `open <token> [bind-addr]` and call `session.Open`.
- `cmd/derpcat/listen.go`
  Keep stdio-only one-shot listener behavior.
- `cmd/derpcat/send.go`
  Keep stdio-only one-shot sender behavior.
- `cmd/derpcat/root_test.go`
  Update root help, command dispatch, and removed TCP flag coverage.
- `cmd/derpcat/share_test.go`
  New CLI tests for `share`.
- `cmd/derpcat/open_test.go`
  New CLI tests for `open`.
- `pkg/token/token.go`
  Replace the token payload with the new service-sharing metadata shape.
- `pkg/token/token_test.go`
  Add round-trip coverage for the new token shape.
- `pkg/session/types.go`
  Add `ShareConfig` / `OpenConfig` and remove one-shot TCP fields from stdio configs.
- `pkg/session/share.go`
  Public `Share` entrypoint, local-mode harness, and common lifecycle helpers.
- `pkg/session/open.go`
  Public `Open` entrypoint and bind-address selection.
- `pkg/session/external_share.go`
  Public-DERP implementation for long-lived `share` / `open`.
- `pkg/session/session_test.go`
  Remove one-shot TCP tests and add multi-connection share/open tests.
- `scripts/smoke-remote-share.sh`
  New remote smoke for persistent TCP sharing.
- `.mise.toml`
  Replace the old TCP smoke task with a share/open smoke task.
- `README.md`
  Document the new service-sharing commands.

### Task 1: Lock The CLI Contract

**Files:**
- Create: `cmd/derpcat/share.go`
- Create: `cmd/derpcat/open.go`
- Create: `cmd/derpcat/share_test.go`
- Create: `cmd/derpcat/open_test.go`
- Modify: `cmd/derpcat/root.go`
- Modify: `cmd/derpcat/root_test.go`
- Modify: `cmd/derpcat/listen.go`
- Modify: `cmd/derpcat/send.go`

- [ ] **Step 1: Write failing root and command tests**

```go
func TestRunShareHelpShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"share", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	for _, want := range []string{
		"Share a local TCP service until Ctrl-C.",
		"derpcat share <target-addr>",
		"127.0.0.1:3000",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestRunOpenHelpShowsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"open", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	for _, want := range []string{
		"Open a shared service locally until Ctrl-C.",
		"derpcat open <token> [bind-addr]",
		"127.0.0.1:8080",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestRunListenRejectsRemovedTCPFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"listen", "--tcp-connect", "127.0.0.1:3000"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.HasPrefix(stderr.String(), "unknown flag: --tcp-connect\n") {
		t.Fatalf("stderr = %q, want removed-flag parse error", stderr.String())
	}
}

func TestRunSendRejectsRemovedTCPFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "token-value", "--tcp-listen", "127.0.0.1:8080"}, nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.HasPrefix(stderr.String(), "unknown flag: --tcp-listen\n") {
		t.Fatalf("stderr = %q, want removed-flag parse error", stderr.String())
	}
}
```

- [ ] **Step 2: Run the CLI package tests and verify they fail for missing commands / old flags**

Run: `mise exec -- go test ./cmd/derpcat -run 'TestRunShare|TestRunOpen|TestRunListenRejectsRemovedTCPFlags|TestRunSendRejectsRemovedTCPFlags' -count=1`

Expected: FAIL with unknown-command errors for `share` / `open`, or stale `listen` / `send` help still mentioning TCP flags.

- [ ] **Step 3: Implement the new parser surface**

```go
// cmd/derpcat/share.go
type shareArgs struct {
	Target string `pos:"0" help:"Local TCP service to expose, for example 127.0.0.1:3000"`
}

func runShare(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, shareFlags, shareArgs](append([]string{"share"}, args...), shareHelpConfig)
	if err != nil {
		if parsed != nil && parsed.HelpText != "" {
			fmt.Fprint(stderr, parsed.HelpText)
			return 0
		}
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, shareHelpText())
		return 2
	}
	_, err = session.Share(context.Background(), session.ShareConfig{
		Emitter:       telemetry.New(stderr, level),
		TokenSink:     nil,
		TargetAddr:    parsed.Args.Target,
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP: usePublicDERPTransport(),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// cmd/derpcat/open.go
type openArgs struct {
	Token   string `pos:"0" help:"Token from the sharer"`
	BindAddr string `pos:"1?" help:"Optional local bind address, for example 127.0.0.1:8080"`
}

func runOpen(args []string, level telemetry.Level, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, openFlags, openArgs](append([]string{"open"}, args...), openHelpConfig)
	if err != nil {
		if parsed != nil && parsed.HelpText != "" {
			fmt.Fprint(stderr, parsed.HelpText)
			return 0
		}
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, openHelpText())
		return 2
	}
	err = session.Open(context.Background(), session.OpenConfig{
		Token:         parsed.Args.Token,
		BindAddr:      parsed.Args.BindAddr,
		BindAddrSink:  nil,
		Emitter:       telemetry.New(stderr, level),
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP: usePublicDERPTransport(),
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// cmd/derpcat/root.go
switch remaining[0] {
case "listen":
	return runListen(remaining[1:], level, stdout, stderr)
case "send":
	return runSend(remaining[1:], level, stdin, stdout, stderr)
case "share":
	return runShare(remaining[1:], level, stdout, stderr)
case "open":
	return runOpen(remaining[1:], level, stdout, stderr)
case "version":
	return runVersion(remaining[1:], stdout, stderr)
}
```

- [ ] **Step 4: Remove one-shot TCP flags from `listen` and `send`**

```go
// cmd/derpcat/listen.go
type listenFlags struct {
	PrintTokenOnly bool `flag:"print-token-only" help:"Print only the session token"`
	ForceRelay     bool `flag:"force-relay" help:"Disable direct probing"`
}

// cmd/derpcat/send.go
type sendFlags struct {
	ForceRelay bool `flag:"force-relay" help:"Disable direct probing"`
}
```

- [ ] **Step 5: Run the CLI package tests and verify they pass**

Run: `mise exec -- go test ./cmd/derpcat -count=1`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/derpcat/root.go cmd/derpcat/root_test.go cmd/derpcat/listen.go cmd/derpcat/send.go cmd/derpcat/share.go cmd/derpcat/open.go cmd/derpcat/share_test.go cmd/derpcat/open_test.go
git commit -m "cmd: add share and open commands"
```

### Task 2: Replace The Token Shape For Share/Open

**Files:**
- Modify: `pkg/token/token.go`
- Test: `pkg/token/token_test.go`

- [ ] **Step 1: Write the failing token tests**

```go
func TestTokenRoundTripShareMetadata(t *testing.T) {
	var sessionID [16]byte
	copy(sessionID[:], []byte("abcdefghijklmnop"))

	encoded, err := Encode(Token{
		Version:         CurrentVersion,
		SessionID:       sessionID,
		ExpiresUnix:     time.Now().Add(time.Hour).Unix(),
		Capabilities:    CapabilityTCPShare,
		ShareTargetAddr: "127.0.0.1:3000",
		DefaultBindHost: "127.0.0.1",
		DefaultBindPort: 0,
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	got, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.ShareTargetAddr != "127.0.0.1:3000" || got.DefaultBindHost != "127.0.0.1" || got.DefaultBindPort != 0 {
		t.Fatalf("decoded token = %#v", got)
	}
}
```

- [ ] **Step 2: Run the token tests and verify they fail**

Run: `mise exec -- go test ./pkg/token -run 'TestTokenRoundTripShareMetadata' -count=1`

Expected: FAIL with missing fields or unsupported share metadata.

- [ ] **Step 3: Replace the token payload with the new shape**

```go
const (
	CurrentVersion uint8 = 2

	CapabilityStdio uint32 = 1 << iota
	CapabilityTCPShare
)

type Token struct {
	Version         uint8
	SessionID       [16]byte
	ExpiresUnix     int64
	BootstrapRegion uint16
	DERPPublic      [32]byte
	WGPublic        [32]byte
	DiscoPublic     [32]byte
	BearerSecret    [32]byte
	Capabilities    uint32

	ShareTargetAddr string
	DefaultBindHost string
	DefaultBindPort uint16
}

func Encode(tok Token) (string, error) {
	if tok.Version == 0 {
		tok.Version = CurrentVersion
	}
	if tok.Version != CurrentVersion {
		return "", ErrUnsupportedVersion
	}
	return encodeCurrent(tok)
}

func Decode(encoded string, now time.Time) (Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Token{}, err
	}
	if len(raw) < 1 || raw[0] != CurrentVersion {
		return Token{}, ErrUnsupportedVersion
	}
	return decodeCurrent(raw, now)
}
```

- [ ] **Step 4: Run token tests and full token package tests**

Run: `mise exec -- go test ./pkg/token -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/token/token.go pkg/token/token_test.go
git commit -m "token: replace token payload for share metadata"
```

### Task 3: Add Persistent Share/Open Session APIs

**Files:**
- Modify: `pkg/session/types.go`
- Create: `pkg/session/share.go`
- Create: `pkg/session/open.go`
- Modify: `pkg/session/attach.go`
- Test: `pkg/session/session_test.go`

- [ ] **Step 1: Write failing session-level tests for repeated forwarding**

```go
func TestLocalShareOpenSupportsSequentialTCPConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	targetLn := mustListenTCP(t)
	defer targetLn.Close()
	go serveFixedReply(t, targetLn, "hello one")

	tokenCh := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			TokenSink:      tokenCh,
			TargetAddr:     targetLn.Addr().String(),
			UsePublicDERP:  false,
		})
		shareErr <- err
	}()

	token := <-tokenCh
	openErr := make(chan error, 1)
	openAddrCh := make(chan string, 1)
	go func() {
		err := Open(ctx, OpenConfig{
			Token:         token,
			BindAddrSink:  openAddrCh,
			UsePublicDERP: false,
		})
		openErr <- err
	}()

	bindAddr := <-openAddrCh
	readOnce(t, bindAddr, "hello one")
	readOnce(t, bindAddr, "hello one")

	cancel()
	<-openErr
	<-shareErr
}
```

- [ ] **Step 2: Run the session tests and verify they fail**

Run: `mise exec -- go test ./pkg/session -run 'TestLocalShareOpenSupportsSequentialTCPConnections' -count=1`

Expected: FAIL with undefined `Share`, `Open`, or missing config types.

- [ ] **Step 3: Add explicit share/open config types and narrow stdio configs**

```go
type ListenConfig struct {
	Emitter       *telemetry.Emitter
	TokenSink     chan<- string
	StdioOut      io.Writer
	ForceRelay    bool
	UsePublicDERP bool
}

type SendConfig struct {
	Token         string
	Emitter       *telemetry.Emitter
	StdioIn       io.Reader
	ForceRelay    bool
	UsePublicDERP bool
}

type ShareConfig struct {
	Emitter        *telemetry.Emitter
	TokenSink      chan<- string
	TargetAddr     string
	PrintTokenOnly bool
	ForceRelay     bool
	UsePublicDERP  bool
}

type OpenConfig struct {
	Token         string
	Emitter       *telemetry.Emitter
	BindAddr      string
	BindAddrSink  chan<- string
	ForceRelay    bool
	UsePublicDERP bool
}
```

- [ ] **Step 4: Implement local-mode `Share` and `Open` harnesses**

```go
func Share(ctx context.Context, cfg ShareConfig) (string, error) {
	if cfg.UsePublicDERP {
		return shareExternal(ctx, cfg)
	}
	return shareLocal(ctx, cfg)
}

func Open(ctx context.Context, cfg OpenConfig) error {
	if cfg.UsePublicDERP {
		return openExternal(ctx, cfg)
	}
	return openLocal(ctx, cfg)
}
```

```go
// local-mode shape for tests only
type localShareSession struct {
	token      token.Token
	claimed    atomic.Bool
	targetAddr string
}
```

- [ ] **Step 5: Run the session tests and verify the local harness passes**

Run: `mise exec -- go test ./pkg/session -run 'TestLocalShareOpenSupportsSequentialTCPConnections' -count=1`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/session/types.go pkg/session/share.go pkg/session/open.go pkg/session/attach.go pkg/session/session_test.go
git commit -m "session: add share and open APIs"
```

### Task 4: Promote The Overlay To A Multi-Connection Forwarder

**Files:**
- Create: `pkg/session/external_share.go`
- Modify: `pkg/session/external.go`
- Test: `pkg/session/session_test.go`

- [ ] **Step 1: Write failing external-style forwarding tests**

```go
func TestLocalShareOpenSupportsConcurrentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	targetLn := mustListenTCP(t)
	defer targetLn.Close()
	go serveEcho(t, targetLn)

	tokenCh := make(chan string, 1)
	go func() {
		_, _ = Share(ctx, ShareConfig{
			TokenSink:     tokenCh,
			TargetAddr:    targetLn.Addr().String(),
			UsePublicDERP: false,
		})
	}()
	token := <-tokenCh

	bindCh := make(chan string, 1)
	go func() {
		_ = Open(ctx, OpenConfig{
			Token:         token,
			BindAddrSink:  bindCh,
			UsePublicDERP: false,
		})
	}()
	bindAddr := <-bindCh

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := fmt.Sprintf("hello-%d", i)
			assertEcho(t, bindAddr, payload)
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run the focused session tests and verify they fail**

Run: `mise exec -- go test ./pkg/session -run 'TestLocalShareOpenSupportsConcurrentConnections' -count=1`

Expected: FAIL because the current implementation still tears down after one bridged connection.

- [ ] **Step 3: Implement persistent overlay forwarding using the existing WG TCP listener**

```go
func shareExternal(ctx context.Context, cfg ShareConfig) (string, error) {
	// issue token with share metadata
	// wait for exactly one claimant
	// build wg.Node
	// ln, err := sessionNode.ListenTCP(overlayPort)
	// accept overlay TCP connections in a loop
	// for each conn: go bridgeOverlayToTarget(ctx, conn, cfg.TargetAddr)
}

func openExternal(ctx context.Context, cfg OpenConfig) error {
	// decode token
	// choose bind addr (explicit or 127.0.0.1:0)
	// claim token, build wg.Node
	// localLn, err := net.Listen("tcp", bindAddr)
	// send chosen bind addr to BindAddrSink
	// for each local accept: go bridgeLocalToOverlay(ctx, localConn, sessionNode, listenerAddr, overlayPort)
}

func bridgeLocalToOverlay(ctx context.Context, local net.Conn, node *wg.Node, dst netip.AddrPort) {
	overlay, err := node.DialTCP(ctx, dst)
	if err != nil {
		_ = local.Close()
		return
	}
	go func() { _ = stream.Bridge(ctx, local, overlay) }()
}
```

- [ ] **Step 4: Make claim semantics single-peer but session semantics multi-connection**

```go
if !session.gate.TryClaim(...) {
	return errors.New("claim rejected")
}

// after claim succeeds, keep the share/open session alive and do not burn it
// after first connection closes; only the token is burned for new claimants
```

- [ ] **Step 5: Run the full session package tests**

Run: `mise exec -- go test ./pkg/session -count=1`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/session/external.go pkg/session/external_share.go pkg/session/session_test.go
git commit -m "session: forward multiple tcp connections over one share session"
```

### Task 5: Update User-Facing CLI, Docs, And Smoke Coverage

**Files:**
- Modify: `README.md`
- Modify: `.mise.toml`
- Create: `scripts/smoke-remote-share.sh`
- Modify: `cmd/derpcat/root_test.go`
- Modify: `cmd/derpcat/share_test.go`
- Modify: `cmd/derpcat/open_test.go`

- [ ] **Step 1: Write the failing docs and smoke expectations**

```bash
rg -n -- '--tcp-listen|--tcp-connect' README.md .mise.toml scripts
```

Expected: matches still exist for the removed one-shot TCP CLI.

- [ ] **Step 2: Add the new share/open smoke script**

```bash
#!/usr/bin/env bash
set -euo pipefail

remote="${1:?remote host alias required}"
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

mise run build
scp "${root_dir}/dist/derpcat" "root@${remote}:/tmp/derpcat"

python3 -m http.server 3000 --bind 127.0.0.1 >/tmp/derpcat-http.log 2>&1 &
http_pid=$!
trap 'kill ${http_pid} || true' EXIT

token="$("${root_dir}/dist/derpcat" share 127.0.0.1:3000 --print-token-only 2>/tmp/derpcat-share.log)"
ssh "root@${remote}" "/tmp/derpcat open ${token} 127.0.0.1:18080 >/tmp/derpcat-open.log 2>&1 &"
sleep 2
curl -fsS "http://127.0.0.1:18080/"
curl -fsS "http://127.0.0.1:18080/"
```

- [ ] **Step 3: Update docs and `mise` tasks**

```toml
[tasks.smoke-remote-share]
run = "./scripts/smoke-remote-share.sh hetz"
```

```md
## Share a local web server

```bash
derpcat share 127.0.0.1:3000
derpcat open <token>
```
```

- [ ] **Step 4: Run doc and smoke checks**

Run: `mise run smoke-local`

Expected: PASS

Run: `./scripts/smoke-remote-share.sh pve1`

Expected: PASS with at least two successful HTTP fetches over one claimed session.

- [ ] **Step 5: Commit**

```bash
git add README.md .mise.toml scripts/smoke-remote-share.sh
git commit -m "docs: document share and open workflow"
```

### Task 6: Full Verification And Cleanup

**Files:**
- Modify: `cmd/derpcat/listen_test.go`
- Modify: `cmd/derpcat/send_test.go`
- Modify: `pkg/session/session_test.go`

- [ ] **Step 1: Remove obsolete one-shot TCP tests**

```go
// delete tests like:
// TestRelayOnlyTCPConnectRoundTrip
// TestRelayOnlyTCPListenRoundTrip
// TestListenRejectsMutuallyExclusiveTCPFlags
// TestSendRejectsMutuallyExclusiveTCPFlags
```

- [ ] **Step 2: Add regression tests for stdio behavior remaining intact**

```go
func TestListenSendStdioStillRoundTrip(t *testing.T) {
	// existing relay-only stdio round-trip should remain untouched
}
```

- [ ] **Step 3: Run the full verification suite**

Run: `mise run check`

Expected: PASS

Run: `mise run smoke-local`

Expected: PASS

Run: `./scripts/smoke-remote-share.sh hetz`

Expected: PASS

Run: `./scripts/smoke-remote-share.sh pve1`

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/derpcat/listen_test.go cmd/derpcat/send_test.go pkg/session/session_test.go
git commit -m "test: replace one-shot tcp coverage with share forwarding tests"
```

## Self-Review

- Spec coverage:
  - CLI split is covered by Task 1.
  - token metadata and single-claimer semantics are covered by Task 2 and Task 4.
  - long-lived multi-connection forwarding is covered by Task 3 and Task 4.
  - docs and smoke coverage are covered by Task 5 and Task 6.
- Placeholder scan:
  - no `TODO`, `TBD`, or deferred implementation language remains.
- Type consistency:
  - `ShareConfig`, `OpenConfig`, `shareExternal`, and `openExternal` are named consistently across tasks.
