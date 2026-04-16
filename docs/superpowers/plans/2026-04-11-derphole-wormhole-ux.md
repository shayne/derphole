# Derphole Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second CLI, `derphole`, that delivers wormhole-shaped text/file/directory/SSH workflows on top of the existing derphole transport stack, and ship both `derphole` and `derphole` from the same release pipeline.

**Architecture:** Introduce a shared one-shot bidirectional attach primitive in `pkg/session`, then build a new `pkg/derphole` application layer and `cmd/derphole` CLI on top of it. Keep `derphole` raw `listen` / `send` and `share` / `open` semantics intact, while refactoring packaging and release scripts so both products reuse the same vendored binaries, build metadata, and npm/release workflow.

**Tech Stack:** Go, `github.com/shayne/yargs`, existing `pkg/session` / `pkg/token` / `pkg/transport`, QUIC/DERP path code already in the repo, Go `archive/tar`, GitHub Actions, npm launcher packages, `mise`.

---

## File map

### New files

- `pkg/session/attach_session.go`
  - shared one-shot bidirectional attach listener/dial API for both local and public DERP modes
- `pkg/session/attach_session_test.go`
  - local attach tests
- `pkg/session/external_attach.go`
  - public DERP attach transport built from the existing share/open QUIC path pieces
- `pkg/session/external_attach_test.go`
  - public attach tests
- `pkg/derphole/protocol/header.go`
  - transfer header format and encode/decode helpers
- `pkg/derphole/protocol/header_test.go`
  - protocol tests
- `pkg/derphole/archive/tarstream.go`
  - streaming tar sender/receiver helpers and extraction safety checks
- `pkg/derphole/archive/tarstream_test.go`
  - directory archive safety tests
- `pkg/derphole/transfer.go`
  - send/receive orchestration for text, file, and directory flows
- `pkg/derphole/transfer_test.go`
  - end-to-end transfer tests over local attach
- `pkg/derphole/ui.go`
  - prompt, instruction, verification-string, and progress helpers
- `pkg/derphole/ui_test.go`
  - prompt/instruction/verification tests
- `pkg/derphole/ssh/invite.go`
  - SSH invite/accept orchestration and payload types
- `pkg/derphole/ssh/authorized_keys.go`
  - authorized_keys update helpers
- `pkg/derphole/ssh/ssh_test.go`
  - SSH workflow tests
- `cmd/derphole/main.go`
  - derphole entrypoint
- `cmd/derphole/root.go`
  - root parser, alias dispatch, global flags
- `cmd/derphole/send.go`
  - `send` / `tx` command handler
- `cmd/derphole/receive.go`
  - `receive` / `rx` / `recv` / `recieve` command handler
- `cmd/derphole/ssh.go`
  - `ssh invite` / `ssh accept` command handlers
- `cmd/derphole/version.go`
  - version command
- `cmd/derphole/root_test.go`
  - CLI help/alias/version tests
- `cmd/derphole/send_test.go`
  - send CLI tests
- `cmd/derphole/receive_test.go`
  - receive CLI tests
- `cmd/derphole/ssh_test.go`
  - ssh CLI tests
- `packaging/npm/derphole/package.json`
  - derphole npm manifest
- `packaging/npm/derphole/bin/derphole.js`
  - derphole launcher
- `packaging/npm/derphole/package.json`
  - derphole npm manifest
- `packaging/npm/derphole/bin/derphole.js`
  - derphole launcher

### Modified files

- `pkg/token/token.go`
  - add attach capability constant
- `pkg/token/token_test.go`
  - add attach-capability round-trip test
- `pkg/session/types.go`
  - add attach config types and keep shared state reporting consistent
- `pkg/session/external_share.go`
  - extract reusable one-shot QUIC connection helpers for attach
- `.mise.toml`
  - make release tasks build/package both products
- `tools/packaging/build-npm.sh`
  - make npm staging package-aware
- `tools/packaging/build-release-assets.sh`
  - package both binaries
- `tools/packaging/build-vendor.sh`
  - vendor both commands per target triple
- `scripts/release-package-smoke.sh`
  - smoke both npm packages
- `.github/workflows/release.yml`
  - build, stage, and publish both products from one workflow
- `README.md`
  - explain `derphole` vs `derphole`
- `docs/releases/npm-bootstrap.md`
  - bootstrap both npm packages
- `AGENTS.md`
  - keep build/release guidance accurate for two products

## Task 1: Add attach capability and local one-shot attach session

**Files:**
- Modify: `pkg/token/token.go`
- Modify: `pkg/token/token_test.go`
- Modify: `pkg/session/types.go`
- Create: `pkg/session/attach_session.go`
- Create: `pkg/session/attach_session_test.go`
- Test: `pkg/token/token_test.go`
- Test: `pkg/session/attach_session_test.go`

- [ ] **Step 1: Write the failing token/session tests**

```go
// pkg/token/token_test.go
func TestEncodeDecodeRoundTripAttachToken(t *testing.T) {
	now := time.Now()
	tok := Token{
		Version:      SupportedVersion,
		ExpiresUnix:  now.Add(time.Minute).Unix(),
		Capabilities: CapabilityAttach,
	}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Capabilities&CapabilityAttach == 0 {
		t.Fatalf("Capabilities = %08b, want attach bit set", decoded.Capabilities)
	}
}

// pkg/session/attach_session_test.go
func TestListenAttachAndDialAttachLocalRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "pong"); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	conn, err := DialAttach(ctx, AttachDialConfig{Token: listener.Token})
	if err != nil {
		t.Fatalf("DialAttach() error = %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("payload = %q, want %q", got, "pong")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/token ./pkg/session -run 'TestEncodeDecodeRoundTripAttachToken|TestListenAttachAndDialAttachLocalRoundTrip' -count=1`

Expected: FAIL with `undefined: CapabilityAttach`, `undefined: ListenAttach`, and `undefined: DialAttach`.

- [ ] **Step 3: Add the minimal attach capability and local attach implementation**

```go
// pkg/token/token.go
const (
	CapabilityStdio uint32 = 1 << iota
	CapabilityShare
	CapabilityAttach
)

// pkg/session/types.go
type AttachListenConfig struct {
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

type AttachDialConfig struct {
	Token          string
	Emitter        *telemetry.Emitter
	ForceRelay     bool
	UsePublicDERP  bool
	ParallelPolicy ParallelPolicy
}

type AttachListener struct {
	Token  string
	accept func(context.Context) (net.Conn, error)
	close  func() error
}

func (l *AttachListener) Accept(ctx context.Context) (net.Conn, error) { return l.accept(ctx) }
func (l *AttachListener) Close() error                                 { return l.close() }

// pkg/session/attach_session.go
var (
	attachMu        sync.Mutex
	attachMailboxes = map[string]chan net.Conn{}
)

func issueLocalAttachToken() (string, chan net.Conn, error) {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return "", nil, err
	}
	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		return "", nil, err
	}
	encoded, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		SessionID:    sessionID,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		BearerSecret: bearerSecret,
		Capabilities: token.CapabilityAttach,
	})
	if err != nil {
		return "", nil, err
	}
	mailbox := make(chan net.Conn, 1)
	attachMu.Lock()
	attachMailboxes[encoded] = mailbox
	attachMu.Unlock()
	return encoded, mailbox, nil
}

func ListenAttach(ctx context.Context, cfg AttachListenConfig) (*AttachListener, error) {
	tok, mailbox, err := issueLocalAttachToken()
	if err != nil {
		return nil, err
	}
	return &AttachListener{
		Token: tok,
		accept: func(ctx context.Context) (net.Conn, error) {
			select {
			case conn := <-mailbox:
				return conn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		close: func() error {
			attachMu.Lock()
			delete(attachMailboxes, tok)
			attachMu.Unlock()
			return nil
		},
	}, nil
}

func DialAttach(ctx context.Context, cfg AttachDialConfig) (net.Conn, error) {
	attachMu.Lock()
	mailbox, ok := attachMailboxes[cfg.Token]
	attachMu.Unlock()
	if !ok {
		return nil, ErrUnknownSession
	}
	left, right := net.Pipe()
	select {
	case mailbox <- right:
		return left, nil
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		return nil, ctx.Err()
	}
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/token ./pkg/session -run 'TestEncodeDecodeRoundTripAttachToken|TestListenAttachAndDialAttachLocalRoundTrip' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/token/token.go pkg/token/token_test.go pkg/session/types.go pkg/session/attach_session.go pkg/session/attach_session_test.go
git commit -m "feat: add local attach session primitive"
```

## Task 2: Add public DERP attach support

**Files:**
- Create: `pkg/session/external_attach.go`
- Create: `pkg/session/external_attach_test.go`
- Modify: `pkg/session/attach_session.go`
- Modify: `pkg/session/external_share.go`
- Test: `pkg/session/external_attach_test.go`

- [ ] **Step 1: Write the failing public attach tests**

```go
// pkg/session/external_attach_test.go
func TestListenAttachAndDialAttachExternalRoundTrip(t *testing.T) {
	srv := newCommandTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{UsePublicDERP: true})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_, err = io.WriteString(conn, "hello over public attach")
		serverDone <- err
	}()

	conn, err := DialAttach(ctx, AttachDialConfig{
		Token:         listener.Token,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("DialAttach() error = %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(got) != "hello over public attach" {
		t.Fatalf("payload = %q, want %q", got, "hello over public attach")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/session -run TestListenAttachAndDialAttachExternalRoundTrip -count=1`

Expected: FAIL because `ListenAttach(...UsePublicDERP: true)` and `DialAttach(...UsePublicDERP: true)` are not implemented.

- [ ] **Step 3: Implement public attach by extracting a one-shot QUIC stream path**

```go
// pkg/session/external_attach.go
type attachPublicSession struct {
	token        token.Token
	derp         *derpbind.Client
	derpMap      *tailcfg.DERPMap
	probeConn    net.PacketConn
	quicIdentity quicpath.SessionIdentity
}

func issuePublicAttachSession(ctx context.Context, cfg AttachListenConfig) (string, *attachPublicSession, error) {
	session, err := newPublicAttachSession(ctx, cfg.Emitter)
	if err != nil {
		return "", nil, err
	}
	session.token.Capabilities = token.CapabilityAttach
	encoded, err := token.Encode(session.token)
	if err != nil {
		closePublicSessionTransport(session)
		_ = session.derp.Close()
		return "", nil, err
	}
	return encoded, session, nil
}

func acceptOneExternalAttachConn(ctx context.Context, session *attachPublicSession, cfg AttachListenConfig) (net.Conn, error) {
	return acceptOneExternalStream(ctx, session.derp, session.derpMap, session.probeConn, session.quicIdentity, session.token, cfg.ForceRelay, cfg.Emitter)
}

func openOneExternalAttachConn(ctx context.Context, cfg AttachDialConfig, tok token.Token) (net.Conn, error) {
	return openOneExternalStream(ctx, tok, cfg.ForceRelay, cfg.Emitter, cfg.ParallelPolicy)
}

func listenAttachExternal(ctx context.Context, cfg AttachListenConfig) (*AttachListener, error) {
	tok, session, err := issuePublicAttachSession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &AttachListener{
		Token: tok,
		accept: func(ctx context.Context) (net.Conn, error) {
			return acceptOneExternalAttachConn(ctx, session, cfg)
		},
		close: func() error {
			closePublicSessionTransport(session)
			return session.derp.Close()
		},
	}, nil
}

func dialAttachExternal(ctx context.Context, cfg AttachDialConfig, tok token.Token) (net.Conn, error) {
	return openOneExternalAttachConn(ctx, cfg, tok)
}

// pkg/session/attach_session.go
func ListenAttach(ctx context.Context, cfg AttachListenConfig) (*AttachListener, error) {
	if cfg.UsePublicDERP {
		return listenAttachExternal(ctx, cfg)
	}
	tok, mailbox, err := issueLocalAttachToken()
	if err != nil {
		return nil, err
	}
	return &AttachListener{
		Token: tok,
		accept: func(ctx context.Context) (net.Conn, error) {
			select {
			case conn := <-mailbox:
				return conn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		close: func() error {
			attachMu.Lock()
			delete(attachMailboxes, tok)
			attachMu.Unlock()
			return nil
		},
	}, nil
}

func DialAttach(ctx context.Context, cfg AttachDialConfig) (net.Conn, error) {
	if cfg.UsePublicDERP {
		tok, err := token.Decode(cfg.Token, time.Now())
		if err != nil {
			return nil, err
		}
		return dialAttachExternal(ctx, cfg, tok)
	}
	attachMu.Lock()
	mailbox, ok := attachMailboxes[cfg.Token]
	attachMu.Unlock()
	if !ok {
		return nil, ErrUnknownSession
	}
	left, right := net.Pipe()
	select {
	case mailbox <- right:
		return left, nil
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		return nil, ctx.Err()
	}
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/session -run TestListenAttachAndDialAttachExternalRoundTrip -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/session/attach_session.go pkg/session/external_attach.go pkg/session/external_attach_test.go pkg/session/external_share.go
git commit -m "feat: add public attach session support"
```

## Task 3: Add the derphole transfer protocol and directory tar helpers

**Files:**
- Create: `pkg/derphole/protocol/header.go`
- Create: `pkg/derphole/protocol/header_test.go`
- Create: `pkg/derphole/archive/tarstream.go`
- Create: `pkg/derphole/archive/tarstream_test.go`
- Test: `pkg/derphole/protocol/header_test.go`
- Test: `pkg/derphole/archive/tarstream_test.go`

- [ ] **Step 1: Write the failing protocol and archive tests**

```go
// pkg/derphole/protocol/header_test.go
func TestWriteReadHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Header{
		Version: 1,
		Kind:    KindFile,
		Name:    "README.md",
		Size:    123,
	}
	if err := WriteHeader(&buf, want); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	got, err := ReadHeader(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("header mismatch (-want +got):\n%s", diff)
	}
}

func TestReadHeaderRejectsBadMagic(t *testing.T) {
	r := bufio.NewReader(bytes.NewBufferString("not-derphole"))
	if _, err := ReadHeader(r); err == nil {
		t.Fatal("ReadHeader() error = nil, want failure")
	}
}

// pkg/derphole/archive/tarstream_test.go
func TestExtractTarRejectsParentTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0600, Size: int64(len("x"))}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	err := ExtractTar(bytes.NewReader(buf.Bytes()), t.TempDir(), "photos")
	if err == nil {
		t.Fatal("ExtractTar() error = nil, want traversal rejection")
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/derphole/protocol ./pkg/derphole/archive -run 'TestWriteReadHeaderRoundTrip|TestReadHeaderRejectsBadMagic|TestExtractTarRejectsParentTraversal' -count=1`

Expected: FAIL because the protocol and archive packages do not exist yet.

- [ ] **Step 3: Implement the protocol framing and tar safety helpers**

```go
// pkg/derphole/protocol/header.go
const magic = "DERPHOLE1"

type Kind string

const (
	KindText         Kind = "text"
	KindFile         Kind = "file"
	KindDirectoryTar Kind = "directory_tar"
	KindSSHInvite    Kind = "ssh_invite"
	KindSSHAccept    Kind = "ssh_accept"
)

type Header struct {
	Version  uint8  `json:"version"`
	Kind     Kind   `json:"kind"`
	Name     string `json:"name,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Verify   string `json:"verify,omitempty"`
	Metadata []byte `json:"metadata,omitempty"`
}

func WriteHeader(w io.Writer, h Header) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(raw))); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func ReadHeader(r *bufio.Reader) (Header, error) {
	var h Header
	magicBuf := make([]byte, len(magic))
	if _, err := io.ReadFull(r, magicBuf); err != nil {
		return h, err
	}
	if string(magicBuf) != magic {
		return h, errors.New("invalid derphole header magic")
	}
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return h, err
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return h, err
	}
	return h, json.Unmarshal(raw, &h)
}

// pkg/derphole/archive/tarstream.go
func ExtractTar(r io.Reader, destRoot, topLevel string) error {
	tr := tar.NewReader(r)
	base := filepath.Join(destRoot, topLevel)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe tar path %q", hdr.Name)
		}
		target := filepath.Join(base, clean)
		if !strings.HasPrefix(target, base) {
			return fmt.Errorf("unsafe tar target %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, hdr.Size)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported tar entry type %d for %q", hdr.Typeflag, hdr.Name)
		}
	}
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/derphole/protocol ./pkg/derphole/archive -run 'TestWriteReadHeaderRoundTrip|TestReadHeaderRejectsBadMagic|TestExtractTarRejectsParentTraversal' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/protocol/header.go pkg/derphole/protocol/header_test.go pkg/derphole/archive/tarstream.go pkg/derphole/archive/tarstream_test.go
git commit -m "feat: add derphole transfer protocol"
```

## Task 4: Scaffold the `derphole` CLI surface and aliases

**Files:**
- Create: `cmd/derphole/main.go`
- Create: `cmd/derphole/root.go`
- Create: `cmd/derphole/send.go`
- Create: `cmd/derphole/receive.go`
- Create: `cmd/derphole/ssh.go`
- Create: `cmd/derphole/version.go`
- Create: `cmd/derphole/root_test.go`
- Create: `cmd/derphole/send_test.go`
- Create: `cmd/derphole/receive_test.go`
- Create: `cmd/derphole/ssh_test.go`
- Test: `cmd/derphole/root_test.go`
- Test: `cmd/derphole/send_test.go`
- Test: `cmd/derphole/receive_test.go`
- Test: `cmd/derphole/ssh_test.go`

- [ ] **Step 1: Write the failing CLI surface tests**

```go
// cmd/derphole/root_test.go
func TestRunHelpReceiveShowsReceiveHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "receive"}, {"receive", "--help"}, {"rx", "--help"}, {"recv", "--help"}, {"recieve", "--help"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, nil, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run() = %d, want 0", code)
			}
			if got, want := stderr.String(), receiveHelpText(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
		})
	}
}

func TestRunHelpSSHInviteShowsSSHHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ssh", "invite", "--help"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "Add a public key to authorized_keys") {
		t.Fatalf("stderr = %q, want ssh invite help", stderr.String())
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./cmd/derphole -run 'TestRunHelpReceiveShowsReceiveHelp|TestRunHelpSSHInviteShowsSSHHelp' -count=1`

Expected: FAIL because `cmd/derphole` does not exist.

- [ ] **Step 3: Add the CLI skeleton and alias dispatch**

```go
// cmd/derphole/root.go
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rootHelpText())
		return 0
	}
	switch args[0] {
	case "send", "tx":
		return runSend(args[1:], telemetry.LevelDefault, stdin, stdout, stderr)
	case "receive", "rx", "recv", "recieve":
		return runReceive(args[1:], telemetry.LevelDefault, stdin, stdout, stderr)
	case "ssh":
		return runSSH(args[1:], telemetry.LevelDefault, stdin, stdout, stderr)
	case "version":
		return runVersion(stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stderr, rootHelpText())
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\nRun 'derphole --help' for usage\n", args[0])
		return 2
	}
}

// cmd/derphole/version.go
func runVersion(stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, version)
	_ = stderr
	return 0
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./cmd/derphole -run 'TestRunHelpReceiveShowsReceiveHelp|TestRunHelpSSHInviteShowsSSHHelp' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/derphole/main.go cmd/derphole/root.go cmd/derphole/send.go cmd/derphole/receive.go cmd/derphole/ssh.go cmd/derphole/version.go cmd/derphole/root_test.go cmd/derphole/send_test.go cmd/derphole/receive_test.go cmd/derphole/ssh_test.go
git commit -m "feat: scaffold derphole cli"
```

## Task 5: Implement text transfer, sender-first/receiver-first flows, prompting, and verification

**Files:**
- Create: `pkg/derphole/transfer.go`
- Create: `pkg/derphole/ui.go`
- Create: `pkg/derphole/transfer_test.go`
- Create: `pkg/derphole/ui_test.go`
- Modify: `cmd/derphole/send.go`
- Modify: `cmd/derphole/receive.go`
- Test: `pkg/derphole/transfer_test.go`
- Test: `pkg/derphole/ui_test.go`
- Test: `cmd/derphole/send_test.go`
- Test: `cmd/derphole/receive_test.go`

- [ ] **Step 1: Write the failing transfer and prompt tests**

```go
// pkg/derphole/transfer_test.go
func TestSendTextIssuesTokenAndTransfersPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	var sendStderr bytes.Buffer
	go func() {
		sendDone <- Send(ctx, SendConfig{
			Text:   "hello derphole",
			Stderr: &sendStderr,
		})
	}()

	token := waitForTokenLine(t, &sendStderr)
	var out bytes.Buffer
	if err := Receive(ctx, ReceiveConfig{
		Token:  token,
		Stdout: &out,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := out.String(); got != "hello derphole" {
		t.Fatalf("stdout = %q, want %q", got, "hello derphole")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestReceiveAllocateIssuesTokenAndAcceptsText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var recvOut, recvErr bytes.Buffer
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- Receive(ctx, ReceiveConfig{
			Allocate: true,
			Stdout:   &recvOut,
			Stderr:   &recvErr,
		})
	}()

	token := waitForTokenLine(t, &recvErr)
	if err := Send(ctx, SendConfig{
		Token: token,
		Text:  "allocated flow",
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if got := recvOut.String(); got != "allocated flow" {
		t.Fatalf("stdout = %q, want %q", got, "allocated flow")
	}
}

func waitForTokenLine(t *testing.T, stderr *bytes.Buffer) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(stderr.String(), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "On the other machine") && !strings.Contains(line, "derphole receive ") {
				return line
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("token line not found in stderr %q", stderr.String())
	return ""
}

// pkg/derphole/ui_test.go
func TestVerificationStringIsStable(t *testing.T) {
	if got, want := VerificationString("token-value"), VerificationString("token-value"); got != want {
		t.Fatalf("VerificationString() = %q, want stable output %q", got, want)
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/derphole ./cmd/derphole -run 'TestSendTextIssuesTokenAndTransfersPayload|TestReceiveAllocateIssuesTokenAndAcceptsText|TestVerificationStringIsStable' -count=1`

Expected: FAIL because `pkg/derphole` send/receive/ui implementations do not exist yet.

- [ ] **Step 3: Implement sender-first text flow, receiver-first allocate, and verification helpers**

```go
// pkg/derphole/ui.go
func VerificationString(token string) string {
	sum := sha256.Sum256([]byte("derphole-verify:" + token))
	hexed := strings.ToUpper(hex.EncodeToString(sum[:6]))
	return hexed[:4] + "-" + hexed[4:8] + "-" + hexed[8:12]
}

func WriteSendInstruction(stderr io.Writer, token string) {
	fmt.Fprintf(stderr, "On the other machine, run: derphole receive %s\n", token)
}

// pkg/derphole/transfer.go
type SendConfig struct {
	Token         string
	Text          string
	What          string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Verbose       bool
	UsePublicDERP bool
	ForceRelay    bool
}

type ReceiveConfig struct {
	Token         string
	Allocate      bool
	OnlyText      bool
	OutputPath    string
	AcceptFile    bool
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	PromptFor     func(io.Reader, io.Writer) (string, error)
	UsePublicDERP bool
	ForceRelay    bool
}

func Send(ctx context.Context, cfg SendConfig) error {
	if cfg.Token == "" {
		listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
		})
		if err != nil {
			return err
		}
		defer listener.Close()
		WriteSendInstruction(cfg.Stderr, listener.Token)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		return writeTextTransfer(conn, cfg.Text, listener.Token)
	}
	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         cfg.Token,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	return writeTextTransfer(conn, cfg.Text, cfg.Token)
}

func Receive(ctx context.Context, cfg ReceiveConfig) error {
	if cfg.Allocate {
		listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
		})
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintln(cfg.Stderr, listener.Token)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		return readTransfer(conn, cfg)
	}
	if cfg.Token == "" && !cfg.Allocate && cfg.PromptFor != nil {
		token, err := cfg.PromptFor(cfg.Stdin, cfg.Stderr)
		if err != nil {
			return err
		}
		cfg.Token = token
	}
	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         cfg.Token,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	return readTransfer(conn, cfg)
}

func writeTextTransfer(w io.Writer, text, token string) error {
	if err := protocol.WriteHeader(w, protocol.Header{
		Version: 1,
		Kind:    protocol.KindText,
		Verify:  VerificationString(token),
	}); err != nil {
		return err
	}
	_, err := io.WriteString(w, text)
	return err
}

func readTransfer(conn net.Conn, cfg ReceiveConfig) error {
	reader := bufio.NewReader(conn)
	hdr, err := protocol.ReadHeader(reader)
	if err != nil {
		return err
	}
	switch hdr.Kind {
	case protocol.KindText:
		_, err = io.Copy(cfg.Stdout, reader)
		return err
	case protocol.KindFile:
		return receiveFile(reader, hdr, cfg)
	case protocol.KindDirectoryTar:
		return receiveDirectory(reader, hdr, cfg)
	default:
		return fmt.Errorf("unsupported derphole transfer kind %q", hdr.Kind)
	}
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/derphole ./cmd/derphole -run 'TestSendTextIssuesTokenAndTransfersPayload|TestReceiveAllocateIssuesTokenAndAcceptsText|TestVerificationStringIsStable' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/transfer.go pkg/derphole/ui.go pkg/derphole/transfer_test.go pkg/derphole/ui_test.go cmd/derphole/send.go cmd/derphole/receive.go cmd/derphole/send_test.go cmd/derphole/receive_test.go
git commit -m "feat: add derphole text transfer flows"
```

## Task 6: Implement file transfer and output-path behavior

**Files:**
- Modify: `pkg/derphole/transfer.go`
- Create: `pkg/derphole/output.go`
- Create: `pkg/derphole/output_test.go`
- Modify: `pkg/derphole/transfer_test.go`
- Modify: `cmd/derphole/send.go`
- Modify: `cmd/derphole/receive.go`
- Test: `pkg/derphole/output_test.go`
- Test: `pkg/derphole/transfer_test.go`

- [ ] **Step 1: Write the failing file/output tests**

```go
// pkg/derphole/output_test.go
func TestResolveOutputPathUsesSuggestedFilenameInsideDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := ResolveOutputPath(dir, "photo.jpg")
	if err != nil {
		t.Fatalf("ResolveOutputPath() error = %v", err)
	}
	want := filepath.Join(dir, "photo.jpg")
	if got != want {
		t.Fatalf("ResolveOutputPath() = %q, want %q", got, want)
	}
}

// pkg/derphole/transfer_test.go
func TestSendFileTransfersSuggestedFilename(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(srcPath, []byte("hello file"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	recvDir := t.TempDir()
	var sendErr bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{What: srcPath, Stderr: &sendErr})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:      token,
		OutputPath: recvDir,
		AcceptFile: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(recvDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "hello file" {
		t.Fatalf("received = %q, want %q", got, "hello file")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/derphole -run 'TestResolveOutputPathUsesSuggestedFilenameInsideDirectory|TestSendFileTransfersSuggestedFilename' -count=1`

Expected: FAIL because file mode and output resolution are not implemented.

- [ ] **Step 3: Implement file-mode headers and receive-side path resolution**

```go
// pkg/derphole/output.go
func ResolveOutputPath(outputPath, suggested string) (string, error) {
	if outputPath == "" {
		return suggested, nil
	}
	info, err := os.Stat(outputPath)
	if err == nil && info.IsDir() {
		return filepath.Join(outputPath, filepath.Base(suggested)), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return outputPath, nil
}

// pkg/derphole/transfer.go
func writeFileTransfer(w io.Writer, path, verify string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := protocol.WriteHeader(w, protocol.Header{
		Version: 1,
		Kind:    protocol.KindFile,
		Name:    filepath.Base(path),
		Size:    info.Size(),
		Verify:  verify,
	}); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func receiveFile(r io.Reader, hdr protocol.Header, cfg ReceiveConfig) error {
	target, err := ResolveOutputPath(cfg.OutputPath, hdr.Name)
	if err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/derphole -run 'TestResolveOutputPathUsesSuggestedFilenameInsideDirectory|TestSendFileTransfersSuggestedFilename' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/transfer.go pkg/derphole/output.go pkg/derphole/output_test.go pkg/derphole/transfer_test.go cmd/derphole/send.go cmd/derphole/receive.go
git commit -m "feat: add derphole file transfer"
```

## Task 7: Implement directory transfer via tar streaming

**Files:**
- Modify: `pkg/derphole/transfer.go`
- Modify: `pkg/derphole/archive/tarstream.go`
- Modify: `pkg/derphole/archive/tarstream_test.go`
- Modify: `pkg/derphole/transfer_test.go`
- Modify: `cmd/derphole/send.go`
- Test: `pkg/derphole/archive/tarstream_test.go`
- Test: `pkg/derphole/transfer_test.go`

- [ ] **Step 1: Write the failing directory transfer tests**

```go
// pkg/derphole/transfer_test.go
func TestSendDirectoryTransfersTree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srcRoot := t.TempDir()
	dirPath := filepath.Join(srcRoot, "photos")
	if err := os.MkdirAll(filepath.Join(dirPath, "nested"), 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirPath, "nested", "a.txt"), []byte("A"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	dstRoot := t.TempDir()
	var sendErr bytes.Buffer
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- Send(ctx, SendConfig{What: dirPath, Stderr: &sendErr})
	}()

	token := waitForTokenLine(t, &sendErr)
	if err := Receive(ctx, ReceiveConfig{
		Token:      token,
		OutputPath: dstRoot,
		AcceptFile: true,
	}); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstRoot, "photos", "nested", "a.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "A" {
		t.Fatalf("received = %q, want %q", got, "A")
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/derphole ./pkg/derphole/archive -run 'TestSendDirectoryTransfersTree|TestExtractTarRejectsParentTraversal' -count=1`

Expected: FAIL because directory mode is not implemented.

- [ ] **Step 3: Implement directory detection, tar writing, and tar extraction**

```go
// pkg/derphole/transfer.go
func writeDirectoryTransfer(w io.Writer, path, verify string) error {
	if err := protocol.WriteHeader(w, protocol.Header{
		Version: 1,
		Kind:    protocol.KindDirectoryTar,
		Name:    filepath.Base(path),
		Verify:  verify,
	}); err != nil {
		return err
	}
	return archive.WriteTar(w, path)
}

func receiveDirectory(r io.Reader, hdr protocol.Header, cfg ReceiveConfig) error {
	destRoot := cfg.OutputPath
	if destRoot == "" {
		destRoot = "."
	}
	return archive.ExtractTar(r, destRoot, hdr.Name)
}

// pkg/derphole/archive/tarstream.go
func WriteTar(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		}
		return nil
	})
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/derphole ./pkg/derphole/archive -run 'TestSendDirectoryTransfersTree|TestExtractTarRejectsParentTraversal' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/transfer.go pkg/derphole/archive/tarstream.go pkg/derphole/archive/tarstream_test.go pkg/derphole/transfer_test.go cmd/derphole/send.go
git commit -m "feat: add derphole directory transfer"
```

## Task 8: Implement SSH invite/accept

**Files:**
- Create: `pkg/derphole/ssh/invite.go`
- Create: `pkg/derphole/ssh/authorized_keys.go`
- Create: `pkg/derphole/ssh/ssh_test.go`
- Modify: `cmd/derphole/ssh.go`
- Modify: `cmd/derphole/ssh_test.go`
- Test: `pkg/derphole/ssh/ssh_test.go`
- Test: `cmd/derphole/ssh_test.go`

- [ ] **Step 1: Write the failing SSH tests**

```go
// pkg/derphole/ssh/ssh_test.go
func TestInviteAcceptAppendsAuthorizedKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	listener, err := session.ListenAttach(ctx, session.AttachListenConfig{})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	inviteDone := make(chan error, 1)
	go func() {
		inviteDone <- Invite(ctx, InviteConfig{
			Listener:      listener,
			AuthorizedKeys: filepath.Join(sshDir, "authorized_keys"),
		})
	}()

	err = Accept(ctx, AcceptConfig{
		Token: listener.Token,
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test",
	})
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := <-inviteDone; err != nil {
		t.Fatalf("Invite() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(got), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test") {
		t.Fatalf("authorized_keys = %q, want appended key", got)
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./pkg/derphole/ssh ./cmd/derphole -run 'TestInviteAcceptAppendsAuthorizedKey' -count=1`

Expected: FAIL because the SSH workflow package does not exist yet.

- [ ] **Step 3: Implement SSH invite/accept and authorized_keys append**

```go
// pkg/derphole/ssh/authorized_keys.go
func AppendAuthorizedKey(path, publicKey string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if !strings.HasSuffix(publicKey, "\n") {
		publicKey += "\n"
	}
	_, err = io.WriteString(f, publicKey)
	return err
}

// pkg/derphole/ssh/invite.go
type InviteConfig struct {
	Listener       *session.AttachListener
	AuthorizedKeys string
}

type AcceptConfig struct {
	Token         string
	PublicKey     string
	UsePublicDERP bool
	ForceRelay    bool
}

func Invite(ctx context.Context, cfg InviteConfig) error {
	conn, err := cfg.Listener.Accept(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := protocol.WriteHeader(conn, protocol.Header{Version: 1, Kind: protocol.KindSSHInvite}); err != nil {
		return err
	}
	hdr, err := protocol.ReadHeader(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if hdr.Kind != protocol.KindSSHAccept {
		return fmt.Errorf("unexpected ssh response %q", hdr.Kind)
	}
	payload, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	return AppendAuthorizedKey(cfg.AuthorizedKeys, string(payload))
}

func Accept(ctx context.Context, cfg AcceptConfig) error {
	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         cfg.Token,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := protocol.ReadHeader(bufio.NewReader(conn)); err != nil {
		return err
	}
	if err := protocol.WriteHeader(conn, protocol.Header{Version: 1, Kind: protocol.KindSSHAccept}); err != nil {
		return err
	}
	_, err = io.WriteString(conn, cfg.PublicKey)
	return err
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./pkg/derphole/ssh ./cmd/derphole -run 'TestInviteAcceptAppendsAuthorizedKey' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/derphole/ssh/invite.go pkg/derphole/ssh/authorized_keys.go pkg/derphole/ssh/ssh_test.go cmd/derphole/ssh.go cmd/derphole/ssh_test.go
git commit -m "feat: add derphole ssh invite and accept"
```

## Task 9: Refactor builds, npm packaging, and release workflow for two products

**Files:**
- Modify: `.mise.toml`
- Modify: `tools/packaging/build-vendor.sh`
- Modify: `tools/packaging/build-npm.sh`
- Modify: `tools/packaging/build-release-assets.sh`
- Modify: `scripts/release-package-smoke.sh`
- Modify: `.github/workflows/release.yml`
- Create: `packaging/npm/derphole/package.json`
- Create: `packaging/npm/derphole/bin/derphole.js`
- Create: `packaging/npm/derphole/package.json`
- Create: `packaging/npm/derphole/bin/derphole.js`
- Test: `.github/workflows/release.yml`

- [ ] **Step 1: Write the failing packaging/release checks**

```bash
# Expect these to fail before the packaging refactor because derphole is not built or staged.
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
test -x dist/raw/derphole-linux-amd64
test -f dist/npm-derphole/package.json
node ./dist/npm-derphole/bin/derphole.js version
```

Expected: FAIL on missing `dist/raw/derphole-*` and `dist/npm-derphole`.

- [ ] **Step 2: Add package-aware npm templates and release tasks**

```json
// packaging/npm/derphole/package.json
{
  "name": "derphole",
  "version": "0.0.0",
  "license": "BSD-3-Clause",
  "bin": {
    "derphole": "bin/derphole.js"
  },
  "type": "module",
  "os": ["linux", "darwin"],
  "cpu": ["x64", "arm64"],
  "engines": {
    "node": ">=16"
  },
  "files": ["bin", "vendor", "README.md", "LICENSE"],
  "repository": {
    "type": "git",
    "url": "git+https://github.com/shayne/derphole.git"
  }
}
```

```bash
# tools/packaging/build-npm.sh
for product in derphole derphole; do
  src_dir="${ROOT_DIR}/packaging/npm/${product}"
  out_dir="${ROOT_DIR}/dist/npm-${product}"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"
  cp -R "${src_dir}/bin" "${out_dir}/"
  cp "${src_dir}/package.json" "${out_dir}/"
  cp "${ROOT_DIR}/README.md" "${out_dir}/"
  cp "${ROOT_DIR}/LICENSE" "${out_dir}/"
  cp -R "${ROOT_DIR}/dist/vendor" "${out_dir}/vendor"
  node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('${out_dir}/package.json','utf8')); pkg.version=process.env.PACKAGE_VERSION; fs.writeFileSync('${out_dir}/package.json', JSON.stringify(pkg,null,2)+'\\n');"
done
```

```toml
# .mise.toml
[tasks.build]
run = """
mkdir -p dist
go build -o dist/derphole ./cmd/derphole
go build -o dist/derphole ./cmd/derphole
"""
```

- [ ] **Step 3: Update the GitHub workflow to build, stage, dry-run, and publish both products**

```yaml
# .github/workflows/release.yml
  build-binaries:
    strategy:
      matrix:
        include:
          - product: derphole
            cmd: ./cmd/derphole
          - product: derphole
            cmd: ./cmd/derphole
          - product: derphole
            goos: linux
            goarch: amd64
            asset: derphole-linux-amd64
          - product: derphole
            goos: linux
            goarch: amd64
            asset: derphole-linux-amd64

  publish-packages-prod:
    steps:
      - run: bash ./tools/packaging/build-npm.sh
      - run: node ./dist/npm-derphole/bin/derphole.js version
      - run: node ./dist/npm-derphole/bin/derphole.js version
      - run: npm publish ./dist/npm-derphole --access public --dry-run
      - run: npm publish ./dist/npm-derphole --access public --dry-run
```

- [ ] **Step 4: Run the packaging/release checks to verify they pass**

Run: `VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all`

Expected: PASS and creates:

- `dist/raw/derphole-linux-amd64`
- `dist/raw/derphole-linux-amd64`
- `dist/npm-derphole`
- `dist/npm-derphole`

Then run: `VERSION=v0.0.1 mise run release:npm-dry-run`

Expected: PASS with dry-run publish output for both packages.

- [ ] **Step 5: Commit**

```bash
git add .mise.toml tools/packaging/build-vendor.sh tools/packaging/build-npm.sh tools/packaging/build-release-assets.sh scripts/release-package-smoke.sh .github/workflows/release.yml packaging/npm/derphole packaging/npm/derphole
git commit -m "build: release derphole and derphole together"
```

## Task 10: Update docs and run final verification

**Files:**
- Modify: `README.md`
- Modify: `docs/releases/npm-bootstrap.md`
- Modify: `AGENTS.md`
- Test: `README.md`
- Test: `docs/releases/npm-bootstrap.md`

- [ ] **Step 1: Update the docs to describe the two-product repo**

```md
<!-- README.md -->
# derphole

This repository ships two CLIs:

- `derphole`: raw byte streams and temporary TCP service sharing
- `derphole`: wormhole-shaped text/file/directory/SSH workflows on the same transport

Use `derphole` when you want low-level transport primitives.
Use `derphole` when you want a friendlier send/receive flow.
```

```md
<!-- docs/releases/npm-bootstrap.md -->
## Build and validate `0.0.1`

```bash
VERSION=v0.0.1 COMMIT=$(git rev-parse HEAD) BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) mise run release:build-all
VERSION=v0.0.1 mise run release:npm-dry-run
node ./dist/npm-derphole/bin/derphole.js version
node ./dist/npm-derphole/bin/derphole.js version
```

## Publish

```bash
npm publish ./dist/npm-derphole --access public
npm publish ./dist/npm-derphole --access public
```
```

- [ ] **Step 2: Run the repo verification suite**

Run: `mise run test`

Expected: PASS

Run: `mise run vet`

Expected: PASS

Run: `mise run build`

Expected: PASS and produces `dist/derphole` and `dist/derphole`

Run: `VERSION=v0.0.1 mise run release:npm-dry-run`

Expected: PASS for both packages

- [ ] **Step 3: Run focused CLI smoke tests for the new product**

Run: `go test ./cmd/derphole ./pkg/derphole ./pkg/derphole/ssh -count=1`

Expected: PASS

Run: `go test ./pkg/session ./pkg/derphole ./pkg/derphole/ssh ./cmd/derphole -count=1`

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add README.md docs/releases/npm-bootstrap.md AGENTS.md
git commit -m "docs: document derphole workflows"
```

## Self-review

- Spec coverage:
  - shared attach primitive: Tasks 1-2
  - derphole protocol/application layer: Tasks 3, 5, 6, 7, 8
  - wormhole-shaped CLI surface: Tasks 4-8
  - text/file/directory/SSH: Tasks 5-8
  - dual release/npm pipeline: Task 9
  - docs/bootstrap updates: Task 10
- Placeholder scan:
  - no `TODO`, `TBD`, or “similar to above” placeholders remain
  - every task includes exact files, concrete code, commands, and commit messages
- Type consistency:
  - attach API uses `ListenAttach`, `DialAttach`, `AttachListenConfig`, `AttachDialConfig`, and `AttachListener` consistently
  - protocol kinds use `KindText`, `KindFile`, `KindDirectoryTar`, `KindSSHInvite`, and `KindSSHAccept` consistently
