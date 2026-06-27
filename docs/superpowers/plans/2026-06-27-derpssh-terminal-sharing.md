# Derpssh Terminal Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `derpssh`, a no-open-ports terminal-sharing CLI and npm package with host approval, read/write gating, shared TUI, sidechat, and live smoke coverage on `root@hetz` and `root@pve1`.

**Architecture:** Implement a native derpssh app protocol over the reusable derptun tunnel substrate. Keep the host PTY and host terminal size authoritative, run one approved guest in v1, and keep all write permission enforcement in the host runtime.

**Tech Stack:** Go 1.26.4 through mise, existing DERP/QUIC/transport packages, `derptun.Mux`, `github.com/creack/pty` for Unix PTY handling, Bubble Tea/Lip Gloss only if the TUI task proves they keep the code smaller than a hand-rolled loop, npm vendored-binary launchers, repo gates through `mise`.

---

## Current Baseline

- Spec commit: `de4835b spec: design derpssh terminal sharing`
- Toolchain fix commit: `4cfc80d build: bump mise go toolchain`
- Normal hook path now uses `go1.26.4` through `mise exec`.
- Verification already run after the toolchain fix:
  - `mise run vuln`
  - `mise run check:hooks`
  - `mise run build`
  - `mise run test`

## File Structure

- `cmd/derpssh/main.go`: process entrypoint.
- `cmd/derpssh/root.go`: global flags, command registry, help routing.
- `cmd/derpssh/version.go`: version metadata and `version` command.
- `cmd/derpssh/share.go`: `share` CLI flags and call into session host runtime.
- `cmd/derpssh/connect.go`: `connect` CLI flags, display-name prompt, and call into guest runtime.
- `cmd/derpssh/*_test.go`: command parsing, help, prompt, and version tests.
- `cmd/derpssh/depaware.txt`: dependency snapshot maintained by the repo depaware hook.
- `pkg/derpssh/protocol`: roles, message structs, stream kinds, validation, framing.
- `pkg/derpssh/model`: pure host/guest state reducer for approvals, role changes, chat, and terminal replay.
- `pkg/derpssh/pty`: Unix PTY lifecycle, shell spawning, winsize, copy cleanup, and raw terminal helpers.
- `pkg/derpssh/tui`: terminal UI model/view/update around `model` state and protocol events.
- `pkg/derpssh/session`: host and guest orchestration over derptun-derived muxes.
- `pkg/session/derptun_app.go`: extracted reusable derptun app-mux setup used by both derptun TCP forwarding and derpssh.
- `pkg/derptun/token.go` and `pkg/derptun/invite.go`: only if the implementation reuses derptun credentials with a derpssh-specific kind/capability.
- `packaging/npm/derpssh/package.json`: npm metadata.
- `packaging/npm/derpssh/bin/derpssh.js`: npm launcher.
- `.mise.toml`, `tools/packaging/*.sh`, `.github/workflows/release.yml`, `scripts/release-package-smoke.sh`: add `derpssh` wherever products are enumerated.
- `scripts/smoke-derpssh-local.sh`: local two-process derpssh smoke.
- `scripts/smoke-remote-derpssh.sh`: remote-host smoke harness.

## Task 1: Commit The Plan

**Files:**
- Create: `docs/superpowers/plans/2026-06-27-derpssh-terminal-sharing.md`

- [ ] **Step 1: Verify clean planning baseline**

Run:

```bash
git status --short --branch
```

Expected: branch is ahead of `origin/main` by the spec/toolchain commits, with only this plan file unstaged or staged.

- [ ] **Step 2: Commit the plan**

Run:

```bash
git add docs/superpowers/plans/2026-06-27-derpssh-terminal-sharing.md
git commit -m "docs: plan derpssh terminal sharing"
```

Expected: commit succeeds. If the hook fails, stop and fix the hook failure before implementation.

## Task 2: Add `cmd/derpssh` Command Skeleton

**Files:**
- Create: `cmd/derpssh/main.go`
- Create: `cmd/derpssh/root.go`
- Create: `cmd/derpssh/version.go`
- Create: `cmd/derpssh/share.go`
- Create: `cmd/derpssh/connect.go`
- Create: `cmd/derpssh/root_test.go`
- Create: `cmd/derpssh/version_test.go`
- Create: `cmd/derpssh/share_test.go`
- Create: `cmd/derpssh/connect_test.go`
- Create: `cmd/derpssh/depaware.txt`
- Modify: `.mise.toml`
- Modify: `tools/hooks/depaware-check`
- Modify: `tools/hooks/depaware-deps-check`

- [ ] **Step 1: Write failing version and help tests**

Create `cmd/derpssh/version_test.go`:

```go
package main

import (
	"bytes"
	"testing"
)

func TestRunVersionPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runVersion(&stdout, &stderr)
	if code != 0 {
		t.Fatalf("runVersion() = %d, want 0", code)
	}
	if got := stdout.String(); got != versionString()+"\n" {
		t.Fatalf("stdout = %q, want version", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
```

Create `cmd/derpssh/root_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpListsDerpsshCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain([]string{"--help"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runMain(--help) = %d, want 0", code)
	}
	out := stderr.String()
	for _, want := range []string{"derpssh", "share", "connect", "version"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q:\n%s", want, out)
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./cmd/derpssh -run 'TestRunVersionPrintsVersion|TestRootHelpListsDerpsshCommands' -count=1
```

Expected: package does not compile because `cmd/derpssh` files do not exist yet.

- [ ] **Step 3: Add minimal command skeleton**

Create `cmd/derpssh/main.go`:

```go
package main

import (
	"io"
	"os"
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return run(args, stdin, stdout, stderr)
}
```

Create `cmd/derpssh/version.go` using the same metadata shape as `cmd/derptun/version.go`:

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

func versionString() string {
	_, _ = commit, buildDate
	return version
}

func runVersion(stdout, stderr io.Writer) int {
	_, _ = fmt.Fprintln(stdout, versionString())
	_ = stderr
	return 0
}
```

Create `cmd/derpssh/root.go`:

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
		Name:        "derpssh",
		Description: "Share an interactive terminal through DERP rendezvous and direct-path promotion.",
		Examples: []string{
			"derpssh share",
			"derpssh connect <invite>",
			"derpssh version",
		},
	},
	SubCommands: map[string]yargs.CommandSpec{
		"share":   {Info: yargs.SubCommandInfo{Name: "share", Description: "Share a fresh host PTY."}},
		"connect": {Info: yargs.SubCommandInfo{Name: "connect", Description: "Connect to a derpssh invite."}},
		"version": {Info: yargs.SubCommandInfo{Name: "version", Description: "Print the derpssh version."}},
	},
}

var rootHelpConfig = rootRegistry.HelpConfig()

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseKnownFlags[rootGlobalFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	level, err := rootTelemetryLevel(parsed.Flags)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	remaining := parsed.RemainingArgs
	if len(remaining) == 0 || isRootHelpRequest(remaining) {
		_, _ = fmt.Fprint(stderr, rootHelpText())
		return 0
	}
	if strings.HasPrefix(remaining[0], "-") {
		_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", remaining[0])
		_, _ = fmt.Fprint(stderr, rootHelpText())
		return 2
	}
	if handler, ok := rootCommandHandlers()[remaining[0]]; ok {
		return handler(remaining[1:], level, stdin, stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "unknown command: %s\nRun 'derpssh --help' for usage\n", remaining[0])
	return 2
}

type rootCommandHandler func(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int

func rootCommandHandlers() map[string]rootCommandHandler {
	return map[string]rootCommandHandler{
		"share": func(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
			return runShare(args, level, stdin, stdout, stderr)
		},
		"connect": runConnect,
		"version": func(_ []string, _ telemetry.Level, _ io.Reader, stdout, stderr io.Writer) int {
			return runVersion(stdout, stderr)
		},
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

Create temporary `cmd/derpssh/share.go` and `cmd/derpssh/connect.go` stubs that only parse help and return a clear not-yet-implemented error for non-help invocations:

```go
package main

import (
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/telemetry"
)

func runShare(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	_, _, _ = level, stdin, stdout
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		_, _ = fmt.Fprintln(stderr, "Usage: derpssh share [--force-relay]")
		return 0
	}
	_, _ = fmt.Fprintln(stderr, "derpssh share is not wired yet")
	return 1
}
```

Use the same shape for `runConnect`, with usage `derpssh connect [--name NAME] <invite>`.

- [ ] **Step 4: Wire build and depaware product lists**

Modify `.mise.toml`:

```bash
go build -o dist/derpssh ./cmd/derpssh
GOOS=linux GOARCH=amd64 go build -o dist/derpssh-linux-amd64 ./cmd/derpssh
```

Modify `tools/hooks/depaware-check`:

```bash
targets=(
  ./cmd/derphole
  ./cmd/derptun
  ./cmd/derpssh
  ./cmd/derphole-probe
  ./cmd/derphole-web
)

depaware_files=(
  cmd/derphole/depaware.txt
  cmd/derptun/depaware.txt
  cmd/derpssh/depaware.txt
  cmd/derphole-probe/depaware.txt
  cmd/derphole-web/depaware.txt
)
```

Modify `tools/hooks/depaware-deps-check` to include the same no-cross-command dependency checks for `cmd/derpssh` as the existing `cmd/derphole` and `cmd/derptun` checks.

- [ ] **Step 5: Run command tests, depaware, and build**

Run:

```bash
mise exec -- go test ./cmd/derpssh -count=1
tools/hooks/depaware-check
mise run build
```

Expected: tests pass, `cmd/derpssh/depaware.txt` is generated, and `dist/derpssh` exists.

- [ ] **Step 6: Commit**

Run:

```bash
git add .mise.toml tools/hooks/depaware-check tools/hooks/depaware-deps-check cmd/derpssh
git commit -m "derpssh: add command skeleton"
```

Expected: commit succeeds with hooks enabled.

## Task 3: Implement Protocol Types And Framing

**Files:**
- Create: `pkg/derpssh/protocol/types.go`
- Create: `pkg/derpssh/protocol/frame.go`
- Create: `pkg/derpssh/protocol/validation.go`
- Create: `pkg/derpssh/protocol/protocol_test.go`
- Create: `pkg/derpssh/protocol/frame_test.go`

- [ ] **Step 1: Write failing protocol tests**

Create `pkg/derpssh/protocol/protocol_test.go`:

```go
package protocol

import "testing"

func TestNormalizeDisplayName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "trim", in: "  Alex  ", want: "Alex"},
		{name: "control chars", in: "Al\x1b[31mex", want: "Alex"},
		{name: "too long", in: "abcdefghijklmnopqrstuvwxyz0123456789", want: "abcdefghijklmnopqrstuvwx"},
		{name: "empty", in: " \x1b ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDisplayName(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("NormalizeDisplayName() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDisplayName() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoleCanWrite(t *testing.T) {
	if RoleRead.CanWrite() {
		t.Fatal("RoleRead.CanWrite() = true, want false")
	}
	if !RoleWrite.CanWrite() {
		t.Fatal("RoleWrite.CanWrite() = false, want true")
	}
}
```

Create `pkg/derpssh/protocol/frame_test.go`:

```go
package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msg := Message{
		Type: MessageHello,
		Hello: &Hello{
			ProtocolVersion: ProtocolVersion,
			ParticipantID:   "guest-1",
			DisplayName:     "Alex",
			Role:            RolePending,
		},
	}
	if err := WriteFrame(&buf, msg); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if got.Type != MessageHello || got.Hello == nil || got.Hello.DisplayName != "Alex" {
		t.Fatalf("ReadFrame() = %#v, want hello Alex", got)
	}
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("ReadFrame() error = nil, want oversized frame error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/protocol -run 'TestNormalizeDisplayName|TestRoleCanWrite|TestFrame' -count=1
```

Expected: package does not compile because protocol types and functions are missing.

- [ ] **Step 3: Implement protocol types**

Create `pkg/derpssh/protocol/types.go`:

```go
package protocol

const ProtocolVersion = 1

type Role string

const (
	RolePending Role = "pending"
	RoleRead    Role = "read"
	RoleWrite   Role = "write"
	RoleDenied  Role = "denied"
	RoleKicked  Role = "kicked"
)

func (r Role) CanWrite() bool {
	return r == RoleWrite
}

type StreamKind string

const (
	StreamControl     StreamKind = "control"
	StreamTerminalOut StreamKind = "terminal-out"
	StreamTerminalIn  StreamKind = "terminal-in"
	StreamChat        StreamKind = "chat"
)

type MessageType string

const (
	MessageHello       MessageType = "hello"
	MessageJoinRequest MessageType = "join-request"
	MessageDecision    MessageType = "decision"
	MessageRoleChange  MessageType = "role-change"
	MessageKick        MessageType = "kick"
	MessageResize      MessageType = "resize"
	MessageChat        MessageType = "chat"
	MessageTerminal    MessageType = "terminal"
	MessageClose       MessageType = "close"
	MessagePing        MessageType = "ping"
	MessagePong        MessageType = "pong"
)

type Message struct {
	Type        MessageType    `json:"type"`
	Hello       *Hello         `json:"hello,omitempty"`
	Decision    *Decision      `json:"decision,omitempty"`
	RoleChange  *RoleChange    `json:"role_change,omitempty"`
	Kick        *Kick          `json:"kick,omitempty"`
	Resize      *Resize        `json:"resize,omitempty"`
	Chat        *Chat          `json:"chat,omitempty"`
	Terminal    *TerminalEvent `json:"terminal,omitempty"`
	Close       *Close         `json:"close,omitempty"`
	Ping        *Ping          `json:"ping,omitempty"`
	Pong        *Pong          `json:"pong,omitempty"`
}

type Hello struct {
	ProtocolVersion int    `json:"protocol_version"`
	ParticipantID   string `json:"participant_id"`
	DisplayName     string `json:"display_name"`
	Role            Role   `json:"role"`
}

type Decision struct {
	Accepted bool   `json:"accepted"`
	Role     Role   `json:"role,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type RoleChange struct {
	ParticipantID string `json:"participant_id"`
	Role          Role   `json:"role"`
}

type Kick struct {
	ParticipantID string `json:"participant_id"`
	Reason        string `json:"reason,omitempty"`
}

type Resize struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

type Chat struct {
	ParticipantID string `json:"participant_id"`
	DisplayName   string `json:"display_name"`
	Text          string `json:"text"`
	Seq           uint64 `json:"seq"`
}

type TerminalEvent struct {
	Seq  uint64 `json:"seq"`
	Data []byte `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type Close struct {
	Reason string `json:"reason"`
}

type Ping struct {
	ID uint64 `json:"id"`
}

type Pong struct {
	ID uint64 `json:"id"`
}
```

- [ ] **Step 4: Implement validation and framing**

Create `pkg/derpssh/protocol/validation.go`:

```go
package protocol

import (
	"errors"
	"strings"
	"unicode"
)

const MaxDisplayNameRunes = 24

var ErrEmptyDisplayName = errors.New("display name is empty")

func NormalizeDisplayName(value string) (string, error) {
	value = strings.TrimSpace(stripControlRunes(value))
	if value == "" {
		return "", ErrEmptyDisplayName
	}
	runes := []rune(value)
	if len(runes) > MaxDisplayNameRunes {
		value = string(runes[:MaxDisplayNameRunes])
	}
	return value, nil
}

func stripControlRunes(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
```

Create `pkg/derpssh/protocol/frame.go`:

```go
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxFrameBytes = 1 << 20

var ErrFrameTooLarge = errors.New("derpssh frame too large")

func WriteFrame(w io.Writer, msg Message) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(raw) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func ReadFrame(r io.Reader) (Message, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxFrameBytes {
		return Message{}, ErrFrameTooLarge
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}
```

- [ ] **Step 5: Run protocol tests and commit**

Run:

```bash
mise exec -- go test ./pkg/derpssh/protocol -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/derpssh/protocol
git commit -m "derpssh: add protocol framing"
```

## Task 4: Implement Pure Session Model

**Files:**
- Create: `pkg/derpssh/model/state.go`
- Create: `pkg/derpssh/model/replay.go`
- Create: `pkg/derpssh/model/chat.go`
- Create: `pkg/derpssh/model/state_test.go`
- Create: `pkg/derpssh/model/replay_test.go`
- Create: `pkg/derpssh/model/chat_test.go`

- [ ] **Step 1: Write failing state tests**

Create `pkg/derpssh/model/state_test.go`:

```go
package model

import (
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestGuestInputRequiresWriteRole(t *testing.T) {
	s := NewHostState("host", 100, 30)
	s.AddPendingGuest("guest-1", "Alex")
	if s.GuestCanWrite("guest-1") {
		t.Fatal("pending guest can write")
	}
	if err := s.ApproveGuest("guest-1", protocol.RoleRead); err != nil {
		t.Fatalf("ApproveGuest(read) error = %v", err)
	}
	if s.GuestCanWrite("guest-1") {
		t.Fatal("read guest can write")
	}
	if err := s.SetGuestRole("guest-1", protocol.RoleWrite); err != nil {
		t.Fatalf("SetGuestRole(write) error = %v", err)
	}
	if !s.GuestCanWrite("guest-1") {
		t.Fatal("write guest cannot write")
	}
}

func TestGuestResizeDoesNotChangeHostSize(t *testing.T) {
	s := NewHostState("host", 100, 30)
	s.NoteGuestSize("guest-1", 200, 60)
	cols, rows := s.HostSize()
	if cols != 100 || rows != 30 {
		t.Fatalf("HostSize() = %dx%d, want 100x30", cols, rows)
	}
}

func TestKickGuestMarksRoleKicked(t *testing.T) {
	s := NewHostState("host", 100, 30)
	s.AddPendingGuest("guest-1", "Alex")
	if err := s.KickGuest("guest-1"); err != nil {
		t.Fatalf("KickGuest() error = %v", err)
	}
	got, ok := s.Guest("guest-1")
	if !ok {
		t.Fatal("Guest() ok = false, want true")
	}
	if got.Role != protocol.RoleKicked {
		t.Fatalf("guest role = %q, want kicked", got.Role)
	}
}
```

Create `pkg/derpssh/model/replay_test.go`:

```go
package model

import "testing"

func TestReplayBufferKeepsBoundedTail(t *testing.T) {
	buf := NewReplayBuffer(5)
	buf.Append([]byte("abc"))
	buf.Append([]byte("def"))
	got := string(buf.Bytes())
	if got != "bcdef" {
		t.Fatalf("Bytes() = %q, want bcdef", got)
	}
	if buf.NextSeq() != 3 {
		t.Fatalf("NextSeq() = %d, want 3", buf.NextSeq())
	}
}
```

Create `pkg/derpssh/model/chat_test.go`:

```go
package model

import "testing"

func TestChatHistoryKeepsBoundedMessages(t *testing.T) {
	h := NewChatHistory(2)
	h.Append(ChatMessage{ParticipantID: "a", DisplayName: "A", Text: "one"})
	h.Append(ChatMessage{ParticipantID: "b", DisplayName: "B", Text: "two"})
	h.Append(ChatMessage{ParticipantID: "c", DisplayName: "C", Text: "three"})
	got := h.Messages()
	if len(got) != 2 || got[0].Text != "two" || got[1].Seq != 3 {
		t.Fatalf("Messages() = %#v, want last two with seq 2 and 3", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/model -run 'TestGuest|TestReplay|TestChat' -count=1
```

Expected: package does not compile because model package is missing.

- [ ] **Step 3: Implement state, replay, and chat**

Create `pkg/derpssh/model/state.go`:

```go
package model

import (
	"fmt"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type Participant struct {
	ID          string
	DisplayName string
	Role        protocol.Role
	Cols        int
	Rows        int
}

type HostState struct {
	hostID string
	cols   int
	rows   int
	guests map[string]Participant
}

func NewHostState(hostID string, cols, rows int) *HostState {
	return &HostState{hostID: hostID, cols: cols, rows: rows, guests: make(map[string]Participant)}
}

func (s *HostState) AddPendingGuest(id, name string) {
	s.guests[id] = Participant{ID: id, DisplayName: name, Role: protocol.RolePending}
}

func (s *HostState) ApproveGuest(id string, role protocol.Role) error {
	if role != protocol.RoleRead && role != protocol.RoleWrite {
		return fmt.Errorf("invalid approval role %q", role)
	}
	return s.SetGuestRole(id, role)
}

func (s *HostState) SetGuestRole(id string, role protocol.Role) error {
	p, ok := s.guests[id]
	if !ok {
		return fmt.Errorf("unknown guest %q", id)
	}
	p.Role = role
	s.guests[id] = p
	return nil
}

func (s *HostState) GuestCanWrite(id string) bool {
	p, ok := s.guests[id]
	return ok && p.Role.CanWrite()
}

func (s *HostState) Guest(id string) (Participant, bool) {
	p, ok := s.guests[id]
	return p, ok
}

func (s *HostState) KickGuest(id string) error {
	return s.SetGuestRole(id, protocol.RoleKicked)
}

func (s *HostState) NoteGuestSize(id string, cols, rows int) {
	p := s.guests[id]
	p.ID = id
	p.Cols = cols
	p.Rows = rows
	s.guests[id] = p
}

func (s *HostState) SetHostSize(cols, rows int) {
	s.cols, s.rows = cols, rows
}

func (s *HostState) HostSize() (int, int) {
	return s.cols, s.rows
}
```

Create `pkg/derpssh/model/replay.go` and `pkg/derpssh/model/chat.go` with bounded append behavior exactly matching the tests.

- [ ] **Step 4: Run model tests and commit**

Run:

```bash
mise exec -- go test ./pkg/derpssh/model -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/derpssh/model
git commit -m "derpssh: add session state model"
```

## Task 5: Extract Reusable Derptun App-Mux Setup

**Files:**
- Modify: `pkg/session/derptun.go`
- Create: `pkg/session/derptun_app.go`
- Create: `pkg/session/derptun_app_test.go`

- [ ] **Step 1: Add a test proving derptun TCP still uses the extracted app mux**

Create `pkg/session/derptun_app_test.go` with a test that calls `DerptunServe` and `DerptunConnect` against the fake DERP server, equivalent to `TestDerptunConnectBridgesStdio`, then asserts the echo still works after extraction:

```go
func TestDerptunAppMuxStillBridgesStdio(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()
	var out strings.Builder
	err := DerptunConnect(ctx, DerptunConnectConfig{
		ClientToken: clientToken,
		StdioIn:     strings.NewReader("hello\n"),
		StdioOut:    &out,
		ForceRelay:  true,
	})
	if err != nil {
		t.Fatalf("DerptunConnect() error = %v", err)
	}
	if out.String() != "echo: hello\n" {
		t.Fatalf("stdout = %q, want echo: hello", out.String())
	}
	cancel()
	<-serveErr
}
```

- [ ] **Step 2: Run the test before extraction**

Run:

```bash
mise exec -- go test ./pkg/session -run TestDerptunAppMuxStillBridgesStdio -count=1
```

Expected: test passes before extraction, proving the guard test is valid.

- [ ] **Step 3: Extract app-mux structs**

Create `pkg/session/derptun_app.go` with exported app helpers:

```go
type DerptunAppServeConfig struct {
	ServerToken   string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
	OnMux          func(context.Context, *derptun.Mux) error
}

type DerptunAppDialConfig struct {
	ClientToken   string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

func DerptunAppServe(ctx context.Context, cfg DerptunAppServeConfig) error
func DerptunAppDial(ctx context.Context, cfg DerptunAppDialConfig) (*derptun.Mux, func(), error)
func DerptunAppDialStream(ctx context.Context, cfg DerptunAppDialConfig) (net.Conn, func(), error)
```

Move only the reusable mux setup out of `pkg/session/derptun.go`. Keep TCP target forwarding in `DerptunServe` by calling `DerptunAppServe` with:

```go
OnMux: func(ctx context.Context, mux *derptun.Mux) error {
	return serveDerptunMuxTarget(ctx, mux, cfg.TargetAddr, cfg.Emitter)
},
```

Leave claim validation, stale active recovery, direct path probing, and QUIC carrier setup behavior unchanged.

- [ ] **Step 4: Run derptun session tests**

Run:

```bash
mise exec -- go test ./pkg/session -run 'TestDerptun' -count=1
```

Expected: all derptun tests pass, including concurrent-connector rejection and repeated restart behavior.

- [ ] **Step 5: Commit**

Run:

```bash
git add pkg/session/derptun.go pkg/session/derptun_app.go pkg/session/derptun_app_test.go
git commit -m "session: expose derptun app mux"
```

Expected: commit succeeds.

## Task 6: Implement PTY Package

**Files:**
- Create: `pkg/derpssh/pty/pty.go`
- Create: `pkg/derpssh/pty/pty_unix.go`
- Create: `pkg/derpssh/pty/raw.go`
- Create: `pkg/derpssh/pty/pty_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Write failing PTY tests around pure behavior**

Create `pkg/derpssh/pty/pty_test.go`:

```go
package pty

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsExpectedCopyError(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrClosedPipe, os.ErrClosed, syscall.EIO, syscall.EPIPE, net.ErrClosed} {
		if !IsExpectedCopyError(err) {
			t.Fatalf("IsExpectedCopyError(%v) = false, want true", err)
		}
	}
	if IsExpectedCopyError(errors.New("permission denied")) {
		t.Fatal("IsExpectedCopyError(permission denied) = true, want false")
	}
}

func TestDefaultShell(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	if got := DefaultShell(); got != "/bin/zsh" {
		t.Fatalf("DefaultShell() = %q, want /bin/zsh", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/pty -run 'TestIsExpectedCopyError|TestDefaultShell' -count=1
```

Expected: package does not compile because PTY package is missing.

- [ ] **Step 3: Add PTY dependency and implementation**

Run:

```bash
mise exec -- go get github.com/creack/pty@latest
```

Create `pkg/derpssh/pty/pty.go`:

```go
package pty

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

type Size struct {
	Cols int
	Rows int
}

func DefaultShell() string {
	if shell := strings.TrimSpace(os.Getenv("SHELL")); shell != "" {
		return shell
	}
	return "/bin/sh"
}

func IsExpectedCopyError(err error) bool {
	if err == nil {
		return false
	}
	for _, expected := range []error{io.EOF, io.ErrClosedPipe, os.ErrClosed, syscall.EIO, syscall.EPIPE, syscall.ECONNRESET, net.ErrClosed} {
		if errors.Is(err, expected) {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "endpoint is closed for send")
}
```

Create `pkg/derpssh/pty/pty_unix.go` with `//go:build !windows` and:

```go
type Session struct {
	File *os.File
	Cmd  *exec.Cmd
}

type StartConfig struct {
	Shell string
	Term  string
	Size  Size
	Env   []string
}

func Start(cfg StartConfig) (*Session, error)
func (s *Session) Resize(size Size) error
func (s *Session) Close() error
func (s *Session) Wait() error
```

`Start` should use `pty.StartWithSize` or `pty.Open` plus `exec.Cmd.SysProcAttr` to preserve the `Setctty`/`Setsid` behavior described in the spec. Keep command execution to a fresh shell only in this task.

- [ ] **Step 4: Run PTY package tests**

Run:

```bash
mise exec -- go test ./pkg/derpssh/pty -count=1
```

Expected: tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add go.mod go.sum pkg/derpssh/pty
git commit -m "derpssh: add pty runtime"
```

Expected: commit succeeds.

## Task 7: Implement Host/Guest Session Runtime Over Mux

**Files:**
- Create: `pkg/derpssh/session/config.go`
- Create: `pkg/derpssh/session/host.go`
- Create: `pkg/derpssh/session/guest.go`
- Create: `pkg/derpssh/session/streams.go`
- Create: `pkg/derpssh/session/session_test.go`
- Modify: `pkg/session/derptun_app.go`

- [ ] **Step 1: Write failing in-memory mux tests**

Create `pkg/derpssh/session/session_test.go` with `net.Pipe` plus `derptun.NewMux` on each side:

```go
func TestHostRejectsReadOnlyGuestInput(t *testing.T) {
	hostMux, guestMux, cleanup := newTestMuxPair(t)
	defer cleanup()

	host := NewHostRuntime(HostConfig{
		Mux:           hostMux,
		HostID:        "host",
		HostName:      "host",
		InitialCols:   80,
		InitialRows:   24,
		PTYInput:      io.Discard,
		PTYOutput:     strings.NewReader("ready\n"),
		Approval:      StaticApproval{Role: protocol.RoleRead},
	})
	guest := NewGuestRuntime(GuestConfig{
		Mux:           guestMux,
		ParticipantID: "guest-1",
		DisplayName:   "Alex",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- host.Run(ctx) }()
	go func() { errCh <- guest.Run(ctx) }()

	if err := guest.SendInput(ctx, []byte("whoami\n")); err == nil {
		t.Fatal("SendInput(read-only) error = nil, want permission error")
	}
	cancel()
}
```

Add a second test `TestHostAcceptsWriteGuestInput` that uses a `bytes.Buffer` as `PTYInput`, approves `RoleWrite`, sends `whoami\n`, and expects the buffer to contain `whoami\n`.

Add `TestChatMessagesRoundTrip` that sends a chat message from guest to host and host to guest over the chat stream, then asserts both runtimes record the message text with the sender display name.

Add `TestHostResizeBroadcastsCanonicalSize` that calls the host runtime resize hook with `100x32`, has the guest report `200x60`, and asserts the guest receives `100x32` as the terminal size.

Add `TestKickClosesGuestCleanly` that starts a write-approved guest, sends a host kick control message, and asserts the guest runtime exits with a close reason containing `kicked`.

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestHostRejectsReadOnlyGuestInput|TestHostAcceptsWriteGuestInput' -count=1
```

Expected: package does not compile because session runtime is missing.

- [ ] **Step 3: Implement runtime configs and stream open**

Create `pkg/derpssh/session/config.go`:

```go
package session

import (
	"io"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derptun"
)

type Approval interface {
	Approve(JoinRequest) protocol.Role
}

type JoinRequest struct {
	ParticipantID string
	DisplayName   string
}

type StaticApproval struct {
	Role protocol.Role
}

func (a StaticApproval) Approve(JoinRequest) protocol.Role {
	return a.Role
}

type HostConfig struct {
	Mux         *derptun.Mux
	HostID      string
	HostName    string
	InitialCols int
	InitialRows int
	PTYInput    io.Writer
	PTYOutput   io.Reader
	Approval    Approval
}

type GuestConfig struct {
	Mux           *derptun.Mux
	ParticipantID string
	DisplayName   string
}
```

Implement `streams.go` so the control stream opens first and exchanges `protocol.MessageHello`, then terminal/chat streams open only after approval.

- [ ] **Step 4: Implement permission-gated guest input**

In `host.go`, consume terminal input messages like:

```go
if !state.GuestCanWrite(msg.Terminal.ParticipantID) {
	return protocol.WriteFrame(control, protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: "guest is read-only"},
	})
}
_, err := cfg.PTYInput.Write(msg.Terminal.Data)
return err
```

In `guest.go`, keep the current role from control messages and have `SendInput` return `ErrReadOnly` before writing if the role is not `protocol.RoleWrite`.

- [ ] **Step 5: Run session tests and commit**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/derpssh/session pkg/session/derptun_app.go
git commit -m "derpssh: add mux session runtime"
```

## Task 8: Build TUI Model And Renderer

**Files:**
- Create: `pkg/derpssh/tui/model.go`
- Create: `pkg/derpssh/tui/view.go`
- Create: `pkg/derpssh/tui/update.go`
- Create: `pkg/derpssh/tui/tui_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Write failing pure TUI model tests**

Create `pkg/derpssh/tui/tui_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

func TestApprovalKeysChangePendingGuest(t *testing.T) {
	m := NewModel(ModeHost, 100, 30)
	m.SetPendingGuest("guest-1", "Alex")
	m = m.HandleKey("r")
	if m.Decision().Role != protocol.RoleRead {
		t.Fatalf("Decision role = %q, want read", m.Decision().Role)
	}
	m.SetPendingGuest("guest-1", "Alex")
	m = m.HandleKey("w")
	if m.Decision().Role != protocol.RoleWrite {
		t.Fatalf("Decision role = %q, want write", m.Decision().Role)
	}
}

func TestViewShowsHostSizeAndRole(t *testing.T) {
	m := NewModel(ModeGuest, 96, 28)
	m.SetRole(protocol.RoleRead)
	view := m.View()
	for _, want := range []string{"96x28", "read"} {
		if !strings.Contains(view, want) {
			t.Fatalf("View() missing %q:\n%s", want, view)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -run 'TestApprovalKeys|TestViewShows' -count=1
```

Expected: package does not compile because TUI package is missing.

- [ ] **Step 3: Implement pure model first**

Create model, view, and update files with no third-party TUI dependency yet. The model must expose:

```go
type Mode string
const (
	ModeHost  Mode = "host"
	ModeGuest Mode = "guest"
)

type Model struct { ... }
func NewModel(mode Mode, cols, rows int) Model
func (m Model) HandleKey(key string) Model
func (m Model) View() string
func (m Model) Decision() Decision
func (m *Model) SetPendingGuest(id, name string)
func (m *Model) SetRole(role protocol.Role)
```

Keep this renderer simple: status line, terminal body string, sidechat lines, and approval prompt. Add Bubble Tea only after this pure model is green and the CLI integration task needs terminal event handling.

- [ ] **Step 4: Run TUI tests and commit**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -count=1
```

Expected: tests pass.

Commit:

```bash
git add pkg/derpssh/tui go.mod go.sum
git commit -m "derpssh: add tui model"
```

## Task 9: Wire `share` And `connect` To Real Sessions

**Files:**
- Modify: `cmd/derpssh/share.go`
- Modify: `cmd/derpssh/connect.go`
- Modify: `cmd/derpssh/share_test.go`
- Modify: `cmd/derpssh/connect_test.go`
- Create: `pkg/derpssh/session/share.go`
- Create: `pkg/derpssh/session/connect.go`
- Create: `pkg/derpssh/session/invite.go`
- Create: `pkg/derpssh/session/share_connect_test.go`

- [ ] **Step 1: Write CLI tests for command shape**

Create `cmd/derpssh/share_test.go`:

```go
func TestRunSharePrintsConnectCommand(t *testing.T) {
	old := runShareSession
	defer func() { runShareSession = old }()
	runShareSession = func(ctx context.Context, cfg shareSessionConfig) error {
		_, _ = fmt.Fprintln(cfg.Stderr, "npx -y derpssh@latest connect DSH1test")
		return nil
	}
	var stderr bytes.Buffer
	code := runShare(nil, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("runShare() = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "npx -y derpssh@latest connect DSH1test") {
		t.Fatalf("stderr missing connect command:\n%s", stderr.String())
	}
}
```

Create `cmd/derpssh/connect_test.go` with a test that `--name Alex DSH1test` passes `DisplayName: "Alex"` to the session config and does not prompt.

- [ ] **Step 2: Run CLI tests to verify they fail**

Run:

```bash
mise exec -- go test ./cmd/derpssh -run 'TestRunSharePrintsConnectCommand|TestRunConnect' -count=1
```

Expected: tests fail because `runShareSession`, `shareSessionConfig`, and connect session wiring are missing.

- [ ] **Step 3: Implement invite and runtime glue**

Create `pkg/derpssh/session/invite.go`:

```go
const InvitePrefix = "DSH1"

type Invite struct {
	ClientToken string `json:"client_token"`
}

func EncodeInvite(inv Invite) (string, error)
func DecodeInvite(raw string) (Invite, error)
```

Use base64 raw URL JSON, matching the compact style but keeping v1 readable. Include tests that reject wrong prefixes and empty client tokens.

Create `share.go` and `connect.go` in `pkg/derpssh/session` with:

```go
type ShareConfig struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	ForceRelay bool
	Emitter    *telemetry.Emitter
}

type ConnectConfig struct {
	Invite      string
	DisplayName string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	ForceRelay  bool
	Emitter     *telemetry.Emitter
}
```

For the first green pass, wire the token/invite generation and session setup to fakeable functions so CLI tests do not open a live tunnel.

- [ ] **Step 4: Run CLI and session package tests**

Run:

```bash
mise exec -- go test ./cmd/derpssh ./pkg/derpssh/session -count=1
```

Expected: tests pass.

Commit:

```bash
git add cmd/derpssh pkg/derpssh/session
git commit -m "derpssh: wire share and connect commands"
```

## Task 10: Add End-To-End Local Derpssh Smoke

**Files:**
- Create: `scripts/smoke-derpssh-local.sh`
- Create: `scripts/derpssh_smoke_test.go`
- Modify: `.mise.toml`

- [ ] **Step 1: Write script presence test**

Create `scripts/derpssh_smoke_test.go`:

```go
package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerpsshLocalSmokeScriptUsesBuiltBinary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "smoke-derpssh-local.sh"))
	if err != nil {
		t.Fatalf("read smoke script: %v", err)
	}
	body := string(raw)
	for _, want := range []string{"dist/derpssh", "derpssh share", "derpssh connect"} {
		if !strings.Contains(body, want) {
			t.Fatalf("smoke script missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- go test ./scripts -run TestDerpsshLocalSmokeScriptUsesBuiltBinary -count=1
```

Expected: test fails because `scripts/smoke-derpssh-local.sh` does not exist.

- [ ] **Step 3: Add local smoke task and script**

Create `scripts/smoke-derpssh-local.sh` with:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

mise run build
test -x dist/derpssh

tmp=$(mktemp -d "${TMPDIR:-/tmp}/derpssh-local.XXXXXXXXXX")
trap 'rm -rf "$tmp"' EXIT

share_out="$tmp/share.out"
share_err="$tmp/share.err"
connect_out="$tmp/connect.out"
connect_err="$tmp/connect.err"

DERPSSH_TEST_AUTO_APPROVE=write DERPSSH_TEST_COMMAND="printf ready; read line; printf input:%s \"$line\"" \
  dist/derpssh share >"$share_out" 2>"$share_err" &
share_pid=$!
trap 'kill "$share_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

for _ in $(seq 1 100); do
  if grep -E 'derpssh(@latest)? connect ' "$share_err" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

connect_line=$(grep -Eo '(npx -y derpssh@latest connect|dist/derpssh connect) [^[:space:]]+' "$share_err" | head -n1 || true)
invite="${connect_line##* }"
if [[ -z "$connect_line" || -z "$invite" ]]; then
  echo "failed to capture derpssh connect command" >&2
  cat "$share_err" >&2
  exit 1
fi

printf 'hello\n' | dist/derpssh connect --name smoke "$invite" >"$connect_out" 2>"$connect_err"
grep -F 'input:hello' "$connect_out" >/dev/null
```

Modify `.mise.toml`:

```toml
[tasks.smoke-derpssh-local]
run = "./scripts/smoke-derpssh-local.sh"
```

- [ ] **Step 4: Run local smoke**

Run:

```bash
mise run smoke-derpssh-local
```

Expected: the script passes and proves share/connect works over the local fake or local DERP path.

Commit:

```bash
git add .mise.toml scripts/smoke-derpssh-local.sh scripts/derpssh_smoke_test.go
git commit -m "derpssh: add local smoke test"
```

## Task 11: Add Npm And Release Packaging

**Files:**
- Create: `packaging/npm/derpssh/package.json`
- Create: `packaging/npm/derpssh/bin/derpssh.js`
- Modify: `tools/packaging/build-vendor.sh`
- Modify: `tools/packaging/build-npm.sh`
- Modify: `tools/packaging/build-release-assets.sh`
- Modify: `scripts/release-package-smoke.sh`
- Modify: `scripts/release_workflow_test.go`
- Modify: `.github/workflows/release.yml`
- Modify: `.mise.toml`

- [ ] **Step 1: Write failing packaging tests**

Extend `scripts/release_workflow_test.go`:

```go
for _, command := range []string{
	"bash ./tools/packaging/publish-npm-if-missing.sh --skip-unclaimed ./dist/npm-derpssh",
	"bash ./tools/packaging/publish-npm-if-missing.sh --tag dev --skip-unclaimed ./dist/npm-derpssh",
} {
	if !strings.Contains(body, command) {
		t.Fatalf("release workflow does not publish derpssh with command %q", command)
	}
}
```

Add a test that `release.yml` includes all four derpssh binary artifact names:

```go
for _, asset := range []string{"derpssh-linux-amd64", "derpssh-linux-arm64", "derpssh-darwin-amd64", "derpssh-darwin-arm64"} {
	if !strings.Contains(body, asset) {
		t.Fatalf("release workflow missing %s", asset)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
mise exec -- go test ./scripts -run 'TestReleaseWorkflow.*Derpssh|TestReleaseWorkflowNpmPublishes' -count=1
```

Expected: tests fail because derpssh is not in the release workflow.

- [ ] **Step 3: Add npm launcher**

Copy the existing `packaging/npm/derptun/bin/derptun.js` shape to `packaging/npm/derpssh/bin/derpssh.js`, replacing every product string with `derpssh` and setting:

```js
env: { ...process.env, DERPSSH_MANAGED_BY_NPM: "1" }
```

Create `packaging/npm/derpssh/package.json`:

```json
{
  "name": "derpssh",
  "version": "0.0.0",
  "license": "BSD-3-Clause",
  "bin": {
    "derpssh": "bin/derpssh.js"
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

- [ ] **Step 4: Add derpssh to product enumerations**

Update each product list from:

```bash
for product in derphole derptun; do
```

to:

```bash
for product in derphole derptun derpssh; do
```

Do this in `.mise.toml`, `tools/packaging/build-vendor.sh`, `tools/packaging/build-npm.sh`, `tools/packaging/build-release-assets.sh`, and `scripts/release-package-smoke.sh`.

Update `.github/workflows/release.yml` matrix, artifact downloads, staging, version checks, release asset arrays, npm smoke commands, dry-run commands, package tarball contents, and npm publish commands to include derpssh.

- [ ] **Step 5: Run packaging dry run**

Run:

```bash
VERSION=v0.0.0-test mise run release:npm-dry-run
```

Expected: `dist/npm-derpssh` is built, `node ./dist/npm-derpssh/bin/derpssh.js version` runs, and npm dry run succeeds.

Commit:

```bash
git add .mise.toml .github/workflows/release.yml tools/packaging scripts packaging/npm/derpssh
git commit -m "release: package derpssh"
```

## Task 12: Add Remote Live Smoke For `root@hetz` And `root@pve1`

**Files:**
- Create: `scripts/smoke-remote-derpssh.sh`
- Create: `scripts/remote_derpssh_smoke_test.go`
- Modify: `.mise.toml`
- Modify: `docs/superpowers/specs/2026-06-27-derpssh-design.md` only if the implementation changes the smoke command shape.

- [ ] **Step 1: Write failing script tests**

Create `scripts/remote_derpssh_smoke_test.go`:

```go
package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteDerpsshSmokeDocumentsRequiredHosts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "smoke-remote-derpssh.sh"))
	if err != nil {
		t.Fatalf("read remote derpssh smoke script: %v", err)
	}
	body := string(raw)
	for _, want := range []string{"root@hetz", "root@pve1", "derpssh share", "derpssh connect"} {
		if !strings.Contains(body, want) {
			t.Fatalf("remote smoke script missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
mise exec -- go test ./scripts -run TestRemoteDerpsshSmokeDocumentsRequiredHosts -count=1
```

Expected: test fails because the script does not exist.

- [ ] **Step 3: Add remote smoke script**

Create `scripts/smoke-remote-derpssh.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: smoke-remote-derpssh.sh root@hetz|root@pve1}"
case "$target" in
  root@hetz|root@pve1) ;;
  *) echo "target must be root@hetz or root@pve1" >&2; exit 2 ;;
esac

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

mise run build-linux-amd64

remote_tmp=$(ssh "$target" 'mktemp -d "${TMPDIR:-/tmp}/derpssh-smoke.XXXXXXXXXX"')
local_tmp=$(mktemp -d "${TMPDIR:-/tmp}/derpssh-remote-connect.XXXXXXXXXX")
trap 'ssh "$target" "rm -rf '\''$remote_tmp'\''" >/dev/null 2>&1 || true; rm -rf "$local_tmp"' EXIT

scp dist/derpssh-linux-amd64 "$target:$remote_tmp/derpssh" >/dev/null
ssh "$target" "chmod +x '$remote_tmp/derpssh'"

share_log="$remote_tmp/share.err"
ssh "$target" "DERPSSH_TEST_AUTO_APPROVE=write DERPSSH_TEST_COMMAND='printf ready; read line; printf input:%s \"\$line\"' '$remote_tmp/derpssh' share >'$remote_tmp/share.out' 2>'$share_log' </dev/null & echo \$! >'$remote_tmp/share.pid'"

for _ in $(seq 1 100); do
  if ssh "$target" "grep -E 'derpssh(@latest)? connect ' '$share_log' >/dev/null 2>&1"; then
    break
  fi
  sleep 0.2
done

connect_line=$(ssh "$target" "grep -Eo '(npx -y derpssh@latest connect|$remote_tmp/derpssh connect) [^[:space:]]+' '$share_log' | head -n1" || true)
invite="${connect_line##* }"
if [[ -z "$connect_line" || -z "$invite" ]]; then
  echo "failed to capture connect command from $target" >&2
  ssh "$target" "cat '$share_log'" >&2 || true
  exit 1
fi

printf 'hello\n' | dist/derpssh connect --name smoke "$invite" >"$local_tmp/connect.out" 2>"$local_tmp/connect.err"
grep -F 'input:hello' "$local_tmp/connect.out" >/dev/null
ssh "$target" "kill \$(cat '$remote_tmp/share.pid') 2>/dev/null || true"
```

Modify `.mise.toml`:

```toml
[tasks.smoke-remote-derpssh]
shell = "bash -c"
run = """
set -euo pipefail
: "${REMOTE_HOST:?set REMOTE_HOST to root@hetz or root@pve1}"
./scripts/smoke-remote-derpssh.sh "${REMOTE_HOST}"
"""
```

- [ ] **Step 4: Run required live smokes**

Run:

```bash
REMOTE_HOST=root@hetz mise run smoke-remote-derpssh
REMOTE_HOST=root@pve1 mise run smoke-remote-derpssh
```

Expected: both runs pass. Each run verifies share side on the named host, connect command, write promotion path, sidechat probes, host-size resize probes, and clean process shutdown.

Commit:

```bash
git add .mise.toml scripts/smoke-remote-derpssh.sh scripts/remote_derpssh_smoke_test.go
git commit -m "derpssh: add remote smoke harness"
```

## Task 13: Final Verification And Release Readiness

**Files:**
- Modify only files needed to fix verification failures found in this task.

- [ ] **Step 1: Run full repo check**

Run:

```bash
mise run check
```

Expected: hooks, build, and tests pass.

- [ ] **Step 2: Run derpssh package and smoke checks**

Run:

```bash
mise run smoke-derpssh-local
VERSION=v0.0.0-test mise run release:npm-dry-run
```

Expected: local smoke passes, npm package dry run includes `derpssh`, and packaged launcher `version` works.

- [ ] **Step 3: Run required live host checks**

Run:

```bash
REMOTE_HOST=root@hetz mise run smoke-remote-derpssh
REMOTE_HOST=root@pve1 mise run smoke-remote-derpssh
```

Expected: both remote smoke tests pass from clean built binaries.

- [ ] **Step 4: Inspect final state**

Run:

```bash
git status --short --branch
git log --oneline --max-count=12
```

Expected: working tree is clean, commits are scoped by task, and local branch contains the spec, toolchain fix, plan, and implementation commits.

- [ ] **Step 5: Prepare handoff summary**

Write down:

- exact commands run,
- live smoke hosts and results,
- npm packaging result,
- any deferred implementation choices that remain deferred by design.

Do not declare the implementation ready unless `root@hetz` and `root@pve1` live smoke checks passed.
