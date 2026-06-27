# derpssh True TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` for parallelizable implementation tasks, or `superpowers:executing-plans` for inline execution. Update each checkbox as it is completed.

**Goal:** Replace the shipped derpssh string dashboard with a true tmux-like terminal sharing TUI: full-screen alternate-screen app, modern top bar, collapsible sidechat sidebar, clickable controls, Ctrl-X shortcuts, host-authoritative terminal sizing, and a rich PTY-backed shared shell.

**Current failure:** `pkg/derpssh/session/console.go` clears the terminal and prints `pkg/derpssh/tui/view.go` as plain strings. `pkg/derpssh/session/input.go` uses colon commands. This is not a TUI, does not support real layout or mouse hit testing, and violates the product requirement.

**Architecture:** Bubble Tea owns the local interactive screen. A terminal emulator adapter owns the shell screen buffer. The session runtime continues to own transport, PTY IO, roles, approval, and chat protocol. The UI communicates with the runtime through typed commands and typed runtime events; no derpssh UI control is sent as shell text.

**Tech Stack:**

- `github.com/charmbracelet/bubbletea@v1.3.10` for the full-screen TUI app, key messages, mouse messages, alternate screen, and program lifecycle.
- `github.com/charmbracelet/bubbles@v1.0.0` for the sidechat composer textarea.
- `github.com/charmbracelet/lipgloss@v1.1.0` for modern TUI styling and layout composition.
- `github.com/hinshun/vt10x` for the first terminal screen adapter because it exposes an `io.Writer` terminal emulator with `View()`.
- Existing `pkg/derpssh/session` runtime and `pkg/derpssh/protocol` message types for collaboration state.

**Reference Repos Used:**

- `~/code/tmate`: tmux-derived model for host-owned pane dimensions, screen state, and role/permission semantics.
- `~/code/sshx`: collaborative terminal concepts: share/connect UX, chat, status, and permission changes.
- `~/code/yeet`: PTY lifecycle, resize propagation, SSH-like interactive transport discipline, and live remote smoke expectations.
- `~/code/asciinema`: PTY spawn/read/write/resize behavior and EOF/EIO handling.
- `~/code/fresh`: modern TUI mouse/layout patterns and responsive terminal UI discipline.

---

## Non-Negotiable Product Gates

- [ ] The visible derpssh app uses Bubble Tea alternate screen, not repeated `fmt.Fprintln` rendering.
- [ ] The primary shell pane is a terminal screen model backed by PTY bytes, not escaped text appended into a string slice.
- [ ] Normal printable input, Enter, arrows, Backspace, Tab, and Ctrl-C/Ctrl-D/Ctrl-Z go to the shared PTY when terminal focus is active.
- [ ] Derpssh controls use Ctrl-X chords and clickable controls. Colon commands are removed from the interactive product path.
- [ ] The host terminal pane size is authoritative. Guest UI shows the host pane dimensions and renders inside them.
- [ ] Sidechat is a real collapsible sidebar with composer, message history, unread badge, and mouse focus.
- [ ] Approval is a modal in the host TUI with clickable read, write, and deny actions plus Ctrl-X shortcuts.
- [ ] The release is not cut until local tests, local smoke, remote smoke on `root@hetz` and `root@pve1`, npm dry run, and public `npx -y derpssh@latest` smoke pass.

---

## Task 1: Add TUI Dependencies With Toolchain Consistency

**Files:**

- `go.mod`
- `go.sum`
- `cmd/derpssh/depaware.txt`

**Steps:**

- [ ] Run:

  ```sh
  mise exec -- go get github.com/charmbracelet/bubbletea@v1.3.10 github.com/charmbracelet/bubbles@v1.0.0 github.com/charmbracelet/lipgloss@v1.1.0 github.com/hinshun/vt10x@latest
  ```

- [ ] Run:

  ```sh
  mise exec -- go mod tidy
  ```

- [ ] Add the new import roots to `cmd/derpssh/depaware.txt` so vendored dependency checks stay intentional.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui ./pkg/derpssh/session`
- [ ] `mise run check:hooks`

---

## Task 2: Replace the String View With a Real Layout Model

**Files:**

- Delete `pkg/derpssh/tui/view.go`
- Add `pkg/derpssh/tui/layout.go`
- Add `pkg/derpssh/tui/layout_test.go`
- Add `pkg/derpssh/tui/styles.go`
- Add `pkg/derpssh/tui/model.go`

**Types and Functions:**

```go
package tui

type Focus int

const (
	FocusTerminal Focus = iota
	FocusChat
	FocusApproval
)

type Rect struct {
	X int
	Y int
	W int
	H int
}

type Layout struct {
	Outer       Rect
	TopBar      Rect
	Terminal    Rect
	Sidebar     Rect
	Status      Rect
	Composer    Rect
	SidebarOpen bool
}

func ComputeLayout(cols int, rows int, sidebarOpen bool) Layout
func (l Layout) Hit(x int, y int) HitTarget
```

**Test First:**

- [ ] `TestComputeLayoutExpandedSidebar` asserts a 120x40 window produces:
  - top bar at row 0
  - status bar at final row
  - terminal pane starts below the top bar
  - sidebar uses the right 34 columns
  - composer is inside the sidebar
- [ ] `TestComputeLayoutCollapsedSidebar` asserts the terminal uses the full width under the top bar and above the status bar.
- [ ] `TestLayoutHitTargets` asserts clicks in the top bar, terminal, sidebar, composer, and status bar return distinct targets.

**Implementation Notes:**

- Top bar height is `1`.
- Status bar height is `1`.
- Expanded sidebar width is `34`, clamped to at most one third of the window and at least `24` when the window is wide enough.
- Composer height is `3`.
- Minimum terminal pane dimensions are clamped to `1x1`.
- Styles live in `styles.go` and use `lipgloss.AdaptiveColor`.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui -run 'TestComputeLayout|TestLayoutHitTargets'`

---

## Task 3: Add a Terminal Screen Adapter

**Files:**

- Add `pkg/derpssh/tui/terminal.go`
- Add `pkg/derpssh/tui/terminal_test.go`

**Types and Functions:**

```go
package tui

type TerminalPane interface {
	Write(p []byte) (int, error)
	Resize(cols int, rows int)
	View(width int, height int) string
	MouseMode() MouseMode
}

type MouseMode struct {
	Enabled bool
	SGR     bool
}

func NewVTTerminalPane(cols int, rows int) TerminalPane
func TrackMouseMode(current MouseMode, output []byte) MouseMode
```

**Test First:**

- [ ] `TestVTTerminalPaneRendersANSIOutput` writes `hello\r\nworld` and asserts both lines render.
- [ ] `TestVTTerminalPaneHandlesCursorMovement` writes `hello\x1b[2D!!` and asserts the visible output is `hel!!`.
- [ ] `TestTrackMouseModeSGREnableDisable` writes CSI `?1000h`, `?1006h`, `?1006l`, and `?1000l` sequences and asserts the mode transitions.

**Implementation Notes:**

- Wrap `vt10x.New()` behind `NewVTTerminalPane`.
- Keep `TerminalPane` narrow so the adapter can be replaced without touching session runtime.
- Track xterm mouse enable/disable sequences from PTY output before writing output into the emulator.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui -run 'TestVTTerminalPane|TestTrackMouseMode'`

---

## Task 4: Build the Bubble Tea App Model

**Files:**

- Add `pkg/derpssh/tui/app.go`
- Add `pkg/derpssh/tui/messages.go`
- Add `pkg/derpssh/tui/app_test.go`
- Update `pkg/derpssh/tui/model.go`

**Types and Functions:**

```go
package tui

type Role string

const (
	RolePending Role = "pending"
	RoleRead    Role = "read"
	RoleWrite   Role = "write"
)

type Peer struct {
	Name string
	Role Role
}

type ChatMessage struct {
	Author string
	Body   string
	Local  bool
}

type Command interface{ command() }

type TerminalInputCommand struct{ Data []byte }
type ChatSendCommand struct{ Body string }
type RoleChangeCommand struct{ Peer string; Role Role }
type KickCommand struct{ Peer string }
type ApprovalDecisionCommand struct{ Peer string; Role Role; Deny bool }

type TerminalDataMsg []byte
type RuntimeStateMsg struct {
	Transport string
	HostCols  int
	HostRows  int
	Peers     []Peer
}
type ChatMsg ChatMessage
type ApprovalRequestMsg struct{ Peer string }

type App struct {
	// concrete fields live in implementation and remain package-private
}

func NewApp(opts Options) *App
func (a *App) Init() tea.Cmd
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd)
func (a *App) View() string
func (a *App) Commands() <-chan Command
```

**Test First:**

- [ ] `TestAppUsesAltScreenCompatibleView` asserts `View()` renders a top bar, terminal pane, status bar, and no old `terminal\n-----` dashboard sections.
- [ ] `TestTerminalDataUpdatesTerminalPane` sends `TerminalDataMsg("root@host:# ")` and asserts the terminal pane renders it.
- [ ] `TestRuntimeStateUpdatesTopBar` sends transport, host size, and peer role state and asserts the top bar reflects them.
- [ ] `TestApprovalRequestRendersModal` sends `ApprovalRequestMsg{Peer:"shayne"}` and asserts read, write, and deny controls are visible in the modal.

**Implementation Notes:**

- The app model owns layout, focus, sidebar state, chat history, unread count, approval modal state, terminal pane, and command channel.
- `tea.WithAltScreen()` and `tea.WithMouseCellMotion()` are applied by the session driver, not inside `NewApp`, so tests can instantiate the app without a terminal.
- `View()` uses Lip Gloss layout composition and fixed-width clipping.
- The status bar always shows Ctrl-X help, current focus, and connection state.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui -run 'TestAppUses|TestTerminalData|TestRuntimeState|TestApprovalRequest'`

---

## Task 5: Implement Ctrl-X Shortcuts and Raw Terminal Key Encoding

**Files:**

- Add `pkg/derpssh/tui/keys.go`
- Add `pkg/derpssh/tui/keys_test.go`
- Update `pkg/derpssh/tui/app.go`

**Shortcut Contract:**

- `Ctrl-X` enters derpssh prefix mode.
- `Ctrl-X S` toggles the sidechat sidebar.
- `Ctrl-X C` focuses the chat composer.
- `Ctrl-X T` focuses the terminal pane.
- `Ctrl-X R` approves the pending guest as read when an approval modal is open.
- `Ctrl-X W` approves the pending guest as write when an approval modal is open.
- `Ctrl-X D` denies the pending guest when an approval modal is open.
- `Ctrl-X K` opens a kick confirmation when the host has a peer.
- `Ctrl-X ?` opens a shortcut help overlay.
- `Esc` cancels prefix mode, composer focus, help overlay, or modal focus according to the active state.

**Types and Functions:**

```go
package tui

func EncodeTerminalKey(msg tea.KeyMsg) ([]byte, bool)
func HandlePrefixKey(app *App, msg tea.KeyMsg) tea.Cmd
```

**Test First:**

- [ ] `TestEncodeTerminalKeyPrintable` asserts printable runes encode as UTF-8 bytes.
- [ ] `TestEncodeTerminalKeyControlBytes` asserts `ctrl+c`, `ctrl+d`, `ctrl+z`, and `ctrl+l` encode to the expected control bytes.
- [ ] `TestEncodeTerminalKeyNavigation` asserts arrows, Home, End, Delete, Backspace, Enter, and Tab encode to standard terminal bytes.
- [ ] `TestPrefixDoesNotReachPTY` sends `ctrl+x` then `s` and asserts no `TerminalInputCommand` is emitted.
- [ ] `TestColonIsPlainShellInput` sends `:`, `c`, `h`, `a`, `t` with terminal focus and asserts those bytes are emitted to the PTY.

**Implementation Notes:**

- No vim-style mode and no colon command parser in the interactive path.
- The only derpssh command prefix is Ctrl-X.
- When chat composer has focus, printable keys update the textarea and Enter sends chat.
- When terminal has focus, keys not consumed by Ctrl-X or active overlays emit `TerminalInputCommand`.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui -run 'TestEncodeTerminalKey|TestPrefix|TestColon'`

---

## Task 6: Implement Mouse Hit Testing and Clickable Controls

**Files:**

- Add `pkg/derpssh/tui/mouse.go`
- Add `pkg/derpssh/tui/mouse_test.go`
- Update `pkg/derpssh/tui/app.go`

**Types and Functions:**

```go
package tui

func EncodeSGRMouse(msg tea.MouseMsg, terminal Rect) ([]byte, bool)
func HandleMouse(app *App, msg tea.MouseMsg) tea.Cmd
```

**Test First:**

- [ ] `TestMouseClickSidebarToggle` clicks the top-bar sidechat control and asserts `SidebarOpen` changes.
- [ ] `TestMouseClickFocusesTerminalAndChat` clicks terminal and composer rectangles and asserts focus changes.
- [ ] `TestMouseClickApprovalButtons` clicks read, write, and deny buttons and asserts the correct approval command is emitted.
- [ ] `TestTerminalMouseOnlyForwardsWhenEnabled` enables terminal mouse mode, clicks inside the terminal pane, and asserts an SGR mouse sequence is emitted. The same click with mouse mode disabled emits no shell bytes.

**Implementation Notes:**

- Derpssh controls always win hit testing before terminal mouse forwarding.
- Terminal app mouse forwarding uses SGR mouse sequences and only activates when `TerminalPane.MouseMode().Enabled` is true.
- Mouse coordinates are converted from outer terminal coordinates to terminal-pane-local 1-based coordinates before encoding.
- Mouse wheel events scroll sidechat when the pointer is over the sidebar; wheel events inside terminal forward only when terminal mouse mode is enabled.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui -run 'TestMouse|TestTerminalMouse'`

---

## Task 7: Replace `terminalConsole` With a Bubble Tea Session Driver

**Files:**

- Replace `pkg/derpssh/session/console.go`
- Update `pkg/derpssh/session/share.go`
- Update `pkg/derpssh/session/connect.go`
- Add `pkg/derpssh/session/tui_console_test.go`

**Types and Functions:**

```go
package session

type tuiConsole struct {
	// fields stay package-private
}

func newTUIConsole(opts tuiConsoleOptions) *tuiConsole
func (c *tuiConsole) Start(ctx context.Context) error
func (c *tuiConsole) Stop() error
func (c *tuiConsole) Write(p []byte) (int, error)
func (c *tuiConsole) RequestApproval(ctx context.Context, peer string) (protocol.Role, bool)
func (c *tuiConsole) HandleRuntimeEvent(event RuntimeEvent)
```

**Test First:**

- [ ] `TestTUIConsoleWriteSendsTerminalData` writes PTY bytes and asserts the app receives `TerminalDataMsg`.
- [ ] `TestTUIConsoleApprovalWaitsForDecision` sends an approval request and completes when an approval command arrives.
- [ ] `TestTUIConsoleRuntimeEventsUpdateApp` sends peer, role, transport, chat, and resize events and asserts typed TUI messages are sent.
- [ ] `TestTUIConsoleCommandsCallRuntimeCallbacks` emits terminal input, chat, role change, kick, and approval commands and asserts the injected callbacks are called.

**Implementation Notes:**

- `newTUIConsole` creates a `tea.Program` with `tea.WithAltScreen()` and `tea.WithMouseCellMotion()` only when stdin/stdout are TTYs.
- Non-TTY tests use the same app model through an in-memory driver and do not use the legacy plain renderer.
- `Write` never prints directly. It sends `TerminalDataMsg` to the Bubble Tea program with `Program.Send`.
- `RequestApproval` renders the host modal and waits for a typed approval decision or context cancellation.
- `HandleRuntimeEvent` maps session runtime events to `tui.RuntimeStateMsg`, `tui.ChatMsg`, and approval messages.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/session -run 'TestTUIConsole'`

---

## Task 8: Remove Colon Commands From Interactive Input

**Files:**

- Update `pkg/derpssh/session/input.go`
- Update `pkg/derpssh/session/input_test.go`
- Update `pkg/derpssh/session/share.go`
- Update `pkg/derpssh/session/connect.go`

**Test First:**

- [ ] `TestInteractiveColonTextGoesToPTY` proves `:chat hello` is sent as shell bytes when terminal focus is active.
- [ ] `TestCtrlXChatSendsSidechat` proves chat uses the UI command path, not shell text.
- [ ] `TestHostRoleChangesUseUICommand` proves read/write/kick actions use typed commands.

**Implementation Notes:**

- Remove the product-facing colon command parser from interactive TTY flows.
- Keep any remaining parser code only for private smoke harnesses under names that include `testHarness`.
- Public help text must advertise Ctrl-X commands and clickable controls only.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/session -run 'TestInteractiveColon|TestCtrlXChat|TestHostRole'`
- [ ] `rg -n ':\(chat|read|write|kick\)|:chat|:read|:write|:kick' pkg/derpssh cmd packaging README.md docs` returns no product help text.

---

## Task 9: Host-Authoritative Resize and Shared Layout State

**Files:**

- Update `pkg/derpssh/session/pty.go`
- Update `pkg/derpssh/session/share.go`
- Update `pkg/derpssh/session/connect.go`
- Update `pkg/derpssh/protocol/messages.go`
- Add `pkg/derpssh/session/resize_test.go`

**Behavior:**

- The host TUI computes terminal-pane dimensions from the current host window and sidebar state.
- The host PTY is resized to the terminal-pane dimensions, not the full outer terminal dimensions.
- The host broadcasts the terminal-pane dimensions to guests.
- Guests display `host <cols>x<rows>` in the top bar and render the shared terminal pane to that host size.
- Guest local window changes recompute local chrome, but do not resize the host PTY.

**Test First:**

- [ ] `TestHostResizeUsesTerminalPaneDimensions` sends a 120x40 host window with sidebar open and asserts the PTY resize request is less than 120 columns and 40 rows.
- [ ] `TestGuestResizeDoesNotResizeHostPTY` sends a guest local resize and asserts no host resize command is emitted.
- [ ] `TestHostLayoutBroadcastUpdatesGuestTopBar` sends layout state and asserts the guest top bar reports the host terminal size.

**Implementation Notes:**

- Reuse the existing protocol resize event if it already carries host dimensions; extend it only when needed for terminal-pane-specific dimensions.
- Keep the wire change backward compatible with older peers by defaulting missing pane dimensions to current outer dimensions.
- Debounce resize events with the existing runtime event loop to avoid resize storms.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/session -run 'TestHostResize|TestGuestResize|TestHostLayout'`

---

## Task 10: Modern Visual Polish Pass

**Files:**

- Update `pkg/derpssh/tui/styles.go`
- Update `pkg/derpssh/tui/app.go`
- Update `pkg/derpssh/tui/app_test.go`

**Visual Contract:**

- Top bar contains `derpssh`, side role, peer status, transport state, host pane size, and sidechat toggle.
- Top bar uses a high-contrast dark background with one restrained accent color.
- Terminal pane occupies the dominant space and has no decorative card wrapper.
- Sidebar has a clean left border, sidechat title, message history, composer, unread badge, and compact controls.
- Status bar shows active focus, Ctrl-X prefix hint, and short transport state.
- Approval modal is centered, bounded, and uses three button-like controls: Read, Write, Deny.
- No long base64 invite token is rendered inside the full-screen app after startup; the invite command is printed before entering the app and is available in the top bar as a compact copied/visible state.

**Test First:**

- [ ] `TestViewDoesNotExposeFullInviteTokenInMainLayout` asserts a long invite command is not rendered across the top-level app layout.
- [ ] `TestViewRendersModernControls` asserts the view contains sidechat, role, transport, focus, and Ctrl-X hints.
- [ ] `TestViewFitsNarrowWindow` renders 60x20 and asserts every line is at most 60 cells.

**Implementation Notes:**

- Use Lip Gloss width helpers for clipping and joining.
- Avoid negative letter spacing and visual noise.
- Keep color choices compatible with light and dark terminal themes through adaptive colors.

**Verification:**

- [ ] `mise exec -- go test ./pkg/derpssh/tui -run 'TestView'`

---

## Task 11: Update Smoke Harnesses for Real TUI Behavior

**Files:**

- Update `scripts/smoke-derpssh-local.sh`
- Update `scripts/smoke-remote-share.sh`
- Update `.mise.toml`
- Add `scripts/smoke-derpssh-tui.sh`

**Behavior:**

- Local smoke runs host and guest through PTYs so Bubble Tea receives TTY semantics.
- Smoke verifies:
  - invite command is produced
  - host approval modal appears
  - write approval works
  - guest shell input is visible on host
  - host shell output is visible on guest
  - Ctrl-X sidechat sends a message
  - sidebar toggle works
- The smoke scripts save compact transcripts under `dist/smoke/`.

**Commands:**

```sh
mise run smoke-local
REMOTE_HOST=root@hetz mise run smoke-remote-share
REMOTE_HOST=root@pve1 mise run smoke-remote-share
```

**Test First:**

- [ ] Add a failing smoke assertion that rejects the old dashboard by searching transcripts for the literal `terminal\n-----`.
- [ ] Add a failing smoke assertion that requires `Ctrl-X` help text and `sidechat` in the TUI transcript.

**Implementation Notes:**

- Use PTY-backed shell tools available in the repo or standard `script`/`expect` commands detected at runtime.
- Do not pipe stdin/stdout directly to derpssh for the interactive smoke path.
- Keep existing transport assertions from the current smoke scripts.

**Verification:**

- [ ] `mise run smoke-local`
- [ ] `REMOTE_HOST=root@hetz mise run smoke-remote-share`
- [ ] `REMOTE_HOST=root@pve1 mise run smoke-remote-share`

---

## Task 12: Packaging, Release, and Public NPM Verification

**Files:**

- Update `docs/releases/npm.md` if release steps or smoke command names change.
- Update package metadata only through existing release scripts.

**Steps:**

- [ ] Run:

  ```sh
  mise run test
  mise run vet
  mise run check
  mise run release:npm-dry-run
  ```

- [ ] Bump to `v0.15.3` using the repo's existing release flow.
- [ ] Publish the npm package only after the dry run and local/remote smoke gates pass.
- [ ] From a clean temp directory, run:

  ```sh
  npx -y derpssh@latest share
  ```

- [ ] In a second clean PTY, run the printed:

  ```sh
  npx -y derpssh@latest connect ...
  ```

- [ ] Verify the public npm package shows:
  - Bubble Tea full-screen UI
  - host approval modal
  - top bar
  - collapsible sidechat
  - raw shell collaboration
  - no old string dashboard

**Verification:**

- [ ] `npm view derpssh version` reports `0.15.3`.
- [ ] `npx -y derpssh@latest --version` reports `0.15.3`.
- [ ] Public `npx` live smoke passes on the local machine.
- [ ] Public `npx` live smoke passes through `root@hetz`.
- [ ] Public `npx` live smoke passes through `root@pve1`.

---

## Final Acceptance Checklist

- [ ] `mise exec -- go test ./pkg/derpssh/tui ./pkg/derpssh/session`
- [ ] `mise run test`
- [ ] `mise run vet`
- [ ] `mise run check`
- [ ] `mise run smoke-local`
- [ ] `REMOTE_HOST=root@hetz mise run smoke-remote-share`
- [ ] `REMOTE_HOST=root@pve1 mise run smoke-remote-share`
- [ ] `mise run release:npm-dry-run`
- [ ] Public `npx -y derpssh@latest share/connect` verified after publish
- [ ] Release tag and `origin/main` point at the verified implementation commit
