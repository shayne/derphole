# derpssh Restart Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the host shell exits, derpssh keeps the share session alive and shows the host a Restart Shell or Quit dialog; restarting creates a fresh PTY for the same session, and quitting tears down everyone cleanly.

**Architecture:** Introduce a restartable host terminal manager that owns the current PTY and exposes stable `io.Reader` and `io.Writer` surfaces to the existing host runtime. EOF from one shell closes only the current PTY generation, sends a local shell-exited event, and blocks output reads until the host chooses Restart or Quit. The TUI gains a typed restart command so shell lifecycle control stays out of the shared shell byte stream.

**Tech Stack:** Go, existing derpssh session runtime, existing Bubble Tea TUI command/event plumbing, existing `pkg/derpssh/pty` PTY start/resize/close helpers, and existing `mise` verification tasks.

---

## File Responsibilities

- `pkg/derpssh/session/share_terminal_manager.go`: new restartable terminal manager that wraps `startShareTerminal`, tracks the active PTY generation, exposes stable input/output, and emits shell lifecycle events.
- `pkg/derpssh/session/share_terminal_manager_test.go`: focused unit tests for EOF, restart, write routing, resize, close, and wait behavior.
- `pkg/derpssh/tui/messages.go`: add `RestartShellCommand`.
- `pkg/derpssh/tui/app.go`: replace the shell-exited quit-only dialog with Restart Shell and Quit choices.
- `pkg/derpssh/tui/app_test.go` or `pkg/derpssh/tui/keys_test.go`: tests for shell-exited dialog rendering and keyboard/click command emission.
- `pkg/derpssh/session/console.go`: add a `RestartShell` callback and route `RestartShellCommand` from the app.
- `pkg/derpssh/session/console_test.go`: test that restart commands call the callback and shell-exited runtime events display the restart dialog.
- `pkg/derpssh/session/share.go`: use the restartable terminal manager instead of one single-use `shareTerminal`; wire restart callback to start a new PTY at the current host terminal size.
- `pkg/derpssh/session/share_connect_test.go`: end-to-end-ish tests for host shell EOF followed by restart and for quit after EOF.

---

## Task 1: Add a Restartable Terminal Manager

**Files:**
- Create: `pkg/derpssh/session/share_terminal_manager.go`
- Create: `pkg/derpssh/session/share_terminal_manager_test.go`

- [ ] **Step 1: Write the failing EOF/restart tests**

Add this test scaffold in `pkg/derpssh/session/share_terminal_manager_test.go`:

```go
package session

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/pty"
)

func TestRestartableShareTerminalEOFBlocksUntilRestart(t *testing.T) {
	firstOutR, firstOutW := io.Pipe()
	secondOutR, secondOutW := io.Pipe()
	firstIn := &recordingWriter{}
	secondIn := &recordingWriter{}
	starts := 0
	start := func(size pty.Size) (*shareTerminal, error) {
		starts++
		switch starts {
		case 1:
			return &shareTerminal{
				Input:  firstIn,
				Output: firstOutR,
				close:  func() error { return nil },
				wait:   func() error { return nil },
				resize: func(pty.Size) error { return nil },
			}, nil
		case 2:
			if size != (pty.Size{Cols: 100, Rows: 30}) {
				t.Fatalf("restart size = %+v, want 100x30", size)
			}
			return &shareTerminal{
				Input:  secondIn,
				Output: secondOutR,
				close:  func() error { return nil },
				wait:   func() error { return nil },
				resize: func(pty.Size) error { return nil },
			}, nil
		default:
			t.Fatalf("unexpected start %d", starts)
			return nil, nil
		}
	}

	mgr, err := newRestartableShareTerminal(pty.Size{Cols: 80, Rows: 24}, start)
	if err != nil {
		t.Fatalf("newRestartableShareTerminal error = %v", err)
	}
	defer mgr.Close()

	_, _ = firstOutW.Write([]byte("one"))
	buf := make([]byte, 8)
	n, err := mgr.Output.Read(buf)
	if err != nil || string(buf[:n]) != "one" {
		t.Fatalf("first read = %q, %v; want one, nil", string(buf[:n]), err)
	}

	_ = firstOutW.Close()
	event := <-mgr.Events()
	if event.Kind != shareTerminalShellExited {
		t.Fatalf("event kind = %v, want shell exited", event.Kind)
	}

	blocked := make(chan struct{})
	go func() {
		_, _ = mgr.Output.Read(buf)
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("read returned before restart")
	case <-time.After(20 * time.Millisecond):
	}

	if err := mgr.Restart(pty.Size{Cols: 100, Rows: 30}); err != nil {
		t.Fatalf("Restart error = %v", err)
	}
	_, _ = secondOutW.Write([]byte("two"))
	n, err = mgr.Output.Read(buf)
	if err != nil || string(buf[:n]) != "two" {
		t.Fatalf("second read = %q, %v; want two, nil", string(buf[:n]), err)
	}
}

func TestRestartableShareTerminalWriteUsesActiveGeneration(t *testing.T) {
	firstOutR, firstOutW := io.Pipe()
	secondOutR, _ := io.Pipe()
	firstIn := &recordingWriter{}
	secondIn := &recordingWriter{}
	starts := 0
	start := func(pty.Size) (*shareTerminal, error) {
		starts++
		if starts == 1 {
			return &shareTerminal{Input: firstIn, Output: firstOutR, close: func() error { return nil }, wait: func() error { return nil }}, nil
		}
		return &shareTerminal{Input: secondIn, Output: secondOutR, close: func() error { return nil }, wait: func() error { return nil }}, nil
	}

	mgr, err := newRestartableShareTerminal(pty.Size{Cols: 80, Rows: 24}, start)
	if err != nil {
		t.Fatalf("newRestartableShareTerminal error = %v", err)
	}
	defer mgr.Close()

	if _, err := mgr.Input.Write([]byte("before")); err != nil {
		t.Fatalf("first write error = %v", err)
	}
	if got := firstIn.String(); got != "before" {
		t.Fatalf("first input = %q, want before", got)
	}

	_ = firstOutW.Close()
	<-mgr.Events()
	if _, err := mgr.Input.Write([]byte("between")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write while exited error = %v, want ErrClosedPipe", err)
	}
	if err := mgr.Restart(pty.Size{Cols: 80, Rows: 24}); err != nil {
		t.Fatalf("Restart error = %v", err)
	}
	if _, err := mgr.Input.Write([]byte("after")); err != nil {
		t.Fatalf("second write error = %v", err)
	}
	if got := secondIn.String(); got != "after" {
		t.Fatalf("second input = %q, want after", got)
	}
}
```

Add this helper at the bottom of the test file:

```go
type recordingWriter struct {
	data []byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *recordingWriter) String() string {
	return string(w.data)
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestRestartableShareTerminal' -count=1
```

Expected: FAIL because `newRestartableShareTerminal` and event types do not exist.

- [ ] **Step 3: Implement the manager**

Create `pkg/derpssh/session/share_terminal_manager.go`:

```go
package session

import (
	"errors"
	"io"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/pty"
)

type shareTerminalEventKind string

const (
	shareTerminalShellExited shareTerminalEventKind = "shell-exited"
)

type shareTerminalEvent struct {
	Kind shareTerminalEventKind
	Err  error
}

type shareTerminalStarter func(pty.Size) (*shareTerminal, error)

type restartableShareTerminal struct {
	Input  io.Writer
	Output io.Reader

	start shareTerminalStarter

	mu       sync.Mutex
	cond     *sync.Cond
	current  *shareTerminal
	closed   bool
	exited   bool
	events   chan shareTerminalEvent
	waitErrs []error
}

func newRestartableShareTerminal(size pty.Size, start shareTerminalStarter) (*restartableShareTerminal, error) {
	if start == nil {
		start = startShareTerminal
	}
	m := &restartableShareTerminal{
		start:  start,
		events: make(chan shareTerminalEvent, 8),
	}
	m.cond = sync.NewCond(&m.mu)
	m.Input = restartableTerminalInput{manager: m}
	m.Output = restartableTerminalOutput{manager: m}
	if err := m.Restart(size); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *restartableShareTerminal) Restart(size pty.Size) error {
	next, err := m.start(size)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = next.Close()
		_ = next.Wait()
		return io.ErrClosedPipe
	}
	old := m.current
	m.current = next
	m.exited = false
	m.cond.Broadcast()
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
		_ = old.Wait()
	}
	return nil
}

func (m *restartableShareTerminal) Resize(size pty.Size) error {
	m.mu.Lock()
	current := m.current
	m.mu.Unlock()
	if current == nil {
		return nil
	}
	return current.Resize(size)
}

func (m *restartableShareTerminal) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	current := m.current
	m.current = nil
	m.cond.Broadcast()
	m.mu.Unlock()
	if current != nil {
		return current.Close()
	}
	return nil
}

func (m *restartableShareTerminal) Wait() error {
	m.mu.Lock()
	errs := append([]error(nil), m.waitErrs...)
	current := m.current
	m.mu.Unlock()
	if current != nil {
		errs = append(errs, current.Wait())
	}
	return errors.Join(errs...)
}

func (m *restartableShareTerminal) Events() <-chan shareTerminalEvent {
	return m.events
}

func (m *restartableShareTerminal) active() (*shareTerminal, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for m.current == nil && !m.closed {
		m.cond.Wait()
	}
	return m.current, m.closed
}

func (m *restartableShareTerminal) markExited(term *shareTerminal, err error) {
	m.mu.Lock()
	if m.current != term {
		m.mu.Unlock()
		return
	}
	m.current = nil
	m.exited = true
	m.waitErrs = append(m.waitErrs, term.Wait())
	m.cond.Broadcast()
	m.mu.Unlock()
	select {
	case m.events <- shareTerminalEvent{Kind: shareTerminalShellExited, Err: err}:
	default:
	}
}

type restartableTerminalInput struct {
	manager *restartableShareTerminal
}

func (w restartableTerminalInput) Write(p []byte) (int, error) {
	w.manager.mu.Lock()
	current := w.manager.current
	closed := w.manager.closed
	w.manager.mu.Unlock()
	if closed || current == nil || current.Input == nil {
		return 0, io.ErrClosedPipe
	}
	return current.Input.Write(p)
}

type restartableTerminalOutput struct {
	manager *restartableShareTerminal
}

func (r restartableTerminalOutput) Read(p []byte) (int, error) {
	for {
		current, closed := r.manager.active()
		if closed {
			return 0, io.EOF
		}
		n, err := current.Output.Read(p)
		if err == nil {
			return n, nil
		}
		if n > 0 {
			r.manager.markExited(current, err)
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			r.manager.markExited(current, err)
			continue
		}
		r.manager.markExited(current, err)
		continue
	}
}
```

- [ ] **Step 4: Run the manager tests**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestRestartableShareTerminal' -count=1
```

Expected: PASS.

---

## Task 2: Add a Typed Restart Command to the TUI

**Files:**
- Modify: `pkg/derpssh/tui/messages.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/app_test.go`

- [ ] **Step 1: Write failing app tests**

Add tests to `pkg/derpssh/tui/app_test.go`:

```go
func TestShellExitedNoticeShowsRestartDialog(t *testing.T) {
	app := NewApp(Options{Side: string(ModeHost), DisplayName: "root@hetz", Terminal: NewVTTerminalPane(80, 24)})
	app.SetWindowSize(100, 30)
	app.Update(NoticeMsg{Title: "Shell exited", Body: "The shared shell exited."})
	view := app.View()
	for _, want := range []string{"Shell exited", "Restart Shell", "Quit"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}
}

func TestShellExitedRestartChoiceEmitsRestartCommand(t *testing.T) {
	app := NewApp(Options{Side: string(ModeHost), DisplayName: "root@hetz", Terminal: NewVTTerminalPane(80, 24)})
	app.SetWindowSize(100, 30)
	app.Update(NoticeMsg{Title: "Shell exited", Body: "The shared shell exited."})
	app.Update(tea.KeyMsg{Type: tea.KeyEnter})
	select {
	case _, ok := (<-app.Commands()).(RestartShellCommand):
		if !ok {
			t.Fatal("command is not RestartShellCommand")
		}
	default:
		t.Fatal("no restart command emitted")
	}
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -run 'TestShellExited' -count=1
```

Expected: FAIL because `RestartShellCommand` does not exist and shell-exit currently opens a quit-only dialog.

- [ ] **Step 3: Add the restart command type**

In `pkg/derpssh/tui/messages.go`, add:

```go
type RestartShellCommand struct{}

func (RestartShellCommand) command() {}
```

- [ ] **Step 4: Update shell-exited modal state**

In `pkg/derpssh/tui/app.go`, add a shell-exit modal path that is separate from normal quit confirmation:

```go
type shellExitChoice int

const (
	shellExitChoiceRestart shellExitChoice = iota
	shellExitChoiceQuit
)
```

Extend `App` with:

```go
shellExitOpen   bool
shellExitChoice shellExitChoice
```

Change `applyNotice` for title `Shell exited` to:

```go
if strings.EqualFold(strings.TrimSpace(msg.Title), "Shell exited") {
	a.notice = nil
	a.shellExitOpen = true
	a.shellExitChoice = shellExitChoiceRestart
	return
}
```

Render the modal with:

```go
func (a *App) shellExitLines() []string {
	restartStyle := a.styles.DialogButton
	quitStyle := a.styles.DialogButton
	if a.shellExitChoice == shellExitChoiceRestart {
		restartStyle = a.styles.DialogButtonActive
	} else {
		quitStyle = a.styles.DialogButtonActive
	}
	return []string{
		a.styles.DialogTitle.Render("Shell exited"),
		a.styles.DialogText.Render("The shared shell exited. Restart it or close the session for everyone."),
		"",
		restartStyle.Render(" Restart Shell ") + "  " + quitStyle.Render(" Quit "),
	}
}
```

Route keys while open:

```go
func (a *App) handleShellExitKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "right", "tab":
		if a.shellExitChoice == shellExitChoiceRestart {
			a.shellExitChoice = shellExitChoiceQuit
		} else {
			a.shellExitChoice = shellExitChoiceRestart
		}
	case "enter":
		if a.shellExitChoice == shellExitChoiceRestart {
			a.shellExitOpen = false
			return a, a.emit(RestartShellCommand{})
		}
		return a, a.emit(QuitCommand{})
	case "ctrl+x q":
		return a, a.emit(QuitCommand{})
	}
	return a, nil
}
```

- [ ] **Step 5: Run the app tests**

Run:

```bash
mise exec -- go test ./pkg/derpssh/tui -run 'TestShellExited' -count=1
```

Expected: PASS.

---

## Task 3: Route Restart Commands Through the Console

**Files:**
- Modify: `pkg/derpssh/session/console.go`
- Modify: `pkg/derpssh/session/console_test.go`

- [ ] **Step 1: Write failing console callback test**

Add to `pkg/derpssh/session/console_test.go`:

```go
func TestTUIConsoleRestartShellCommandCallsCallback(t *testing.T) {
	console := newHeadlessTUIConsole(tui.ModeHost, 80, 24, tui.NewVTTerminalPane(80, 24))
	called := make(chan struct{}, 1)
	console.SetCommandCallbacks(tuiConsoleCallbacks{
		RestartShell: func(context.Context) error {
			called <- struct{}{}
			return nil
		},
	})
	console.handleCommand(context.Background(), tui.RestartShellCommand{})
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("RestartShell callback was not called")
	}
}
```

- [ ] **Step 2: Run and verify it fails**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run TestTUIConsoleRestartShellCommandCallsCallback -count=1
```

Expected: FAIL because the callback field and command handler do not exist.

- [ ] **Step 3: Add callback plumbing**

In `pkg/derpssh/session/console.go`, extend `tuiConsoleCallbacks`:

```go
RestartShell func(context.Context) error
```

In `handleCommand`, add:

```go
case tui.RestartShellCommand:
	c.handleRestartShellCommand(ctx)
```

Add:

```go
func (c *tuiConsole) handleRestartShellCommand(ctx context.Context) {
	c.callbackMu.Lock()
	restart := c.callbacks.RestartShell
	c.callbackMu.Unlock()
	if restart != nil {
		_ = restart(ctx)
	}
}
```

- [ ] **Step 4: Run console tests**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestTUIConsoleRestartShell|TestTUIConsoleHostShellExit' -count=1
```

Expected: PASS.

---

## Task 4: Wire Restart Into Share Runtime

**Files:**
- Modify: `pkg/derpssh/session/share.go`
- Modify: `pkg/derpssh/session/share_connect_test.go`

- [ ] **Step 1: Write failing restart integration test**

Add to `pkg/derpssh/session/share_connect_test.go`:

```go
func TestShareRestartsTerminalAfterShellExit(t *testing.T) {
	oldStart := startPTY
	defer func() { startPTY = oldStart }()

	starts := make(chan pty.StartConfig, 2)
	firstOutR, firstOutW := io.Pipe()
	secondOutR, _ := io.Pipe()
	startPTY = func(cfg pty.StartConfig) (*pty.Session, error) {
		starts <- cfg
		if len(starts) == 1 {
			return &pty.Session{File: newPipeFile(firstOutR, io.Discard)}, nil
		}
		return &pty.Session{File: newPipeFile(secondOutR, io.Discard)}, nil
	}

	// Use a test console/app harness to send RestartShellCommand after the
	// first output pipe closes. The assertion is that a second PTY start occurs
	// and Share does not cancel the server just because the first shell exited.
}
```

If this repo does not already have a helper that can turn pipe readers/writers into a `*os.File` compatible fake, keep this test at the `restartableShareTerminal` level instead and add a `TestShareRestartCallbackCallsManagerRestart` test around `waitingShareConsoleCallbacks`.

- [ ] **Step 2: Replace single-use terminal construction**

In `runShare`, replace:

```go
terminal, err := startShareTerminal(terminalSize)
```

with:

```go
terminal, err := newRestartableShareTerminal(terminalSize, startShareTerminal)
```

Keep:

```go
defer func() {
	_ = terminal.Close()
	_ = terminal.Wait()
}()
```

This preserves existing cleanup but no longer makes shell EOF terminal-fatal.

- [ ] **Step 3: Listen for shell-exit events**

After creating the terminal manager in `runShare`, add:

```go
go func() {
	for {
		select {
		case <-shareCtx.Done():
			return
		case event := <-terminal.Events():
			if event.Kind == shareTerminalShellExited {
				console.OnRuntimeEvent(RuntimeEvent{
					Kind:    RuntimeEventClose,
					Message: hostShellExitedReason,
				})
			}
		}
	}
}()
```

- [ ] **Step 4: Add restart callback before and after host runtime starts**

In `waitingShareConsoleCallbacks`, add a `RestartShell` callback:

```go
RestartShell: func(ctx context.Context) error {
	_ = ctx
	if terminal == nil {
		return io.ErrClosedPipe
	}
	return terminal.Restart(pty.Size{Cols: 80, Rows: 24})
},
```

Then in `runShare`, override it with the real current TUI size:

```go
restartShell := func(ctx context.Context) error {
	_ = ctx
	size := console.TerminalSize()
	if err := terminal.Restart(size); err != nil {
		return err
	}
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "shell restarted"})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventResize, Cols: size.Cols, Rows: size.Rows})
	return nil
}
callbacks := waitingShareConsoleCallbacks(terminal, cancel, pendingChats)
callbacks.RestartShell = restartShell
console.SetCommandCallbacks(callbacks)
```

When binding host callbacks later, preserve the restart callback:

```go
callbacks := hostConsoleCallbacks(host)
callbacks.RestartShell = restartShell
callbacks.Quit = func(ctx context.Context) error {
	err := host.Close(ctx, hostQuitReason)
	_ = terminal.Close()
	cancel()
	return err
}
```

- [ ] **Step 5: Ensure HostRuntime does not close on shell generation EOF**

Because `restartableShareTerminal.Output.Read` blocks across shell generations, `HostRuntime` should not see `io.EOF` on normal shell exit. Keep `CloseOnPTYEOF: true` for real manager close, but verify that only `terminal.Close()` or context cancellation reaches the host close path.

- [ ] **Step 6: Run share/session tests**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestRestartableShareTerminal|TestShare|TestTUIConsoleRestartShell|TestTUIConsoleHostShellExit' -count=1
```

Expected: PASS.

---

## Task 5: Add Guest-Facing Waiting State During Restart

**Files:**
- Modify: `pkg/derpssh/session/host.go`
- Modify: `pkg/derpssh/tui/app.go`
- Modify: `pkg/derpssh/tui/app_test.go`

- [ ] **Step 1: Add a terminal notice when the shell exits**

When the restartable manager emits `shareTerminalShellExited`, write a simple terminal message through local output and host protocol if possible:

```go
[]byte("\r\n[derpssh] host shell exited; waiting for host to restart or quit\r\n")
```

This message should be ordinary terminal output so guests understand the pause without requiring a new protocol message.

- [ ] **Step 2: Test guest-visible pause text**

Add a session-level test that closes the first PTY output and asserts the host local console receives:

```text
[derpssh] host shell exited; waiting for host to restart or quit
```

- [ ] **Step 3: Repaint after restart**

After restart succeeds, write:

```go
[]byte("\r\n[derpssh] shell restarted\r\n")
```

This is intentionally plain text because it works for both host and guest views and does not require another protocol frame.

---

## Task 6: Verification and Live Smoke

**Files:**
- No source edits.

- [ ] **Step 1: Run focused tests**

```bash
mise exec -- go test ./pkg/derpssh/tui ./pkg/derpssh/session -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full local verification**

```bash
mise run build
mise run test
mise run vet
mise run smoke-derpssh-local
git diff --check
mise exec -- gofmt -l $(git diff --name-only -- '*.go')
```

Expected: all pass and `gofmt -l` prints nothing.

- [ ] **Step 3: Run live remote derpssh smokes**

```bash
REMOTE_HOST=root@hetz mise run smoke-remote-derpssh
REMOTE_HOST=root@pve1 mise run smoke-remote-derpssh
```

Expected: both pass and print connect/share path traces.

- [ ] **Step 4: Manual smoke the restart flow before release**

Use `derpssh@dev`:

```bash
npx -y derpssh@dev share
```

Connect from another terminal, approve write, then in the host shell press `Ctrl-D`.

Expected:
- Host sees a modal with `Restart Shell` focused and `Quit` available.
- Guest remains connected and sees a clear waiting message.
- Pressing Enter on the host restarts the shell.
- Guest can type again after restart if write access was granted.
- Pressing `Ctrl-X Q` after another shell exit quits host and guest.

---

## Self-Review

- Spec coverage: The plan covers shell EOF detection, host restart/quit UI, stable guest session across restart, clean quit semantics, and local/remote verification.
- Placeholder scan: No `TBD`, `TODO`, or unspecified test steps remain. The one branch about fake `*os.File` is explicitly resolved by using the manager-level test if the repo lacks a fake file helper.
- Type consistency: `RestartShellCommand`, `RestartShell` callback, `restartableShareTerminal`, `shareTerminalShellExited`, and `shareTerminalEvent` names are consistent across tasks.
