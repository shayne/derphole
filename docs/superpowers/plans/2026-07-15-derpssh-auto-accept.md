# derpssh Auto-Accept Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `derpssh share --auto-accept read|write` so a host can apply one automatic role to every join attempt without opening the approval modal.

**Architecture:** Parse the flag in the existing manual `derpssh share` parser and carry a validated `protocol.Role` through `session.ShareConfig`. At host construction, select the existing `StaticApproval` implementation for configured roles and wrap it in the existing start-on-join adapter so a guest still moves the host from the invite interstitial into the TUI. Leave the console-backed approval path untouched when the field is empty.

**Tech Stack:** Go 1.26, the existing derpssh session and TUI packages, shell smoke tests, `mise`, and GitButler.

## Global Constraints

- The only accepted CLI values are the exact lowercase strings `read` and `write`.
- `--auto-accept read`, `--auto-accept write`, `--auto-accept=read`, and `--auto-accept=write` are supported.
- The zero `ShareConfig` value preserves interactive approval.
- The selected role applies to every join attempt for the lifetime of the `share` process.
- Auto-accept starts the host TUI when a guest arrives but never calls the TUI approval callback or opens its modal.
- Host-side read/write enforcement and the existing promote, demote, and kick controls remain authoritative.
- Invalid programmatic roles fail before invite generation, network setup, or PTY startup.
- Do not expose or reuse `DERPSSH_TEST_AUTO_APPROVE` as production configuration.
- Do not change the wire protocol, invite format, token format, or `derpssh connect`.
- Use `mise` for Go commands and GitButler for version-control writes.
- When editing `README.md`, use the repository-required Caveman skill with concise, grammatical prose.

---

### Task 1: Add the CLI and Configuration Boundary

**Files:**
- Modify: `cmd/derpssh/share.go:67-184`
- Modify: `cmd/derpssh/share.go:237-239`
- Modify: `cmd/derpssh/share_test.go:7-100`
- Modify: `pkg/derpssh/session/share.go:29-74`
- Modify: `pkg/derpssh/session/share_connect_test.go`

**Interfaces:**
- Consumes: existing `protocol.RoleRead`, `protocol.RoleWrite`, `ShareConfig`, and `runShareSession` seam.
- Produces: `ShareConfig.AutoAcceptRole protocol.Role`, `parseAutoAcceptRole(string, io.Writer) (protocol.Role, bool)`, and `validateShareAutoAcceptRole(protocol.Role) error` for Task 2.

- [ ] **Step 1: Write failing CLI parsing and propagation tests**

Add the protocol import and these tests to `cmd/derpssh/share_test.go`. Update the existing help assertion to expect `Usage: derpssh share [--auto-accept read|write]`.

```go
import "github.com/shayne/derphole/pkg/derpssh/protocol"

func TestRunSharePassesAutoAcceptRole(t *testing.T) {
	old := runShareSession
	defer func() { runShareSession = old }()

	tests := []struct {
		name string
		args []string
		want protocol.Role
	}{
		{name: "interactive default", want: ""},
		{name: "read separate", args: []string{"--auto-accept", "read"}, want: protocol.RoleRead},
		{name: "write equals", args: []string{"--auto-accept=write"}, want: protocol.RoleWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got protocol.Role
			runShareSession = func(_ context.Context, cfg shareSessionConfig) error {
				got = cfg.AutoAcceptRole
				return nil
			}
			var stderr bytes.Buffer
			if code := runShare(tt.args, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr); code != 0 {
				t.Fatalf("runShare(%v) = %d stderr=%s", tt.args, code, stderr.String())
			}
			if got != tt.want {
				t.Fatalf("AutoAcceptRole = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunShareRejectsInvalidAutoAcceptRole(t *testing.T) {
	old := runShareSession
	defer func() { runShareSession = old }()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing", args: []string{"--auto-accept"}, want: "--auto-accept requires a value"},
		{name: "empty", args: []string{"--auto-accept="}, want: "invalid --auto-accept value"},
		{name: "unknown", args: []string{"--auto-accept", "admin"}, want: "invalid --auto-accept value"},
		{name: "case sensitive", args: []string{"--auto-accept", "Read"}, want: "invalid --auto-accept value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			runShareSession = func(context.Context, shareSessionConfig) error {
				called = true
				return nil
			}
			var stderr bytes.Buffer
			if code := runShare(tt.args, telemetry.LevelDefault, strings.NewReader(""), io.Discard, &stderr); code != 2 {
				t.Fatalf("runShare(%v) = %d, want 2", tt.args, code)
			}
			if called {
				t.Fatal("runShareSession called for invalid auto-accept role")
			}
			if got := stderr.String(); !strings.Contains(got, tt.want) || !strings.Contains(got, shareUsage()) {
				t.Fatalf("stderr = %q, want %q and usage", got, tt.want)
			}
		})
	}
}

func TestParseShareArgsCombinesAutoAcceptWithExistingFlags(t *testing.T) {
	var stderr bytes.Buffer
	parsed, ok := parseShareArgs([]string{
		"--force-relay",
		"--auto-accept", "read",
		"--register", "ops-shell",
		"--registry", "registry.json",
	}, &stderr)
	if !ok {
		t.Fatalf("parseShareArgs() failed: %s", stderr.String())
	}
	if !parsed.forceRelay || parsed.autoAccept != protocol.RoleRead || parsed.register != "ops-shell" || parsed.registry != "registry.json" {
		t.Fatalf("parsed = %+v", parsed)
	}
}
```

- [ ] **Step 2: Write the failing defensive-validation test**

Add this test to `pkg/derpssh/session/share_connect_test.go`:

```go
func TestShareRejectsInvalidAutoAcceptRoleBeforeInvite(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	defer func() { generateServerToken = oldGenerateServerToken }()

	called := false
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) {
		called = true
		return "", errors.New("invite generation should not run")
	}
	err := Share(context.Background(), ShareConfig{
		Stdin:          strings.NewReader(""),
		Stdout:         io.Discard,
		Stderr:         io.Discard,
		AutoAcceptRole: protocol.Role("admin"),
	})
	if err == nil || !strings.Contains(err.Error(), `invalid auto-accept role "admin"`) {
		t.Fatalf("Share() error = %v, want invalid role", err)
	}
	if called {
		t.Fatal("generateServerToken called before auto-accept validation")
	}
}
```

- [ ] **Step 3: Run the focused tests to verify RED**

Run:

```bash
mise exec -- go test ./cmd/derpssh ./pkg/derpssh/session -run 'TestRunShare.*AutoAccept|TestParseShareArgsCombinesAutoAccept|TestShareRejectsInvalidAutoAccept' -count=1
```

Expected: compilation fails because `parsedShareArgs.autoAccept` and `ShareConfig.AutoAcceptRole` do not exist.

- [ ] **Step 4: Implement the CLI parser and config validation**

In `cmd/derpssh/share.go`, import `github.com/shayne/derphole/pkg/derpssh/protocol`, add `autoAccept protocol.Role` to `parsedShareArgs`, pass it into `shareSessionConfig`, and add both flag forms:

```go
err := runShareSession(ctx, shareSessionConfig{
	Stdin:          stdin,
	Stdout:         stdout,
	Stderr:         stderr,
	ForceRelay:     parsed.forceRelay,
	AutoAcceptRole: parsed.autoAccept,
	Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
})
```

```go
case arg == "--auto-accept":
	value, ok := shareFlagValue(args, index, "--auto-accept", stderr)
	if !ok {
		return true, false
	}
	parsed.autoAccept, ok = parseAutoAcceptRole(value, stderr)
	return true, ok
case strings.HasPrefix(arg, "--auto-accept="):
	value := strings.TrimPrefix(arg, "--auto-accept=")
	role, ok := parseAutoAcceptRole(value, stderr)
	parsed.autoAccept = role
	return true, ok
```

Add this helper and update `shareUsage`:

```go
func parseAutoAcceptRole(value string, stderr io.Writer) (protocol.Role, bool) {
	role := protocol.Role(value)
	switch role {
	case protocol.RoleRead, protocol.RoleWrite:
		return role, true
	default:
		_, _ = fmt.Fprintf(stderr, "invalid --auto-accept value %q: want read or write\n", value)
		_, _ = fmt.Fprintln(stderr, shareUsage())
		return "", false
	}
}

func shareUsage() string {
	return "Usage: derpssh share [--auto-accept read|write] [--force-relay] [--register NAME] [--registry PATH]"
}
```

In `pkg/derpssh/session/share.go`, add the field, validate it before invite generation, and add the helper:

```go
type ShareConfig struct {
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	ForceRelay     bool
	AutoAcceptRole protocol.Role
	Emitter        *telemetry.Emitter
}
```

```go
func Share(ctx context.Context, cfg ShareConfig) error {
	cfg = normalizeShareConfig(cfg)
	if err := validateShareAutoAcceptRole(cfg.AutoAcceptRole); err != nil {
		return err
	}
	serverToken, connectCommand, err := newShareInviteCommand()
	if err != nil {
		return err
	}
	plainInvite := canUseShareInvitePreflight(cfg)
	if !plainInvite {
		if err := presentShareInvite(cfg, connectCommand); err != nil {
			if errors.Is(err, errInvitePreflightQuit) {
				reportSessionCloseReason(cfg.Stderr, hostQuitReason)
				return nil
			}
			return err
		}
	}
	return runShare(ctx, cfg, serverToken, connectCommand, plainInvite)
}

func validateShareAutoAcceptRole(role protocol.Role) error {
	switch role {
	case "", protocol.RoleRead, protocol.RoleWrite:
		return nil
	default:
		return fmt.Errorf("invalid auto-accept role %q: want read or write", role)
	}
}
```

Format the changed Go files:

```bash
mise exec -- gofmt -w cmd/derpssh/share.go cmd/derpssh/share_test.go pkg/derpssh/session/share.go pkg/derpssh/session/share_connect_test.go
```

- [ ] **Step 5: Run the focused tests to verify GREEN**

Run:

```bash
mise exec -- go test ./cmd/derpssh ./pkg/derpssh/session -run 'TestRunShare.*AutoAccept|TestParseShareArgsCombinesAutoAccept|TestShareRejectsInvalidAutoAccept' -count=1
```

Expected: all selected tests pass.

- [ ] **Step 6: Commit the CLI/config boundary**

Run `but diff` and verify the only uncommitted files are the four Task 1 files. If any unrelated file appears, stop and preserve it. Then run:

```bash
but commit codex/derpssh-auto-accept -m "derpssh: parse auto-accept policy"
```

Expected: one new commit on `codex/derpssh-auto-accept` and no uncommitted changes.

---

### Task 2: Apply Automatic Approval Without Opening the Modal

**Files:**
- Modify: `pkg/derpssh/session/share.go:261-283`
- Modify: `pkg/derpssh/session/share_connect_test.go`
- Modify: `scripts/smoke-derpssh-local.sh:71-115`
- Modify: `scripts/derpssh_smoke_test.go:14-46`

**Interfaces:**
- Consumes: `ShareConfig.AutoAcceptRole` from Task 1, existing `Approval`, `StaticApproval`, `startingShareApproval`, `terminalShareApproval`, and `shareConsoleStarter.Start`.
- Produces: `selectShareApproval(ShareConfig, Approval, func()) Approval`; a host config that uses `StaticApproval` for automatic roles and the console approval path otherwise.

- [ ] **Step 1: Write failing approval-selection tests**

Add these tests to `pkg/derpssh/session/share_connect_test.go`:

```go
func TestSelectShareApprovalAutoAcceptsEveryJoinWithoutConsoleApproval(t *testing.T) {
	oldNewApproval := newShareApproval
	defer func() { newShareApproval = oldNewApproval }()
	interactiveFactoryCalls := 0
	newShareApproval = func(ShareConfig) Approval {
		interactiveFactoryCalls++
		return StaticApproval{Role: protocol.RoleDenied}
	}

	for _, role := range []protocol.Role{protocol.RoleRead, protocol.RoleWrite} {
		t.Run(string(role), func(t *testing.T) {
			modalCalls := 0
			consoleApproval := approvalFunc(func(JoinRequest) protocol.Role {
				modalCalls++
				return protocol.RoleDenied
			})
			startCalls := 0
			var startOnce sync.Once
			approval := selectShareApproval(
				ShareConfig{AutoAcceptRole: role},
				consoleApproval,
				func() { startOnce.Do(func() { startCalls++ }) },
			)
			for _, req := range []JoinRequest{
				{ParticipantID: "guest-1", DisplayName: "Alex"},
				{ParticipantID: "guest-2", DisplayName: "Sam"},
			} {
				if got := approval.Approve(req); got != role {
					t.Fatalf("Approve(%s) = %q, want %q", req.ParticipantID, got, role)
				}
			}
			if modalCalls != 0 {
				t.Fatalf("console approval calls = %d, want 0", modalCalls)
			}
			if interactiveFactoryCalls != 0 {
				t.Fatalf("interactive approval factory calls = %d, want 0", interactiveFactoryCalls)
			}
			if startCalls != 1 {
				t.Fatalf("start calls = %d, want 1", startCalls)
			}
		})
	}
}

func TestSelectShareApprovalKeepsInteractiveConsolePath(t *testing.T) {
	oldNewApproval := newShareApproval
	defer func() { newShareApproval = oldNewApproval }()
	newShareApproval = func(cfg ShareConfig) Approval {
		return terminalShareApproval{stdin: cfg.Stdin, stderr: cfg.Stderr}
	}

	modalCalls := 0
	consoleApproval := approvalFunc(func(JoinRequest) protocol.Role {
		modalCalls++
		return protocol.RoleRead
	})
	startCalls := 0
	approval := selectShareApproval(ShareConfig{}, consoleApproval, func() { startCalls++ })
	if got := approval.Approve(JoinRequest{ParticipantID: "guest-1", DisplayName: "Alex"}); got != protocol.RoleRead {
		t.Fatalf("Approve() = %q, want %q", got, protocol.RoleRead)
	}
	if modalCalls != 1 || startCalls != 1 {
		t.Fatalf("modal/start calls = %d/%d, want 1/1", modalCalls, startCalls)
	}
}
```

- [ ] **Step 2: Run the approval-selection tests to verify RED**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestSelectShareApproval' -count=1
```

Expected: compilation fails because `selectShareApproval` does not exist.

- [ ] **Step 3: Implement approval selection and wire it into the host config**

Add this helper to `pkg/derpssh/session/share.go`:

```go
func selectShareApproval(cfg ShareConfig, console Approval, start func()) Approval {
	if cfg.AutoAcceptRole != "" {
		return startingShareApproval{
			Approval: StaticApproval{Role: cfg.AutoAcceptRole},
			Start:    start,
		}
	}
	approval := newShareApproval(cfg)
	if _, ok := approval.(terminalShareApproval); ok {
		return startingShareApproval{Approval: console, Start: start}
	}
	return approval
}
```

Replace the approval-selection block in `shareHostConfig`:

```go
func shareHostConfig(mux *derptun.Mux, opts shareHostMuxOptions) HostConfig {
	approval := selectShareApproval(opts.Config, opts.Console, opts.Starter.Start)
	return HostConfig{
		Mux:           mux,
		HostID:        randomID("host"),
		HostName:      opts.DisplayName,
		InitialCols:   opts.Size.Cols,
		InitialRows:   opts.Size.Rows,
		PTYInput:      opts.Terminal.Input,
		PTYOutput:     opts.Fanout.LazyReader(),
		CloseOnPTYEOF: true,
		PTYResize: func(cols int, rows int) error {
			return opts.Terminal.Resize(pty.Size{Cols: cols, Rows: rows})
		},
		LocalInput:  emptyReader{},
		LocalOutput: io.Discard,
		Approval:    approval,
		Observer:    opts.Console,
	}
}
```

Format the files:

```bash
mise exec -- gofmt -w pkg/derpssh/session/share.go pkg/derpssh/session/share_connect_test.go
```

- [ ] **Step 4: Run the session tests to verify GREEN and preserve role enforcement**

Run:

```bash
mise exec -- go test ./pkg/derpssh/session -run 'TestSelectShareApproval|TestHostRejectsReadOnlyGuestInput|TestHostAcceptsWriteGuestInput|TestShareUsesApprovalSeam' -count=1
```

Expected: all selected tests pass. The two host tests prove the selected static roles still gate terminal input on the host side.

- [ ] **Step 5: Write the failing production-smoke regression**

Update `scripts/derpssh_smoke_test.go` so its required strings include the production flag:

```go
"dist/derpssh share --auto-accept write",
```

Remove `"DERPSSH_TEST_AUTO_APPROVE=write"` from the required list. Keep the existing old-command loop unchanged, then add a dedicated test-only seam assertion:

```go
if strings.Contains(body, "DERPSSH_TEST_AUTO_APPROVE") {
	t.Fatal("smoke script uses test-only auto approval instead of --auto-accept")
}
```

- [ ] **Step 6: Run the smoke-script unit test to verify RED**

Run:

```bash
mise exec -- go test ./scripts -run TestDerpsshLocalSmokeScriptUsesBuiltBinary -count=1
```

Expected: failure because the script still uses `DERPSSH_TEST_AUTO_APPROVE=write` and does not pass `--auto-accept write`.

- [ ] **Step 7: Move the local smoke test onto the production flag**

In `scripts/smoke-derpssh-local.sh`, remove the test-only approval variable and add the production flag to the host command:

```bash
DERPSSH_TEST_HARNESS=1 \
DERPSSH_TEST_COMMAND="printf ready; read line; printf input:%s \"\$line\"" \
DERPSSH_TEST_HOST_ACTIONS=$'chat host-side\nsleep 5s\nquit' \
  dist/derpssh share --auto-accept write <&$share_fd >"$share_out" 2>"$share_err" &
```

After the existing `role: write` assertion, reject evidence that the host approval modal rendered:

```bash
if grep -F 'wants to join' "$share_out" >/dev/null 2>&1; then
  echo "auto-accept unexpectedly opened the host approval modal" >&2
  cat "$share_out" >&2
  exit 1
fi
```

- [ ] **Step 8: Run the script test and real local smoke to verify GREEN**

Run:

```bash
mise exec -- go test ./scripts -run TestDerpsshLocalSmokeScriptUsesBuiltBinary -count=1
mise run smoke-derpssh-local
```

Expected: both commands pass; the guest reaches `role: write`, terminal input reaches the host PTY, and no host approval modal text appears.

- [ ] **Step 9: Commit the runtime behavior and smoke coverage**

Run `but diff` and verify the only uncommitted files are the four Task 2 files. If any unrelated file appears, stop and preserve it. Then run:

```bash
but commit codex/derpssh-auto-accept -m "derpssh: apply automatic approval role"
```

Expected: one new commit on the session branch and no uncommitted changes.

---

### Task 3: Document the Host Policy and Run Final Gates

**Files:**
- Modify: `README.md:151-177`

**Interfaces:**
- Consumes: the final CLI contract and runtime semantics from Tasks 1 and 2.
- Produces: user-facing examples and an explicit warning that any valid invite holder receives the configured role.

- [ ] **Step 1: Update the README terminal-sharing section**

Invoke the repository-required Caveman skill, then keep the existing host/connect example and add this concise text after it:

````markdown
The host normally approves each guest as read-only or read/write. To use one
policy for every join attempt while the host is running:

```bash
npx -y derpssh@latest share --auto-accept read
npx -y derpssh@latest share --auto-accept write
```

Anyone with the valid invite is accepted. `read` lets the guest watch and chat.
`write` also gives the guest control of the shared shell. The host can still
change the role or kick the guest.
````

Change the service-name paragraph to say:

```markdown
The service name only finds the invite. It does not change the host's approval
policy.
```

- [ ] **Step 2: Verify help text and focused behavior**

Run:

```bash
mise run build
dist/derpssh share --help
mise exec -- go test -race ./cmd/derpssh ./pkg/derpssh/session -run 'AutoAccept|SelectShareApproval|HostRejectsReadOnly|HostAcceptsWrite' -count=1
```

Expected: help includes `[--auto-accept read|write]`; all selected race tests pass.

- [ ] **Step 3: Run the full repository gate**

Run:

```bash
mise run check
```

Expected: every pre-commit hook, build, and test passes.

- [ ] **Step 4: Re-run the local derpssh smoke on the final tree**

Run:

```bash
mise run smoke-derpssh-local
```

Expected: the production `--auto-accept write` path establishes a session, skips the host approval modal, carries guest input to the host PTY, exchanges chat, and exits cleanly.

- [ ] **Step 5: Commit the documentation**

Run `but diff` and verify `README.md` is the only uncommitted file. If any unrelated file appears, stop and preserve it. Then run:

```bash
but commit codex/derpssh-auto-accept -m "docs: explain derpssh auto-accept"
```

Expected: the branch contains the design, CLI/config, runtime/smoke, and documentation commits with a clean workspace. Do not push or land unless the user asks.
