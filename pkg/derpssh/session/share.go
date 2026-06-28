// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/pty"
	"github.com/shayne/derphole/pkg/derpssh/tui"
	"github.com/shayne/derphole/pkg/derptun"
	appsession "github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

type ShareConfig struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	ForceRelay bool
	Emitter    *telemetry.Emitter
}

var generateServerToken = derptun.GenerateServerToken
var generateClientToken = derptun.GenerateClientToken
var serveAppMux = appsession.DerptunAppServe
var startPTY = pty.Start
var newShareApproval = newTerminalShareApproval
var showShareInvitePreflight = showInvitePreflight
var runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
	host := NewHostRuntime(cfg)
	if bindConsole != nil {
		bindConsole(host)
	}
	return host.Run(ctx)
}

func Share(ctx context.Context, cfg ShareConfig) error {
	cfg = normalizeShareConfig(cfg)
	serverToken, connectCommand, err := newShareInviteCommand()
	if err != nil {
		return err
	}
	if err := presentShareInvite(cfg, connectCommand); err != nil {
		if errors.Is(err, errInvitePreflightQuit) {
			return nil
		}
		return err
	}
	return runShare(ctx, cfg, serverToken, connectCommand)
}

func newShareInviteCommand() (string, string, error) {
	serverToken, err := generateServerToken(derptun.ServerTokenOptions{})
	if err != nil {
		return "", "", err
	}
	clientToken, err := generateClientToken(derptun.ClientTokenOptions{ServerToken: serverToken})
	if err != nil {
		return "", "", err
	}
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
	if err != nil {
		return "", "", err
	}
	return serverToken, fmt.Sprintf("npx -y derpssh@latest connect %s", invite), nil
}

func presentShareInvite(cfg ShareConfig, connectCommand string) error {
	preflightShown, err := showShareInvitePreflight(cfg.Stdin, cfg.Stdout, connectCommand)
	if err != nil {
		return err
	}
	if !preflightShown {
		_, _ = fmt.Fprintln(cfg.Stderr, connectCommand)
	}
	return nil
}

func runShare(ctx context.Context, cfg ShareConfig, serverToken, connectCommand string) error {
	size := terminalSize(cfg.Stdout)
	displayName := shareDisplayName()
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:          tui.ModeHost,
		Cols:          size.Cols,
		Rows:          size.Rows,
		Stdin:         cfg.Stdin,
		Stdout:        cfg.Stdout,
		DisplayName:   displayName,
		InviteCommand: connectCommand,
	})
	terminalSize := console.TerminalSize()
	terminal, err := startShareTerminal(terminalSize)
	if err != nil {
		return err
	}
	defer func() {
		_ = terminal.Close()
		_ = terminal.Wait()
	}()

	shareCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var hostStarted atomic.Bool
	fanout := newTerminalFanout(terminal.Output, console)
	go func() {
		_ = fanout.Run(shareCtx)
		if !hostStarted.Load() {
			cancel()
		}
	}()

	pendingChats := newPendingShareChats()
	console.SetCommandCallbacks(waitingShareConsoleCallbacks(terminal, cancel, pendingChats))
	console.Start(shareCtx)
	defer console.Stop()
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "waiting for guest"})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventResize, Cols: terminalSize.Cols, Rows: terminalSize.Rows})

	return serveAppMux(shareCtx, appsession.DerptunAppServeConfig{
		ServerToken: serverToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
		OnMux: func(ctx context.Context, mux *derptun.Mux) error {
			hostStarted.Store(true)
			approval := newShareApproval(cfg)
			if _, ok := approval.(terminalShareApproval); ok {
				approval = console
			}
			hostCfg := HostConfig{
				Mux:         mux,
				HostID:      randomID("host"),
				HostName:    displayName,
				InitialCols: terminalSize.Cols,
				InitialRows: terminalSize.Rows,
				PTYInput:    terminal.Input,
				PTYOutput:   fanout.LazyReader(),
				PTYResize: func(cols int, rows int) error {
					return terminal.Resize(pty.Size{Cols: cols, Rows: rows})
				},
				LocalInput:  emptyReader{},
				LocalOutput: io.Discard,
				Approval:    approval,
				Observer:    console,
			}
			return runHostSession(ctx, hostCfg, func(host *HostRuntime) {
				callbacks := hostConsoleCallbacks(host)
				callbacks.Quit = cancel
				console.SetCommandCallbacks(callbacks)
				go pendingChats.flush(ctx, callbacks.Chat)
			})
		},
	})
}

func shareDisplayName() string {
	host, _ := os.Hostname()
	return joinUserHost(os.Getenv("USER"), host)
}

func joinUserHost(user, host string) string {
	user = strings.TrimSpace(user)
	host = strings.TrimSpace(host)
	switch {
	case user != "" && host != "":
		return user + "@" + host
	case user != "":
		return user
	case host != "":
		return host
	default:
		return "host"
	}
}

func waitingShareConsoleCallbacks(terminal *shareTerminal, cancel context.CancelFunc, pendingChats *pendingShareChats) tuiConsoleCallbacks {
	return tuiConsoleCallbacks{
		TerminalInput: func(ctx context.Context, data []byte) error {
			_ = ctx
			if terminal == nil || terminal.Input == nil {
				return io.ErrClosedPipe
			}
			_, err := terminal.Input.Write(data)
			return err
		},
		Resize: func(ctx context.Context, cols int, rows int) error {
			_ = ctx
			if terminal == nil {
				return nil
			}
			return terminal.Resize(pty.Size{Cols: cols, Rows: rows})
		},
		Chat: func(ctx context.Context, body string) error {
			_ = ctx
			if pendingChats != nil {
				pendingChats.append(body)
			}
			return nil
		},
		Quit: cancel,
	}
}

type pendingShareChats struct {
	mu     sync.Mutex
	bodies []string
}

func newPendingShareChats() *pendingShareChats {
	return &pendingShareChats{}
}

func (p *pendingShareChats) append(body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bodies = append(p.bodies, body)
}

func (p *pendingShareChats) flush(ctx context.Context, send func(context.Context, string) error) {
	if p == nil || send == nil {
		return
	}
	p.mu.Lock()
	bodies := append([]string(nil), p.bodies...)
	p.bodies = nil
	p.mu.Unlock()
	for _, body := range bodies {
		if ctx.Err() != nil {
			return
		}
		_ = send(ctx, body)
	}
}

var errInvitePreflightQuit = errors.New("invite preflight quit")

func showInvitePreflight(stdin io.Reader, stdout io.Writer, command string) (bool, error) {
	inFile, ok := invitePreflightFiles(stdin, stdout)
	if !ok {
		return false, nil
	}
	if err := renderInvitePreflight(stdout, command); err != nil {
		return true, err
	}
	return readRawInvitePreflightInput(inFile)
}

func invitePreflightFiles(stdin io.Reader, stdout io.Writer) (*os.File, bool) {
	inFile, inOK := stdin.(*os.File)
	outFile, outOK := stdout.(*os.File)
	if !inOK || !outOK || !pty.IsTerminal(inFile.Fd()) || !pty.IsTerminal(outFile.Fd()) {
		return nil, false
	}
	return inFile, true
}

func renderInvitePreflight(stdout io.Writer, command string) error {
	_, err := io.WriteString(stdout, "\x1b[2J\x1b[H"+invitePreflightScreen(command))
	return err
}

func readRawInvitePreflightInput(inFile *os.File) (bool, error) {
	state, err := pty.MakeRaw(inFile.Fd())
	if err != nil {
		return true, err
	}
	defer func() { _ = pty.Restore(inFile.Fd(), state) }()
	return readInvitePreflightInput(inFile)
}

func readInvitePreflightInput(r io.Reader) (bool, error) {
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			switch invitePreflightKeyAction(b[0]) {
			case invitePreflightContinue:
				return true, nil
			case invitePreflightQuit:
				return true, errInvitePreflightQuit
			}
		}
		if err != nil {
			return true, err
		}
	}
}

type invitePreflightAction int

const (
	invitePreflightIgnore invitePreflightAction = iota
	invitePreflightContinue
	invitePreflightQuit
)

func invitePreflightKeyAction(b byte) invitePreflightAction {
	switch b {
	case '\r', '\n':
		return invitePreflightContinue
	case 'q', 'Q', 0x03:
		return invitePreflightQuit
	default:
		return invitePreflightIgnore
	}
}

func invitePreflightScreen(command string) string {
	return strings.Join([]string{
		"derpssh invite",
		"",
		"Copy this command and send it to the other person:",
		"",
		strings.TrimSpace(command),
		"",
		"Press Enter to start sharing. Press q to quit.",
		"",
	}, "\n")
}

func normalizeShareConfig(cfg ShareConfig) ShareConfig {
	if cfg.Stdin == nil {
		cfg.Stdin = emptyReader{}
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	return cfg
}

type terminalShareApproval struct {
	stdin  io.Reader
	stderr io.Writer
}

func newTerminalShareApproval(cfg ShareConfig) Approval {
	return terminalShareApproval{stdin: cfg.Stdin, stderr: cfg.Stderr}
}

func (a terminalShareApproval) Approve(req JoinRequest) protocol.Role {
	if role, ok := envApprovalRole(); ok {
		return role
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		name = req.ParticipantID
	}
	_, _ = fmt.Fprintf(a.stderr, "Allow %s to join? [r]ead/[w]rite/[n]o: ", name)
	line, err := readApprovalLine(a.stdin)
	if err != nil && strings.TrimSpace(line) == "" {
		_, _ = fmt.Fprintln(a.stderr)
		return protocol.RoleDenied
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "r":
		return protocol.RoleRead
	case "w":
		return protocol.RoleWrite
	default:
		return protocol.RoleDenied
	}
}

type shareTerminal struct {
	Input  io.Writer
	Output io.Reader
	close  func() error
	wait   func() error
	resize func(pty.Size) error
}

func startShareTerminal(size pty.Size) (*shareTerminal, error) {
	if command := strings.TrimSpace(testHarnessEnv("DERPSSH_TEST_COMMAND")); command != "" {
		cmd := exec.Command("/bin/sh", "-c", command)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return &shareTerminal{
			Input:  stdin,
			Output: stdout,
			close:  stdin.Close,
			wait:   cmd.Wait,
			resize: func(pty.Size) error { return nil },
		}, nil
	}

	ptySession, err := startPTY(pty.StartConfig{
		Size: size,
		Term: sharePTYTerm(),
	})
	if err != nil {
		return nil, err
	}
	return &shareTerminal{
		Input:  ptySession.File,
		Output: ptySession.File,
		close:  ptySession.Close,
		wait:   ptySession.Wait,
		resize: ptySession.Resize,
	}, nil
}

func sharePTYTerm() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TERM"))) {
	case "", "dumb", "unknown":
		return "xterm-256color"
	default:
		return ""
	}
}

func terminalSize(output io.Writer) pty.Size {
	size := pty.Size{Cols: 80, Rows: 24}
	file, ok := output.(*os.File)
	if !ok || !pty.IsTerminal(file.Fd()) {
		return size
	}
	got, err := pty.GetSize(file.Fd())
	if err != nil || got.Cols <= 0 || got.Rows <= 0 {
		return size
	}
	return got
}

func (t *shareTerminal) Close() error {
	if t == nil || t.close == nil {
		return nil
	}
	return t.close()
}

func (t *shareTerminal) Wait() error {
	if t == nil || t.wait == nil {
		return nil
	}
	return t.wait()
}

func (t *shareTerminal) Resize(size pty.Size) error {
	if t == nil || t.resize == nil {
		return nil
	}
	return t.resize(size)
}

func randomID(prefix string) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return prefix
	}
	return prefix + "-" + hex.EncodeToString(raw[:])
}
