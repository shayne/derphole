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
	"golang.org/x/sys/unix"
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
var canUseShareInvitePreflight = func(cfg ShareConfig) bool {
	_, ok := invitePreflightFiles(cfg.Stdin, cfg.Stdout)
	return ok
}
var startShareInvitePreflight = startRawShareInvitePreflight
var clearInvitePreflightScreen = "\x1b[H\x1b[2J\x1b[3J"
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
	plainInvite := canUseShareInvitePreflight(cfg)
	if !plainInvite {
		if err := presentShareInvite(cfg, connectCommand); err != nil {
			if errors.Is(err, errInvitePreflightQuit) {
				return nil
			}
			return err
		}
	}
	return runShare(ctx, cfg, serverToken, connectCommand, plainInvite)
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
	if preflightShown {
		_, _ = io.WriteString(cfg.Stdout, clearInvitePreflightScreen)
	}
	if err != nil {
		return err
	}
	if preflightShown {
		return nil
	}
	_, _ = fmt.Fprintln(cfg.Stderr, connectCommand)
	return nil
}

func runShare(ctx context.Context, cfg ShareConfig, serverToken, connectCommand string, plainInvite bool) error {
	size := terminalSize(cfg.Stdout)
	displayName := shareDisplayName()
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:              tui.ModeHost,
		Cols:              size.Cols,
		Rows:              size.Rows,
		Stdin:             cfg.Stdin,
		Stdout:            cfg.Stdout,
		DisplayName:       displayName,
		InviteCommand:     connectCommand,
		InitialInviteOpen: false,
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
	quitBeforeGuest := atomic.Bool{}

	var hostStarted atomic.Bool
	fanout := newTerminalFanout(terminal.Output, console)
	go func() {
		_ = fanout.Run(shareCtx)
		if !hostStarted.Load() {
			cancel()
		}
	}()

	pendingChats := newPendingShareChats()
	preflight, plainInvite, err := prepareShareInvitePreflight(shareCtx, cfg, connectCommand, plainInvite)
	if err != nil {
		return err
	}
	if preflight != nil {
		defer func() {
			preflight.Interrupt()
			_ = preflight.Wait()
		}()
	}
	starter := newShareConsoleStarter(console, shareCtx, preflight)
	console.SetCommandCallbacks(waitingShareConsoleCallbacks(terminal, cancel, pendingChats))
	var preflightErr atomic.Value
	var preflightExit <-chan struct{}
	if plainInvite {
		preflightExit = watchShareInvitePreflight(preflight, starter, terminal, cancel, &quitBeforeGuest, &preflightErr)
	} else {
		starter.Start()
	}
	defer console.Stop()
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "waiting for guest"})
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventResize, Cols: terminalSize.Cols, Rows: terminalSize.Rows})
	sessionEmitter := telemetry.WithStatusHook(cfg.Emitter, func(msg string) {
		msg = strings.TrimSpace(msg)
		if msg != "" {
			console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: msg})
		}
	})

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serveAppMux(shareCtx, appsession.DerptunAppServeConfig{
			ServerToken: serverToken,
			Emitter:     sessionEmitter,
			ForceRelay:  cfg.ForceRelay,
			OnMux: func(ctx context.Context, mux *derptun.Mux) error {
				hostStarted.Store(true)
				approval := newShareApproval(cfg)
				if _, ok := approval.(terminalShareApproval); ok {
					approval = startingShareApproval{Approval: console, Start: starter.Start}
				}
				hostCfg := HostConfig{
					Mux:           mux,
					HostID:        randomID("host"),
					HostName:      displayName,
					InitialCols:   terminalSize.Cols,
					InitialRows:   terminalSize.Rows,
					PTYInput:      terminal.Input,
					PTYOutput:     fanout.LazyReader(),
					CloseOnPTYEOF: true,
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
					callbacks.Quit = func(ctx context.Context) error {
						err := host.Close(ctx, hostQuitReason)
						_ = terminal.Close()
						cancel()
						return err
					}
					console.SetCommandCallbacks(callbacks)
					go pendingChats.flush(ctx, callbacks.Chat)
				})
			},
		})
	}()
	select {
	case err = <-serveErr:
	case <-preflightExit:
		err = context.Canceled
	}
	return finishShareError(err, shareCtx, &quitBeforeGuest, &preflightErr)
}

func prepareShareInvitePreflight(ctx context.Context, cfg ShareConfig, command string, enabled bool) (shareInvitePreflight, bool, error) {
	if !enabled {
		return nil, false, nil
	}
	preflight, err := startShareInvitePreflight(ctx, cfg, command)
	if err != nil {
		return nil, false, err
	}
	return preflight, preflight != nil, nil
}

func watchShareInvitePreflight(
	preflight shareInvitePreflight,
	starter *shareConsoleStarter,
	terminal *shareTerminal,
	cancel context.CancelFunc,
	quitBeforeGuest *atomic.Bool,
	preflightErr *atomic.Value,
) <-chan struct{} {
	exited := make(chan struct{})
	go func() {
		result := preflight.Wait()
		if result.Err != nil {
			preflightErr.Store(result.Err)
			quitBeforeGuest.Store(true)
			_ = terminal.Close()
			cancel()
			close(exited)
			return
		}
		switch result.Action {
		case invitePreflightContinue:
			starter.Start()
		case invitePreflightQuit:
			quitBeforeGuest.Store(true)
			_ = terminal.Close()
			cancel()
			close(exited)
		}
	}()
	return exited
}

func finishShareError(err error, ctx context.Context, quitBeforeGuest *atomic.Bool, preflightErr *atomic.Value) error {
	if errValue := preflightErr.Load(); errValue != nil {
		return errValue.(error)
	}
	if quitBeforeGuest.Load() || isShareQuitError(err, ctx) {
		return nil
	}
	return err
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
		Quit: func(context.Context) error {
			if terminal != nil {
				_ = terminal.Close()
			}
			cancel()
			return nil
		},
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

type shareInvitePreflight interface {
	Interrupt()
	Wait() shareInvitePreflightResult
}

type shareInvitePreflightResult struct {
	Action invitePreflightAction
	Err    error
}

type rawShareInvitePreflight struct {
	done      chan shareInvitePreflightResult
	inFile    *os.File
	rawState  *pty.RawState
	wakeRead  *os.File
	wakeWrite *os.File
	wakeOnce  sync.Once
	waitOnce  sync.Once
	result    shareInvitePreflightResult
}

func startRawShareInvitePreflight(_ context.Context, cfg ShareConfig, command string) (shareInvitePreflight, error) {
	inFile, ok := invitePreflightFiles(cfg.Stdin, cfg.Stdout)
	if !ok {
		return nil, nil
	}
	state, err := pty.MakeRaw(inFile.Fd())
	if err != nil {
		return nil, err
	}
	if err := renderRawInvitePreflight(cfg.Stdout, command); err != nil {
		_ = pty.Restore(inFile.Fd(), state)
		return nil, err
	}
	wakeRead, wakeWrite, err := os.Pipe()
	if err != nil {
		_ = pty.Restore(inFile.Fd(), state)
		return nil, err
	}
	preflight := &rawShareInvitePreflight{
		done:      make(chan shareInvitePreflightResult, 1),
		inFile:    inFile,
		rawState:  state,
		wakeRead:  wakeRead,
		wakeWrite: wakeWrite,
	}
	go preflight.read()
	return preflight, nil
}

func (p *rawShareInvitePreflight) read() {
	defer close(p.done)
	defer func() { _ = pty.Restore(p.inFile.Fd(), p.rawState) }()
	defer func() { _ = p.wakeRead.Close() }()
	defer p.closeWakeWriter()
	p.done <- readInvitePreflightInputInterruptible(p.inFile, p.wakeRead)
}

func (p *rawShareInvitePreflight) Interrupt() {
	p.wakeOnce.Do(func() {
		_, _ = p.wakeWrite.Write([]byte{1})
		_ = p.wakeWrite.Close()
	})
}

func (p *rawShareInvitePreflight) closeWakeWriter() {
	p.wakeOnce.Do(func() {
		_ = p.wakeWrite.Close()
	})
}

func (p *rawShareInvitePreflight) Wait() shareInvitePreflightResult {
	p.waitOnce.Do(func() {
		result, ok := <-p.done
		if !ok {
			result = shareInvitePreflightResult{Action: invitePreflightInterrupted}
		}
		p.result = result
	})
	return p.result
}

type shareConsoleStarter struct {
	console   *tuiConsole
	ctx       context.Context
	preflight shareInvitePreflight
	once      sync.Once
}

func newShareConsoleStarter(console *tuiConsole, ctx context.Context, preflight shareInvitePreflight) *shareConsoleStarter {
	return &shareConsoleStarter{console: console, ctx: ctx, preflight: preflight}
}

func (s *shareConsoleStarter) Start() {
	if s == nil || s.console == nil {
		return
	}
	s.once.Do(func() {
		if s.preflight != nil {
			s.preflight.Interrupt()
			if s.preflight.Wait().Action == invitePreflightQuit {
				return
			}
		}
		s.console.Start(s.ctx)
	})
}

type startingShareApproval struct {
	Approval Approval
	Start    func()
}

func (a startingShareApproval) Approve(req JoinRequest) protocol.Role {
	if a.Start != nil {
		a.Start()
	}
	if a.Approval == nil {
		return protocol.RoleDenied
	}
	return a.Approval.Approve(req)
}

func isShareQuitError(err error, ctx context.Context) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	return ctx.Err() != nil && strings.Contains(err.Error(), context.Canceled.Error())
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
	_, err := io.WriteString(stdout, clearInvitePreflightScreen+invitePreflightScreen(command))
	return err
}

func renderRawInvitePreflight(stdout io.Writer, command string) error {
	text := strings.ReplaceAll(clearInvitePreflightScreen+invitePreflightScreen(command), "\n", "\r\n")
	_, err := io.WriteString(stdout, text)
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

func readInvitePreflightInputInterruptible(inFile, wakeRead *os.File) shareInvitePreflightResult {
	var b [1]byte
	for {
		action, err := pollInvitePreflightInput(inFile, wakeRead, b[:])
		if err != nil {
			return shareInvitePreflightResult{Action: invitePreflightQuit, Err: err}
		}
		if action == invitePreflightInterrupted {
			return shareInvitePreflightResult{Action: action}
		}
		switch invitePreflightKeyAction(b[0]) {
		case invitePreflightContinue:
			return shareInvitePreflightResult{Action: invitePreflightContinue}
		case invitePreflightQuit:
			return shareInvitePreflightResult{Action: invitePreflightQuit}
		}
	}
}

func pollInvitePreflightInput(inFile, wakeRead *os.File, buf []byte) (invitePreflightAction, error) {
	for {
		fds := []unix.PollFd{
			{Fd: int32(inFile.Fd()), Events: unix.POLLIN},
			{Fd: int32(wakeRead.Fd()), Events: unix.POLLIN | unix.POLLHUP},
		}
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return invitePreflightQuit, err
		}
		if fds[1].Revents != 0 {
			return invitePreflightInterrupted, nil
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := inFile.Read(buf)
		if n > 0 {
			return invitePreflightContinue, nil
		}
		if err != nil {
			return invitePreflightQuit, err
		}
	}
}

type invitePreflightAction int

const (
	invitePreflightIgnore invitePreflightAction = iota
	invitePreflightContinue
	invitePreflightQuit
	invitePreflightInterrupted
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
