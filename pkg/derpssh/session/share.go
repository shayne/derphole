// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

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
var runHostSession = func(ctx context.Context, cfg HostConfig, bindConsole func(*HostRuntime)) error {
	host := NewHostRuntime(cfg)
	if bindConsole != nil {
		bindConsole(host)
	}
	return host.Run(ctx)
}

func Share(ctx context.Context, cfg ShareConfig) error {
	cfg = normalizeShareConfig(cfg)
	serverToken, err := generateServerToken(derptun.ServerTokenOptions{})
	if err != nil {
		return err
	}
	clientToken, err := generateClientToken(derptun.ClientTokenOptions{ServerToken: serverToken})
	if err != nil {
		return err
	}
	invite, err := EncodeInvite(Invite{ClientToken: clientToken})
	if err != nil {
		return err
	}
	connectCommand := fmt.Sprintf("npx -y derpssh@latest connect %s", invite)
	_, _ = fmt.Fprintln(cfg.Stderr, connectCommand)
	size := terminalSize(cfg.Stdout)
	console := newTerminalConsoleWithOptions(tuiConsoleOptions{
		Mode:          tui.ModeHost,
		Cols:          size.Cols,
		Rows:          size.Rows,
		Stdin:         cfg.Stdin,
		Stdout:        cfg.Stdout,
		InviteCommand: connectCommand,
	})
	terminalSize := console.TerminalSize()
	console.Start(ctx)
	defer console.Stop()

	return serveAppMux(ctx, appsession.DerptunAppServeConfig{
		ServerToken: serverToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
		OnMux: func(ctx context.Context, mux *derptun.Mux) error {
			terminal, err := startShareTerminal(terminalSize)
			if err != nil {
				return err
			}
			defer func() {
				_ = terminal.Close()
				_ = terminal.Wait()
			}()

			hostName, _ := os.Hostname()
			if hostName == "" {
				hostName = "host"
			}
			approval := newShareApproval(cfg)
			if _, ok := approval.(terminalShareApproval); ok {
				approval = console
			}
			hostCfg := HostConfig{
				Mux:         mux,
				HostID:      randomID("host"),
				HostName:    hostName,
				InitialCols: terminalSize.Cols,
				InitialRows: terminalSize.Rows,
				PTYInput:    terminal.Input,
				PTYOutput:   terminal.Output,
				PTYResize: func(cols int, rows int) error {
					return terminal.Resize(pty.Size{Cols: cols, Rows: rows})
				},
				LocalInput:  emptyReader{},
				LocalOutput: console,
				Approval:    approval,
				Observer:    console,
			}
			return runHostSession(ctx, hostCfg, func(host *HostRuntime) {
				console.SetCommandCallbacks(hostConsoleCallbacks(host))
			})
		},
	})
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
