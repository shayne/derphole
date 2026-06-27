// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/pty"
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
var runHostSession = func(ctx context.Context, cfg HostConfig) error {
	return NewHostRuntime(cfg).Run(ctx)
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
	_, _ = fmt.Fprintf(cfg.Stderr, "npx -y derpssh@latest connect %s\n", invite)

	return serveAppMux(ctx, appsession.DerptunAppServeConfig{
		ServerToken: serverToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
		OnMux: func(ctx context.Context, mux *derptun.Mux) error {
			ptySession, err := startPTY(pty.StartConfig{
				Size: pty.Size{Cols: 80, Rows: 24},
			})
			if err != nil {
				return err
			}
			defer func() { _ = ptySession.Close() }()
			go func() { _ = ptySession.Wait() }()

			hostName, _ := os.Hostname()
			if hostName == "" {
				hostName = "host"
			}
			return runHostSession(ctx, HostConfig{
				Mux:         mux,
				HostID:      randomID("host"),
				HostName:    hostName,
				InitialCols: 80,
				InitialRows: 24,
				PTYInput:    ptySession.File,
				PTYOutput:   ptySession.File,
				Approval:    newShareApproval(cfg),
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
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		name = req.ParticipantID
	}
	_, _ = fmt.Fprintf(a.stderr, "Allow %s to join? [r]ead/[w]rite/[n]o: ", name)
	line, err := bufio.NewReader(a.stdin).ReadString('\n')
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

func randomID(prefix string) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return prefix
	}
	return prefix + "-" + hex.EncodeToString(raw[:])
}
