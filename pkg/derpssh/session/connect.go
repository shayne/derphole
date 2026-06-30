// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/tui"
	appsession "github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

type ConnectConfig struct {
	Invite      string
	DisplayName string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	ForceRelay  bool
	Emitter     *telemetry.Emitter
}

var dialAppMux = appsession.DerptunAppDial
var runGuestSession = func(ctx context.Context, guest *GuestRuntime) error {
	return guest.Run(ctx)
}
var newConnectConsole = func(opts tuiConsoleOptions) connectConsole {
	return newTerminalConsoleWithOptions(opts)
}

type connectConsole interface {
	io.Writer
	RuntimeObserver
	Start(context.Context)
	Stop()
	SetCommandCallbacks(tuiConsoleCallbacks)
}

func Connect(ctx context.Context, cfg ConnectConfig) error {
	cfg = normalizeConnectConfig(cfg)
	inv, err := DecodeInvite(cfg.Invite)
	if err != nil {
		return err
	}
	var statusMu sync.Mutex
	var statusConsole connectConsole
	var lastTransportStatus string
	statusEmitter := telemetry.WithStatusHook(cfg.Emitter, func(msg string) {
		msg = strings.TrimSpace(msg)
		if msg == "" {
			return
		}
		statusMu.Lock()
		lastTransportStatus = msg
		console := statusConsole
		statusMu.Unlock()
		if console != nil {
			console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: msg})
		}
	})
	mux, cleanup, err := dialAppMux(ctx, appsession.DerptunAppDialConfig{
		ClientToken: inv.ClientToken,
		Emitter:     statusEmitter,
		ForceRelay:  cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer cleanup()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if closer, ok := cfg.Stdin.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}

	size := terminalSize(cfg.Stdout)
	console := newConnectConsole(tuiConsoleOptions{
		Mode:        tui.ModeGuest,
		Cols:        size.Cols,
		Rows:        size.Rows,
		Stdin:       cfg.Stdin,
		Stdout:      cfg.Stdout,
		DisplayName: cfg.DisplayName,
	})
	guestCfg := GuestConfig{
		Mux:            mux,
		ParticipantID:  randomID("guest"),
		DisplayName:    cfg.DisplayName,
		TerminalOutput: console,
		Observer:       console,
	}
	guest := NewGuestRuntime(guestCfg)
	callbacks := guestConsoleCallbacks(guest)
	callbacks.Quit = func(ctx context.Context) error {
		err := guest.Close(ctx, guestQuitReason)
		cancel()
		return err
	}
	console.SetCommandCallbacks(callbacks)
	console.Start(runCtx)
	statusMu.Lock()
	statusConsole = console
	initialTransportStatus := lastTransportStatus
	statusMu.Unlock()
	if initialTransportStatus != "" {
		console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: initialTransportStatus})
	}
	console.OnRuntimeEvent(RuntimeEvent{Kind: RuntimeEventStatus, Message: "waiting for host approval"})
	err = runGuestSession(runCtx, guest)
	console.Stop()
	reportGuestCloseReason(cfg.Stderr, guest.CloseReason())
	return err
}

func normalizeConnectConfig(cfg ConnectConfig) ConnectConfig {
	if cfg.Stdin == nil {
		cfg.Stdin = emptyReader{}
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if strings.TrimSpace(cfg.DisplayName) == "" {
		host, _ := os.Hostname()
		cfg.DisplayName = joinUserHost(os.Getenv("USER"), host)
		if strings.TrimSpace(cfg.DisplayName) == "" {
			cfg.DisplayName = "guest"
		}
	}
	return cfg
}

func reportGuestCloseReason(w io.Writer, reason string) {
	reason = strings.TrimSpace(reason)
	if w == nil || reason == "" {
		return
	}
	reportSessionCloseReason(w, reason)
}

type guestInputSender interface {
	Role() protocol.Role
	SendInput(context.Context, []byte) error
}

func sendGuestInput(ctx context.Context, guest guestInputSender, data []byte) {
	for {
		if ctx.Err() != nil {
			return
		}
		switch guest.Role() {
		case protocol.RoleWrite:
			_ = guest.SendInput(ctx, data)
			return
		case protocol.RoleRead, protocol.RoleDenied, protocol.RoleKicked:
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}
