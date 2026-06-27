// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
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

func Connect(ctx context.Context, cfg ConnectConfig) error {
	cfg = normalizeConnectConfig(cfg)
	inv, err := DecodeInvite(cfg.Invite)
	if err != nil {
		return err
	}
	mux, cleanup, err := dialAppMux(ctx, appsession.DerptunAppDialConfig{
		ClientToken: inv.ClientToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer cleanup()

	guest := NewGuestRuntime(GuestConfig{
		Mux:            mux,
		ParticipantID:  randomID("guest"),
		DisplayName:    cfg.DisplayName,
		TerminalOutput: cfg.Stdout,
	})
	go pumpGuestInput(ctx, guest, cfg.Stdin)
	return guest.Run(ctx)
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
		if user := strings.TrimSpace(os.Getenv("USER")); user != "" {
			cfg.DisplayName = user
		} else {
			cfg.DisplayName = "guest"
		}
	}
	return cfg
}

func pumpGuestInput(ctx context.Context, guest *GuestRuntime, stdin io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			sendGuestInput(ctx, guest, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func sendGuestInput(ctx context.Context, guest *GuestRuntime, data []byte) {
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
