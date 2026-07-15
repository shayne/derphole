// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	derpsshsession "github.com/shayne/derphole/pkg/derpssh/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

type shareSessionConfig = derpsshsession.ShareConfig

var runShareSession = derpsshsession.Share

var commandSignalReset = signal.Reset
var commandSignalSelf = func(sig os.Signal) error {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return proc.Signal(sig)
}

var commandContext = func() (context.Context, context.CancelFunc) {
	baseCtx, baseStop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(baseCtx)
	sigquitCh := make(chan os.Signal, 1)
	signal.Notify(sigquitCh, syscall.SIGQUIT)

	var sigquit atomic.Bool
	go func() {
		select {
		case <-sigquitCh:
			sigquit.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			baseStop()
			signal.Stop(sigquitCh)
			if sigquit.Load() {
				commandSignalReset(syscall.SIGQUIT)
				_ = commandSignalSelf(syscall.SIGQUIT)
			}
		})
	}
	return ctx, stop
}

func runShare(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	if shareHelpRequested(args) {
		_, _ = fmt.Fprintln(stderr, shareUsage())
		return 0
	}
	parsed, ok := parseShareArgs(args, stderr)
	if !ok {
		return 2
	}
	stdout, stderr, registerer := shareRegisteringWriters(parsed, stdout, stderr)

	ctx, stop := commandContext()
	defer stop()
	err := runShareSession(ctx, shareSessionConfig{
		Stdin:          stdin,
		Stdout:         stdout,
		Stderr:         stderr,
		ForceRelay:     parsed.forceRelay,
		AutoAcceptRole: parsed.autoAccept,
		Emitter:        telemetry.New(stderr, commandSessionTelemetryLevel(level)),
	})
	if code, failed := handleShareError(err, stderr); failed {
		return code
	}
	return finishShareRegister(registerer, stderr)
}

type parsedShareArgs struct {
	forceRelay bool
	autoAccept protocol.Role
	register   string
	registry   string
}

func parseShareArgs(args []string, stderr io.Writer) (parsedShareArgs, bool) {
	var parsed parsedShareArgs
	for i := 0; i < len(args); i++ {
		if !parseShareArg(args, &i, stderr, &parsed) {
			return parsedShareArgs{}, false
		}
	}
	return parsed, true
}

func shareHelpRequested(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help")
}

func shareRegisteringWriters(parsed parsedShareArgs, stdout, stderr io.Writer) (io.Writer, io.Writer, *shareInviteRegisterer) {
	if parsed.register == "" {
		return stdout, stderr, nil
	}
	registerer := &shareInviteRegisterer{name: parsed.register, registry: parsed.registry}
	return registerer.wrap(stdout), registerer.wrap(stderr), registerer
}

func handleShareError(err error, stderr io.Writer) (int, bool) {
	if err == nil || errors.Is(err, context.Canceled) {
		return 0, false
	}
	_, _ = fmt.Fprintln(stderr, err)
	return 1, true
}

func finishShareRegister(registerer *shareInviteRegisterer, stderr io.Writer) int {
	if registerer == nil || registerer.err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(stderr, registerer.err)
	return serviceErrorCode(registerer.err)
}

func parseShareArg(args []string, index *int, stderr io.Writer, parsed *parsedShareArgs) bool {
	arg := args[*index]
	if handled, ok := parseShareFlagArg(args, index, stderr, parsed); handled {
		return ok
	}
	if len(arg) > 0 && arg[0] == '-' {
		_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
		_, _ = fmt.Fprintln(stderr, shareUsage())
		return false
	}
	_, _ = fmt.Fprintln(stderr, shareUsage())
	return false
}

func parseShareFlagArg(args []string, index *int, stderr io.Writer, parsed *parsedShareArgs) (bool, bool) {
	arg := args[*index]
	switch {
	case arg == "--force-relay":
		parsed.forceRelay = true
		return true, true
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
	case arg == "--register":
		value, ok := shareFlagValue(args, index, "--register", stderr)
		parsed.register = value
		return true, ok
	case strings.HasPrefix(arg, "--register="):
		parsed.register = strings.TrimPrefix(arg, "--register=")
		return true, true
	case arg == "--registry":
		value, ok := shareFlagValue(args, index, "--registry", stderr)
		parsed.registry = value
		return true, ok
	case strings.HasPrefix(arg, "--registry="):
		parsed.registry = strings.TrimPrefix(arg, "--registry=")
		return true, true
	default:
		return false, false
	}
}

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

func shareFlagValue(args []string, index *int, flag string, stderr io.Writer) (string, bool) {
	if *index+1 >= len(args) {
		_, _ = fmt.Fprintf(stderr, "%s requires a value\n", flag)
		_, _ = fmt.Fprintln(stderr, shareUsage())
		return "", false
	}
	*index = *index + 1
	return args[*index], true
}

type shareInviteRegisterer struct {
	name     string
	registry string
	once     sync.Once
	err      error
}

type shareInviteRegisteringWriter struct {
	dst  io.Writer
	reg  *shareInviteRegisterer
	tail string
}

func (r *shareInviteRegisterer) wrap(dst io.Writer) io.Writer {
	return &shareInviteRegisteringWriter{dst: dst, reg: r}
}

func (w *shareInviteRegisteringWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.capture(string(p))
	if err != nil {
		return n, err
	}
	return n, w.reg.err
}

func (w *shareInviteRegisteringWriter) capture(chunk string) {
	w.tail += chunk
	if len(w.tail) > 4096 {
		w.tail = w.tail[len(w.tail)-4096:]
	}
	if invite := firstInvite(w.tail); invite != "" {
		w.reg.publish(invite)
	}
}

func (r *shareInviteRegisterer) publish(invite string) {
	r.once.Do(func() {
		r.err = publishDerpsshInvite(context.Background(), r.name, invite, r.registry)
	})
}

func firstInvite(text string) string {
	for _, field := range strings.Fields(text) {
		if strings.HasPrefix(field, derpsshsession.InvitePrefix) {
			return field
		}
	}
	return ""
}

func shareUsage() string {
	return "Usage: derpssh share [--auto-accept read|write] [--force-relay] [--register NAME] [--registry PATH]"
}

func commandSessionTelemetryLevel(level telemetry.Level) telemetry.Level {
	if level == telemetry.LevelDefault {
		return telemetry.LevelQuiet
	}
	return level
}
