// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type routedInputSink struct {
	sendData      func(context.Context, []byte) error
	sendChat      func(context.Context, string) error
	handleCommand func(context.Context, inputCommand) (bool, error)
}

type inputCommand struct {
	Name string
	Arg  string
}

type inputRouter struct {
	atLineStart bool
	pending     []byte
}

func newInputRouter() inputRouter {
	return inputRouter{atLineStart: true}
}

func pumpRoutedInput(ctx context.Context, src io.Reader, sink routedInputSink) error {
	router := newInputRouter()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if routeErr := router.route(ctx, buf[:n], sink); routeErr != nil {
				return routeErr
			}
		}
		if err != nil {
			if len(router.pending) > 0 {
				if routeErr := router.flush(ctx, sink); routeErr != nil {
					return routeErr
				}
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (r *inputRouter) route(ctx context.Context, data []byte, sink routedInputSink) error {
	var passthrough []byte
	flushPassthrough := func() error {
		if len(passthrough) == 0 {
			return nil
		}
		chunk := append([]byte(nil), passthrough...)
		passthrough = passthrough[:0]
		return sink.sendData(ctx, chunk)
	}

	for _, b := range data {
		if len(r.pending) > 0 {
			r.pending = append(r.pending, b)
			if b == '\n' {
				if err := r.handlePending(ctx, sink); err != nil {
					return err
				}
			}
			continue
		}
		if r.atLineStart && b == ':' {
			if err := flushPassthrough(); err != nil {
				return err
			}
			r.pending = append(r.pending, b)
			r.atLineStart = false
			continue
		}
		passthrough = append(passthrough, b)
		r.atLineStart = b == '\n'
	}
	return flushPassthrough()
}

func (r *inputRouter) flush(ctx context.Context, sink routedInputSink) error {
	return r.handlePending(ctx, sink)
}

func (r *inputRouter) handlePending(ctx context.Context, sink routedInputSink) error {
	line := append([]byte(nil), r.pending...)
	r.pending = nil
	r.atLineStart = bytes.HasSuffix(line, []byte("\n"))
	cmd, ok := parseInputCommand(line)
	if !ok {
		return sink.sendData(ctx, line)
	}
	switch cmd.Name {
	case "chat", "c":
		if strings.TrimSpace(cmd.Arg) == "" {
			return nil
		}
		return sink.sendChat(ctx, cmd.Arg)
	default:
		if sink.handleCommand == nil {
			return sink.sendData(ctx, line)
		}
		handled, err := sink.handleCommand(ctx, cmd)
		if err != nil || handled {
			return err
		}
		return sink.sendData(ctx, line)
	}
}

func parseInputCommand(line []byte) (inputCommand, bool) {
	raw := strings.TrimSpace(string(line))
	if !strings.HasPrefix(raw, ":") {
		return inputCommand{}, false
	}
	raw = strings.TrimSpace(strings.TrimPrefix(raw, ":"))
	if raw == "" {
		return inputCommand{}, false
	}
	name, arg, _ := strings.Cut(raw, " ")
	return inputCommand{Name: strings.ToLower(strings.TrimSpace(name)), Arg: strings.TrimSpace(arg)}, true
}

func hostInputSink(host *HostRuntime) routedInputSink {
	return routedInputSink{
		sendData: func(ctx context.Context, data []byte) error {
			if _, err := host.cfg.PTYInput.Write(data); err != nil {
				_ = host.writeControlCtx(ctx, protocol.Message{
					Type:  protocol.MessageClose,
					Close: &protocol.Close{Reason: err.Error()},
				})
				return err
			}
			return nil
		},
		sendChat: func(ctx context.Context, text string) error {
			return host.SendChat(ctx, text)
		},
		handleCommand: func(ctx context.Context, cmd inputCommand) (bool, error) {
			switch cmd.Name {
			case "read":
				return true, host.SetGuestRole(ctx, "", protocol.RoleRead)
			case "write":
				return true, host.SetGuestRole(ctx, "", protocol.RoleWrite)
			case "kick":
				return true, host.Kick(ctx, "", cmd.Arg)
			default:
				return false, nil
			}
		},
	}
}

type guestInteractiveSender interface {
	guestInputSender
	SendChat(context.Context, string) error
}

func guestInputSink(guest guestInteractiveSender) routedInputSink {
	return routedInputSink{
		sendData: func(ctx context.Context, data []byte) error {
			sendGuestInput(ctx, guest, data)
			return nil
		},
		sendChat: func(ctx context.Context, text string) error {
			return guest.SendChat(ctx, text)
		},
	}
}
