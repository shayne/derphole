// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/model"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type GuestRuntime struct {
	cfg GuestConfig

	chat *model.ChatHistory

	mu          sync.Mutex
	role        protocol.Role
	cols        int
	rows        int
	closeReason string
	control     net.Conn
	terminalIn  net.Conn
	terminalOut net.Conn
	chatConn    net.Conn

	controlMu  sync.Mutex
	terminalMu sync.Mutex
	chatMu     sync.Mutex

	terminalInReady chan net.Conn
	chatReady       chan net.Conn
}

const guestQuitReason = "guest quit"

func NewGuestRuntime(cfg GuestConfig) *GuestRuntime {
	if cfg.TerminalOutput == nil {
		cfg.TerminalOutput = io.Discard
	}
	return &GuestRuntime{
		cfg:             cfg,
		role:            protocol.RolePending,
		chat:            model.NewChatHistory(256),
		terminalInReady: make(chan net.Conn, 1),
		chatReady:       make(chan net.Conn, 1),
	}
}

func (r *GuestRuntime) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer r.closeSessionConns()
	defer func() {
		if r.cfg.Mux != nil {
			_ = r.cfg.Mux.Close()
		}
	}()

	go func() {
		<-ctx.Done()
		r.closeSessionConns()
		if r.cfg.Mux != nil {
			_ = r.cfg.Mux.Close()
		}
	}()

	if err := r.openControl(ctx); err != nil {
		return err
	}
	approved, err := r.waitForApproval(ctx)
	if err != nil || !approved {
		return err
	}
	if err := r.openApprovedStreams(ctx); err != nil {
		return err
	}
	terminalOutErrCh := r.startTerminalOut(ctx)

	return r.runUntilControlOrTerminalOutExit(ctx, terminalOutErrCh)
}

func (r *GuestRuntime) openControl(ctx context.Context) error {
	control, err := r.cfg.Mux.OpenStream(ctx)
	if err != nil {
		return ignoreContextErr(ctx, err)
	}
	r.setControl(control)
	return r.writeControl(protocol.Message{
		Type: protocol.MessageHello,
		Hello: &protocol.Hello{
			ProtocolVersion: protocol.ProtocolVersion,
			ParticipantID:   r.cfg.ParticipantID,
			DisplayName:     r.cfg.DisplayName,
			Role:            protocol.RolePending,
		},
	})
}

func (r *GuestRuntime) waitForApproval(ctx context.Context) (bool, error) {
	r.mu.Lock()
	control := r.control
	r.mu.Unlock()
	for {
		msg, err := protocol.ReadFrame(control)
		if err != nil {
			return false, ignoreContextErr(ctx, err)
		}
		done, approved, err := r.handleApprovalMessage(msg)
		if done || err != nil {
			return approved, err
		}
	}
}

func (r *GuestRuntime) handleApprovalMessage(msg protocol.Message) (bool, bool, error) {
	switch msg.Type {
	case protocol.MessageDecision:
		return true, r.applyDecision(msg.Decision), nil
	case protocol.MessageResize:
		if msg.Resize != nil {
			r.setSize(msg.Resize.Cols, msg.Resize.Rows)
		}
	case protocol.MessageClose:
		if msg.Close != nil {
			r.setCloseReason(msg.Close.Reason)
		}
		return true, false, nil
	}
	return false, false, nil
}

func (r *GuestRuntime) applyDecision(decision *protocol.Decision) bool {
	if decision == nil || !decision.Accepted {
		if decision != nil {
			r.setCloseReason(decision.Reason)
		}
		r.notify(RuntimeEvent{Kind: RuntimeEventRole, Role: protocol.RoleDenied})
		return false
	}
	r.setRole(decision.Role)
	return true
}

func (r *GuestRuntime) readControlLoop(ctx context.Context) error {
	r.mu.Lock()
	control := r.control
	r.mu.Unlock()
	defer func() { _ = control.Close() }()
	for {
		msg, err := protocol.ReadFrame(control)
		if err != nil {
			return ignoreContextErr(ctx, err)
		}
		if r.handleControlMessage(msg) {
			return nil
		}
	}
}

func (r *GuestRuntime) handleControlMessage(msg protocol.Message) bool {
	switch msg.Type {
	case protocol.MessageRoleChange:
		if msg.RoleChange != nil && msg.RoleChange.ParticipantID == r.cfg.ParticipantID {
			r.setRole(msg.RoleChange.Role)
		}
	case protocol.MessageKick:
		r.handleKick(msg.Kick)
	case protocol.MessageResize:
		if msg.Resize != nil {
			r.setSize(msg.Resize.Cols, msg.Resize.Rows)
		}
	case protocol.MessageClose:
		if msg.Close != nil {
			r.setCloseReason(msg.Close.Reason)
		}
		return true
	}
	return false
}

func (r *GuestRuntime) handleKick(kick *protocol.Kick) {
	if kick == nil || kick.ParticipantID != r.cfg.ParticipantID {
		return
	}
	reason := kick.Reason
	if reason == "" {
		reason = "kicked"
	}
	r.setRole(protocol.RoleKicked)
	r.setCloseReason(reason)
}

func (r *GuestRuntime) SendInput(ctx context.Context, data []byte) error {
	if r.Role() != protocol.RoleWrite {
		return ErrReadOnly
	}
	conn, err := waitConn(ctx, r.terminalInReady)
	if err != nil {
		return err
	}
	r.terminalInReady <- conn
	return lockedWriter{conn: conn, mu: &r.terminalMu}.write(protocol.Message{
		Type:     protocol.MessageTerminal,
		Terminal: &protocol.TerminalEvent{Data: append([]byte(nil), data...)},
	})
}

func (r *GuestRuntime) SendChat(ctx context.Context, text string) error {
	conn, err := waitConn(ctx, r.chatReady)
	if err != nil {
		return err
	}
	r.chatReady <- conn
	msg := model.ChatMessage{ParticipantID: r.cfg.ParticipantID, DisplayName: r.cfg.DisplayName, Text: text}
	r.appendChat(msg)
	return lockedWriter{conn: conn, mu: &r.chatMu}.write(protocol.Message{
		Type: protocol.MessageChat,
		Chat: &protocol.Chat{ParticipantID: msg.ParticipantID, DisplayName: msg.DisplayName, Text: msg.Text},
	})
}

func (r *GuestRuntime) Close(ctx context.Context, reason string) error {
	if reason == "" {
		reason = guestQuitReason
	}
	r.setCloseReason(reason)
	err := r.writeControlClose(reason)
	_ = r.writeTerminalInClose(reason)
	_ = r.writeChatClose(reason)
	gracefullyDrainCloseNotice()
	r.closeSessionConns()
	return ignoreContextErr(ctx, err)
}

func (r *GuestRuntime) ReportSize(ctx context.Context, cols, rows int) error {
	r.notify(RuntimeEvent{Kind: RuntimeEventResize, ParticipantID: r.cfg.ParticipantID, Cols: cols, Rows: rows})
	return r.writeControlCtx(ctx, protocol.Message{
		Type:   protocol.MessageResize,
		Resize: &protocol.Resize{Cols: cols, Rows: rows},
	})
}

func (r *GuestRuntime) Role() protocol.Role {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.role
}

func (r *GuestRuntime) TerminalSize() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cols, r.rows
}

func (r *GuestRuntime) ChatMessages() []ChatMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.chat.Messages()
}

func (r *GuestRuntime) CloseReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeReason
}

func (r *GuestRuntime) openApprovedStreams(ctx context.Context) error {
	terminalIn, err := openStream(ctx, r.cfg.Mux, protocol.StreamTerminalIn, r.cfg.ParticipantID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.terminalIn = terminalIn
	r.mu.Unlock()
	r.terminalInReady <- terminalIn

	chatConn, err := openStream(ctx, r.cfg.Mux, protocol.StreamChat, r.cfg.ParticipantID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.chatConn = chatConn
	r.mu.Unlock()
	r.chatReady <- chatConn
	go r.readChat(ctx, chatConn)
	return nil
}

func (r *GuestRuntime) startTerminalOut(ctx context.Context) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- r.acceptTerminalOut(ctx)
	}()
	return errCh
}

func (r *GuestRuntime) acceptTerminalOut(ctx context.Context) error {
	conn, err := acceptStream(ctx, r.cfg.Mux, protocol.StreamTerminalOut)
	if err != nil {
		return ignoreContextErr(ctx, err)
	}
	r.mu.Lock()
	r.terminalOut = conn
	r.mu.Unlock()
	defer func() { _ = conn.Close() }()
	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			return ignoreContextErr(ctx, err)
		}
		switch msg.Type {
		case protocol.MessageTerminal:
			if msg.Terminal != nil && len(msg.Terminal.Data) > 0 {
				if _, err := r.cfg.TerminalOutput.Write(msg.Terminal.Data); err != nil {
					r.setCloseReason(err.Error())
					return err
				}
			}
		case protocol.MessageClose:
			if msg.Close == nil {
				continue
			}
			r.setCloseReason(msg.Close.Reason)
			return nil
		}
	}
}

func (r *GuestRuntime) runUntilControlOrTerminalOutExit(ctx context.Context, terminalOutErrCh <-chan error) error {
	controlErrCh := make(chan error, 1)
	go func() {
		controlErrCh <- r.readControlLoop(ctx)
	}()

	for {
		select {
		case err := <-controlErrCh:
			return err
		case err := <-terminalOutErrCh:
			if err == nil {
				r.closeSessionConns()
				if r.cfg.Mux != nil {
					_ = r.cfg.Mux.Close()
				}
				return nil
			}
			r.closeSessionConns()
			if r.cfg.Mux != nil {
				_ = r.cfg.Mux.Close()
			}
			return ignoreContextErr(ctx, err)
		case <-ctx.Done():
			r.closeSessionConns()
			if r.cfg.Mux != nil {
				_ = r.cfg.Mux.Close()
			}
			return nil
		}
	}
}

func (r *GuestRuntime) readChat(ctx context.Context, conn net.Conn) {
	_ = ctx
	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		if msg.Type == protocol.MessageChat && msg.Chat != nil {
			r.appendChat(model.ChatMessage{
				ParticipantID: msg.Chat.ParticipantID,
				DisplayName:   msg.Chat.DisplayName,
				Text:          msg.Chat.Text,
				Seq:           msg.Chat.Seq,
			})
		}
	}
}

func (r *GuestRuntime) setControl(conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.control = conn
}

func (r *GuestRuntime) closeSessionConns() {
	r.mu.Lock()
	conns := []net.Conn{r.control, r.terminalIn, r.terminalOut, r.chatConn}
	r.mu.Unlock()
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (r *GuestRuntime) writeControl(msg protocol.Message) error {
	r.mu.Lock()
	conn := r.control
	r.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return lockedWriter{conn: conn, mu: &r.controlMu}.write(msg)
}

func (r *GuestRuntime) writeControlCtx(ctx context.Context, msg protocol.Message) error {
	r.mu.Lock()
	conn := r.control
	r.mu.Unlock()
	if conn == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return net.ErrClosed
		}
	}
	return lockedWriter{conn: conn, mu: &r.controlMu}.write(msg)
}

func (r *GuestRuntime) writeControlClose(reason string) error {
	r.mu.Lock()
	conn := r.control
	r.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return lockedWriter{conn: conn, mu: &r.controlMu}.writeWithDeadline(protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: reason},
	}, hostCloseNotifyTimeout)
}

func (r *GuestRuntime) writeTerminalInClose(reason string) error {
	r.mu.Lock()
	conn := r.terminalIn
	r.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return lockedWriter{conn: conn, mu: &r.terminalMu}.writeWithDeadline(protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: reason},
	}, hostCloseNotifyTimeout)
}

func (r *GuestRuntime) writeChatClose(reason string) error {
	r.mu.Lock()
	conn := r.chatConn
	r.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return lockedWriter{conn: conn, mu: &r.chatMu}.writeWithDeadline(protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: reason},
	}, hostCloseNotifyTimeout)
}

func (r *GuestRuntime) setRole(role protocol.Role) {
	r.mu.Lock()
	r.role = role
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventRole, Role: role})
}

func (r *GuestRuntime) setSize(cols, rows int) {
	r.mu.Lock()
	r.cols, r.rows = cols, rows
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventResize, Cols: cols, Rows: rows})
}

func (r *GuestRuntime) setCloseReason(reason string) {
	r.mu.Lock()
	r.closeReason = reason
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventClose, Message: reason})
}

func (r *GuestRuntime) appendChat(msg model.ChatMessage) {
	r.mu.Lock()
	r.chat.Append(msg)
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventChat, Chat: msg})
}

func (r *GuestRuntime) notify(event RuntimeEvent) {
	if r.cfg.Observer != nil {
		r.cfg.Observer.OnRuntimeEvent(event)
	}
}
