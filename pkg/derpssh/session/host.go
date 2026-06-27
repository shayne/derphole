// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/model"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type HostRuntime struct {
	cfg HostConfig

	state *model.HostState
	chat  *model.ChatHistory

	mu          sync.Mutex
	guestID     string
	guestName   string
	control     net.Conn
	terminalIn  net.Conn
	terminalOut net.Conn
	chatConn    net.Conn
	closeReason string

	controlMu sync.Mutex
	chatMu    sync.Mutex

	terminalInReady  chan net.Conn
	terminalOutReady chan net.Conn
	chatReady        chan net.Conn
}

func NewHostRuntime(cfg HostConfig) *HostRuntime {
	if cfg.InitialCols == 0 {
		cfg.InitialCols = 80
	}
	if cfg.InitialRows == 0 {
		cfg.InitialRows = 24
	}
	if cfg.PTYInput == nil {
		cfg.PTYInput = io.Discard
	}
	if cfg.PTYOutput == nil {
		cfg.PTYOutput = emptyReader{}
	}
	if cfg.Approval == nil {
		cfg.Approval = StaticApproval{Role: protocol.RoleRead}
	}
	return &HostRuntime{
		cfg:              cfg,
		state:            model.NewHostState(cfg.HostID, cfg.InitialCols, cfg.InitialRows),
		chat:             model.NewChatHistory(256),
		terminalInReady:  make(chan net.Conn, 1),
		terminalOutReady: make(chan net.Conn, 1),
		chatReady:        make(chan net.Conn, 1),
	}
}

func (r *HostRuntime) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = r.cfg.Mux.Close() }()
	defer r.closePTYOutput()

	go func() {
		<-ctx.Done()
		_ = r.cfg.Mux.Close()
	}()

	guestID, approved, err := r.handshake(ctx)
	if err != nil {
		return err
	}
	if !approved {
		return r.readDeniedControlLoop(ctx)
	}

	go func() {
		r.acceptApprovedStreams(ctx)
	}()
	go func() {
		_ = r.pumpPTYOutput(ctx)
	}()

	return r.readControlLoop(ctx, guestID)
}

func (r *HostRuntime) handshake(ctx context.Context) (string, bool, error) {
	control, err := r.cfg.Mux.Accept(ctx)
	if err != nil {
		return "", false, ignoreContextErr(ctx, err)
	}
	r.setControl(control)

	hello, err := protocol.ReadFrame(control)
	if err != nil {
		return "", false, ignoreContextErr(ctx, err)
	}
	guestID, guestName, err := guestFromHello(hello)
	if err != nil {
		return "", false, err
	}
	role, err := r.approveGuest(guestID, guestName)
	if err != nil {
		return "", false, err
	}
	if !roleGranted(role) {
		return "", false, r.writeControl(protocol.Message{
			Type:     protocol.MessageDecision,
			Decision: &protocol.Decision{Accepted: false, Role: protocol.RoleDenied, Reason: "join denied"},
		})
	}
	return guestID, true, r.sendApproval(role)
}

func (r *HostRuntime) approveGuest(guestID, guestName string) (protocol.Role, error) {
	role := r.cfg.Approval.Approve(JoinRequest{ParticipantID: guestID, DisplayName: guestName})
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guestID = guestID
	r.guestName = guestName
	r.state.AddPendingGuest(guestID, guestName)
	if roleGranted(role) {
		return role, r.state.ApproveGuest(guestID, role)
	}
	return role, nil
}

func (r *HostRuntime) sendApproval(role protocol.Role) error {
	if err := r.writeControl(protocol.Message{
		Type:  protocol.MessageHello,
		Hello: &protocol.Hello{ProtocolVersion: protocol.ProtocolVersion, ParticipantID: r.cfg.HostID, DisplayName: r.cfg.HostName, Role: protocol.RoleWrite},
	}); err != nil {
		return err
	}
	if err := r.writeControl(r.resizeMessage()); err != nil {
		return err
	}
	return r.writeControl(protocol.Message{
		Type:     protocol.MessageDecision,
		Decision: &protocol.Decision{Accepted: true, Role: role},
	})
}

func (r *HostRuntime) readControlLoop(ctx context.Context, guestID string) error {
	r.mu.Lock()
	control := r.control
	r.mu.Unlock()
	defer func() { _ = control.Close() }()
	for {
		msg, err := protocol.ReadFrame(control)
		if err != nil {
			return ignoreContextErr(ctx, err)
		}
		switch msg.Type {
		case protocol.MessageResize:
			if msg.Resize != nil {
				r.mu.Lock()
				r.state.NoteGuestSize(guestID, msg.Resize.Cols, msg.Resize.Rows)
				r.mu.Unlock()
			}
		case protocol.MessageClose:
			if msg.Close != nil {
				r.setCloseReason(msg.Close.Reason)
			}
			return nil
		}
	}
}

func (r *HostRuntime) readDeniedControlLoop(ctx context.Context) error {
	r.mu.Lock()
	control := r.control
	r.mu.Unlock()
	defer func() { _ = control.Close() }()
	for {
		msg, err := protocol.ReadFrame(control)
		if err != nil {
			return ignoreContextErr(ctx, err)
		}
		if msg.Type == protocol.MessageClose {
			if msg.Close != nil {
				r.setCloseReason(msg.Close.Reason)
			}
			return nil
		}
	}
}

func (r *HostRuntime) Resize(ctx context.Context, cols, rows int) error {
	r.mu.Lock()
	r.state.SetHostSize(cols, rows)
	r.mu.Unlock()
	return r.writeControlCtx(ctx, r.resizeMessage())
}

func (r *HostRuntime) Kick(ctx context.Context, participantID, reason string) error {
	if reason == "" {
		reason = "kicked"
	}
	r.mu.Lock()
	_ = r.state.KickGuest(participantID)
	r.closeReason = reason
	r.mu.Unlock()
	if err := r.writeControlCtx(ctx, protocol.Message{
		Type: protocol.MessageKick,
		Kick: &protocol.Kick{ParticipantID: participantID, Reason: reason},
	}); err != nil {
		return err
	}
	return r.writeControlCtx(ctx, protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: reason},
	})
}

func (r *HostRuntime) SendChat(ctx context.Context, text string) error {
	conn, err := waitConn(ctx, r.chatReady)
	if err != nil {
		return err
	}
	r.chatReady <- conn
	msg := model.ChatMessage{ParticipantID: r.cfg.HostID, DisplayName: r.cfg.HostName, Text: text}
	r.appendChat(msg)
	return lockedWriter{conn: conn, mu: &r.chatMu}.write(protocol.Message{
		Type: protocol.MessageChat,
		Chat: &protocol.Chat{ParticipantID: msg.ParticipantID, DisplayName: msg.DisplayName, Text: msg.Text},
	})
}

func (r *HostRuntime) ChatMessages() []ChatMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.chat.Messages()
}

func (r *HostRuntime) CloseReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeReason
}

func (r *HostRuntime) acceptApprovedStreams(ctx context.Context) {
	streams, err := r.acceptGuestStreams(ctx)
	if err != nil {
		closeReady(r.terminalInReady)
		closeReady(r.chatReady)
		return
	}
	r.mu.Lock()
	r.terminalIn = streams.terminalIn
	r.chatConn = streams.chat
	r.mu.Unlock()
	r.terminalInReady <- streams.terminalIn
	r.chatReady <- streams.chat
	go r.readTerminalInput(ctx, streams.terminalIn)
	go r.readChat(ctx, streams.chat)

	terminalOut, err := openStream(ctx, r.cfg.Mux, protocol.StreamTerminalOut, r.cfg.HostID)
	if err != nil {
		closeReady(r.terminalOutReady)
		return
	}
	r.mu.Lock()
	r.terminalOut = terminalOut
	r.mu.Unlock()
	r.terminalOutReady <- terminalOut
}

type guestStreams struct {
	terminalIn net.Conn
	chat       net.Conn
}

func (r *HostRuntime) acceptGuestStreams(ctx context.Context) (guestStreams, error) {
	var streams guestStreams
	for streams.terminalIn == nil || streams.chat == nil {
		stream, err := acceptAnyStream(ctx, r.cfg.Mux)
		if err != nil {
			closeGuestStreams(streams)
			return guestStreams{}, err
		}
		switch stream.kind {
		case protocol.StreamTerminalIn:
			if streams.terminalIn != nil {
				_ = stream.conn.Close()
				continue
			}
			streams.terminalIn = stream.conn
		case protocol.StreamChat:
			if streams.chat != nil {
				_ = stream.conn.Close()
				continue
			}
			streams.chat = stream.conn
		default:
			_ = stream.conn.Close()
		}
	}
	return streams, nil
}

func closeGuestStreams(streams guestStreams) {
	if streams.terminalIn != nil {
		_ = streams.terminalIn.Close()
	}
	if streams.chat != nil {
		_ = streams.chat.Close()
	}
}

func (r *HostRuntime) readTerminalInput(ctx context.Context, conn net.Conn) {
	for {
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		if msg.Type != protocol.MessageTerminal || msg.Terminal == nil {
			continue
		}
		r.mu.Lock()
		guestID := r.guestID
		canWrite := r.state.GuestCanWrite(guestID)
		r.mu.Unlock()
		if !canWrite {
			_ = r.writeControlCtx(ctx, protocol.Message{
				Type:  protocol.MessageClose,
				Close: &protocol.Close{Reason: "guest is read-only"},
			})
			return
		}
		if _, err := r.cfg.PTYInput.Write(msg.Terminal.Data); err != nil {
			_ = r.writeControlCtx(ctx, protocol.Message{
				Type:  protocol.MessageClose,
				Close: &protocol.Close{Reason: err.Error()},
			})
			return
		}
	}
}

func (r *HostRuntime) readChat(ctx context.Context, conn net.Conn) {
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

func (r *HostRuntime) pumpPTYOutput(ctx context.Context) error {
	conn, err := waitConn(ctx, r.terminalOutReady)
	if err != nil {
		return err
	}
	buf := make([]byte, 32*1024)
	for {
		n, err := r.cfg.PTYOutput.Read(buf)
		if n > 0 {
			if writeErr := protocol.WriteFrame(conn, protocol.Message{
				Type:     protocol.MessageTerminal,
				Terminal: &protocol.TerminalEvent{Data: append([]byte(nil), buf[:n]...)},
			}); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (r *HostRuntime) resizeMessage() protocol.Message {
	r.mu.Lock()
	cols, rows := r.state.HostSize()
	r.mu.Unlock()
	return protocol.Message{Type: protocol.MessageResize, Resize: &protocol.Resize{Cols: cols, Rows: rows}}
}

func (r *HostRuntime) setControl(conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.control = conn
}

func (r *HostRuntime) writeControl(msg protocol.Message) error {
	r.mu.Lock()
	conn := r.control
	r.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return lockedWriter{conn: conn, mu: &r.controlMu}.write(msg)
}

func (r *HostRuntime) writeControlCtx(ctx context.Context, msg protocol.Message) error {
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

func (r *HostRuntime) appendChat(msg model.ChatMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chat.Append(msg)
}

func (r *HostRuntime) setCloseReason(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeReason = reason
}

func (r *HostRuntime) closePTYOutput() {
	closer, ok := r.cfg.PTYOutput.(io.Closer)
	if !ok {
		return
	}
	_ = closer.Close()
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func ignoreContextErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	if strings.Contains(err.Error(), "read/write on closed pipe") {
		return nil
	}
	return err
}
