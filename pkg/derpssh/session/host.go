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
	"time"

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

const hostShellExitedReason = "host shell exited"
const hostCloseNotifyTimeout = 300 * time.Millisecond

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
	if cfg.LocalInput == nil {
		cfg.LocalInput = emptyReader{}
	}
	if cfg.LocalOutput == nil {
		cfg.LocalOutput = io.Discard
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
		_ = r.pumpLocalInput(ctx)
	}()
	go func() {
		r.acceptApprovedStreams(ctx)
	}()
	ptyErrCh := r.startPTYOutputPump(ctx)

	if !r.cfg.CloseOnPTYEOF {
		return r.readControlLoop(ctx, guestID)
	}
	return r.runUntilControlOrPTYExit(ctx, cancel, guestID, ptyErrCh)
}

func (r *HostRuntime) handshake(ctx context.Context) (string, bool, error) {
	control, err := r.cfg.Mux.Accept(ctx)
	if err != nil {
		return "", false, ignoreContextErr(ctx, err)
	}
	r.setControl(control)
	r.notify(RuntimeEvent{Kind: RuntimeEventStatus, Message: "guest pending"})

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
		r.notify(RuntimeEvent{Kind: RuntimeEventPeer, ParticipantID: guestID, DisplayName: guestName, Role: protocol.RoleDenied})
		return "", false, r.writeControl(protocol.Message{
			Type:     protocol.MessageDecision,
			Decision: &protocol.Decision{Accepted: false, Role: protocol.RoleDenied, Reason: "join denied"},
		})
	}
	r.notify(RuntimeEvent{Kind: RuntimeEventPeer, ParticipantID: guestID, DisplayName: guestName, Role: role})
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
				r.notify(RuntimeEvent{Kind: RuntimeEventResize, ParticipantID: guestID, Cols: msg.Resize.Cols, Rows: msg.Resize.Rows})
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
	if cols <= 0 || rows <= 0 {
		return nil
	}
	if r.cfg.PTYResize != nil {
		if err := r.cfg.PTYResize(cols, rows); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.state.SetHostSize(cols, rows)
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventResize, Cols: cols, Rows: rows})
	return r.writeControlCtx(ctx, r.resizeMessage())
}

func (r *HostRuntime) SetGuestRole(ctx context.Context, participantID string, role protocol.Role) error {
	if role != protocol.RoleRead && role != protocol.RoleWrite {
		return ErrInvalidRole
	}
	r.mu.Lock()
	if participantID == "" {
		participantID = r.guestID
	}
	guestName := r.guestName
	err := r.state.SetGuestRole(participantID, role)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	r.notify(RuntimeEvent{Kind: RuntimeEventPeer, ParticipantID: participantID, DisplayName: guestName, Role: role})
	return r.writeControlCtx(ctx, protocol.Message{
		Type:       protocol.MessageRoleChange,
		RoleChange: &protocol.RoleChange{ParticipantID: participantID, Role: role},
	})
}

func (r *HostRuntime) Kick(ctx context.Context, participantID, reason string) error {
	if reason == "" {
		reason = "kicked"
	}
	r.mu.Lock()
	if participantID == "" {
		participantID = r.guestID
	}
	_ = r.state.KickGuest(participantID)
	r.closeReason = reason
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventPeer, ParticipantID: participantID, Role: protocol.RoleKicked})
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
			data := append([]byte(nil), buf[:n]...)
			if _, writeErr := r.cfg.LocalOutput.Write(data); writeErr != nil {
				return writeErr
			}
			if writeErr := protocol.WriteFrame(conn, protocol.Message{
				Type:     protocol.MessageTerminal,
				Terminal: &protocol.TerminalEvent{Data: data},
			}); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if r.cfg.CloseOnPTYEOF {
					r.notifyTerminalOutputClosed(conn, hostShellExitedReason)
					_ = conn.Close()
				}
				return nil
			}
			return err
		}
	}
}

func (r *HostRuntime) notifyTerminalOutputClosed(conn net.Conn, reason string) {
	if !r.cfg.CloseOnPTYEOF {
		return
	}
	_ = writeFrameWithDeadline(conn, protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: reason},
	}, hostCloseNotifyTimeout)
}

func (r *HostRuntime) startPTYOutputPump(ctx context.Context) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- r.pumpPTYOutput(ctx)
	}()
	return errCh
}

func (r *HostRuntime) runUntilControlOrPTYExit(ctx context.Context, cancel context.CancelFunc, guestID string, ptyErrCh <-chan error) error {
	controlErrCh := make(chan error, 1)
	go func() {
		controlErrCh <- r.readControlLoop(ctx, guestID)
	}()

	select {
	case err := <-controlErrCh:
		return err
	case err := <-ptyErrCh:
		return r.closeAfterPTYOutputExit(ctx, cancel, err, controlErrCh)
	case <-ctx.Done():
		r.closeSessionConns()
		_ = r.cfg.Mux.Close()
		r.closePTYOutput()
		return nil
	}
}

func (r *HostRuntime) closeAfterPTYOutputExit(ctx context.Context, cancel context.CancelFunc, err error, controlErrCh <-chan error) error {
	if err != nil {
		cancel()
		return ignoreContextErr(ctx, err)
	}
	r.setCloseReason(hostShellExitedReason)
	_ = r.writeControlWithDeadline(protocol.Message{
		Type:  protocol.MessageClose,
		Close: &protocol.Close{Reason: hostShellExitedReason},
	}, hostCloseNotifyTimeout)
	waitForControlClose(ctx, controlErrCh, hostCloseNotifyTimeout)
	cancel()
	_ = r.cfg.Mux.Close()
	return nil
}

func waitForControlClose(ctx context.Context, controlErrCh <-chan error, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-controlErrCh:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (r *HostRuntime) pumpLocalInput(ctx context.Context) error {
	return pumpRoutedInput(ctx, r.cfg.LocalInput, hostInputSink(r))
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

func (r *HostRuntime) writeControlWithDeadline(msg protocol.Message, timeout time.Duration) error {
	r.mu.Lock()
	conn := r.control
	r.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return lockedWriter{conn: conn, mu: &r.controlMu}.writeWithDeadline(msg, timeout)
}

func (r *HostRuntime) appendChat(msg model.ChatMessage) {
	r.mu.Lock()
	r.chat.Append(msg)
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventChat, Chat: msg})
}

func (r *HostRuntime) setCloseReason(reason string) {
	r.mu.Lock()
	r.closeReason = reason
	r.mu.Unlock()
	r.notify(RuntimeEvent{Kind: RuntimeEventClose, Message: reason})
}

func (r *HostRuntime) notify(event RuntimeEvent) {
	if r.cfg.Observer != nil {
		r.cfg.Observer.OnRuntimeEvent(event)
	}
}

func (r *HostRuntime) closePTYOutput() {
	closer, ok := r.cfg.PTYOutput.(io.Closer)
	if !ok {
		return
	}
	_ = closer.Close()
}

func (r *HostRuntime) closeSessionConns() {
	r.mu.Lock()
	conns := []net.Conn{r.control, r.terminalIn, r.terminalOut, r.chatConn}
	r.mu.Unlock()
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
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
