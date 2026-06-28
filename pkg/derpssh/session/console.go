// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/pty"
	"github.com/shayne/derphole/pkg/derpssh/tui"
)

type teaProgram interface {
	Send(tea.Msg)
	Run() (tea.Model, error)
	Quit()
}

var isTerminalFD = pty.IsTerminal
var newTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) teaProgram {
	return tea.NewProgram(model, opts...)
}

type tuiConsoleCallbacks struct {
	TerminalInput func(context.Context, []byte) error
	Chat          func(context.Context, string) error
	RoleChange    func(context.Context, string, protocol.Role) error
	Kick          func(context.Context, string, string) error
	Resize        func(context.Context, int, int) error
	Quit          func(context.Context) error
}

type harnessActionHandler func(*tuiConsole, context.Context, string)

var harnessActionHandlers = map[string]harnessActionHandler{
	"input": runHarnessInputAction,
	"chat":  runHarnessChatAction,
	"role":  runHarnessRoleAction,
	"kick":  runHarnessKickAction,
	"quit":  runHarnessQuitAction,
	"sleep": runHarnessSleepAction,
}

type tuiConsoleOptions struct {
	Mode                      tui.Mode
	Cols                      int
	Rows                      int
	Stdin                     io.Reader
	Stdout                    io.Writer
	DisplayName               string
	InviteCommand             string
	InitialInviteOpen         bool
	Terminal                  tui.TerminalPane
	ForceHeadless             bool
	AllowHeadlessApprovalWait bool
}

type tuiConsole struct {
	app     *tui.App
	program teaProgram
	tty     bool
	mode    tui.Mode
	output  io.Writer

	appMu     sync.Mutex
	stateMu   sync.Mutex
	transport string
	hostCols  int
	hostRows  int
	localRole tui.Role
	peers     map[string]tui.Peer
	peerOrder []string

	callbackMu sync.Mutex
	callbacks  tuiConsoleCallbacks

	approvalMu sync.Mutex
	approvals  map[string]chan protocol.Role
	stopped    bool

	programMu             sync.Mutex
	programStartRequested bool
	programQueue          []tea.Msg
	programNotify         chan struct{}
	startOnce             sync.Once
	cancel                context.CancelFunc

	harnessMu           sync.Mutex
	harnessCtx          context.Context
	harnessStarted      bool
	harnessCallbacksSet bool
	harnessOnce         sync.Once

	transcriptMu      sync.Mutex
	transcriptStarted bool
	transcriptLast    string

	allowHeadlessApprovalWait bool
}

func newTerminalConsoleWithOptions(opts tuiConsoleOptions) *tuiConsole {
	return newTUIConsole(opts)
}

func newHeadlessTUIConsole(mode tui.Mode, cols, rows int, terminal tui.TerminalPane) *tuiConsole {
	return newTUIConsole(tuiConsoleOptions{
		Mode:                      mode,
		Cols:                      cols,
		Rows:                      rows,
		Terminal:                  terminal,
		ForceHeadless:             true,
		AllowHeadlessApprovalWait: true,
	})
}

func newTUIConsole(opts tuiConsoleOptions) *tuiConsole {
	opts = normalizeTUIConsoleOptions(opts)
	terminal := opts.Terminal
	if terminal == nil {
		terminal = tui.NewVTTerminalPane(opts.Cols, opts.Rows)
	}
	app := tui.NewApp(tui.Options{
		Side:              string(opts.Mode),
		DisplayName:       opts.DisplayName,
		InviteCommand:     opts.InviteCommand,
		InitialInviteOpen: opts.InitialInviteOpen,
		Terminal:          terminal,
	})
	app.SetWindowSize(opts.Cols, opts.Rows)

	c := &tuiConsole{
		app:                       app,
		mode:                      opts.Mode,
		output:                    opts.Stdout,
		peers:                     make(map[string]tui.Peer),
		approvals:                 make(map[string]chan protocol.Role),
		allowHeadlessApprovalWait: opts.AllowHeadlessApprovalWait,
	}
	c.configureProgram(opts)
	return c
}

func normalizeTUIConsoleOptions(opts tuiConsoleOptions) tuiConsoleOptions {
	if opts.Mode == "" {
		opts.Mode = tui.ModeGuest
	}
	if opts.Cols <= 0 {
		opts.Cols = 80
	}
	if opts.Rows <= 0 {
		opts.Rows = 24
	}
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stdin == nil {
		opts.Stdin = emptyReader{}
	}
	return opts
}

func (c *tuiConsole) configureProgram(opts tuiConsoleOptions) {
	if !shouldRunTeaProgram(opts) {
		return
	}
	c.tty = true
	c.programNotify = make(chan struct{}, 1)
	c.program = newTeaProgram(
		c.app,
		tea.WithInput(opts.Stdin),
		tea.WithOutput(opts.Stdout),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
}

func shouldRunTeaProgram(opts tuiConsoleOptions) bool {
	if opts.ForceHeadless {
		return false
	}
	stdinFile, stdinOK := opts.Stdin.(*os.File)
	stdoutFile, stdoutOK := opts.Stdout.(*os.File)
	return stdinOK && stdoutOK && isTerminalFD(stdinFile.Fd()) && isTerminalFD(stdoutFile.Fd())
}

func (c *tuiConsole) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.startOnce.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		c.cancel = cancel
		c.approvalMu.Lock()
		c.stopped = false
		c.approvalMu.Unlock()
		c.programMu.Lock()
		if c.program != nil && c.programNotify == nil {
			c.programNotify = make(chan struct{}, 1)
		}
		c.programStartRequested = c.program != nil
		c.programMu.Unlock()
		go c.consumeCommands(runCtx)
		go func() {
			<-runCtx.Done()
			c.resolvePendingApprovals(protocol.RoleDenied)
			if c.program != nil {
				c.program.Quit()
			}
		}()
		if c.program == nil {
			c.markHarnessStarted(runCtx)
			return
		}
		runStarted := make(chan struct{})
		go c.pumpProgramMessages(runCtx, runStarted)
		go func() {
			close(runStarted)
			_, _ = c.program.Run()
			cancel()
		}()
	})
}

func (c *tuiConsole) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.resolvePendingApprovals(protocol.RoleDenied)
	if c.program != nil {
		c.program.Quit()
	}
}

func (c *tuiConsole) SetCommandCallbacks(callbacks tuiConsoleCallbacks) {
	c.callbackMu.Lock()
	c.callbacks = callbacks
	c.callbackMu.Unlock()
	c.markHarnessCallbacksSet()
}

func (c *tuiConsole) SetInviteCommand(string) {}

func (c *tuiConsole) TerminalSize() pty.Size {
	c.appMu.Lock()
	defer c.appMu.Unlock()
	cols, rows := c.app.TerminalSize()
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	return pty.Size{Cols: cols, Rows: rows}
}

func (c *tuiConsole) Write(data []byte) (int, error) {
	c.send(tui.TerminalDataMsg(append([]byte(nil), data...)))
	return len(data), nil
}

func (c *tuiConsole) Approve(req JoinRequest) protocol.Role {
	if role, ok := envApprovalRole(); ok {
		return role
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		name = strings.TrimSpace(req.ParticipantID)
	}
	if c.program == nil && !c.allowHeadlessApprovalWait {
		c.send(tui.ApprovalRequestMsg{PeerID: req.ParticipantID, Peer: name})
		c.writeTranscriptLine("approval denied: " + name)
		return protocol.RoleDenied
	}
	key := approvalKey(req.ParticipantID, name)
	result := make(chan protocol.Role, 1)

	c.approvalMu.Lock()
	if c.stopped {
		c.approvalMu.Unlock()
		return protocol.RoleDenied
	}
	c.approvals[key] = result
	c.approvalMu.Unlock()
	defer func() {
		c.approvalMu.Lock()
		delete(c.approvals, key)
		c.approvalMu.Unlock()
	}()

	c.send(tui.ApprovalRequestMsg{PeerID: req.ParticipantID, Peer: name})
	return <-result
}

func (c *tuiConsole) resolvePendingApprovals(role protocol.Role) {
	c.approvalMu.Lock()
	c.stopped = true
	pending := make([]chan protocol.Role, 0, len(c.approvals))
	for key, result := range c.approvals {
		pending = append(pending, result)
		delete(c.approvals, key)
	}
	c.approvalMu.Unlock()

	for _, result := range pending {
		select {
		case result <- role:
		default:
		}
	}
}

func (c *tuiConsole) OnRuntimeEvent(event RuntimeEvent) {
	switch event.Kind {
	case RuntimeEventStatus:
		c.updateRuntimeState(func() { c.transport = event.Message })
	case RuntimeEventPeer:
		c.applyPeerRuntimeEvent(event)
	case RuntimeEventRole:
		c.applyRoleRuntimeEvent(event)
	case RuntimeEventResize:
		c.applyResizeRuntimeEvent(event)
	case RuntimeEventChat:
		c.sendChatRuntimeEvent(event)
	case RuntimeEventClose:
		c.applyCloseRuntimeEvent(event)
	}
}

func (c *tuiConsole) updateRuntimeState(update func()) {
	c.stateMu.Lock()
	update()
	msg := c.runtimeStateLocked()
	c.stateMu.Unlock()
	c.send(msg)
}

func (c *tuiConsole) applyPeerRuntimeEvent(event RuntimeEvent) {
	c.updateRuntimeState(func() {
		c.setPeerLocked(event.ParticipantID, event.DisplayName, event.Role)
		c.transport = transportAfterPeerRole(c.transport, event.Role)
	})
}

func (c *tuiConsole) applyCloseRuntimeEvent(event RuntimeEvent) {
	message := strings.TrimSpace(event.Message)
	c.updateRuntimeState(func() {
		c.transport = closedTransportStatus(message)
		if c.mode == tui.ModeHost && strings.TrimSpace(event.ParticipantID) != "" {
			c.clearPeersLocked()
		}
	})
	if c.mode == tui.ModeHost && strings.TrimSpace(event.ParticipantID) != "" {
		name := displayNameOrID(event.DisplayName, event.ParticipantID)
		body := message
		if body == "" {
			body = name + " disconnected"
		}
		c.send(tui.NoticeMsg{Title: "Guest left", Body: body})
	}
}

func transportAfterPeerRole(current string, role protocol.Role) string {
	if roleGranted(role) && current == "guest pending" {
		return "guest connected"
	}
	return current
}

func (c *tuiConsole) applyRoleRuntimeEvent(event RuntimeEvent) {
	c.updateRuntimeState(func() {
		c.localRole = tuiRoleFromProtocol(event.Role)
		c.transport = transportAfterLocalRole(c.transport, event.Role)
	})
}

func transportAfterLocalRole(current string, role protocol.Role) string {
	if roleGranted(role) && current == "waiting for host approval" {
		return "approved"
	}
	return current
}

func (c *tuiConsole) applyResizeRuntimeEvent(event RuntimeEvent) {
	if strings.TrimSpace(event.ParticipantID) != "" {
		return
	}
	c.updateRuntimeState(func() {
		c.hostCols = event.Cols
		c.hostRows = event.Rows
	})
}

func (c *tuiConsole) sendChatRuntimeEvent(event RuntimeEvent) {
	c.send(tui.ChatMsg{
		Author: displayNameOrID(event.Chat.DisplayName, event.Chat.ParticipantID),
		Body:   event.Chat.Text,
	})
}

func closedTransportStatus(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "closed"
	}
	return "closed: " + message
}

func (c *tuiConsole) View() string {
	c.appMu.Lock()
	defer c.appMu.Unlock()
	return c.app.View()
}

func (c *tuiConsole) consumeCommands(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-c.app.Commands():
			c.handleCommand(ctx, cmd)
		}
	}
}

func (c *tuiConsole) handleCommand(ctx context.Context, cmd tui.Command) {
	switch cmd := cmd.(type) {
	case tui.ApprovalDecisionCommand:
		c.handleApprovalDecision(cmd)
	case tui.TerminalInputCommand:
		c.handleTerminalInputCommand(ctx, cmd)
	case tui.ChatSendCommand:
		c.handleChatCommand(ctx, cmd)
	case tui.QuitCommand:
		c.handleQuitCommand(ctx)
	case tui.CopyInviteCommand:
		c.handleCopyInviteCommand(cmd)
	case tui.RoleChangeCommand:
		c.handleRoleChangeCommand(ctx, cmd)
	case tui.KickCommand:
		c.handleKickCommand(ctx, cmd)
	case tui.TerminalResizeCommand:
		c.handleResizeCommand(ctx, cmd)
	}
}

func (c *tuiConsole) handleQuitCommand(ctx context.Context) {
	callbacks := c.currentCallbacks()
	if callbacks.Quit != nil {
		_ = callbacks.Quit(ctx)
	}
	c.Stop()
}

func (c *tuiConsole) handleCopyInviteCommand(cmd tui.CopyInviteCommand) {
	command := strings.TrimSpace(cmd.Command)
	if command == "" || c.output == nil {
		return
	}
	_, _ = io.WriteString(c.output, osc52(command))
}

func (c *tuiConsole) handleTerminalInputCommand(ctx context.Context, cmd tui.TerminalInputCommand) {
	callbacks := c.currentCallbacks()
	if callbacks.TerminalInput != nil {
		_ = callbacks.TerminalInput(ctx, append([]byte(nil), cmd.Data...))
	}
}

func (c *tuiConsole) handleChatCommand(ctx context.Context, cmd tui.ChatSendCommand) {
	callbacks := c.currentCallbacks()
	if callbacks.Chat != nil {
		_ = callbacks.Chat(ctx, cmd.Body)
	}
}

func (c *tuiConsole) handleRoleChangeCommand(ctx context.Context, cmd tui.RoleChangeCommand) {
	role, ok := protocolRoleFromTUI(cmd.Role)
	if !ok {
		return
	}
	callbacks := c.currentCallbacks()
	if callbacks.RoleChange != nil {
		_ = callbacks.RoleChange(ctx, cmd.PeerID, role)
	}
}

func (c *tuiConsole) handleKickCommand(ctx context.Context, cmd tui.KickCommand) {
	callbacks := c.currentCallbacks()
	if callbacks.Kick != nil {
		_ = callbacks.Kick(ctx, cmd.PeerID, "kicked")
	}
}

func (c *tuiConsole) handleResizeCommand(ctx context.Context, cmd tui.TerminalResizeCommand) {
	if cmd.Cols <= 0 || cmd.Rows <= 0 {
		return
	}
	callbacks := c.currentCallbacks()
	if callbacks.Resize != nil {
		_ = callbacks.Resize(ctx, cmd.Cols, cmd.Rows)
	}
}

func (c *tuiConsole) handleApprovalDecision(cmd tui.ApprovalDecisionCommand) {
	key := approvalKey(cmd.PeerID, cmd.Peer)
	c.approvalMu.Lock()
	result := c.approvals[key]
	c.approvalMu.Unlock()
	if result == nil {
		return
	}
	role := protocol.RoleDenied
	if !cmd.Deny {
		if mapped, ok := protocolRoleFromTUI(cmd.Role); ok {
			role = mapped
		}
	}
	select {
	case result <- role:
	default:
	}
}

func (c *tuiConsole) currentCallbacks() tuiConsoleCallbacks {
	c.callbackMu.Lock()
	defer c.callbackMu.Unlock()
	return c.callbacks
}

func osc52(text string) string {
	return "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\x07"
}

func hostConsoleCallbacks(host *HostRuntime) tuiConsoleCallbacks {
	sink := hostInputSink(host)
	return tuiConsoleCallbacks{
		TerminalInput: sink.sendData,
		Chat: func(ctx context.Context, body string) error {
			return host.SendChat(ctx, body)
		},
		RoleChange: func(ctx context.Context, peerID string, role protocol.Role) error {
			return host.SetGuestRole(ctx, peerID, role)
		},
		Kick: func(ctx context.Context, peerID string, reason string) error {
			return host.Kick(ctx, peerID, reason)
		},
		Resize: func(ctx context.Context, cols int, rows int) error {
			return host.Resize(ctx, cols, rows)
		},
		Quit: func(ctx context.Context) error {
			return host.Close(ctx, hostQuitReason)
		},
	}
}

func guestConsoleCallbacks(guest *GuestRuntime) tuiConsoleCallbacks {
	return tuiConsoleCallbacks{
		TerminalInput: func(ctx context.Context, data []byte) error {
			sendGuestInput(ctx, guest, data)
			return nil
		},
		Chat: func(ctx context.Context, body string) error {
			return guest.SendChat(ctx, body)
		},
		Resize: func(ctx context.Context, cols int, rows int) error {
			return guest.ReportSize(ctx, cols, rows)
		},
		Quit: func(ctx context.Context) error {
			return guest.Close(ctx, guestQuitReason)
		},
	}
}

func (c *tuiConsole) send(msg tea.Msg) {
	if c.program != nil {
		if c.isProgramStartRequested() {
			c.enqueueProgramMessage(msg)
			return
		}
		c.appMu.Lock()
		_, cmd := c.app.Update(msg)
		c.appMu.Unlock()
		c.runTeaCommand(cmd)
		return
	}
	c.appMu.Lock()
	_, cmd := c.app.Update(msg)
	c.appMu.Unlock()
	c.writeTranscript(msg)
	c.runTeaCommand(cmd)
}

func (c *tuiConsole) enqueueProgramMessage(msg tea.Msg) {
	c.programMu.Lock()
	c.programQueue = append(c.programQueue, msg)
	notify := c.programNotify
	c.programMu.Unlock()
	if notify == nil {
		return
	}
	select {
	case notify <- struct{}{}:
	default:
	}
}

func (c *tuiConsole) pumpProgramMessages(ctx context.Context, runStarted <-chan struct{}) {
	select {
	case <-ctx.Done():
		return
	case <-runStarted:
	}
	for {
		msg, ok := c.nextProgramMessage(ctx)
		if !ok {
			return
		}
		c.program.Send(msg)
	}
}

func (c *tuiConsole) nextProgramMessage(ctx context.Context) (tea.Msg, bool) {
	for {
		c.programMu.Lock()
		if len(c.programQueue) > 0 {
			msg := c.programQueue[0]
			copy(c.programQueue, c.programQueue[1:])
			c.programQueue[len(c.programQueue)-1] = nil
			c.programQueue = c.programQueue[:len(c.programQueue)-1]
			c.programMu.Unlock()
			return msg, true
		}
		notify := c.programNotify
		c.programMu.Unlock()
		if notify == nil {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-notify:
		}
	}
}

func (c *tuiConsole) writeTranscript(msg tea.Msg) {
	switch msg := msg.(type) {
	case tui.TerminalDataMsg:
		c.writeTranscriptData("terminal", string(msg))
	case tui.RuntimeStateMsg:
		c.writeRuntimeTranscript(msg)
	case tui.ChatMsg:
		c.writeChatTranscript(msg)
	case tui.ApprovalRequestMsg:
		c.writeApprovalTranscript(msg)
	}
}

func (c *tuiConsole) writeRuntimeTranscript(msg tui.RuntimeStateMsg) {
	if strings.TrimSpace(msg.Transport) != "" {
		c.writeTranscriptLine("status: " + msg.Transport)
	}
	if msg.LocalRole != "" {
		c.writeTranscriptLine("role: " + string(msg.LocalRole))
	}
	if msg.HostCols > 0 && msg.HostRows > 0 {
		c.writeTranscriptLine("size: " + intString(msg.HostCols) + "x" + intString(msg.HostRows))
	}
	for _, peer := range msg.Peers {
		c.writePeerTranscript(peer)
	}
}

func (c *tuiConsole) writePeerTranscript(peer tui.Peer) {
	name := displayNameOrID(peer.Name, peer.ID)
	if name != "" {
		c.writeTranscriptLine("peer: " + name + "/" + string(peer.Role))
	}
}

func (c *tuiConsole) writeChatTranscript(msg tui.ChatMsg) {
	author := strings.TrimSpace(msg.Author)
	if author == "" {
		author = "chat"
	}
	c.writeTranscriptLine("chat: " + author + ": " + msg.Body)
}

func (c *tuiConsole) writeApprovalTranscript(msg tui.ApprovalRequestMsg) {
	peer := displayNameOrID(msg.Peer, msg.PeerID)
	if peer != "" {
		c.writeTranscriptLine("approval requested: " + peer)
	}
}

func (c *tuiConsole) writeTranscriptData(label, data string) {
	data = strings.ReplaceAll(data, "\r\n", "\n")
	data = strings.ReplaceAll(data, "\r", "\n")
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		c.writeTranscriptLine(label + ": " + line)
	}
}

func (c *tuiConsole) writeTranscriptLine(line string) {
	if c.output == nil {
		return
	}
	c.transcriptMu.Lock()
	defer c.transcriptMu.Unlock()
	if c.transcriptLast == line {
		return
	}
	if !c.transcriptStarted {
		_, _ = io.WriteString(c.output, "derpssh transcript\n")
		c.transcriptStarted = true
	}
	_, _ = io.WriteString(c.output, line+"\n")
	c.transcriptLast = line
}

func intString(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	n := v
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func (c *tuiConsole) markHarnessStarted(ctx context.Context) {
	c.harnessMu.Lock()
	defer c.harnessMu.Unlock()
	c.harnessStarted = true
	c.harnessCtx = ctx
	c.startHarnessActionsLocked()
}

func (c *tuiConsole) markHarnessCallbacksSet() {
	c.harnessMu.Lock()
	defer c.harnessMu.Unlock()
	c.harnessCallbacksSet = true
	c.startHarnessActionsLocked()
}

func (c *tuiConsole) startHarnessActionsLocked() {
	if !c.harnessStarted || !c.harnessCallbacksSet || c.harnessCtx == nil {
		return
	}
	ctx := c.harnessCtx
	c.harnessOnce.Do(func() {
		go c.runHarnessActions(ctx)
	})
}

func (c *tuiConsole) runHarnessActions(ctx context.Context) {
	if !testHarnessEnabled() {
		return
	}
	raw := ""
	switch c.mode {
	case tui.ModeHost:
		raw = testHarnessEnv("DERPSSH_TEST_HOST_ACTIONS")
	case tui.ModeGuest:
		raw = testHarnessEnv("DERPSSH_TEST_GUEST_ACTIONS")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	for _, line := range strings.Split(raw, "\n") {
		if ctx.Err() != nil {
			return
		}
		c.runHarnessAction(ctx, strings.TrimSpace(line))
	}
}

func (c *tuiConsole) runHarnessAction(ctx context.Context, line string) {
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	name, arg, _ := strings.Cut(line, " ")
	handler := harnessActionHandlers[strings.ToLower(strings.TrimSpace(name))]
	if handler == nil {
		return
	}
	handler(c, ctx, arg)
}

func runHarnessInputAction(c *tuiConsole, ctx context.Context, arg string) {
	c.handleCommand(ctx, tui.TerminalInputCommand{Data: []byte(unescapeHarnessAction(arg))})
}

func runHarnessChatAction(c *tuiConsole, ctx context.Context, arg string) {
	c.handleCommand(ctx, tui.ChatSendCommand{Body: strings.TrimSpace(arg)})
}

func runHarnessRoleAction(c *tuiConsole, ctx context.Context, arg string) {
	fields := strings.Fields(arg)
	if len(fields) < 2 {
		return
	}
	role := tui.Role(fields[1])
	if _, ok := protocolRoleFromTUI(role); !ok {
		return
	}
	c.handleCommand(ctx, tui.RoleChangeCommand{PeerID: fields[0], Role: role})
}

func runHarnessKickAction(c *tuiConsole, ctx context.Context, arg string) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return
	}
	c.handleCommand(ctx, tui.KickCommand{PeerID: fields[0]})
}

func runHarnessQuitAction(c *tuiConsole, ctx context.Context, _ string) {
	c.handleCommand(ctx, tui.QuitCommand{})
}

func runHarnessSleepAction(_ *tuiConsole, ctx context.Context, arg string) {
	sleepHarnessAction(ctx, arg)
}

func sleepHarnessAction(ctx context.Context, raw string) {
	d, ok := parseHarnessSleepDuration(raw)
	if !ok {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func parseHarnessSleepDuration(raw string) (time.Duration, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = "1s"
	}
	if d, err := time.ParseDuration(value); err == nil {
		return d, true
	}
	if isBareDurationNumber(value) {
		if d, err := time.ParseDuration(value + "s"); err == nil {
			return d, true
		}
	}
	return 0, false
}

func isBareDurationNumber(value string) bool {
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

func unescapeHarnessAction(raw string) string {
	var b strings.Builder
	escaped := false
	for _, r := range raw {
		if escaped {
			switch r {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\':
				b.WriteByte('\\')
			default:
				b.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}

func (c *tuiConsole) isProgramStartRequested() bool {
	c.programMu.Lock()
	defer c.programMu.Unlock()
	return c.programStartRequested
}

func (c *tuiConsole) runTeaCommand(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	go func() {
		if msg := cmd(); msg != nil {
			c.send(msg)
		}
	}()
}

func (c *tuiConsole) setPeerLocked(id, name string, role protocol.Role) {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	if id == "" {
		id = name
	}
	if id == "" {
		return
	}
	if existing, ok := c.peers[id]; ok {
		if name == "" {
			name = existing.Name
		}
	} else {
		c.peerOrder = append(c.peerOrder, id)
	}
	name = displayNameOrID(name, id)
	c.peers[id] = tui.Peer{ID: id, Name: name, Role: tuiRoleFromProtocol(role)}
}

func (c *tuiConsole) clearPeersLocked() {
	clear(c.peers)
	c.peerOrder = nil
}

func (c *tuiConsole) runtimeStateLocked() tui.RuntimeStateMsg {
	peers := make([]tui.Peer, 0, len(c.peerOrder))
	for _, id := range c.peerOrder {
		peer, ok := c.peers[id]
		if ok {
			peers = append(peers, peer)
		}
	}
	return tui.RuntimeStateMsg{
		Transport: c.transport,
		HostCols:  c.hostCols,
		HostRows:  c.hostRows,
		LocalRole: c.localRole,
		Peers:     peers,
	}
}

func displayNameOrID(name, id string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	return strings.TrimSpace(id)
}

func tuiRoleFromProtocol(role protocol.Role) tui.Role {
	if role == "" {
		return tui.RolePending
	}
	return tui.Role(role)
}

func protocolRoleFromTUI(role tui.Role) (protocol.Role, bool) {
	switch role {
	case tui.RoleRead:
		return protocol.RoleRead, true
	case tui.RoleWrite:
		return protocol.RoleWrite, true
	default:
		return "", false
	}
}

func envApprovalRole() (protocol.Role, bool) {
	switch strings.ToLower(strings.TrimSpace(testHarnessEnv("DERPSSH_TEST_AUTO_APPROVE"))) {
	case "read":
		return protocol.RoleRead, true
	case "write":
		return protocol.RoleWrite, true
	case "deny":
		return protocol.RoleDenied, true
	default:
		return "", false
	}
}

func testHarnessEnv(name string) string {
	if !testHarnessEnabled() {
		return ""
	}
	return os.Getenv(name)
}

func testHarnessEnabled() bool {
	return strings.TrimSpace(os.Getenv("DERPSSH_TEST_HARNESS")) == "1"
}

func approvalKey(peerID, peer string) string {
	if id := strings.TrimSpace(peerID); id != "" {
		return id
	}
	return strings.TrimSpace(peer)
}

func readApprovalLine(r io.Reader) (string, error) {
	if r == nil {
		return "", io.EOF
	}
	var b strings.Builder
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n > 0 {
			b.WriteByte(one[0])
			if one[0] == '\n' {
				return b.String(), nil
			}
		}
		if err != nil {
			return b.String(), err
		}
	}
}
