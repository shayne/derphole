// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

type Options struct {
	Side          string
	DisplayName   string
	InviteCommand string
	Terminal      TerminalPane
}

type App struct {
	side          string
	displayName   string
	inviteCommand string
	terminal      TerminalPane
	commands      chan Command
	commandMu     sync.Mutex
	commandQueue  []Command
	commandPump   bool

	width          int
	height         int
	layout         Layout
	sidebarOpen    bool
	focus          Focus
	prefix         bool
	helpOpen       bool
	approvalPeerID string
	approvalPeer   string
	kickPeerID     string
	kickPeer       string

	localRole    Role
	transport    string
	hostCols     int
	hostRows     int
	peers        []Peer
	chatMessages []ChatMessage
	composer     textarea.Model
}

func NewApp(opts Options) *App {
	side := strings.TrimSpace(opts.Side)
	if side == "" {
		side = string(ModeGuest)
	}
	terminal := opts.Terminal
	if terminal == nil {
		terminal = NewVTTerminalPane(80, 24)
	}

	composer := textarea.New()
	composer.Prompt = ""
	composer.Placeholder = "Message"
	composer.ShowLineNumbers = false
	composer.CharLimit = 4096
	composer.SetHeight(3)

	app := &App{
		side:          side,
		displayName:   opts.DisplayName,
		inviteCommand: opts.InviteCommand,
		terminal:      terminal,
		commands:      make(chan Command, 64),
		width:         80,
		height:        24,
		sidebarOpen:   true,
		focus:         FocusTerminal,
		localRole:     RolePending,
		transport:     "starting",
		composer:      composer,
	}
	app.applyLayout()
	return app
}

func (a *App) Init() tea.Cmd {
	return nil
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.resize(msg.Width, msg.Height, true)
	case TerminalDataMsg:
		_, _ = a.terminal.Write([]byte(msg))
	case RuntimeStateMsg:
		a.transport = valueOr(msg.Transport, a.transport)
		a.hostCols = msg.HostCols
		a.hostRows = msg.HostRows
		if msg.LocalRole != "" {
			a.localRole = msg.LocalRole
		}
		a.peers = append([]Peer(nil), msg.Peers...)
	case ChatMsg:
		a.chatMessages = append(a.chatMessages, ChatMessage(msg))
	case ApprovalRequestMsg:
		a.approvalPeerID = strings.TrimSpace(msg.PeerID)
		a.approvalPeer = strings.TrimSpace(valueOr(msg.Peer, msg.PeerID))
		if a.approvalActive() {
			a.focus = FocusApproval
		}
	case tea.KeyMsg:
		return a, a.handleKey(msg)
	case tea.MouseMsg:
		return a, HandleMouse(a, msg)
	}
	return a, nil
}

func (a *App) View() string {
	if a.width <= 0 || a.height <= 0 {
		return ""
	}
	a.applyLayout()

	lines := a.baseViewLines()
	a.applyOverlays(lines)
	return a.joinFittedLines(lines)
}

func (a *App) baseViewLines() []string {
	lines := make([]string, a.height)
	lines[0] = fitLine(topBarStyle.Width(a.width).Render(a.topBar()), a.width)
	if a.height == 1 {
		return lines
	}

	content := a.contentLines()
	for i := 0; i < a.layout.Terminal.H && i < len(content) && i+1 < a.height-1; i++ {
		lines[i+1] = content[i]
	}
	lines[a.height-1] = fitLine(statusBarStyle.Width(a.width).Render(a.statusBar()), a.width)
	return lines
}

func (a *App) applyOverlays(lines []string) {
	if a.helpOpen {
		a.overlay(lines, a.helpLines())
	}
	if a.kickPeer != "" {
		a.overlay(lines, []string{
			"Kick " + a.kickPeer + "?",
			"Enter confirms. Esc cancels.",
		})
	}
	if a.approvalActive() {
		a.overlay(lines, a.approvalLines())
	}
}

func (a *App) joinFittedLines(lines []string) string {
	for i := range lines {
		lines[i] = fitLine(lines[i], a.width)
	}
	return strings.Join(lines, "\n")
}

func (a *App) Commands() <-chan Command {
	return a.commands
}

func (a *App) SetWindowSize(cols int, rows int) {
	a.resize(cols, rows, false)
}

func (a *App) TerminalSize() (int, int) {
	a.applyLayout()
	return a.layout.Terminal.W, a.layout.Terminal.H
}

func (a *App) resize(cols int, rows int, emitResize bool) {
	oldTerminal := a.layout.Terminal
	if cols > 0 {
		a.width = cols
	}
	if rows > 0 {
		a.height = rows
	}
	a.applyLayout()
	if emitResize {
		a.emitTerminalResizeIfChanged(oldTerminal)
	}
}

func (a *App) applyLayout() {
	a.layout = ComputeLayout(a.width, a.height, a.sidebarOpen)
	if !a.layout.Terminal.empty() {
		a.terminal.Resize(a.layout.Terminal.W, a.layout.Terminal.H)
	}
	if !a.layout.Composer.empty() {
		a.composer.SetWidth(a.layout.Composer.W)
		a.composer.SetHeight(a.layout.Composer.H)
	}
}

func (a *App) setSidebarOpen(open bool) {
	oldTerminal := a.layout.Terminal
	a.sidebarOpen = open
	a.applyLayout()
	a.emitTerminalResizeIfChanged(oldTerminal)
}

func (a *App) emitTerminalResizeIfChanged(oldTerminal Rect) {
	nextTerminal := a.layout.Terminal
	if nextTerminal.empty() {
		return
	}
	if oldTerminal.W == nextTerminal.W && oldTerminal.H == nextTerminal.H {
		return
	}
	a.emit(TerminalResizeCommand{Cols: nextTerminal.W, Rows: nextTerminal.H})
}

func (a *App) handleKey(msg tea.KeyMsg) tea.Cmd {
	if a.handleEscapeKey(msg) {
		return nil
	}
	if a.helpOpen {
		return nil
	}
	if a.approvalActive() {
		if a.prefix {
			return HandlePrefixKey(a, msg)
		}
		if msg.Type == tea.KeyCtrlX {
			a.prefix = true
		}
		return nil
	}
	if a.kickPeer != "" {
		return a.handleKickOverlayKey(msg)
	}
	if a.prefix {
		return HandlePrefixKey(a, msg)
	}
	if msg.Type == tea.KeyCtrlX {
		a.prefix = true
		return nil
	}

	if a.focus == FocusChat {
		return a.handleChatKey(msg)
	}

	return a.handleTerminalKey(msg)
}

func (a *App) handleEscapeKey(msg tea.KeyMsg) bool {
	if msg.Type != tea.KeyEsc {
		return false
	}
	switch {
	case a.approvalActive():
		a.approve("", true)
	case a.prefix:
		a.prefix = false
	case a.helpOpen:
		a.helpOpen = false
	case a.kickPeer != "":
		a.kickPeerID = ""
		a.kickPeer = ""
		a.focusTerminal()
	case a.focus == FocusChat:
		a.focusTerminal()
	default:
		return false
	}
	return true
}

func (a *App) handleKickOverlayKey(msg tea.KeyMsg) tea.Cmd {
	if msg.Type == tea.KeyEnter {
		a.emit(KickCommand{PeerID: a.kickPeerID, Peer: a.kickPeer})
		a.kickPeerID = ""
		a.kickPeer = ""
		a.focusTerminal()
	}
	return nil
}

func (a *App) handleChatKey(msg tea.KeyMsg) tea.Cmd {
	if msg.Type == tea.KeyEnter {
		body := strings.TrimSpace(a.composer.Value())
		if body != "" {
			a.emit(ChatSendCommand{Body: body})
			a.chatMessages = append(a.chatMessages, ChatMessage{Author: valueOr(a.displayName, "me"), Body: body, Local: true})
			a.composer.Reset()
		}
		return nil
	}
	var cmd tea.Cmd
	a.composer, cmd = a.composer.Update(msg)
	return cmd
}

func (a *App) handleTerminalKey(msg tea.KeyMsg) tea.Cmd {
	if data, ok := EncodeTerminalKey(msg); ok {
		a.emit(TerminalInputCommand{Data: data})
	}
	return nil
}

func (a *App) topBar() string {
	var parts []string
	parts = append(parts, "derpssh", a.side)
	if a.displayName != "" {
		parts = append(parts, a.displayName)
	}
	if a.hostCols > 0 && a.hostRows > 0 {
		parts = append(parts, fmt.Sprintf("host %dx%d", a.hostCols, a.hostRows))
	}
	if a.localRole != "" && a.localRole != RolePending {
		parts = append(parts, "role "+string(a.localRole))
	}
	parts = append(parts, valueOr(a.transport, "starting"))
	if len(a.peers) > 0 {
		parts = append(parts, "peer "+peerSummary(a.peers))
	}
	if a.inviteCommand != "" {
		parts = append(parts, "Invite ready")
	}
	if a.sidebarOpen {
		parts = append(parts, "sidechat open")
	} else {
		parts = append(parts, "sidechat hidden")
	}
	return strings.Join(parts, " | ")
}

func (a *App) contentLines() []string {
	if !a.sidebarOpen || a.layout.Sidebar.empty() {
		return padLines(splitAndFit(a.terminal.View(a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.H, a.layout.Terminal.W)
	}

	terminalLines := padLines(splitAndFit(a.terminal.View(a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.H, a.layout.Terminal.W)
	sidebarLines := a.sidebarLines(a.layout.Sidebar.W, a.layout.Sidebar.H)
	lines := make([]string, a.layout.Terminal.H)
	for i := range lines {
		lines[i] = fitLine(terminalLines[i], a.layout.Terminal.W) + fitLine(sidebarLines[i], a.layout.Sidebar.W)
	}
	return lines
}

func (a *App) sidebarLines(width int, height int) []string {
	lines := make([]string, height)
	if height <= 0 || width <= 0 {
		return lines
	}
	contentW := sidebarContentWidth(width)
	content := make([]string, height)
	a.writeSidebarHeader(content, contentW)
	a.writeSidebarMessages(content, contentW, height)
	a.writeSidebarComposer(content, contentW, height)
	for i := range lines {
		lines[i] = fitLine(separatorStyle.Render(" ")+sidebarStyle.Render(fitLine(content[i], contentW)), width)
	}
	return lines
}

func sidebarContentWidth(width int) int {
	return nonNegative(width - 1)
}

func (a *App) writeSidebarHeader(content []string, width int) {
	if len(content) == 0 {
		return
	}
	content[0] = fitLine(labelStyle.Render("Sidechat")+" "+dimStyle.Render("Ctrl-X C"), width)
}

func (a *App) writeSidebarMessages(content []string, width int, height int) {
	row := 1
	for _, msg := range a.chatMessages {
		if row >= height-3 {
			return
		}
		content[row] = fitLine(renderChatMessage(msg), width)
		row++
	}
}

func renderChatMessage(msg ChatMessage) string {
	prefix := strings.TrimSpace(msg.Author)
	body := msg.Body
	if prefix != "" && !strings.HasPrefix(body, prefix+":") {
		body = prefix + ": " + body
	}
	if msg.Local {
		body = localChatStyle.Render(body)
	}
	return body
}

func (a *App) writeSidebarComposer(content []string, width int, height int) {
	if height < 4 {
		return
	}
	content[height-3] = fitLine(labelStyle.Render("Composer")+" "+dimStyle.Render("Enter sends"), width)
	composerLines := splitAndFit(a.composer.View(), width, 2)
	for i := 0; i < 2 && height-2+i < height; i++ {
		if i < len(composerLines) {
			content[height-2+i] = fitLine(composerLines[i], width)
		}
	}
}

func (a *App) statusBar() string {
	focus := "Terminal"
	if a.focus == FocusChat {
		focus = "Chat"
	}
	if a.focus == FocusApproval {
		focus = "Approval"
	}
	state := fmt.Sprintf("Status %s | Ctrl-X ? Help | Ctrl-X S Sidechat | Ctrl-X C Chat | Ctrl-X T Terminal | Ctrl-X R/W Role | Ctrl-X K Kick | Focus %s", valueOr(a.transport, "starting"), focus)
	if a.prefix {
		state = "Status prefix | S Sidechat | C Chat | T Terminal | ? Help"
	}
	return state
}

func (a *App) approvalLines() []string {
	return []string{
		"Approve " + a.approvalPeer,
		"approve " + a.approvalPeer + " access request",
		"Choose access for this guest.",
		"",
		" [Read]   [Write]   [Deny] ",
	}
}

func (a *App) helpLines() []string {
	return []string{
		"derpssh help",
		"Ctrl-X S toggles Sidechat",
		"Ctrl-X C focuses Chat",
		"Ctrl-X T focuses Terminal",
		"Ctrl-X R grants Read",
		"Ctrl-X W grants Write",
		"Ctrl-X K kicks peer",
		"Ctrl-X ? closes with Esc",
	}
}

func (a *App) overlay(lines []string, body []string) {
	if !a.canOverlay(lines) {
		return
	}
	box := strings.Split(modalStyle.Render(strings.Join(body, "\n")), "\n")
	boxW := a.overlayWidth(box)
	x := (a.width - boxW) / 2
	y := a.overlayY(len(box))
	for i, line := range box {
		row := y + i
		a.overlayLine(lines, row, x, line, boxW)
	}
}

func (a *App) canOverlay(lines []string) bool {
	return len(lines) > 0 && a.width > 0 && a.height > 0
}

func (a *App) overlayWidth(box []string) int {
	boxW := 0
	for _, line := range box {
		boxW = maxInt(boxW, displayWidth(line))
	}
	boxW = minInt(boxW, a.width-2)
	return maxInt(boxW, 1)
}

func (a *App) overlayY(boxH int) int {
	return maxInt((a.height-boxH)/2, 1)
}

func (a *App) overlayLine(lines []string, row int, x int, line string, width int) {
	if row < 0 || row >= len(lines) {
		return
	}
	prefix := fitLine(lines[row], x)
	lines[row] = prefix + fitLine(line, width)
}

func (a *App) approvalHit(x int, y int) HitTarget {
	read, write, deny := approvalButtonRects(a.layout)
	switch {
	case read.contains(x, y):
		return HitApprovalRead
	case write.contains(x, y):
		return HitApprovalWrite
	case deny.contains(x, y):
		return HitApprovalDeny
	default:
		return HitNone
	}
}

func (a *App) approvalActive() bool {
	return a.approvalPeer != "" || a.approvalPeerID != ""
}

func (a *App) approve(role Role, deny bool) {
	if !a.approvalActive() {
		return
	}
	a.emit(ApprovalDecisionCommand{PeerID: a.approvalPeerID, Peer: a.approvalPeer, Role: role, Deny: deny})
	a.approvalPeerID = ""
	a.approvalPeer = ""
	a.focusTerminal()
}

func (a *App) focusTerminal() {
	a.focus = FocusTerminal
	a.composer.Blur()
}

func (a *App) focusChat() {
	a.focus = FocusChat
	_ = a.composer.Focus()
}

func (a *App) changeFirstPeerRole(role Role) {
	if len(a.peers) == 0 {
		return
	}
	if role != RoleRead && role != RoleWrite {
		return
	}
	peer := a.peers[0]
	a.emit(RoleChangeCommand{PeerID: peer.ID, Peer: valueOr(peer.Name, peer.ID), Role: role})
}

func (a *App) emit(cmd Command) {
	a.commandMu.Lock()
	if len(a.commandQueue) > 0 || a.commandPump {
		a.commandQueue = append(a.commandQueue, cmd)
		if !a.commandPump {
			a.commandPump = true
			go a.pumpCommands()
		}
		a.commandMu.Unlock()
		return
	}
	a.commandMu.Unlock()

	select {
	case a.commands <- cmd:
		return
	default:
	}
	a.commandMu.Lock()
	a.commandQueue = append(a.commandQueue, cmd)
	if !a.commandPump {
		a.commandPump = true
		go a.pumpCommands()
	}
	a.commandMu.Unlock()
}

func (a *App) pumpCommands() {
	for {
		a.commandMu.Lock()
		if len(a.commandQueue) == 0 {
			a.commandPump = false
			a.commandMu.Unlock()
			return
		}
		cmd := a.commandQueue[0]
		a.commandQueue[0] = nil
		a.commandQueue = a.commandQueue[1:]
		a.commandMu.Unlock()

		a.commands <- cmd
	}
}

func approvalButtonRects(l Layout) (Rect, Rect, Rect) {
	w := 44
	if l.Outer.W > 0 && w > l.Outer.W-4 {
		w = l.Outer.W - 4
	}
	if w < 1 {
		w = 1
	}
	h := 9
	x := (l.Outer.W - w) / 2
	y := (l.Outer.H - h) / 2
	if y < 1 {
		y = 1
	}
	return Rect{X: x + 10, Y: y + 7, W: 8, H: 1},
		Rect{X: x + 20, Y: y + 7, W: 9, H: 1},
		Rect{X: x + 31, Y: y + 7, W: 8, H: 1}
}

func peerSummary(peers []Peer) string {
	parts := make([]string, 0, len(peers))
	for _, peer := range peers {
		if strings.TrimSpace(peer.Name) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s/%s", peer.Name, peer.Role))
	}
	return strings.Join(parts, ", ")
}

func splitAndFit(s string, width int, height int) []string {
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	lines := make([]string, 0, height)
	for _, line := range raw {
		if len(lines) >= height {
			break
		}
		lines = append(lines, fitLine(line, width))
	}
	return padLines(lines, height, width)
}

func padLines(lines []string, height int, width int) []string {
	for len(lines) < height {
		lines = append(lines, "")
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = fitLine(lines[i], width)
	}
	return lines
}

func fitLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	fitted := ansi.Truncate(s, width, "")
	used := ansi.StringWidth(fitted)
	if used < width {
		fitted += strings.Repeat(" ", width-used)
	}
	return fitted
}

func displayWidth(s string) int {
	return ansi.StringWidth(s)
}

func valueOr(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
