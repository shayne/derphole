// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"os"
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

type approvalChoice int

const (
	approvalChoiceRead approvalChoice = iota
	approvalChoiceWrite
	approvalChoiceDeny
)

var approvalChoiceOrder = []approvalChoice{
	approvalChoiceRead,
	approvalChoiceWrite,
	approvalChoiceDeny,
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

	width           int
	height          int
	layout          Layout
	sidebarOpen     bool
	sidebarWidth    int
	draggingDivider bool
	focus           Focus
	prefix          bool
	copyMode        bool
	helpOpen        bool
	approvalPeerID  string
	approvalPeer    string
	approvalChoice  approvalChoice
	kickPeerID      string
	kickPeer        string
	inviteOpen      bool

	localRole    Role
	transport    string
	hostCols     int
	hostRows     int
	peers        []Peer
	chatMessages []ChatMessage
	chatScroll   int
	unreadChat   int
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
	composer.SetHeight(1)

	app := &App{
		side:          side,
		displayName:   opts.DisplayName,
		inviteCommand: opts.InviteCommand,
		terminal:      terminal,
		commands:      make(chan Command, 64),
		width:         80,
		height:        24,
		sidebarOpen:   false,
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
		a.appendChatMessage(ChatMessage(msg))
	case ApprovalRequestMsg:
		a.approvalPeerID = strings.TrimSpace(msg.PeerID)
		a.approvalPeer = strings.TrimSpace(valueOr(msg.Peer, msg.PeerID))
		if a.approvalActive() {
			a.focus = FocusApproval
			a.approvalChoice = approvalChoiceWrite
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
	if a.inviteOpen {
		return a.inviteView()
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
	for i := 0; i < len(content) && i+1 < a.height; i++ {
		lines[i+1] = content[i]
	}
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
	a.layout = ComputeLayoutWithSidebarWidth(a.width, a.height, a.sidebarOpen, a.sidebarWidth)
	if a.layout.SidebarOpen && a.layout.Sidebar.W > 0 {
		a.sidebarWidth = a.layout.Sidebar.W
	}
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
	if open {
		a.unreadChat = 0
	}
	a.applyLayout()
	a.emitTerminalResizeIfChanged(oldTerminal)
}

func (a *App) setSidebarWidth(width int) {
	oldTerminal := a.layout.Terminal
	a.sidebarWidth = clampSidebarWidth(a.width, width)
	a.sidebarOpen = true
	a.unreadChat = 0
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
	if a.inviteOpen {
		return a.handleInviteKey(msg)
	}
	if a.handleEscapeKey(msg) {
		return nil
	}
	if cmd, handled := a.handleHelpKey(msg); handled {
		return cmd
	}
	if cmd, handled := a.handleApprovalKey(msg); handled {
		return cmd
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

func (a *App) handleHelpKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	if !a.helpOpen {
		return nil, false
	}
	if a.prefix {
		return HandlePrefixKey(a, msg), true
	}
	if msg.Type == tea.KeyCtrlX {
		a.prefix = true
	}
	return nil, true
}

func (a *App) handleApprovalKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	if !a.approvalActive() {
		return nil, false
	}
	if a.prefix {
		return HandlePrefixKey(a, msg), true
	}
	if msg.Type == tea.KeyCtrlX {
		a.prefix = true
		return nil, true
	}
	switch msg.Type {
	case tea.KeyEnter, tea.KeySpace:
		a.approveSelected()
	case tea.KeyTab, tea.KeyRight, tea.KeyDown:
		a.moveApprovalChoice(1)
	case tea.KeyShiftTab, tea.KeyLeft, tea.KeyUp:
		a.moveApprovalChoice(-1)
	}
	return nil, true
}

func (a *App) handleInviteKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case msg.Type == tea.KeyEsc || msg.Type == tea.KeyEnter:
		a.inviteOpen = false
		if !a.copyMode {
			return tea.EnableMouseCellMotion
		}
	case msg.Type == tea.KeyRunes && strings.EqualFold(string(msg.Runes), "q"):
		a.emit(QuitCommand{})
	default:
		return nil
	}
	return nil
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
			a.appendChatMessage(ChatMessage{Author: a.localDisplayName(), Body: body, Local: true})
			a.composer.Reset()
		}
		return nil
	}
	var cmd tea.Cmd
	a.composer, cmd = a.composer.Update(msg)
	return cmd
}

func (a *App) appendChatMessage(msg ChatMessage) {
	if a.isLocalEcho(msg) {
		return
	}
	a.chatMessages = append(a.chatMessages, msg)
	if msg.Local {
		a.chatScroll = 0
	}
	if !a.sidebarOpen && !msg.Local {
		a.unreadChat++
	}
}

func (a *App) isLocalEcho(msg ChatMessage) bool {
	if msg.Local {
		return false
	}
	author := strings.TrimSpace(msg.Author)
	body := strings.TrimSpace(msg.Body)
	if author == "" || body == "" {
		return false
	}
	for i := len(a.chatMessages) - 1; i >= 0; i-- {
		existing := a.chatMessages[i]
		if !existing.Local {
			continue
		}
		if strings.TrimSpace(existing.Author) == author && strings.TrimSpace(existing.Body) == body {
			a.chatMessages[i].Local = false
			return true
		}
	}
	return false
}

func (a *App) handleTerminalKey(msg tea.KeyMsg) tea.Cmd {
	if data, ok := EncodeTerminalKeyWithMode(msg, a.terminal.InputMode()); ok {
		a.emit(TerminalInputCommand{Data: data})
	}
	return nil
}

func (a *App) topBar() string {
	return strings.Join(a.topBarSegments(), " | ")
}

func (a *App) topBarSegments() []string {
	parts := []string{"derpssh"}
	parts = append(parts, a.identityTopBarSegments()...)
	parts = append(parts, a.stateTopBarSegments()...)
	parts = append(parts, a.chatTopBarSegments()...)
	parts = append(parts, a.actionTopBarSegments()...)
	return parts
}

func (a *App) identityTopBarSegments() []string {
	var parts []string
	if side := strings.TrimSpace(a.side); side != "" {
		parts = append(parts, side)
	}
	if name := a.displayHandle(a.displayName, 18); name != "" {
		parts = append(parts, name)
	}
	return parts
}

func (a *App) stateTopBarSegments() []string {
	var parts []string
	if a.hostCols > 0 && a.hostRows > 0 {
		parts = append(parts, fmt.Sprintf("%dx%d", a.hostCols, a.hostRows))
	}
	if a.localRole != "" && a.localRole != RolePending {
		parts = append(parts, string(a.localRole))
	}
	if transport := compactTransportStatus(a.transport); transport != "" {
		parts = append(parts, transport)
	}
	if len(a.peers) > 0 {
		parts = append(parts, peerSummary(a.peers, a.identityCounts()))
	}
	if a.approvalActive() {
		parts = append(parts, "approve "+a.displayHandle(a.approvalPeer, 18))
	}
	return parts
}

func (a *App) chatTopBarSegments() []string {
	if a.sidebarOpen {
		return []string{"chat"}
	}
	if a.unreadChat > 0 {
		return []string{fmt.Sprintf("%d new Ctrl-X S", a.unreadChat)}
	}
	return nil
}

func (a *App) actionTopBarSegments() []string {
	if a.copyMode {
		return []string{"select mode", "Ctrl-X actions", "? help"}
	}
	if a.prefix {
		return []string{"S chat I invite Y select Q quit"}
	}
	return []string{"Ctrl-X actions", "? help"}
}

func (a *App) localDisplayName() string {
	if name := strings.TrimSpace(a.displayName); name != "" {
		return name
	}
	if name := strings.TrimSpace(os.Getenv("USER")); name != "" {
		return name
	}
	if side := strings.TrimSpace(a.side); side != "" {
		return side
	}
	return "local"
}

func (a *App) contentLines() []string {
	a.setTerminalCursorActive(a.focus == FocusTerminal && !a.copyMode)
	if !a.sidebarOpen || a.layout.Sidebar.empty() {
		return padLines(splitAndFit(a.terminal.View(a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.H, a.layout.Terminal.W)
	}

	terminalLines := padLines(splitAndFit(a.terminal.View(a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.W, a.layout.Terminal.H), a.layout.Terminal.H, a.layout.Terminal.W)
	sidebarLines := a.sidebarLines(a.layout.Sidebar.W, a.layout.Sidebar.H)
	lines := make([]string, a.layout.Terminal.H)
	for i := range lines {
		divider := separatorStyle.Render(" ")
		lines[i] = fitLine(terminalLines[i], a.layout.Terminal.W) + fitLine(divider, a.layout.Divider.W) + fitLine(sidebarLines[i], a.layout.Sidebar.W)
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
	messageStart := 1
	a.writeSidebarMessages(content, contentW, height, messageStart)
	a.writeSidebarComposer(content, contentW, height)
	for i := range lines {
		lines[i] = fitLine(sidebarStyle.Render(fitLine(content[i], contentW)), width)
	}
	return lines
}

func sidebarContentWidth(width int) int {
	return nonNegative(width)
}

func (a *App) writeSidebarHeader(content []string, width int) {
	if len(content) == 0 {
		return
	}
	content[0] = fitLine(labelStyle.Render("Chat"), width)
}

func (a *App) writeSidebarMessages(content []string, width int, height int, row int) {
	messageRows := a.chatRenderLines(width)
	available := maxInt(0, height-a.layout.Composer.H-row)
	start := chatWindowStart(len(messageRows), available, a.chatScroll)
	for _, line := range messageRows[start:minInt(start+available, len(messageRows))] {
		if row >= height-a.layout.Composer.H {
			return
		}
		content[row] = fitLine(line, width)
		row++
	}
}

func (a *App) chatRenderLines(width int) []string {
	counts := a.identityCounts()
	lines := make([]string, 0, len(a.chatMessages))
	for _, msg := range a.chatMessages {
		lines = append(lines, a.renderChatMessageLines(msg, width, counts)...)
	}
	return lines
}

func (a *App) renderChatMessageLines(msg ChatMessage, width int, counts map[string]int) []string {
	prefix := a.displayHandleWithCounts(msg.Author, 16, counts)
	body := msg.Body
	if prefix != "" && !strings.HasPrefix(body, prefix+":") {
		body = prefix + ": " + body
	}
	wrapped := wrapPlainLines(body, width)
	if msg.Local {
		for i := range wrapped {
			wrapped[i] = localChatStyle.Render(wrapped[i])
		}
	}
	return wrapped
}

func wrapPlainLines(s string, width int) []string {
	width = maxInt(width, 1)
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		wrapped := ansi.Wrap(line, width, " ")
		parts := strings.Split(wrapped, "\n")
		if len(parts) == 0 {
			out = append(out, "")
			continue
		}
		out = append(out, parts...)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func chatWindowStart(total int, available int, scroll int) int {
	if available <= 0 || total <= available {
		return 0
	}
	maxStart := total - available
	if scroll < 0 {
		scroll = 0
	}
	if scroll > maxStart {
		scroll = maxStart
	}
	return maxStart - scroll
}

func (a *App) writeSidebarComposer(content []string, width int, height int) {
	if height < 2 {
		return
	}
	composerLines := splitAndFit(a.composer.View(), width, 1)
	for i := 0; i < 1 && height-1+i < height; i++ {
		if i < len(composerLines) {
			content[height-1+i] = fitLine(composerLines[i], width)
		}
	}
}

func (a *App) approvalLines() []string {
	width := a.approvalContentWidth()
	return []string{
		fitLine(labelStyle.Render(a.approvalPeer+" wants to join"), width),
		fitLine(dimStyle.Render("Select access, then press Enter."), width),
		"",
		a.approvalButtonLine(width),
	}
}

func (a *App) helpLines() []string {
	return []string{
		"derpssh help",
		"Ctrl-X S toggles Chat",
		"Ctrl-X C focuses Chat",
		"Ctrl-X T focuses Terminal",
		"Ctrl-X I shows Invite",
		"Ctrl-X Y toggles native selection",
		"Ctrl-X Left/Right resizes Chat",
		"Ctrl-X Q quits",
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
	read, write, deny := a.approvalButtonRects()
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

func (a *App) approvalButtonRects() (Rect, Rect, Rect) {
	contentW := a.approvalContentWidth()
	contentX, contentY := a.approvalContentOrigin()
	buttonLineW := approvalButtonsWidth()
	startX := contentX + maxInt((contentW-buttonLineW)/2, 0)
	y := contentY + approvalButtonLineIndex

	read := Rect{X: startX, Y: y, W: approvalButtonWidth(approvalChoiceRead), H: 1}
	write := Rect{X: read.X + read.W + approvalButtonGap, Y: y, W: approvalButtonWidth(approvalChoiceWrite), H: 1}
	deny := Rect{X: write.X + write.W + approvalButtonGap, Y: y, W: approvalButtonWidth(approvalChoiceDeny), H: 1}
	return read, write, deny
}

func (a *App) approvalContentOrigin() (int, int) {
	box := strings.Split(modalStyle.Render(strings.Join(a.approvalLines(), "\n")), "\n")
	boxW := a.overlayWidth(box)
	boxX := (a.width - boxW) / 2
	boxY := a.overlayY(len(box))
	return boxX + modalStyle.GetBorderLeftSize() + modalStyle.GetPaddingLeft(),
		boxY + modalStyle.GetBorderTopSize() + modalStyle.GetPaddingTop()
}

func (a *App) approvalContentWidth() int {
	width := maxInt(42, displayWidth(a.approvalPeer+" wants to join"))
	width = maxInt(width, displayWidth("Select access, then press Enter."))
	width = maxInt(width, approvalButtonsWidth())
	if a.width > 0 {
		maxWidth := a.width - modalStyle.GetHorizontalBorderSize() - modalStyle.GetHorizontalPadding() - 2
		width = minInt(width, maxInt(maxWidth, 1))
	}
	return maxInt(width, 1)
}

func (a *App) approvalButtonLine(width int) string {
	lineW := approvalButtonsWidth()
	pad := strings.Repeat(" ", maxInt((width-lineW)/2, 0))
	parts := []string{
		a.renderApprovalButton(approvalChoiceRead),
		a.renderApprovalButton(approvalChoiceWrite),
		a.renderApprovalButton(approvalChoiceDeny),
	}
	return fitLine(pad+strings.Join(parts, strings.Repeat(" ", approvalButtonGap)), width)
}

func (a *App) renderApprovalButton(choice approvalChoice) string {
	text := approvalButtonText(choice)
	if a.approvalChoice == choice {
		return approvalButtonSelectedStyle.Render(text)
	}
	return approvalButtonStyle.Render(text)
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
	a.approvalChoice = approvalChoiceWrite
	a.focusTerminal()
}

func (a *App) approveSelected() {
	switch a.approvalChoice {
	case approvalChoiceRead:
		a.approve(RoleRead, false)
	case approvalChoiceWrite:
		a.approve(RoleWrite, false)
	case approvalChoiceDeny:
		a.approve("", true)
	}
}

func (a *App) moveApprovalChoice(delta int) {
	idx := 0
	for i, choice := range approvalChoiceOrder {
		if choice == a.approvalChoice {
			idx = i
			break
		}
	}
	next := (idx + delta) % len(approvalChoiceOrder)
	if next < 0 {
		next += len(approvalChoiceOrder)
	}
	a.approvalChoice = approvalChoiceOrder[next]
}

func (a *App) focusTerminal() {
	a.focus = FocusTerminal
	a.composer.Blur()
}

func (a *App) focusChat() {
	a.focus = FocusChat
	_ = a.composer.Focus()
	a.unreadChat = 0
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

func (a *App) openInvite() tea.Cmd {
	if strings.TrimSpace(a.inviteCommand) == "" {
		return nil
	}
	a.inviteOpen = true
	return tea.DisableMouse
}

type terminalCursorController interface {
	SetCursorActive(active bool)
}

func (a *App) setTerminalCursorActive(active bool) {
	if cursor, ok := a.terminal.(terminalCursorController); ok {
		cursor.SetCursorActive(active)
	}
}

func (a *App) inviteView() string {
	width := maxInt(a.width, 1)
	command := strings.TrimSpace(a.inviteCommand)
	lines := []string{
		"derpssh invite",
		"",
	}
	lines = append(lines, wrapPlainLines("Copy this command and send it to the other person:", width)...)
	lines = append(lines, "", command, "")
	lines = append(lines, wrapPlainLines("Press Enter or Esc to return. Press q to quit.", width)...)
	if a.height <= 0 {
		return strings.Join(lines, "\n")
	}
	padded := make([]string, 0, a.height)
	padded = append(padded, lines...)
	for len(padded) < a.height {
		padded = append(padded, "")
	}
	if len(padded) > a.height {
		padded = padded[:a.height]
	}
	return strings.Join(padded, "\n")
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

const (
	approvalButtonGap       = 3
	approvalButtonLineIndex = 3
)

func approvalButtonsWidth() int {
	return approvalButtonWidth(approvalChoiceRead) +
		approvalButtonWidth(approvalChoiceWrite) +
		approvalButtonWidth(approvalChoiceDeny) +
		approvalButtonGap*2
}

func approvalButtonWidth(choice approvalChoice) int {
	return displayWidth(approvalButtonText(choice))
}

func approvalButtonText(choice approvalChoice) string {
	switch choice {
	case approvalChoiceRead:
		return " Read "
	case approvalChoiceWrite:
		return " Write "
	case approvalChoiceDeny:
		return " Deny "
	default:
		return "      "
	}
}

func (a *App) identityCounts() map[string]int {
	return identityCounts(a.displayName, a.peers, a.chatMessages)
}

func identityCounts(local string, peers []Peer, messages []ChatMessage) map[string]int {
	counts := make(map[string]int)
	seen := make(map[string]map[string]struct{})
	add := func(name string) {
		user, _ := splitUserHost(name)
		if user != "" {
			if seen[user] == nil {
				seen[user] = make(map[string]struct{})
			}
			seen[user][strings.TrimSpace(name)] = struct{}{}
			counts[user] = len(seen[user])
		}
	}
	add(local)
	for _, peer := range peers {
		add(peer.Name)
	}
	for _, msg := range messages {
		add(msg.Author)
	}
	return counts
}

func (a *App) displayHandle(name string, maxWidth int) string {
	return a.displayHandleWithCounts(name, maxWidth, a.identityCounts())
}

func (a *App) displayHandleWithCounts(name string, maxWidth int, counts map[string]int) string {
	return displayHandleWithCounts(name, maxWidth, counts)
}

func displayHandleWithCounts(name string, maxWidth int, counts map[string]int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	user, host := splitUserHost(name)
	out := name
	if user != "" {
		out = user
		if host != "" && counts[user] > 1 {
			out = user + "@" + compactHost(host)
		}
	}
	if maxWidth > 0 {
		out = ansi.Truncate(out, maxWidth, "...")
	}
	return out
}

func splitUserHost(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}
	user, host, ok := strings.Cut(name, "@")
	if !ok {
		return name, ""
	}
	return strings.TrimSpace(user), strings.TrimSpace(host)
}

func compactHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".local")
	return host
}

func compactTransportStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "starting"
	}
	if compact, ok := compactTransportStatuses[status]; ok {
		return compact
	}
	return status
}

var compactTransportStatuses = map[string]string{
	"connected-relay":           "relay",
	"connected-direct":          "direct",
	"direct-fallback-relay":     "relay fallback",
	"trying-direct":             "trying direct",
	"probing-direct":            "probing direct",
	"waiting for host approval": "waiting approval",
	"waiting for guest":         "waiting guest",
	"waiting-for-claim":         "waiting guest",
	"guest pending":             "guest pending",
	"claimed":                   "guest pending",
	"guest connected":           "connected",
	"approved":                  "connected",
	"stream-complete":           "complete",
}

func peerSummary(peers []Peer, counts map[string]int) string {
	parts := make([]string, 0, len(peers))
	for _, peer := range peers {
		if strings.TrimSpace(peer.Name) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s/%s", displayHandleWithCounts(peer.Name, 18, counts), peer.Role))
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
