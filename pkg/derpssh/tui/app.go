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
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type Options struct {
	Side              string
	DisplayName       string
	InviteCommand     string
	InitialInviteOpen bool
	Terminal          TerminalPane
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

type quitChoice int

const (
	quitChoiceQuit quitChoice = iota
	quitChoiceCancel
)

var quitChoiceOrder = []quitChoice{
	quitChoiceQuit,
	quitChoiceCancel,
}

type topBarAction int

const (
	topBarActionNone topBarAction = iota
	topBarActionQuit
	topBarActionChat
	topBarActionInvite
	topBarActionHelp
)

type topBarSegment struct {
	text   string
	style  lipgloss.Style
	action topBarAction
}

type topBarHit struct {
	rect   Rect
	action topBarAction
}

type menuAction int

const (
	menuActionNone menuAction = iota
	menuActionChat
	menuActionFocusChat
	menuActionFocusTerminal
	menuActionInvite
	menuActionCopyMode
	menuActionQuit
	menuActionRead
	menuActionWrite
	menuActionKick
)

type menuEntry struct {
	label    string
	shortcut string
	action   menuAction
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
	quitOpen        bool
	quitChoice      quitChoice
	quitTitle       string
	quitBody        string
	noticeTitle     string
	noticeBody      string
	topBarHits      []topBarHit

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
		inviteOpen:    opts.InitialInviteOpen,
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
	if cmd, handled := a.handleInteractiveMessage(msg); handled {
		return a, cmd
	}
	a.applyMessage(msg)
	return a, nil
}

func (a *App) handleInteractiveMessage(msg tea.Msg) (tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return a.handleKey(msg), true
	case tea.MouseMsg:
		return HandleMouse(a, msg), true
	default:
		return nil, false
	}
}

func (a *App) applyMessage(msg tea.Msg) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.resize(msg.Width, msg.Height, true)
	case TerminalDataMsg:
		_, _ = a.terminal.Write([]byte(msg))
	case RuntimeStateMsg:
		a.applyRuntimeState(msg)
	case ChatMsg:
		a.appendChatMessage(ChatMessage(msg))
	case ApprovalRequestMsg:
		a.applyApprovalRequest(msg)
	case NoticeMsg:
		a.applyNotice(msg)
	}
}

func (a *App) applyRuntimeState(msg RuntimeStateMsg) {
	a.transport = valueOr(msg.Transport, a.transport)
	a.hostCols = msg.HostCols
	a.hostRows = msg.HostRows
	if msg.LocalRole != "" {
		a.localRole = msg.LocalRole
	}
	a.peers = append([]Peer(nil), msg.Peers...)
}

func (a *App) applyApprovalRequest(msg ApprovalRequestMsg) {
	a.inviteOpen = false
	a.approvalPeerID = strings.TrimSpace(msg.PeerID)
	a.approvalPeer = strings.TrimSpace(valueOr(msg.Peer, msg.PeerID))
	if a.approvalActive() {
		a.focus = FocusApproval
		a.approvalChoice = approvalChoiceWrite
	}
}

func (a *App) applyNotice(msg NoticeMsg) {
	title := strings.TrimSpace(msg.Title)
	body := strings.TrimSpace(msg.Body)
	if strings.EqualFold(title, "Shell exited") {
		a.noticeTitle = ""
		a.noticeBody = ""
		a.quitTitle = title
		a.quitBody = valueOr(body, "The shared shell exited.")
		a.quitOpen = true
		a.quitChoice = quitChoiceQuit
		return
	}
	a.noticeTitle = title
	a.noticeBody = body
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
	lines[0] = a.renderTopBar()
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
	if a.resizeWarningOpen() {
		a.overlay(lines, a.resizeWarningLines())
	}
	if a.waitingApprovalOpen() {
		a.overlay(lines, a.waitingApprovalLines())
	}
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
	if a.quitOpen {
		a.overlay(lines, a.quitLines())
	}
	if a.noticeOpen() {
		a.overlay(lines, a.noticeLines())
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
	terminal := a.currentTerminalRect()
	return terminal.W, terminal.H
}

func (a *App) resize(cols int, rows int, emitResize bool) {
	oldTerminal := a.currentTerminalRect()
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
		composerRows := a.desiredComposerRows(a.layout.Sidebar.W)
		composerRows = minInt(composerRows, maxInt(a.layout.Sidebar.H-1, 1))
		a.layout.Composer = Rect{
			X: a.layout.Sidebar.X,
			Y: a.layout.Sidebar.Y + maxInt(a.layout.Sidebar.H-composerRows, 0),
			W: a.layout.Sidebar.W,
			H: composerRows,
		}
	}
	if !a.currentTerminalRect().empty() {
		cols, rows := a.terminalBufferSize()
		a.terminal.Resize(cols, rows)
	}
	if !a.layout.Composer.empty() {
		a.composer.SetWidth(a.layout.Composer.W)
		a.composer.SetHeight(a.layout.Composer.H)
	}
}

func (a *App) terminalBufferSize() (int, int) {
	if a.isGuest() && a.hostCols > 0 && a.hostRows > 0 {
		return a.hostCols, a.hostRows
	}
	terminal := a.currentTerminalRect()
	return terminal.W, terminal.H
}

func (a *App) currentTerminalRect() Rect {
	if a.guestChatOverlay() {
		_, contentH := contentRect(a.height)
		return Rect{X: 0, Y: 1, W: a.width, H: contentH}
	}
	return a.layout.Terminal
}

func (a *App) desiredComposerRows(width int) int {
	width = maxInt(width, 1)
	value := a.composer.Value()
	if strings.TrimSpace(value) == "" {
		return 1
	}
	rows := len(wrapPlainLines(value, width))
	return clampInt(rows, 1, 3)
}

func (a *App) guestChatOverlay() bool {
	return a.isGuest() && a.hostCols > 0 && a.hostRows > 0 && a.sidebarOpen && !a.layout.Sidebar.empty()
}

func (a *App) isGuest() bool {
	return strings.EqualFold(strings.TrimSpace(a.side), string(ModeGuest))
}

func (a *App) setSidebarOpen(open bool) {
	oldTerminal := a.currentTerminalRect()
	a.sidebarOpen = open
	if open {
		a.unreadChat = 0
	}
	a.applyLayout()
	a.emitTerminalResizeIfChanged(oldTerminal)
}

func (a *App) setSidebarWidth(width int) {
	oldTerminal := a.currentTerminalRect()
	a.sidebarWidth = clampSidebarWidth(a.width, width)
	a.sidebarOpen = true
	a.unreadChat = 0
	a.applyLayout()
	a.emitTerminalResizeIfChanged(oldTerminal)
}

func (a *App) emitTerminalResizeIfChanged(oldTerminal Rect) {
	nextTerminal := a.currentTerminalRect()
	if nextTerminal.empty() {
		return
	}
	if oldTerminal.W == nextTerminal.W && oldTerminal.H == nextTerminal.H {
		return
	}
	a.emit(TerminalResizeCommand{Cols: nextTerminal.W, Rows: nextTerminal.H})
}

func (a *App) handleKey(msg tea.KeyMsg) tea.Cmd {
	if cmd, handled := a.handleScreenKey(msg); handled {
		return cmd
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

func (a *App) handleScreenKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	if a.inviteOpen {
		return a.handleInviteKey(msg), true
	}
	if a.noticeOpen() {
		return a.handleNoticeKey(msg), true
	}
	if cmd, handled := a.handleQuitKey(msg); handled {
		return cmd, true
	}
	if a.handleEscapeKey(msg) {
		return nil, true
	}
	if cmd, handled := a.handleHelpKey(msg); handled {
		return cmd, true
	}
	if cmd, handled := a.handleWaitingApprovalKey(msg); handled {
		return cmd, true
	}
	if cmd, handled := a.handleApprovalKey(msg); handled {
		return cmd, true
	}
	if a.kickPeer != "" {
		return a.handleKickOverlayKey(msg), true
	}
	return nil, false
}

func (a *App) handleNoticeKey(msg tea.KeyMsg) tea.Cmd {
	if a.prefix {
		if strings.EqualFold(msg.String(), "q") {
			a.closeNotice()
		}
		return HandlePrefixKey(a, msg)
	}
	if msg.Type == tea.KeyCtrlX {
		a.prefix = true
		return nil
	}
	switch msg.Type {
	case tea.KeyEnter, tea.KeyEsc, tea.KeySpace:
		a.closeNotice()
	case tea.KeyRunes:
		switch strings.ToLower(string(msg.Runes)) {
		case "q", "x":
			a.closeNotice()
		}
	}
	return nil
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

func (a *App) handleWaitingApprovalKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	if !a.waitingApprovalOpen() {
		return nil, false
	}
	if a.prefix {
		return HandlePrefixKey(a, msg), true
	}
	if msg.Type == tea.KeyCtrlX {
		a.prefix = true
		return nil, true
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
		a.inviteOpen = false
		if !a.copyMode {
			return tea.EnableMouseCellMotion
		}
	case msg.Type == tea.KeyRunes && strings.EqualFold(string(msg.Runes), "c"):
		a.emit(CopyInviteCommand{Command: strings.TrimSpace(a.inviteCommand)})
	default:
		return nil
	}
	return nil
}

func (a *App) handleQuitKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	if !a.quitOpen {
		return nil, false
	}
	if a.prefix {
		a.prefix = false
		if msg.Type == tea.KeyRunes && strings.EqualFold(string(msg.Runes), "q") {
			a.quitChoice = quitChoiceQuit
			a.confirmQuitChoice()
			return nil, true
		}
	}
	a.dispatchQuitKey(msg)
	return nil, true
}

func (a *App) dispatchQuitKey(msg tea.KeyMsg) {
	switch msg.Type {
	case tea.KeyEnter, tea.KeySpace:
		a.confirmQuitChoice()
	case tea.KeyEsc:
		a.closeQuitConfirm()
	case tea.KeyTab, tea.KeyRight, tea.KeyDown:
		a.moveQuitChoice(1)
	case tea.KeyShiftTab, tea.KeyLeft, tea.KeyUp:
		a.moveQuitChoice(-1)
	case tea.KeyRunes:
		a.handleQuitRune(string(msg.Runes))
	case tea.KeyCtrlX:
		a.prefix = true
	}
}

func (a *App) handleQuitRune(key string) {
	switch strings.ToLower(key) {
	case "y":
		a.quitChoice = quitChoiceQuit
		a.confirmQuitChoice()
	case "n", "q":
		a.closeQuitConfirm()
	}
}

func (a *App) handleEscapeKey(msg tea.KeyMsg) bool {
	if msg.Type != tea.KeyEsc {
		return false
	}
	switch {
	case a.approvalActive():
		a.approve("", true)
	case a.quitOpen:
		a.closeQuitConfirm()
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

func (a *App) renderTopBar() string {
	width := maxInt(a.width, 1)
	left := a.leftTopBarSegments()
	right := a.rightTopBarSegments()
	rightLine, rightHits := a.renderTopBarSegments(right, width)
	rightW := displayWidth(rightLine)
	leftMax := maxInt(width-rightW-1, 0)
	leftLine, leftHits := a.renderTopBarSegments(left, leftMax)
	leftW := displayWidth(leftLine)
	gapW := maxInt(width-leftW-rightW, 0)
	gap := topBarStyle.Render(strings.Repeat(" ", gapW))

	a.topBarHits = append(leftHits[:0:0], leftHits...)
	rightX := leftW + gapW
	for _, hit := range rightHits {
		hit.rect.X += rightX
		a.topBarHits = append(a.topBarHits, hit)
	}

	return fitLine(leftLine+gap+rightLine, width)
}

func (a *App) renderTopBarSegments(segments []topBarSegment, maxWidth int) (string, []topBarHit) {
	if maxWidth <= 0 {
		return "", nil
	}
	var b strings.Builder
	hits := make([]topBarHit, 0, len(segments))
	x := 0
	for _, segment := range segments {
		if strings.TrimSpace(segment.text) == "" {
			continue
		}
		sep := ""
		sepW := 0
		if x > 0 {
			sep = topBarSeparatorStyle.Render("›")
			sepW = displayWidth(sep)
		}
		part := segment.style.Render(" " + segment.text + " ")
		partW := displayWidth(part)
		if x+sepW+partW > maxWidth {
			continue
		}
		if sep != "" {
			b.WriteString(sep)
			x += sepW
		}
		start := x
		b.WriteString(part)
		x += partW
		if segment.action != topBarActionNone {
			hits = append(hits, topBarHit{
				rect:   Rect{X: start, Y: 0, W: partW, H: 1},
				action: segment.action,
			})
		}
	}
	return b.String(), hits
}

func (a *App) leftTopBarSegments() []topBarSegment {
	segments := []topBarSegment{
		{text: "×", style: topBarQuitStyle, action: topBarActionQuit},
		{text: "derpssh", style: topBarBrandStyle},
	}
	segments = append(segments, a.identityTopBarSegments()...)
	segments = append(segments, a.stateTopBarSegments()...)
	return segments
}

func (a *App) rightTopBarSegments() []topBarSegment {
	segments := a.chatTopBarSegments()
	segments = append(segments, a.actionTopBarSegments()...)
	return segments
}

func (a *App) identityTopBarSegments() []topBarSegment {
	var parts []topBarSegment
	if side := strings.TrimSpace(a.side); side != "" {
		label := side
		if name := a.displayHandle(a.displayName, 16); name != "" {
			label += " " + name
		}
		parts = append(parts, topBarSegment{text: label, style: topBarChipStyle})
	}
	return parts
}

func (a *App) stateTopBarSegments() []topBarSegment {
	var parts []topBarSegment
	if transport := compactTransportStatus(a.transport); transport != "" {
		parts = append(parts, topBarSegment{text: transport, style: topBarMutedStyle})
	}
	if a.hostCols > 0 && a.hostRows > 0 {
		parts = append(parts, topBarSegment{text: fmt.Sprintf("%dx%d", a.hostCols, a.hostRows), style: topBarMutedStyle})
	}
	if a.localRole != "" && a.localRole != RolePending {
		parts = append(parts, topBarSegment{text: string(a.localRole), style: topBarChipStyle})
	}
	if len(a.peers) > 0 {
		parts = append(parts, topBarSegment{text: peerSummary(a.peers, a.identityCounts()), style: topBarChipStyle})
	}
	if a.approvalActive() {
		parts = append(parts, topBarSegment{text: "approve " + a.displayHandle(a.approvalPeer, 18), style: topBarWarnStyle})
	}
	return parts
}

func (a *App) chatTopBarSegments() []topBarSegment {
	if a.sidebarOpen {
		return []topBarSegment{{text: "Chat", style: topBarActionStyle, action: topBarActionChat}}
	}
	if a.unreadChat > 0 {
		return []topBarSegment{{text: fmt.Sprintf("Chat %d", a.unreadChat), style: topBarWarnStyle, action: topBarActionChat}}
	}
	return []topBarSegment{{text: "Chat", style: topBarMutedStyle, action: topBarActionChat}}
}

func (a *App) actionTopBarSegments() []topBarSegment {
	segments := []topBarSegment{}
	segments = append(segments, topBarSegment{text: "☰", style: topBarMutedStyle, action: topBarActionHelp})
	if a.copyMode {
		segments = append([]topBarSegment{{text: "select", style: topBarWarnStyle}}, segments...)
		return segments
	}
	if a.prefix {
		segments = append([]topBarSegment{{text: a.prefixHintText(), style: topBarWarnStyle}}, segments...)
		return segments
	}
	return segments
}

func (a *App) prefixHintText() string {
	parts := []string{"S Chat"}
	if a.canShowInvite() {
		parts = append(parts, "I Invite")
	}
	parts = append(parts, "Y Select", "Q Quit")
	return strings.Join(parts, " · ")
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
	a.setTerminalCursorActive(a.focus == FocusTerminal && !a.copyMode && !a.modalActive())
	terminal := a.currentTerminalRect()
	if terminal.empty() {
		return nil
	}
	if !a.sidebarOpen || a.layout.Sidebar.empty() {
		return a.terminalLines(terminal)
	}
	if a.guestChatOverlay() {
		return a.contentLinesWithSidebarOverlay(terminal)
	}

	terminalLines := a.terminalLines(terminal)
	sidebarLines := a.sidebarLines(a.layout.Sidebar.W, a.layout.Sidebar.H)
	lines := make([]string, terminal.H)
	for i := range lines {
		divider := separatorStyle.Render("│")
		lines[i] = fitLine(terminalLines[i], terminal.W) + fitLine(divider, a.layout.Divider.W) + fitLine(sidebarLines[i], a.layout.Sidebar.W)
	}
	return lines
}

func (a *App) terminalLines(terminal Rect) []string {
	return padLines(splitAndFit(a.terminal.View(terminal.W, terminal.H), terminal.W, terminal.H), terminal.H, terminal.W)
}

func (a *App) contentLinesWithSidebarOverlay(terminal Rect) []string {
	terminalLines := a.terminalLines(terminal)
	sidebarLines := a.sidebarLines(a.layout.Sidebar.W, a.layout.Sidebar.H)
	lines := make([]string, terminal.H)
	for i := range lines {
		divider := separatorStyle.Render("│")
		panel := fitLine(divider, a.layout.Divider.W) + fitLine(sidebarLines[i], a.layout.Sidebar.W)
		lines[i] = overlayFromColumn(terminalLines[i], a.layout.Divider.X, panel, terminal.W)
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
		lines[i] = fitLine(sidebarStyle.Width(width).Render(fitLine(content[i], width)), width)
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
	content[0] = fitLine(sidebarHeaderStyle.Width(width).Render(" Chat"), width)
}

func (a *App) writeSidebarMessages(content []string, width int, height int, row int) {
	messageRows := a.chatRenderLines(width)
	reserved := a.sidebarComposerRows(height)
	available := maxInt(0, height-reserved-row)
	start := chatWindowStart(len(messageRows), available, a.chatScroll)
	for _, line := range messageRows[start:minInt(start+available, len(messageRows))] {
		if row >= height-reserved {
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
		for _, part := range parts {
			out = append(out, hardWrapPlainLine(part, width)...)
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func hardWrapPlainLine(line string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	if displayWidth(line) <= width {
		return []string{line}
	}
	lines := make([]string, 0, displayWidth(line)/width+1)
	var b strings.Builder
	used := 0
	for _, r := range line {
		rw := displayWidth(string(r))
		if rw == 0 {
			b.WriteRune(r)
			continue
		}
		if used+rw > width && b.Len() > 0 {
			lines = append(lines, b.String())
			b.Reset()
			used = 0
		}
		b.WriteRune(r)
		used += rw
	}
	if b.Len() > 0 || len(lines) == 0 {
		lines = append(lines, b.String())
	}
	return lines
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
	rows := clampInt(a.layout.Composer.H, 1, 3)
	rows = minInt(rows, height)
	borderY := height - rows - 1
	if borderY >= 0 {
		content[borderY] = fitLine(composerBorderStyle.Width(width).Render(strings.Repeat(" ", width)), width)
	}
	start := height - rows
	composerLines := splitAndFit(a.composer.View(), width, rows)
	for i := 0; i < rows && start+i < height; i++ {
		if i < len(composerLines) {
			content[start+i] = fitLine(composerStyle.Width(width).Render(fitLine(composerLines[i], width)), width)
		} else {
			content[start+i] = fitLine(composerStyle.Width(width).Render(strings.Repeat(" ", width)), width)
		}
	}
}

func (a *App) sidebarComposerRows(height int) int {
	rows := clampInt(a.layout.Composer.H, 1, 3)
	if height > rows {
		return rows + 1
	}
	return rows
}

func (a *App) approvalLines() []string {
	width := a.approvalContentWidth()
	return []string{
		fitLine(labelStyle.Render(a.approvalPeer+" wants to join"), width),
		fitLine(dimStyle.Render("Select access, then press Enter."), width),
		fitLine("", width),
		a.approvalButtonLine(width),
	}
}

func (a *App) quitLines() []string {
	width := a.quitContentWidth()
	title := valueOr(a.quitTitle, "Quit derpssh?")
	body := valueOr(a.quitBody, "This closes the shared terminal for everyone.")
	return []string{
		fitLine(labelStyle.Render(title), width),
		fitLine(dimStyle.Render(body), width),
		fitLine("", width),
		a.quitButtonLine(width),
	}
}

func (a *App) noticeLines() []string {
	width := a.noticeContentWidth()
	body := strings.TrimSpace(a.noticeBody)
	if body == "" {
		body = "Session closed."
	}
	lines := []string{fitLine(labelStyle.Render(valueOr(a.noticeTitle, "Notice")), width)}
	lines = append(lines, wrapPlainLines(body, width)...)
	lines = append(lines, fitLine("", width), fitLine(dimStyle.Render("Enter or Esc closes this."), width))
	return lines
}

func (a *App) resizeWarningLines() []string {
	width := a.resizeWarningContentWidth()
	terminal := a.currentTerminalRect()
	current := fmt.Sprintf("%dx%d", terminal.W, terminal.H)
	required := fmt.Sprintf("%dx%d", a.hostCols, a.hostRows)
	lines := []string{fitLine(labelStyle.Render("Resize terminal"), width)}
	lines = append(lines, wrapPlainLines("The host terminal is "+required+". Your current view is "+current+".", width)...)
	lines = append(lines, wrapPlainLines("Resize this window until the shared terminal fits.", width)...)
	return lines
}

func (a *App) waitingApprovalLines() []string {
	width := a.waitingApprovalContentWidth()
	return []string{
		fitLine(labelStyle.Render("Waiting for host approval"), width),
		fitLine(dimStyle.Render("The host will choose read or write access."), width),
		fitLine("", width),
		fitLine(dimStyle.Render("Ctrl-X Q quits"), width),
	}
}

func (a *App) helpLines() []string {
	width := a.helpContentWidth()
	lines := []string{fitLine(labelStyle.Render("derpssh menu"), width), fitLine("", width)}
	for _, entry := range a.menuEntries() {
		lines = append(lines, a.menuEntryLine(entry, width))
	}
	lines = append(lines, fitLine("", width), fitLine(dimStyle.Render("Esc closes"), width))
	return lines
}

func (a *App) overlay(lines []string, body []string) {
	if !a.canOverlay(lines) {
		return
	}
	box := renderModalBox(body)
	boxW := a.overlayWidth(box)
	x := (a.width - boxW) / 2
	y := a.overlayY(len(box))
	for i, line := range box {
		row := y + i
		a.overlayLine(lines, row, x, line, boxW)
	}
}

func renderModalBox(body []string) []string {
	width := modalBodyWidth(body)
	border := lipgloss.RoundedBorder()
	borderStyle := lipgloss.NewStyle().Foreground(catSapphire)
	interiorStyle := lipgloss.NewStyle().
		Foreground(catText).
		Background(catBase)

	innerWidth := width + 2
	box := make([]string, 0, len(body)+2)
	box = append(box, borderStyle.Render(border.TopLeft+strings.Repeat(border.Top, innerWidth)+border.TopRight))
	for _, line := range body {
		line = strings.TrimRight(line, " ")
		line = ansi.Truncate(line, width, "")
		pad := strings.Repeat(" ", maxInt(width-displayWidth(line), 0))
		box = append(box,
			borderStyle.Render(border.Left)+
				interiorStyle.Render(" ")+
				line+
				interiorStyle.Render(pad+" ")+
				borderStyle.Render(border.Right),
		)
	}
	box = append(box, borderStyle.Render(border.BottomLeft+strings.Repeat(border.Bottom, innerWidth)+border.BottomRight))
	return box
}

func modalBodyWidth(body []string) int {
	width := 1
	for _, line := range body {
		width = maxInt(width, displayWidth(strings.TrimRight(line, " ")))
	}
	return width
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
	lines[row] = replaceRange(lines[row], x, width, fitLine(line, width), a.width)
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
	box := renderModalBox(a.approvalLines())
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

func (a *App) quitHit(x int, y int) quitChoice {
	quit, cancel := a.quitButtonRects()
	switch {
	case quit.contains(x, y):
		return quitChoiceQuit
	case cancel.contains(x, y):
		return quitChoiceCancel
	default:
		return -1
	}
}

func (a *App) quitButtonRects() (Rect, Rect) {
	contentW := a.quitContentWidth()
	contentX, contentY := a.quitContentOrigin()
	buttonLineW := quitButtonsWidth()
	startX := contentX + maxInt((contentW-buttonLineW)/2, 0)
	y := contentY + quitButtonLineIndex

	quit := Rect{X: startX, Y: y, W: quitButtonWidth(quitChoiceQuit), H: 1}
	cancel := Rect{X: quit.X + quit.W + quitButtonGap, Y: y, W: quitButtonWidth(quitChoiceCancel), H: 1}
	return quit, cancel
}

func (a *App) quitContentOrigin() (int, int) {
	box := renderModalBox(a.quitLines())
	boxW := a.overlayWidth(box)
	boxX := (a.width - boxW) / 2
	boxY := a.overlayY(len(box))
	return boxX + modalStyle.GetBorderLeftSize() + modalStyle.GetPaddingLeft(),
		boxY + modalStyle.GetBorderTopSize() + modalStyle.GetPaddingTop()
}

func (a *App) quitContentWidth() int {
	title := valueOr(a.quitTitle, "Quit derpssh?")
	body := valueOr(a.quitBody, "This closes the shared terminal for everyone.")
	width := maxInt(displayWidth(title), displayWidth(body))
	width = maxInt(width, 44)
	width = maxInt(width, quitButtonsWidth())
	if a.width > 0 {
		maxWidth := a.width - modalStyle.GetHorizontalBorderSize() - modalStyle.GetHorizontalPadding() - 2
		width = minInt(width, maxInt(maxWidth, 1))
	}
	return maxInt(width, 1)
}

func (a *App) helpContentOrigin() (int, int) {
	box := renderModalBox(a.helpLines())
	boxW := a.overlayWidth(box)
	boxX := (a.width - boxW) / 2
	boxY := a.overlayY(len(box))
	return boxX + modalStyle.GetBorderLeftSize() + modalStyle.GetPaddingLeft(),
		boxY + modalStyle.GetBorderTopSize() + modalStyle.GetPaddingTop()
}

func (a *App) helpContentWidth() int {
	width := displayWidth("derpssh menu")
	for _, entry := range a.menuEntries() {
		width = maxInt(width, displayWidth(entry.label)+displayWidth(entry.shortcut)+4)
	}
	width = maxInt(width, displayWidth("Esc closes"))
	if a.width > 0 {
		maxWidth := a.width - modalStyle.GetHorizontalBorderSize() - modalStyle.GetHorizontalPadding() - 2
		width = minInt(width, maxInt(maxWidth, 1))
	}
	return maxInt(width, 1)
}

func (a *App) menuEntryLine(entry menuEntry, width int) string {
	label := entry.label
	shortcutW := displayWidth(entry.shortcut)
	labelW := displayWidth(label)
	if shortcutW > 0 && labelW+shortcutW+2 <= width {
		label = fitLine(label, width-shortcutW-2)
		gap := strings.Repeat(" ", maxInt(width-displayWidth(label)-shortcutW, 1))
		return fitLine(label+dimStyle.Render(gap+entry.shortcut), width)
	}
	return fitLine(label, width)
}

func (a *App) menuEntries() []menuEntry {
	entries := []menuEntry{
		{label: "Toggle Chat", shortcut: "Ctrl-X S", action: menuActionChat},
		{label: "Focus Chat", shortcut: "Ctrl-X C", action: menuActionFocusChat},
		{label: "Focus Terminal", shortcut: "Ctrl-X T", action: menuActionFocusTerminal},
	}
	if a.canShowInvite() {
		entries = append(entries, menuEntry{label: "Show Invite", shortcut: "Ctrl-X I", action: menuActionInvite})
	}
	entries = append(entries,
		menuEntry{label: "Native Selection", shortcut: "Ctrl-X Y", action: menuActionCopyMode},
		menuEntry{label: "Quit", shortcut: "Ctrl-X Q", action: menuActionQuit},
	)
	if len(a.peers) > 0 {
		entries = append(entries,
			menuEntry{label: "Grant Read", shortcut: "Ctrl-X R", action: menuActionRead},
			menuEntry{label: "Grant Write", shortcut: "Ctrl-X W", action: menuActionWrite},
			menuEntry{label: "Kick Peer", shortcut: "Ctrl-X K", action: menuActionKick},
		)
	}
	return entries
}

func (a *App) quitButtonLine(width int) string {
	lineW := quitButtonsWidth()
	pad := strings.Repeat(" ", maxInt((width-lineW)/2, 0))
	parts := []string{
		a.renderQuitButton(quitChoiceQuit),
		a.renderQuitButton(quitChoiceCancel),
	}
	return fitLine(pad+strings.Join(parts, strings.Repeat(" ", quitButtonGap)), width)
}

func (a *App) noticeContentWidth() int {
	width := maxInt(34, displayWidth(valueOr(a.noticeTitle, "Notice")))
	for _, line := range wrapPlainLines(strings.TrimSpace(a.noticeBody), 54) {
		width = maxInt(width, displayWidth(line))
	}
	width = maxInt(width, displayWidth("Enter or Esc closes this."))
	if a.width > 0 {
		maxWidth := a.width - modalStyle.GetHorizontalBorderSize() - modalStyle.GetHorizontalPadding() - 2
		width = minInt(width, maxInt(maxWidth, 1))
	}
	return maxInt(width, 1)
}

func (a *App) resizeWarningContentWidth() int {
	width := maxInt(44, displayWidth("Resize terminal"))
	terminal := a.currentTerminalRect()
	width = maxInt(width, displayWidth(fmt.Sprintf("The host terminal is %dx%d. Your current view is %dx%d.", a.hostCols, a.hostRows, terminal.W, terminal.H)))
	width = maxInt(width, displayWidth("Resize this window until the shared terminal fits."))
	if a.width > 0 {
		maxWidth := a.width - modalStyle.GetHorizontalBorderSize() - modalStyle.GetHorizontalPadding() - 2
		width = minInt(width, maxInt(maxWidth, 1))
	}
	return maxInt(width, 1)
}

func (a *App) waitingApprovalContentWidth() int {
	width := maxInt(38, displayWidth("Waiting for host approval"))
	width = maxInt(width, displayWidth("The host will choose read or write access."))
	width = maxInt(width, displayWidth("Ctrl-X Q quits"))
	if a.width > 0 {
		maxWidth := a.width - modalStyle.GetHorizontalBorderSize() - modalStyle.GetHorizontalPadding() - 2
		width = minInt(width, maxInt(maxWidth, 1))
	}
	return maxInt(width, 1)
}

func (a *App) renderQuitButton(choice quitChoice) string {
	text := quitButtonText(choice)
	if a.quitChoice == choice {
		return approvalButtonSelectedStyle.Render(text)
	}
	return approvalButtonStyle.Render(text)
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

func (a *App) openQuitConfirm() {
	a.prefix = false
	a.quitOpen = true
	a.quitChoice = quitChoiceQuit
	a.quitTitle = ""
	a.quitBody = ""
}

func (a *App) closeQuitConfirm() {
	a.quitOpen = false
	a.quitChoice = quitChoiceQuit
	a.quitTitle = ""
	a.quitBody = ""
}

func (a *App) confirmQuitChoice() {
	if a.quitChoice == quitChoiceQuit {
		a.emit(QuitCommand{})
		return
	}
	a.closeQuitConfirm()
}

func (a *App) moveQuitChoice(delta int) {
	idx := 0
	for i, choice := range quitChoiceOrder {
		if choice == a.quitChoice {
			idx = i
			break
		}
	}
	next := (idx + delta) % len(quitChoiceOrder)
	if next < 0 {
		next += len(quitChoiceOrder)
	}
	a.quitChoice = quitChoiceOrder[next]
}

func (a *App) noticeOpen() bool {
	return strings.TrimSpace(a.noticeTitle) != "" || strings.TrimSpace(a.noticeBody) != ""
}

func (a *App) closeNotice() {
	a.noticeTitle = ""
	a.noticeBody = ""
}

func (a *App) openInvite() tea.Cmd {
	if !a.canShowInvite() {
		return nil
	}
	a.inviteOpen = true
	return tea.DisableMouse
}

func (a *App) canShowInvite() bool {
	// The invite command must stay on the normal terminal screen so users can
	// manually select one soft-wrapped shell line, including over SSH.
	return false
}

type terminalCursorController interface {
	SetCursorActive(active bool)
}

func (a *App) setTerminalCursorActive(active bool) {
	if cursor, ok := a.terminal.(terminalCursorController); ok {
		cursor.SetCursorActive(active)
	}
}

func (a *App) modalActive() bool {
	return a.helpOpen || a.resizeWarningOpen() || a.waitingApprovalOpen() || a.approvalActive() || a.kickPeer != "" || a.quitOpen || a.noticeOpen()
}

func (a *App) resizeWarningOpen() bool {
	if !a.isGuest() {
		return false
	}
	if a.hostCols <= 0 || a.hostRows <= 0 {
		return false
	}
	a.applyLayout()
	terminal := a.currentTerminalRect()
	return terminal.W < a.hostCols || terminal.H < a.hostRows
}

func (a *App) waitingApprovalOpen() bool {
	if !a.isGuest() || a.localRole != RolePending {
		return false
	}
	transport := strings.TrimSpace(a.transport)
	return transport != "" && !strings.EqualFold(transport, "starting")
}

func (a *App) inviteView() string {
	width := maxInt(a.width, 1)
	command := strings.TrimSpace(a.inviteCommand)
	lines := []string{
		"derpssh invite",
		"",
	}
	lines = append(lines, wrapPlainLines("Copy this command and send it to the other person:", width)...)
	lines = append(lines, "")
	lines = append(lines, command)
	lines = append(lines, "")
	lines = append(lines, wrapPlainLines("Press c to copy. Press Enter, Esc, or q to return.", width)...)
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
	quitButtonGap           = 3
	quitButtonLineIndex     = 3
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

func quitButtonsWidth() int {
	return quitButtonWidth(quitChoiceQuit) +
		quitButtonWidth(quitChoiceCancel) +
		quitButtonGap
}

func quitButtonWidth(choice quitChoice) int {
	return displayWidth(quitButtonText(choice))
}

func quitButtonText(choice quitChoice) string {
	switch choice {
	case quitChoiceQuit:
		return " Quit "
	case quitChoiceCancel:
		return " Cancel "
	default:
		return "        "
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

func overlayFromColumn(base string, x int, overlay string, width int) string {
	if width <= 0 {
		return ""
	}
	x = clampMin(x, 0)
	x = clampMax(x, width)
	prefix := fitLine(base, x)
	return fitLine(prefix+fitLine(overlay, width-x), width)
}

func replaceRange(base string, x int, span int, replacement string, width int) string {
	if width <= 0 {
		return ""
	}
	if x < 0 {
		x = 0
	}
	if x > width {
		x = width
	}
	if span < 0 {
		span = 0
	}
	end := x + span
	if end > width {
		end = width
	}
	prefix := ansi.Cut(base, 0, x)
	suffix := ansi.Cut(base, end, width)
	return fitLine(fitLine(prefix, x)+fitLine(replacement, end-x)+suffix, width)
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
