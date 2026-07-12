// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
)

var encodedTerminalKeys = map[rune][]byte{
	tea.KeySpace:     []byte{' '},
	tea.KeyEnter:     []byte{'\r'},
	tea.KeyTab:       []byte{'\t'},
	tea.KeyBackspace: []byte{0x7f},
	tea.KeyEsc:       []byte{0x1b},
	tea.KeyUp:        []byte("\x1b[A"),
	tea.KeyDown:      []byte("\x1b[B"),
	tea.KeyRight:     []byte("\x1b[C"),
	tea.KeyLeft:      []byte("\x1b[D"),
	tea.KeyHome:      []byte("\x1b[H"),
	tea.KeyEnd:       []byte("\x1b[F"),
	tea.KeyDelete:    []byte("\x1b[3~"),
	tea.KeyInsert:    []byte("\x1b[2~"),
	tea.KeyPgUp:      []byte("\x1b[5~"),
	tea.KeyPgDown:    []byte("\x1b[6~"),
	tea.KeyF1:        []byte("\x1bOP"),
	tea.KeyF2:        []byte("\x1bOQ"),
	tea.KeyF3:        []byte("\x1bOR"),
	tea.KeyF4:        []byte("\x1bOS"),
	tea.KeyF5:        []byte("\x1b[15~"),
	tea.KeyF6:        []byte("\x1b[17~"),
	tea.KeyF7:        []byte("\x1b[18~"),
	tea.KeyF8:        []byte("\x1b[19~"),
	tea.KeyF9:        []byte("\x1b[20~"),
	tea.KeyF10:       []byte("\x1b[21~"),
	tea.KeyF11:       []byte("\x1b[23~"),
	tea.KeyF12:       []byte("\x1b[24~"),
}

var applicationCursorKeys = map[rune][]byte{
	tea.KeyUp:    []byte("\x1bOA"),
	tea.KeyDown:  []byte("\x1bOB"),
	tea.KeyRight: []byte("\x1bOC"),
	tea.KeyLeft:  []byte("\x1bOD"),
}

type xtermModifiedKey struct {
	parameter string
	final     byte
}

var xtermModifiedKeys = map[rune]xtermModifiedKey{
	tea.KeyUp:     {parameter: "1", final: 'A'},
	tea.KeyDown:   {parameter: "1", final: 'B'},
	tea.KeyRight:  {parameter: "1", final: 'C'},
	tea.KeyLeft:   {parameter: "1", final: 'D'},
	tea.KeyHome:   {parameter: "1", final: 'H'},
	tea.KeyEnd:    {parameter: "1", final: 'F'},
	tea.KeyInsert: {parameter: "2", final: '~'},
	tea.KeyDelete: {parameter: "3", final: '~'},
	tea.KeyPgUp:   {parameter: "5", final: '~'},
	tea.KeyPgDown: {parameter: "6", final: '~'},
	tea.KeyF1:     {parameter: "1", final: 'P'},
	tea.KeyF2:     {parameter: "1", final: 'Q'},
	tea.KeyF3:     {parameter: "1", final: 'R'},
	tea.KeyF4:     {parameter: "1", final: 'S'},
	tea.KeyF5:     {parameter: "15", final: '~'},
	tea.KeyF6:     {parameter: "17", final: '~'},
	tea.KeyF7:     {parameter: "18", final: '~'},
	tea.KeyF8:     {parameter: "19", final: '~'},
	tea.KeyF9:     {parameter: "20", final: '~'},
	tea.KeyF10:    {parameter: "21", final: '~'},
	tea.KeyF11:    {parameter: "23", final: '~'},
	tea.KeyF12:    {parameter: "24", final: '~'},
}

func EncodeTerminalKey(msg tea.KeyPressMsg) ([]byte, bool) {
	return EncodeTerminalKeyWithMode(msg, TerminalInputMode{})
}

func EncodeTerminalKeyWithMode(msg tea.KeyPressMsg, mode TerminalInputMode) ([]byte, bool) {
	if data, ok := encodeTerminalText(msg); ok {
		return data, true
	}
	if unsupportedTerminalModifier(msg.Mod) {
		return nil, false
	}
	if data, ok := encodeTerminalControl(msg); ok {
		return data, true
	}
	if data, ok := encodeAltPrintableKey(msg); ok {
		return data, true
	}
	modifier, modified := xtermModifier(msg.Mod)
	if modifier == 0 {
		return nil, false
	}
	if data, ok := encodeModifiedTerminalKey(msg.Code, modifier, modified); ok {
		return data, true
	}
	return encodeUnmodifiedTerminalKey(msg.Code, mode, modified)
}

func encodeUnmodifiedTerminalKey(code rune, mode TerminalInputMode, modified bool) ([]byte, bool) {
	if modified {
		return nil, false
	}
	if mode.ApplicationCursor {
		if data, ok := applicationCursorKeys[code]; ok {
			return append([]byte(nil), data...), true
		}
	}
	if data, ok := encodedTerminalKeys[code]; ok {
		return append([]byte(nil), data...), true
	}
	return nil, false
}

func encodeTerminalText(msg tea.KeyPressMsg) ([]byte, bool) {
	if len(msg.Text) == 0 {
		return nil, false
	}
	return prefixTerminalAlt(msg.Mod, []byte(msg.Text)), true
}

func encodeAltPrintableKey(msg tea.KeyPressMsg) ([]byte, bool) {
	if !msg.Mod.Contains(tea.ModAlt) || msg.Mod.Contains(tea.ModCtrl) {
		return nil, false
	}
	code := msg.Code
	if msg.Mod.Contains(tea.ModShift) {
		switch {
		case msg.ShiftedCode != 0:
			code = msg.ShiftedCode
		case unicode.IsLetter(code):
			code = unicode.ToUpper(code)
		default:
			return nil, false
		}
	}
	if !unicode.IsPrint(code) {
		return nil, false
	}
	return prefixTerminalAlt(msg.Mod, []byte(string(code))), true
}

func encodeModifiedTerminalKey(code rune, modifier int, modified bool) ([]byte, bool) {
	if !modified {
		return nil, false
	}
	if code == tea.KeyTab && modifier == 2 {
		return []byte("\x1b[Z"), true
	}
	key, ok := xtermModifiedKeys[code]
	if !ok {
		return nil, false
	}
	return []byte(fmt.Sprintf("\x1b[%s;%d%c", key.parameter, modifier, key.final)), true
}

func encodeTerminalControl(msg tea.KeyPressMsg) ([]byte, bool) {
	if !msg.Mod.Contains(tea.ModCtrl) {
		return nil, false
	}
	if msg.Code == tea.KeySpace {
		return prefixTerminalAlt(msg.Mod, []byte{0x00}), true
	}
	code := unicode.ToUpper(msg.Code)
	if code >= '@' && code <= '_' {
		return prefixTerminalAlt(msg.Mod, []byte{byte(code) & 0x1f}), true
	}
	return nil, false
}

func prefixTerminalAlt(mod tea.KeyMod, data []byte) []byte {
	if !mod.Contains(tea.ModAlt) {
		return data
	}
	return append([]byte{0x1b}, data...)
}

func xtermModifier(mod tea.KeyMod) (int, bool) {
	value := 1
	if mod.Contains(tea.ModShift) {
		value++
	}
	if mod.Contains(tea.ModAlt) {
		value += 2
	}
	if mod.Contains(tea.ModCtrl) {
		value += 4
	}
	if mod.Contains(tea.ModMeta) {
		value += 8
	}
	if unsupportedTerminalModifier(mod) {
		return 0, false
	}
	return value, value != 1
}

func unsupportedTerminalModifier(mod tea.KeyMod) bool {
	return mod.Contains(tea.ModHyper) || mod.Contains(tea.ModSuper)
}

func EncodeTerminalPaste(msg tea.PasteMsg, mode TerminalInputMode) []byte {
	data := []byte(msg.Content)
	if !mode.BracketedPaste {
		return data
	}
	wrapped := make([]byte, 0, len(data)+12)
	wrapped = append(wrapped, "\x1b[200~"...)
	wrapped = append(wrapped, data...)
	return append(wrapped, "\x1b[201~"...)
}

func isCtrlKey(msg tea.KeyPressMsg, code rune) bool {
	return msg.Code == code && msg.Mod.Contains(tea.ModCtrl)
}

func isShiftTab(msg tea.KeyPressMsg) bool {
	return msg.Code == tea.KeyTab && msg.Mod.Contains(tea.ModShift)
}

func HandlePrefixKey(app *App, msg tea.KeyPressMsg) tea.Cmd {
	if app == nil {
		return nil
	}
	app.prefix = false
	key := strings.ToLower(msg.String())

	switch key {
	case "q":
		return app.runAction(ActionQuit)
	case "?":
		return app.runAction(ActionShowMenu)
	}

	if app.approvalActive() {
		app.handleApprovalPrefix(key)
		return nil
	}

	return app.handleGlobalPrefix(key)
}

func (a *App) handleApprovalPrefix(key string) {
	switch key {
	case "r":
		a.approve(RoleRead, false)
	case "w":
		a.approve(RoleWrite, false)
	case "d":
		a.approve("", true)
	}
}

func (a *App) handleGlobalPrefix(key string) tea.Cmd {
	if id, ok := globalPrefixActions[key]; ok {
		return a.runAction(id)
	}
	return nil
}

var globalPrefixActions = map[string]ActionID{
	"s":     ActionToggleChat,
	"c":     ActionFocusChat,
	"t":     ActionFocusTerminal,
	"i":     ActionShowInvite,
	"y":     ActionToggleSelect,
	"left":  ActionWidenChat,
	"[":     ActionWidenChat,
	"right": ActionNarrowChat,
	"]":     ActionNarrowChat,
	"q":     ActionQuit,
	"r":     ActionGrantRead,
	"w":     ActionGrantWrite,
	"k":     ActionKickPeer,
	"?":     ActionShowMenu,
}

func toggleSidebarAction(a *App) tea.Cmd {
	a.setSidebarOpen(!a.sidebarOpen)
	return nil
}

func focusChatAction(a *App) tea.Cmd {
	a.setSidebarOpen(true)
	a.focusChat()
	return nil
}

func focusTerminalAction(a *App) tea.Cmd {
	a.focusTerminal()
	return nil
}

func inviteAction(a *App) tea.Cmd {
	return a.openInvite()
}

func copyModeAction(a *App) tea.Cmd {
	return a.setCopyMode(!a.copyMode)
}

func widenChatAction(a *App) tea.Cmd {
	if a.sidebarOpen {
		a.setSidebarWidth(a.layout.Sidebar.W + 4)
	}
	return nil
}

func narrowChatAction(a *App) tea.Cmd {
	if a.sidebarOpen {
		a.setSidebarWidth(a.layout.Sidebar.W - 4)
	}
	return nil
}

func quitAction(a *App) tea.Cmd {
	a.openQuitConfirm()
	return nil
}

func readRoleAction(a *App) tea.Cmd {
	a.changeFirstPeerRole(RoleRead)
	return nil
}

func writeRoleAction(a *App) tea.Cmd {
	a.changeFirstPeerRole(RoleWrite)
	return nil
}

func kickPeerAction(a *App) tea.Cmd {
	a.beginKickFirstPeer()
	return nil
}

func helpAction(a *App) tea.Cmd {
	a.clearPointerCapture()
	a.helpOpen = true
	return nil
}

func denyGuestAction(a *App) tea.Cmd {
	a.approve("", true)
	return nil
}

func restartShellAction(a *App) tea.Cmd {
	a.shellExitChoice = shellExitChoiceRestart
	a.confirmShellExitChoice()
	return nil
}

func (a *App) beginKickFirstPeer() {
	if len(a.peers) == 0 {
		return
	}
	a.clearPointerCapture()
	a.kickPeerID = a.peers[0].ID
	a.kickPeer = valueOr(a.peers[0].Name, a.peers[0].ID)
	a.focus = FocusApproval
}
