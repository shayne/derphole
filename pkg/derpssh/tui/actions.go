// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import tea "github.com/charmbracelet/bubbletea"

type ActionID string

const (
	ActionQuit          ActionID = "quit"
	ActionToggleChat    ActionID = "toggle_chat"
	ActionFocusChat     ActionID = "focus_chat"
	ActionFocusTerminal ActionID = "focus_terminal"
	ActionToggleSelect  ActionID = "toggle_select"
	ActionShowMenu      ActionID = "show_menu"
	ActionShowInvite    ActionID = "show_invite"
	ActionGrantRead     ActionID = "grant_read"
	ActionGrantWrite    ActionID = "grant_write"
	ActionDenyGuest     ActionID = "deny_guest"
	ActionKickPeer      ActionID = "kick_peer"
	ActionRestartShell  ActionID = "restart_shell"
)

type KeyChord string

type ActionContext struct {
	Mode      Mode
	HasInvite bool
	HasPeers  bool
}

type Action struct {
	ID       ActionID
	Label    string
	Shortcut KeyChord
	Visible  func(ActionContext) bool
	Enabled  func(ActionContext) bool
	Run      func(*App, ActionContext) tea.Cmd
}

type ActionRegistry struct {
	actions []Action
}

func NewActionRegistry() ActionRegistry {
	return ActionRegistry{actions: []Action{
		{ID: ActionToggleChat, Label: "Toggle Chat", Shortcut: "Ctrl-X S", Visible: alwaysVisible, Enabled: alwaysEnabled},
		{ID: ActionFocusChat, Label: "Focus Chat", Shortcut: "Ctrl-X C", Visible: alwaysVisible, Enabled: alwaysEnabled},
		{ID: ActionFocusTerminal, Label: "Focus Terminal", Shortcut: "Ctrl-X T", Visible: alwaysVisible, Enabled: alwaysEnabled},
		{ID: ActionShowInvite, Label: "Show Invite", Shortcut: "Ctrl-X I", Visible: hostInviteVisible, Enabled: alwaysEnabled},
		{ID: ActionToggleSelect, Label: "Native Selection", Shortcut: "Ctrl-X Y", Visible: alwaysVisible, Enabled: alwaysEnabled},
		{ID: ActionQuit, Label: "Quit", Shortcut: "Ctrl-X Q", Visible: alwaysVisible, Enabled: alwaysEnabled},
		{ID: ActionGrantRead, Label: "Grant Read", Shortcut: "Ctrl-X R", Visible: hostPeerVisible, Enabled: alwaysEnabled},
		{ID: ActionGrantWrite, Label: "Grant Write", Shortcut: "Ctrl-X W", Visible: hostPeerVisible, Enabled: alwaysEnabled},
		{ID: ActionKickPeer, Label: "Kick Peer", Shortcut: "Ctrl-X K", Visible: hostPeerVisible, Enabled: alwaysEnabled},
		{ID: ActionDenyGuest, Label: "Deny Guest", Shortcut: "Esc", Visible: hostInviteVisible, Enabled: alwaysEnabled},
		{ID: ActionRestartShell, Label: "Restart Shell", Shortcut: "R", Visible: hostVisible, Enabled: alwaysEnabled},
		{ID: ActionShowMenu, Label: "Menu", Shortcut: "Ctrl-X ?", Visible: alwaysVisible, Enabled: alwaysEnabled},
	}}
}

func (r ActionRegistry) Visible(ctx ActionContext) []Action {
	visible := make([]Action, 0, len(r.actions))
	for _, action := range r.actions {
		if action.Visible == nil || action.Visible(ctx) {
			visible = append(visible, action)
		}
	}
	return visible
}

func alwaysVisible(ActionContext) bool { return true }

func alwaysEnabled(ActionContext) bool { return true }

func hostVisible(ctx ActionContext) bool {
	return ctx.Mode == ModeHost
}

func hostInviteVisible(ctx ActionContext) bool {
	return ctx.Mode == ModeHost && ctx.HasInvite
}

func hostPeerVisible(ctx ActionContext) bool {
	return ctx.Mode == ModeHost && ctx.HasPeers
}

func (a *App) actionContext() ActionContext {
	return ActionContext{
		Mode:      Mode(a.side),
		HasInvite: a.canShowInvite(),
		HasPeers:  len(a.peers) > 0,
	}
}
