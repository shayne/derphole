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
	ActionWidenChat     ActionID = "widen_chat"
	ActionNarrowChat    ActionID = "narrow_chat"
	ActionGrantRead     ActionID = "grant_read"
	ActionGrantWrite    ActionID = "grant_write"
	ActionManagePeer    ActionID = "manage_peer"
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
	Menu     bool
	Visible  func(ActionContext) bool
	Enabled  func(ActionContext) bool
	Run      func(*App, ActionContext) tea.Cmd
}

type ActionRegistry struct {
	actions []Action
}

func NewActionRegistry() ActionRegistry {
	return ActionRegistry{actions: []Action{
		{ID: ActionToggleChat, Label: "Toggle Chat", Shortcut: "Ctrl-X S", Menu: true, Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(toggleSidebarAction)},
		{ID: ActionFocusChat, Label: "Focus Chat", Shortcut: "Ctrl-X C", Menu: true, Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(focusChatAction)},
		{ID: ActionFocusTerminal, Label: "Focus Terminal", Shortcut: "Ctrl-X T", Menu: true, Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(focusTerminalAction)},
		{ID: ActionShowInvite, Label: "Show Invite", Shortcut: "Ctrl-X I", Menu: true, Visible: hostInviteVisible, Enabled: alwaysEnabled, Run: appAction(inviteAction)},
		{ID: ActionToggleSelect, Label: "Native Selection", Shortcut: "Ctrl-X Y", Menu: true, Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(copyModeAction)},
		{ID: ActionQuit, Label: "Quit", Shortcut: "Ctrl-X Q", Menu: true, Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(quitAction)},
		{ID: ActionWidenChat, Label: "Widen Chat", Shortcut: "Ctrl-X [", Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(widenChatAction)},
		{ID: ActionNarrowChat, Label: "Narrow Chat", Shortcut: "Ctrl-X ]", Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(narrowChatAction)},
		{ID: ActionGrantRead, Label: "Grant Read", Shortcut: "Ctrl-X R", Menu: true, Visible: hostPeerVisible, Enabled: alwaysEnabled, Run: appAction(readRoleAction)},
		{ID: ActionGrantWrite, Label: "Grant Write", Shortcut: "Ctrl-X W", Menu: true, Visible: hostPeerVisible, Enabled: alwaysEnabled, Run: appAction(writeRoleAction)},
		{ID: ActionManagePeer, Label: "Manage Peer", Visible: hostPeerVisible, Enabled: alwaysEnabled},
		{ID: ActionKickPeer, Label: "Kick Peer", Shortcut: "Ctrl-X K", Menu: true, Visible: hostPeerVisible, Enabled: alwaysEnabled, Run: appAction(kickPeerAction)},
		{ID: ActionDenyGuest, Label: "Deny Guest", Shortcut: "Esc", Visible: hostInviteVisible, Enabled: alwaysEnabled, Run: appAction(denyGuestAction)},
		{ID: ActionRestartShell, Label: "Restart Shell", Shortcut: "R", Visible: hostVisible, Enabled: alwaysEnabled, Run: appAction(restartShellAction)},
		{ID: ActionShowMenu, Label: "Menu", Shortcut: "Ctrl-X ?", Visible: alwaysVisible, Enabled: alwaysEnabled, Run: appAction(helpAction)},
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

func (r ActionRegistry) Action(ctx ActionContext, id ActionID) (Action, bool) {
	for _, action := range r.actions {
		if action.ID != id {
			continue
		}
		if action.Visible != nil && !action.Visible(ctx) {
			return Action{}, false
		}
		if action.Enabled != nil && !action.Enabled(ctx) {
			return Action{}, false
		}
		return action, true
	}
	return Action{}, false
}

func (r ActionRegistry) Run(app *App, id ActionID) (tea.Cmd, bool) {
	if app == nil {
		return nil, false
	}
	ctx := app.actionContext()
	action, ok := r.Action(ctx, id)
	if !ok || action.Run == nil {
		return nil, false
	}
	return action.Run(app, ctx), true
}

func (a *App) runAction(id ActionID) tea.Cmd {
	cmd, _ := NewActionRegistry().Run(a, id)
	return cmd
}

func appAction(fn func(*App) tea.Cmd) func(*App, ActionContext) tea.Cmd {
	return func(app *App, _ ActionContext) tea.Cmd {
		return fn(app)
	}
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
