// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
	"github.com/shayne/derphole/pkg/derpssh/pty"
	"github.com/shayne/derphole/pkg/derpssh/tui"
)

const terminalTailLimit = 48 * 1024

type terminalConsole struct {
	mu     sync.Mutex
	model  tui.Model
	stdin  io.Reader
	output io.Writer
	screen bool
	last   string
}

func newTerminalConsole(mode tui.Mode, cols, rows int, stdin io.Reader, output io.Writer) *terminalConsole {
	if output == nil {
		output = io.Discard
	}
	c := &terminalConsole{
		model:  tui.NewModel(mode, cols, rows),
		stdin:  stdin,
		output: output,
	}
	if f, ok := output.(*os.File); ok {
		c.screen = pty.IsTerminal(f.Fd())
	}
	return c
}

func (c *terminalConsole) SetInviteCommand(command string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.model.SetInviteCommand(command)
	_ = c.renderLocked()
}

func (c *terminalConsole) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.model.AppendTerminalText(string(data), terminalTailLimit)
	return len(data), c.renderLocked()
}

func (c *terminalConsole) Approve(req JoinRequest) protocol.Role {
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		name = req.ParticipantID
	}
	c.mu.Lock()
	c.model.SetPendingGuest(req.ParticipantID, name)
	c.model.SetPeer(name, protocol.RolePending)
	c.model.SetTransportStatus("waiting for approval")
	_ = c.renderLocked()
	c.mu.Unlock()

	switch strings.ToLower(strings.TrimSpace(os.Getenv("DERPSSH_TEST_AUTO_APPROVE"))) {
	case "read":
		return c.approveWithKey("r")
	case "write":
		return c.approveWithKey("w")
	case "deny":
		return c.approveWithKey("n")
	}

	line, err := readApprovalLine(c.stdin)
	if err != nil && strings.TrimSpace(line) == "" {
		return c.approveWithKey("n")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "r":
		return c.approveWithKey("r")
	case "w":
		return c.approveWithKey("w")
	default:
		return c.approveWithKey("n")
	}
}

func (c *terminalConsole) approveWithKey(key string) protocol.Role {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.model.HandleKey(key)
	decision := c.model.Decision()
	if decision.Accepted {
		c.model.SetPeer(decision.GuestName, decision.Role)
		c.model.SetTransportStatus("approved")
	} else {
		c.model.SetPeer(decision.GuestName, protocol.RoleDenied)
		c.model.SetTransportStatus("denied")
	}
	_ = c.renderLocked()
	return decision.Role
}

func (c *terminalConsole) OnRuntimeEvent(event RuntimeEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch event.Kind {
	case RuntimeEventStatus:
		c.model.SetTransportStatus(event.Message)
	case RuntimeEventChat:
		c.model.AddSidechatLine(formatChat(event.Chat))
	case RuntimeEventRole:
		c.model.SetRole(event.Role)
	case RuntimeEventPeer:
		c.model.SetPeer(event.DisplayName, event.Role)
	case RuntimeEventResize:
		if event.ParticipantID == "" {
			c.model.SetSize(event.Cols, event.Rows)
		}
	case RuntimeEventClose:
		if strings.TrimSpace(event.Message) != "" {
			c.model.SetTransportStatus("closed: " + event.Message)
		} else {
			c.model.SetTransportStatus("closed")
		}
	}
	_ = c.renderLocked()
}

func (c *terminalConsole) renderLocked() error {
	view := c.model.View()
	if view == c.last {
		return nil
	}
	c.last = view
	if c.screen {
		_, err := fmt.Fprint(c.output, "\x1b[H\x1b[2J", view)
		return err
	}
	_, err := fmt.Fprintln(c.output, view)
	return err
}

func formatChat(msg ChatMessage) string {
	name := strings.TrimSpace(msg.DisplayName)
	if name == "" {
		name = msg.ParticipantID
	}
	return fmt.Sprintf("%s: %s", name, msg.Text)
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
