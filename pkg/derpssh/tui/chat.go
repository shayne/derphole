// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "strings"

type DisplayName string

type ChatPaneOptions struct {
	Width int
	Peers []DisplayName
}

type ChatPane struct {
	open        bool
	messages    []ChatLine
	wasAtBottom bool
	composer    Composer
	unread      int
	width       int
	peers       []DisplayName
	seenIDs     map[string]struct{}
}

type ChatLine struct {
	ID     string
	Author DisplayName
	Text   string
	Local  bool
}

func NewChatPane(opts ChatPaneOptions) *ChatPane {
	return &ChatPane{
		width:       maxInt(opts.Width, 1),
		peers:       append([]DisplayName(nil), opts.Peers...),
		wasAtBottom: true,
		composer:    NewComposer(ComposerOptions{Width: opts.Width, MaxVisibleLines: 3}),
		seenIDs:     make(map[string]struct{}),
	}
}

func (p *ChatPane) Append(line ChatLine) {
	if p == nil {
		return
	}
	if id := strings.TrimSpace(line.ID); id != "" {
		if _, ok := p.seenIDs[id]; ok {
			return
		}
		p.seenIDs[id] = struct{}{}
	}
	if p.absorbLocalEcho(line) {
		return
	}
	p.messages = append(p.messages, line)
	if !line.Local && !p.open {
		p.unread++
	}
}

func (p *ChatPane) RenderLines(Theme) []string {
	if p == nil {
		return nil
	}
	counts := p.displayNameCounts()
	lines := make([]string, 0, len(p.messages))
	for _, msg := range p.messages {
		prefix := displayHandleWithCounts(string(msg.Author), 16, counts)
		if prefix == "" {
			prefix = "peer"
		}
		body := strings.TrimSpace(msg.Text)
		lines = append(lines, wrapPlainLines(prefix+": "+body, p.width)...)
	}
	return lines
}

func (p *ChatPane) absorbLocalEcho(line ChatLine) bool {
	if line.Local {
		return false
	}
	for i := len(p.messages) - 1; i >= 0; i-- {
		existing := p.messages[i]
		if !existing.Local {
			continue
		}
		if strings.TrimSpace(string(existing.Author)) == strings.TrimSpace(string(line.Author)) &&
			strings.TrimSpace(existing.Text) == strings.TrimSpace(line.Text) {
			p.messages[i].Local = false
			return true
		}
	}
	return false
}

func (p *ChatPane) displayNameCounts() map[string]int {
	counts := make(map[string]int)
	for _, peer := range p.peers {
		incrementDisplayNameCount(counts, string(peer))
	}
	for _, msg := range p.messages {
		incrementDisplayNameCount(counts, string(msg.Author))
	}
	return counts
}

func incrementDisplayNameCount(counts map[string]int, name string) {
	user, _ := splitUserHost(name)
	if user != "" {
		counts[user]++
	}
}
