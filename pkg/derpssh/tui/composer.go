// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

type ComposerOptions struct {
	Width           int
	Placeholder     string
	MaxVisibleLines int
}

type Composer struct {
	width           int
	placeholder     string
	maxVisibleLines int
	text            string
	focused         bool
}

func NewComposer(opts ComposerOptions) Composer {
	placeholder := opts.Placeholder
	if placeholder == "" {
		placeholder = "Message"
	}
	maxVisible := opts.MaxVisibleLines
	if maxVisible <= 0 {
		maxVisible = 3
	}
	return Composer{
		width:           maxInt(opts.Width, 1),
		placeholder:     placeholder,
		maxVisibleLines: maxVisible,
	}
}

func (c *Composer) SetText(text string) {
	c.text = text
}

func (c *Composer) Focus() {
	c.focused = true
}

func (c Composer) VisibleLines() []string {
	lines := wrapPlainLines(c.text, maxInt(c.width, 1))
	maxVisible := clampInt(c.maxVisibleLines, 1, 3)
	if len(lines) > maxVisible {
		return lines[:maxVisible]
	}
	return lines
}

func (c Composer) RenderLines(Theme) []string {
	width := maxInt(c.width, 1)
	if c.text == "" {
		return []string{renderComposerPlaceholderLine(c.placeholder, width, c.focused)}
	}
	lines := c.VisibleLines()
	for i := range lines {
		lines[i] = renderComposerLine(lines[i], composerStyle, width, c.focused && i == len(lines)-1)
	}
	return lines
}
