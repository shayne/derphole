// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import "strings"

type Header struct {
	app *App
}

func (h Header) View() string {
	if h.app == nil {
		return ""
	}
	a := h.app
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
