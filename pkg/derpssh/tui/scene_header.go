// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

const (
	headerBaseLayerZ = 10
	headerItemLayerZ = 11
)

type packedHeaderItem struct {
	x       int
	content string
	target  layerTarget
}

func actionTarget(id ActionID) layerTarget {
	return layerTarget("action:" + string(id))
}

func peerTarget(id string) layerTarget {
	return layerTarget("peer:" + id)
}

func (a *App) buildHeaderLayers(layout Layout) []*lipgloss.Layer {
	rect := layout.TopBar
	if rect.empty() {
		return nil
	}

	right, rightW := a.packHeaderSegments(a.rightTopBarSegments(), rect.W)
	leftMax := maxInt(rect.W-rightW-1, 0)
	left, leftW := a.packHeaderSegments(a.leftTopBarSegments(), leftMax)
	rightX := rect.X + leftW + maxInt(rect.W-leftW-rightW, 0)

	layers := []*lipgloss.Layer{
		sceneLayer(targetBase, rect, headerBaseLayerZ, sceneFill(a.styles.TopBar, rect)),
	}
	layers = append(layers, a.positionHeaderItems(left, rect.X, rect.Y)...)
	layers = append(layers, a.positionHeaderItems(right, rightX, rect.Y)...)
	return layers
}

func (a *App) packHeaderSegments(segments []topBarSegment, maxWidth int) ([]packedHeaderItem, int) {
	if maxWidth <= 0 {
		return nil, 0
	}
	items := make([]packedHeaderItem, 0, len(segments)*2)
	x := 0
	for _, segment := range segments {
		if strings.TrimSpace(segment.text) == "" {
			continue
		}
		separator := ""
		separatorW := 0
		if x > 0 {
			separator = a.styles.TopBarSeparator.Render("›")
			separatorW = displayWidth(separator)
		}
		part := segment.style.Render(" " + segment.text + " ")
		partW := displayWidth(part)
		if x+separatorW+partW > maxWidth {
			continue
		}
		if separator != "" {
			items = append(items, packedHeaderItem{x: x, content: separator, target: targetBase})
			x += separatorW
		}
		items = append(items, packedHeaderItem{
			x:       x,
			content: part,
			target:  headerSegmentTarget(segment),
		})
		x += partW
	}
	return items, x
}

func (a *App) positionHeaderItems(items []packedHeaderItem, originX int, y int) []*lipgloss.Layer {
	layers := make([]*lipgloss.Layer, 0, len(items))
	for _, item := range items {
		width := displayWidth(item.content)
		rect := Rect{X: originX + item.x, Y: y, W: width, H: 1}
		layers = append(layers, sceneLayer(item.target, rect, headerItemLayerZ, item.content))
	}
	return layers
}

func headerSegmentTarget(segment topBarSegment) layerTarget {
	if id := strings.TrimSpace(segment.peer.ID); id != "" {
		return peerTarget(id)
	}
	if segment.action != "" {
		return actionTarget(segment.action)
	}
	return targetBase
}
