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

	leftSegments := a.leftTopBarSegments()
	brandSegments := leftSegments
	metadataSegments := []topBarSegment(nil)
	if len(leftSegments) > 1 {
		brandSegments = leftSegments[:1]
		metadataSegments = leftSegments[1:]
	}
	fixedRightSegments, transientRightSegments := fixedAndTransientRightSegments(a.rightTopBarSegments())

	brand, brandW := a.packHeaderSegments(brandSegments, rect.W)
	remaining := maxInt(rect.W-brandW, 0)
	fixedRight, fixedRightW := a.packHeaderSegments(fixedRightSegments, remaining)
	remaining = maxInt(remaining-fixedRightW, 0)
	transientRight, transientRightW := a.packHeaderSegments(transientRightSegments, remaining)
	remaining = maxInt(remaining-transientRightW, 0)
	metadata, metadataW := a.packHeaderSegments(metadataSegments, remaining)

	left := append(brand, shiftPackedHeaderItems(metadata, brandW)...)
	leftW := brandW + metadataW
	right := append(transientRight, shiftPackedHeaderItems(fixedRight, transientRightW)...)
	rightW := transientRightW + fixedRightW
	rightX := rect.X + leftW + maxInt(rect.W-leftW-rightW, 0)

	layers := []*lipgloss.Layer{
		sceneLayer(targetBase, rect, headerBaseLayerZ, sceneFill(a.styles.TopBar, rect)),
	}
	layers = append(layers, a.positionHeaderItems(left, rect.X, rect.Y)...)
	layers = append(layers, a.positionHeaderItems(right, rightX, rect.Y)...)
	return layers
}

func fixedAndTransientRightSegments(segments []topBarSegment) (fixed []topBarSegment, transient []topBarSegment) {
	for _, segment := range segments {
		switch segment.action {
		case ActionToggleChat, ActionShowMenu, ActionQuit:
			fixed = append(fixed, segment)
		default:
			transient = append(transient, segment)
		}
	}
	return fixed, transient
}

func shiftPackedHeaderItems(items []packedHeaderItem, offset int) []packedHeaderItem {
	shifted := make([]packedHeaderItem, len(items))
	copy(shifted, items)
	for i := range shifted {
		shifted[i].x += offset
	}
	return shifted
}

func (a *App) packHeaderSegments(segments []topBarSegment, maxWidth int) ([]packedHeaderItem, int) {
	if maxWidth <= 0 {
		return nil, 0
	}
	items := make([]packedHeaderItem, 0, len(segments))
	x := 0
	for _, segment := range segments {
		if strings.TrimSpace(segment.text) == "" {
			continue
		}
		target := headerSegmentTarget(segment)
		part := a.headerSegmentStyle(segment, target).Render(" " + segment.text + " ")
		partW := displayWidth(part)
		if x+partW > maxWidth {
			continue
		}
		items = append(items, packedHeaderItem{
			x:       x,
			content: part,
			target:  target,
		})
		x += partW
	}
	return items, x
}

func (a *App) headerSegmentStyle(segment topBarSegment, target layerTarget) lipgloss.Style {
	base := segment.style
	if !segment.preserveHoverStyle && segment.action == ActionToggleChat && a.sidebarVisible() {
		base = a.styles.TopBarActive
	}
	if segment.action == "" && segment.peer.ID == "" {
		return base
	}
	hover := a.styles.TopBarHover.
		Foreground(base.GetForeground()).
		Bold(base.GetBold())
	if segment.action == ActionQuit {
		hover = a.styles.TopBarDangerHover
	}
	return a.interactionStyle(target, base, hover, a.styles.TopBarPressed)
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
