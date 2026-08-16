// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
)

const targetModalBlocker layerTarget = "modal:blocker"

const (
	modalLayerZ      = 1000
	modalLayerStride = 4
)

func modalTarget(id ModalID) layerTarget {
	return layerTarget("modal:" + string(id))
}

func modalChoiceTarget(id ModalID, choice string) layerTarget {
	return layerTarget(string(id) + ":" + choice)
}

func (a *App) buildModalLayers(frame ModalFrame) []*lipgloss.Layer {
	stack := a.modalStack()
	if !stack.HasDialogs() || frame.Width <= 0 || frame.Height <= 0 {
		return nil
	}

	var front []*lipgloss.Layer
	outer := Rect{W: frame.Width, H: frame.Height}
	backdrop := dimModalBackdrop(frame.Backdrop, frame.Width, frame.Height, frame.Styles.ModalBackdrop)
	for i, dialog := range stack.dialogs {
		z := modalLayerZ + i*modalLayerStride
		modalLayers := []*lipgloss.Layer{sceneLayer(
			targetModalBlocker,
			outer,
			z,
			backdrop,
		)}
		modalLayers = append(modalLayers, modalPanelLayers(dialog, frame, z+1)...)
		modalLayers = append(modalLayers, a.modalControlLayers(dialog.ID(), z+3)...)
		front = modalLayers
		if i+1 < len(stack.dialogs) {
			backdrop = composeScene(frame.Width, frame.Height, modalLayers...).Content
		}
	}
	return front
}

func dimModalBackdrop(backdrop string, width int, height int, style lipgloss.Style) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	canvas := lipgloss.NewCanvas(width, height)
	uv.NewStyledString(fitSceneContent(backdrop, width, height)).Draw(canvas, canvas.Bounds())
	target := style.GetBackground()
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			cell := canvas.CellAt(x, y).Clone()
			if cell.Style.Fg == nil {
				cell.Style.Fg = style.GetForeground()
			} else {
				cell.Style.Fg = dimModalColor(cell.Style.Fg, target, 0.35)
			}
			cell.Style.Bg = dimModalColor(cell.Style.Bg, target, 0.45)
			canvas.SetCell(x, y, cell)
		}
	}
	return fitSceneContent(canvas.Render(), width, height)
}

func dimModalColor(value color.Color, target color.Color, amount float64) color.Color {
	if value == nil || target == nil {
		return value
	}
	vr, vg, vb, _ := value.RGBA()
	tr, tg, tb, _ := target.RGBA()
	mix := func(from uint32, to uint32) uint8 {
		return uint8(float64(from>>8)*(1-amount) + float64(to>>8)*amount)
	}
	return color.RGBA{R: mix(vr, tr), G: mix(vg, tg), B: mix(vb, tb), A: 0xFF}
}

func modalPanelLayers(dialog ModalDialog, frame ModalFrame, z int) []*lipgloss.Layer {
	lines := dialog.Lines()
	bounds := modalBounds(frame, lines)
	if bounds.empty() {
		return nil
	}

	id := modalTarget(dialog.ID())
	panel := frame.Styles.Modal.
		Width(bounds.W).
		Height(bounds.H).
		Render("")
	layers := []*lipgloss.Layer{sceneLayer(id, bounds, z, panel)}

	content := modalContentRect(bounds, frame.Styles)
	if content.empty() {
		return layers
	}
	return append(layers, sceneLayer(
		id,
		content,
		z+1,
		renderModalSceneContent(lines, frame.Styles, content.W, content.H),
	))
}

func modalContentRect(bounds Rect, styles StyleSet) Rect {
	x := bounds.X + styles.Modal.GetBorderLeftSize() + styles.Modal.GetPaddingLeft()
	y := bounds.Y + styles.Modal.GetBorderTopSize() + styles.Modal.GetPaddingTop()
	return Rect{
		X: x,
		Y: y,
		W: maxInt(bounds.W-styles.Modal.GetHorizontalBorderSize()-styles.Modal.GetHorizontalPadding(), 0),
		H: maxInt(bounds.H-styles.Modal.GetVerticalBorderSize()-styles.Modal.GetVerticalPadding(), 0),
	}
}

func renderModalSceneContent(lines []string, styles StyleSet, width int, height int) string {
	rendered := make([]string, height)
	for i := range rendered {
		line := ""
		if i < len(lines) {
			line = ansi.Truncate(strings.TrimRight(lines[i], " "), width, "")
		}
		padding := strings.Repeat(" ", maxInt(width-displayWidth(line), 0))
		if strings.Contains(line, "\x1b[") {
			rendered[i] = line + styles.ModalInterior.Render(padding)
		} else {
			rendered[i] = styles.ModalInterior.Render(line + padding)
		}
	}
	return strings.Join(rendered, "\n")
}

func (a *App) modalControlLayers(id ModalID, z int) []*lipgloss.Layer {
	switch id {
	case ModalApproval:
		read, write, deny := a.approvalButtonRects()
		return []*lipgloss.Layer{
			sceneLayer(modalChoiceTarget(id, "read"), read, z, a.renderApprovalButton(approvalChoiceRead)),
			sceneLayer(modalChoiceTarget(id, "write"), write, z, a.renderApprovalButton(approvalChoiceWrite)),
			sceneLayer(modalChoiceTarget(id, "deny"), deny, z, a.renderApprovalButton(approvalChoiceDeny)),
		}
	case ModalPeerAction:
		read, write, kick := a.peerActionButtonRects()
		return []*lipgloss.Layer{
			sceneLayer(modalChoiceTarget(id, "read"), read, z, a.renderPeerActionButton(peerActionRead)),
			sceneLayer(modalChoiceTarget(id, "write"), write, z, a.renderPeerActionButton(peerActionWrite)),
			sceneLayer(modalChoiceTarget(id, "kick"), kick, z, a.renderPeerActionButton(peerActionKick)),
		}
	case ModalQuit:
		quit, cancel := a.quitButtonRects()
		return []*lipgloss.Layer{
			sceneLayer(modalChoiceTarget(id, "quit"), quit, z, a.renderQuitButton(quitChoiceQuit)),
			sceneLayer(modalChoiceTarget(id, "cancel"), cancel, z, a.renderQuitButton(quitChoiceCancel)),
		}
	case ModalShellExit:
		restart, quit := a.shellExitButtonRects()
		return []*lipgloss.Layer{
			sceneLayer(modalChoiceTarget(id, "restart"), restart, z, a.renderShellExitButton(shellExitChoiceRestart)),
			sceneLayer(modalChoiceTarget(id, "quit"), quit, z, a.renderShellExitButton(shellExitChoiceQuit)),
		}
	case ModalHelp:
		return a.helpActionLayers(z)
	default:
		return nil
	}
}

func (a *App) helpActionLayers(z int) []*lipgloss.Layer {
	contentX, contentY := a.helpContentOrigin()
	width := a.helpContentWidth()
	entries := a.menuEntries()
	layers := make([]*lipgloss.Layer, 0, len(entries))
	for i, entry := range entries {
		rect := Rect{X: contentX, Y: contentY + 2 + i, W: width, H: 1}
		layers = append(layers, sceneLayer(
			actionTarget(entry.action),
			rect,
			z,
			a.menuEntryLine(entry, width),
		))
	}
	return layers
}
