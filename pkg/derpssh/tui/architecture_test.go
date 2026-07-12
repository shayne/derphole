// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tui

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCharmV2ArchitectureHasNoLegacyFiles(t *testing.T) {
	for _, path := range []string{"canvas.go", "composer.go"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy file %s still exists or returned unexpected error: %v", path, err)
		}
	}
}

func TestCharmV2ArchitectureHasNoLegacySurface(t *testing.T) {
	var violations []string
	err := filepath.WalkDir("..", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, violation := range charmV2ArchitectureViolations(path, source) {
			violations = append(violations, fmt.Sprintf("%s: %s", path, violation))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("legacy Charm surface remains:\n%s", strings.Join(violations, "\n"))
	}
}

func TestCharmV2ArchitectureRulesRejectForbiddenSnippets(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "v1 import", source: `package sample; import "github.com/charmbracelet/bubbletea"`, want: "legacy Charm import github.com/charmbracelet/bubbletea"},
		{name: "v1 subpackage import", source: `package sample; import "charm.land/bubbles/textarea"`, want: "legacy Charm import charm.land/bubbles/textarea"},
		{name: "compat import", source: `package sample; import "charm.land/lipgloss/v2/compat"`, want: "legacy Charm import charm.land/lipgloss/v2/compat"},
		{name: "custom canvas", source: "package sample; type " + legacyCanvasTypeName + " struct{}", want: "banned type " + legacyCanvasTypeName},
		{name: "custom composer", source: `package sample; type Composer struct{}`, want: "banned type Composer"},
		{name: "coordinate hit dispatch", source: `package sample; func (Layout) Hit(int, int) HitTarget { return 0 }`, want: "banned method Layout.Hit"},
		{name: "manual renderer", source: `package sample; func renderComposerLine() {}`, want: "banned function renderComposerLine"},
		{name: "manual hit state", source: "package sample; var " + manualTopBarStateName + " []int", want: "banned identifier " + manualTopBarStateName},
		{name: "manual hit type", source: `package sample; type topBarHit struct{}`, want: "banned type topBarHit"},
		{name: "clipboard command", source: "package sample; type " + copyInviteCommandName + " struct{}", want: "banned type " + copyInviteCommandName},
		{name: "osc52", source: "package sample; func " + osc52Name + "() {}", want: "banned function " + osc52Name},
		{name: "compat color", source: "package sample; var _ = " + adaptiveColorName + "{}", want: "banned identifier " + adaptiveColorName},
		{name: "imperative mouse", source: "package sample; var _ = tea." + enableMouseCellMotionName, want: "banned identifier " + enableMouseCellMotionName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := charmV2ArchitectureViolations(tt.name+".go", []byte(tt.source))
			if !slices.Contains(got, tt.want) {
				t.Fatalf("violations = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCharmV2ArchitectureRulesAllowV2SceneSurface(t *testing.T) {
	source := []byte(`package sample
import (
	"charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)
type Scene struct{}
type StyleSet struct { Composer int }
`)
	if got := charmV2ArchitectureViolations("scene.go", source); len(got) != 0 {
		t.Fatalf("v2 Scene violations = %q, want none", got)
	}
}

var bannedCharmImports = map[string]struct{}{
	"github.com/charmbracelet/bubbles":   {},
	"github.com/charmbracelet/bubbletea": {},
	"github.com/charmbracelet/lipgloss":  {},
	"charm.land/bubbles":                 {},
	"charm.land/bubbletea":               {},
	"charm.land/lipgloss":                {},
	"charm.land/lipgloss/v2/compat":      {},
}

const (
	adaptiveColorName         = "Adaptive" + "Color"
	copyInviteCommandName     = "CopyInvite" + "Command"
	enableMouseCellMotionName = "EnableMouse" + "CellMotion"
	legacyCanvasTypeName      = "Frame" + "Canvas"
	legacyCanvasCtorName      = "NewFrame" + "Canvas"
	manualTopBarStateName     = "topBar" + "Hits"
	osc52Name                 = "osc" + "52"
)

var bannedCharmTypes = map[string]struct{}{
	"Canvas":              {},
	"Cell":                {},
	"Composer":            {},
	"ComposerOptions":     {},
	copyInviteCommandName: {},
	legacyCanvasTypeName:  {},
	"Header":              {},
	"HitTarget":           {},
	"Point":               {},
	"topBarHit":           {},
}

var bannedCharmFunctions = map[string]struct{}{
	"NewComposer":                   {},
	legacyCanvasCtorName:            {},
	"approvalHit":                   {},
	"helpActionAt":                  {},
	"modalOverlayWidth":             {},
	"osc52":                         {},
	"overlayFromColumn":             {},
	"overlayLine":                   {},
	"peerActionHit":                 {},
	"quitHit":                       {},
	"renderComposerLine":            {},
	"renderComposerPlaceholderLine": {},
	"renderContent":                 {},
	"renderModalBox":                {},
	"renderModalContentLine":        {},
	"renderTopBar":                  {},
	"replaceRange":                  {},
	"selectApprovalHit":             {},
	"shellExitHit":                  {},
	"topBarHitAt":                   {},
	"usesLegacyFrameRendering":      {},
}

var bannedCharmIdentifiers = map[string]struct{}{
	adaptiveColorName:         {},
	"ClearScreen":             {},
	"Disable" + "Mouse":       {},
	"EnableMouseAllMotion":    {},
	enableMouseCellMotionName: {},
	"EnterAltScreen":          {},
	"ExitAltScreen":           {},
	manualTopBarStateName:     {},
	"WithAltScreen":           {},
	"WithMouseAllMotion":      {},
	"WithMouseCellMotion":     {},
}

func charmV2ArchitectureViolations(filename string, source []byte) []string {
	file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		return []string{"parse error: " + err.Error()}
	}
	var violations []string
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if isBannedCharmImport(path) {
			violations = append(violations, "legacy Charm import "+path)
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.TypeSpec:
			if _, banned := bannedCharmTypes[node.Name.Name]; banned {
				violations = append(violations, "banned type "+node.Name.Name)
			}
		case *ast.FuncDecl:
			if isLayoutHitMethod(node) {
				violations = append(violations, "banned method Layout.Hit")
			} else if _, banned := bannedCharmFunctions[node.Name.Name]; banned {
				violations = append(violations, "banned function "+node.Name.Name)
			}
		case *ast.Ident:
			if _, banned := bannedCharmIdentifiers[node.Name]; banned {
				violations = append(violations, "banned identifier "+node.Name)
			}
		}
		return true
	})
	slices.Sort(violations)
	return slices.Compact(violations)
}

func isBannedCharmImport(path string) bool {
	if _, banned := bannedCharmImports[path]; banned {
		return true
	}
	if strings.HasPrefix(path, "github.com/charmbracelet/bubbles/") ||
		strings.HasPrefix(path, "github.com/charmbracelet/bubbletea/") ||
		strings.HasPrefix(path, "github.com/charmbracelet/lipgloss/") ||
		strings.HasPrefix(path, "charm.land/lipgloss/v2/compat/") {
		return true
	}
	for _, module := range []string{"charm.land/bubbles", "charm.land/bubbletea", "charm.land/lipgloss"} {
		suffix, ok := strings.CutPrefix(path, module+"/")
		if ok && suffix != "v2" && !strings.HasPrefix(suffix, "v2/") {
			return true
		}
	}
	return false
}

func isLayoutHitMethod(decl *ast.FuncDecl) bool {
	if decl.Name.Name != "Hit" || decl.Recv == nil || len(decl.Recv.List) != 1 {
		return false
	}
	receiver := decl.Recv.List[0].Type
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver = pointer.X
	}
	name, ok := receiver.(*ast.Ident)
	return ok && name.Name == "Layout"
}
