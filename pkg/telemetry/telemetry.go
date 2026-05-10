// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package telemetry

import (
	"fmt"
	"io"
)

type Level int

const (
	LevelDefault Level = iota
	LevelVerbose
	LevelQuiet
	LevelSilent
)

type Emitter struct {
	w     io.Writer
	level Level
}

func New(w io.Writer, level Level) *Emitter {
	return &Emitter{w: w, level: level}
}

func (e *Emitter) Status(msg string) {
	if e.level == LevelQuiet || e.level == LevelSilent {
		return
	}
	_, _ = fmt.Fprintln(e.w, msg)
}

func (e *Emitter) Debug(msg string) {
	if e.level != LevelVerbose {
		return
	}
	_, _ = fmt.Fprintln(e.w, msg)
}

func (e *Emitter) DebugEnabled() bool {
	return e != nil && e.level == LevelVerbose
}
