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
	w          io.Writer
	level      Level
	statusHook func(string)
}

func New(w io.Writer, level Level) *Emitter {
	if w == nil {
		w = io.Discard
	}
	return &Emitter{w: w, level: level}
}

func WithStatusHook(e *Emitter, hook func(string)) *Emitter {
	if e == nil {
		return &Emitter{w: io.Discard, level: LevelQuiet, statusHook: hook}
	}
	next := *e
	next.statusHook = hook
	return &next
}

func (e *Emitter) Status(msg string) {
	if e == nil {
		return
	}
	if e.statusHook != nil {
		e.statusHook(msg)
	}
	if e.level == LevelQuiet || e.level == LevelSilent {
		return
	}
	_, _ = fmt.Fprintln(e.w, msg)
}

func (e *Emitter) Debug(msg string) {
	if e == nil {
		return
	}
	if e.level != LevelVerbose {
		return
	}
	_, _ = fmt.Fprintln(e.w, msg)
}

func (e *Emitter) DebugEnabled() bool {
	return e != nil && e.level == LevelVerbose
}
