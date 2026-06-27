// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pty

import "golang.org/x/term"

type RawState = term.State

func MakeRaw(fd uintptr) (*RawState, error) {
	return term.MakeRaw(int(fd))
}

func Restore(fd uintptr, state *RawState) error {
	return term.Restore(int(fd), state)
}

func IsTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}
