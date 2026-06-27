// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pty

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

type Size struct {
	Cols int
	Rows int
}

func DefaultShell() string {
	if shell := strings.TrimSpace(os.Getenv("SHELL")); shell != "" {
		return shell
	}
	return "/bin/sh"
}

func IsExpectedCopyError(err error) bool {
	if err == nil {
		return false
	}
	for _, expected := range []error{io.EOF, io.ErrClosedPipe, os.ErrClosed, syscall.EIO, syscall.EPIPE, syscall.ECONNRESET, net.ErrClosed} {
		if errors.Is(err, expected) {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "endpoint is closed for send")
}
