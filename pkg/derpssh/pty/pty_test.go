// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pty

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsExpectedCopyError(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrClosedPipe, os.ErrClosed, syscall.EIO, syscall.EPIPE, net.ErrClosed} {
		if !IsExpectedCopyError(err) {
			t.Fatalf("IsExpectedCopyError(%v) = false, want true", err)
		}
	}
	if IsExpectedCopyError(errors.New("permission denied")) {
		t.Fatal("IsExpectedCopyError(permission denied) = true, want false")
	}
}

func TestDefaultShell(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	if got := DefaultShell(); got != "/bin/zsh" {
		t.Fatalf("DefaultShell() = %q, want /bin/zsh", got)
	}
}
