//go:build darwin

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentifyProcessUsesDarwinNativeStartIdentity(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	process, err := IdentifyProcess(context.Background(), filepath.Base(executable), os.Getpid(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(process.StartIdentity, "darwin-") || process.ExecutableIdentity != executable {
		t.Fatalf("darwin process identity = %#v", process)
	}
}
