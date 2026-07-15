// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestLinuxOpenFileIdentityUsesRealFileStat(t *testing.T) {
	path := t.TempDir() + "/executable"
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open executable: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat executable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("real Linux FileInfo.Sys() has type %T, want *syscall.Stat_t", info.Sys())
	}
	want := fmt.Sprintf("dev:%d-ino:%d", uint64(stat.Dev), stat.Ino)

	got, err := linuxOpenFileIdentity(file)
	if err != nil {
		t.Fatalf("linuxOpenFileIdentity: %v", err)
	}
	if got != want {
		t.Fatalf("linuxOpenFileIdentity() = %q, want %q", got, want)
	}
}
