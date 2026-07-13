// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package derphole

import (
	"os"
	"syscall"
	"testing"
)

func TestAllocateReceiveBlockFileReservesDiskBlocks(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "receive-preallocate-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	const size = int64(8 << 20)
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	allocated, err := allocateReceiveBlockFile(file, size)
	if err != nil {
		t.Fatal(err)
	}
	if !allocated {
		t.Skip("filesystem does not support fallocate")
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file stat did not expose Linux block accounting")
	}
	if allocated := int64(stat.Blocks) * 512; allocated < size {
		t.Fatalf("allocated bytes = %d, want at least %d", allocated, size)
	}
}
