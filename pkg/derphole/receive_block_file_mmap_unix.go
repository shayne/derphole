// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux

package derphole

import (
	"os"

	"golang.org/x/sys/unix"
)

func mapReceiveBlockFile(file *os.File, size int64) ([]byte, error) {
	if size == 0 || size > int64(^uint(0)>>1) {
		return nil, nil
	}
	return unix.Mmap(int(file.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
}

func unmapReceiveBlockFile(buffer []byte) error {
	if len(buffer) == 0 {
		return nil
	}
	return unix.Munmap(buffer)
}
