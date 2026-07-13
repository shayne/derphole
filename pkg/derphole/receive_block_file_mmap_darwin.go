// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package derphole

import (
	"os"

	"golang.org/x/sys/unix"
)

func allocateReceiveBlockFile(*os.File, int64) (bool, error) { return false, nil }

func prepareReceiveBlockFile(buffer []byte, start, end int64) error {
	if start >= end {
		return nil
	}
	return unix.Madvise(buffer[int(start):int(end)], unix.MADV_WILLNEED)
}

func prepareReceiveBlockFileWindow(buffer []byte, start, end int64) error {
	return prepareReceiveBlockFile(buffer, start, end)
}

func releaseReceiveBlockFile(buffer []byte, start, end int64) error {
	if start >= end {
		return nil
	}
	window := buffer[int(start):int(end)]
	if err := unix.Msync(window, unix.MS_ASYNC); err != nil {
		return err
	}
	return unix.Madvise(window, unix.MADV_DONTNEED)
}
