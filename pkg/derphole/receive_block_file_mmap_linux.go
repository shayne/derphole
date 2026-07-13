// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package derphole

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func allocateReceiveBlockFile(file *os.File, size int64) (bool, error) {
	if file == nil || size <= 0 {
		return false, nil
	}
	for {
		err := unix.Fallocate(int(file.Fd()), 0, 0, size)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EINVAL):
			return false, nil
		default:
			return false, err
		}
	}
}

func prepareReceiveBlockFile(buffer []byte, start, end int64) error {
	if start >= end {
		return nil
	}
	return unix.Madvise(buffer[int(start):int(end)], unix.MADV_POPULATE_WRITE)
}

// The initial receive window is populated before transport setup. For later
// windows, let the decrypt workers fault pages naturally instead of running
// MADV_POPULATE_WRITE concurrently with the latency-sensitive UDP receive
// path. The background window still reclaims completed regions.
func prepareReceiveBlockFileWindow([]byte, int64, int64) error { return nil }

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
