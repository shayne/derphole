// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin && !linux

package derphole

import "os"

func allocateReceiveBlockFile(*os.File, int64) (bool, error) { return false, nil }

func mapReceiveBlockFile(*os.File, int64) ([]byte, error) { return nil, nil }

func unmapReceiveBlockFile([]byte) error { return nil }

func prepareReceiveBlockFile([]byte, int64, int64) error { return nil }

func prepareReceiveBlockFileWindow([]byte, int64, int64) error { return nil }

func releaseReceiveBlockFile([]byte, int64, int64) error { return nil }
