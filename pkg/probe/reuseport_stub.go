// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !darwin

package probe

import (
	"errors"
	"syscall"
)

func reusePortControl(network, address string, c syscall.RawConn) error {
	return errors.New("SO_REUSEPORT unsupported on this platform")
}
