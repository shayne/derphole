//go:build linux

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func observePlatformProcess(ctx context.Context, name string, pid int, _ time.Duration) (ProcessRef, error) {
	if err := ctx.Err(); err != nil {
		return ProcessRef{}, err
	}
	processRoot := filepath.Join("/proc", strconv.Itoa(pid))
	statInput, err := readHealthFile(filepath.Join(processRoot, "stat"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProcessRef{}, fmt.Errorf("process %d is absent", pid)
		}
		return ProcessRef{}, fmt.Errorf("inspect Linux process %d start identity: %w", pid, err)
	}
	observedName, startIdentity, err := parseLinuxProcessNameAndStartIdentity(statInput)
	if err != nil {
		return ProcessRef{}, err
	}
	if observedName != name {
		return ProcessRef{}, fmt.Errorf("linux process %d name does not match %s", pid, name)
	}
	executableIdentity, err := linuxExecutableIdentityAt(processRoot, pid)
	if err != nil {
		return ProcessRef{}, err
	}
	process := ProcessRef{Name: name, PID: pid, StartIdentity: startIdentity, ExecutableIdentity: executableIdentity}
	if err := verifyLinuxProcessIdentity(process, processRoot); err != nil {
		return ProcessRef{}, err
	}
	if err := ctx.Err(); err != nil {
		return ProcessRef{}, err
	}
	return process, nil
}

func verifyLinuxProcessIdentity(expected ProcessRef, processRoot string) error {
	if err := verifyLinuxProcessStartIdentity(expected, processRoot); err != nil {
		return err
	}
	executableIdentity, err := linuxExecutableIdentityAt(processRoot, expected.PID)
	if err != nil {
		return err
	}
	if executableIdentity != expected.ExecutableIdentity {
		return fmt.Errorf("linux process %d executable changed during identity capture", expected.PID)
	}
	return nil
}
