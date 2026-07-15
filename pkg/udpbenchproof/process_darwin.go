//go:build darwin

// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func observePlatformProcess(ctx context.Context, name string, pid int, timeout time.Duration) (ProcessRef, error) {
	inspector := darwinProcessInspector{
		exists:        darwinProcessExists,
		startIdentity: darwinNativeProcessStartIdentity,
		command: func(ctx context.Context, path string, args ...string) (healthCommandResult, error) {
			return runHealthCommandResultWithExecutor(ctx, timeout, executeHealthCommand, path, args...)
		},
	}
	return observeDarwinProcess(ctx, name, pid, inspector)
}

func observeDarwinProcess(ctx context.Context, name string, pid int, inspector darwinProcessInspector) (ProcessRef, error) {
	present, err := inspector.exists(pid)
	if err != nil {
		return ProcessRef{}, fmt.Errorf("inspect Darwin process %d: %w", pid, err)
	}
	if !present {
		return ProcessRef{}, fmt.Errorf("process %d is absent", pid)
	}
	startIdentity, err := inspector.startIdentity(pid)
	if err != nil {
		return ProcessRef{}, err
	}
	executableResult, err := inspector.command(ctx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	if err != nil {
		return ProcessRef{}, err
	}
	if executableResult.ExitCode != 0 || executableResult.Stderr != "" {
		return ProcessRef{}, fmt.Errorf("darwin ps executable identity failed")
	}
	executableIdentity := strings.TrimSpace(executableResult.Stdout)
	if executableIdentity == "" || filepath.Base(executableIdentity) != name {
		return ProcessRef{}, fmt.Errorf("darwin process %d name does not match %s", pid, name)
	}
	return ProcessRef{Name: name, PID: pid, StartIdentity: startIdentity, ExecutableIdentity: executableIdentity}, nil
}
