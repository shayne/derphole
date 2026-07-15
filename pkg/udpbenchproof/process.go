// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type processIdentityObserver func(context.Context, string, int, time.Duration) (ProcessRef, error)

type processIdentityResult struct {
	process ProcessRef
	err     error
}

var processIdentityGate = make(chan struct{}, 1)

// IdentifyProcess returns a stable, read-only identity for one exact live process.
func IdentifyProcess(ctx context.Context, name string, pid int, timeout time.Duration) (ProcessRef, error) {
	return identifyProcessWithObserverAndGate(ctx, name, pid, timeout, observePlatformProcess, processIdentityGate)
}

func identifyProcessWithObserverAndGate(ctx context.Context, name string, pid int, timeout time.Duration, observer processIdentityObserver, gate chan struct{}) (ProcessRef, error) {
	if err := validateProcessIdentityRequest(ctx, name, pid, timeout, observer, gate); err != nil {
		return ProcessRef{}, err
	}
	identityContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := runBoundedProcessIdentity(identityContext, name, pid, timeout, observer, gate)
	if err != nil {
		return ProcessRef{}, err
	}
	if result.err != nil {
		return ProcessRef{}, result.err
	}
	if err := validateIdentifiedProcess(result.process, name, pid); err != nil {
		return ProcessRef{}, err
	}
	return result.process, nil
}

func validateProcessIdentityRequest(ctx context.Context, name string, pid int, timeout time.Duration, observer processIdentityObserver, gate chan struct{}) error {
	if ctx == nil || observer == nil || gate == nil {
		return fmt.Errorf("process identity dependencies are nil")
	}
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "/\\\x00\r\n") || pid <= 0 || timeout <= 0 {
		return fmt.Errorf("process identity request is invalid")
	}
	return nil
}

func runBoundedProcessIdentity(ctx context.Context, name string, pid int, timeout time.Duration, observer processIdentityObserver, gate chan struct{}) (processIdentityResult, error) {
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return processIdentityResult{}, fmt.Errorf("process identity deadline waiting for bounded worker: %w", ctx.Err())
	}
	result := make(chan processIdentityResult, 1)
	go func() {
		defer func() { <-gate }()
		result <- observeStableProcessIdentity(ctx, name, pid, timeout, observer)
	}()
	select {
	case identity := <-result:
		if err := ctx.Err(); err != nil {
			return processIdentityResult{}, fmt.Errorf("process identity deadline: %w", err)
		}
		return identity, nil
	case <-ctx.Done():
		return processIdentityResult{}, fmt.Errorf("process identity deadline: %w", ctx.Err())
	}
}

func observeStableProcessIdentity(ctx context.Context, name string, pid int, timeout time.Duration, observer processIdentityObserver) (result processIdentityResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result.err = fmt.Errorf("process identity observation panic: %v", recovered)
		}
	}()
	first, err := observer(ctx, name, pid, timeout)
	if err != nil {
		return processIdentityResult{err: err}
	}
	second, err := observer(ctx, name, pid, timeout)
	if err != nil {
		return processIdentityResult{err: err}
	}
	if first != second {
		return processIdentityResult{err: fmt.Errorf("process identity changed during capture")}
	}
	return processIdentityResult{process: first}
}

func validateIdentifiedProcess(process ProcessRef, name string, pid int) error {
	if process.Name != name || process.PID != pid {
		return fmt.Errorf("observed process does not match identity request")
	}
	if err := validateOwnedProcessOptions([]ProcessRef{process}); err != nil {
		return fmt.Errorf("observed process identity is invalid: %w", err)
	}
	return nil
}
