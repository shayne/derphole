// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"io"
	"sync"
	"testing"
)

type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }

func TestExternalHandoffCarrierRuntimeWaitAllowsDynamicAdd(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)

	runtime := newExternalHandoffCarrierRuntime(func(io.ReadWriteCloser) error {
		started <- struct{}{}
		<-release
		return nil
	})

	if err := runtime.Add(nopReadWriteCloser{}); err != nil {
		t.Fatalf("Add(first) error = %v", err)
	}
	<-started

	var (
		waitErr error
		waitWG  sync.WaitGroup
	)
	waitWG.Add(1)
	go func() {
		defer waitWG.Done()
		waitErr = runtime.Wait()
	}()

	if err := runtime.Add(nopReadWriteCloser{}); err != nil {
		t.Fatalf("Add(second) error = %v", err)
	}
	<-started

	close(release)
	waitWG.Wait()
	if waitErr != nil {
		t.Fatalf("Wait() error = %v", waitErr)
	}
}

func TestExternalHandoffCarrierRuntimeCloseRejectsNewAdditions(t *testing.T) {
	runtime := newExternalHandoffCarrierRuntime(func(io.ReadWriteCloser) error { return nil })
	runtime.Close()
	if err := runtime.Add(nopReadWriteCloser{}); err != errExternalHandoffRuntimeClosed {
		t.Fatalf("Add() error = %v, want %v", err, errExternalHandoffRuntimeClosed)
	}
}
