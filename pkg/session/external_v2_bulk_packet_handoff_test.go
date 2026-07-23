// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type handoffDeadlineConn struct {
	net.PacketConn
	mu                 sync.Mutex
	read               time.Time
	write              time.Time
	clearErr           error
	readClearCalls     int
	writeClearCalls    int
	deadlineClearCalls int
	closeCalls         int
	onClear            func()
}

func (c *handoffDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.read = deadline
	var onClear func()
	var err error
	if deadline.IsZero() {
		c.readClearCalls++
		onClear = c.onClear
		err = c.clearErr
	}
	c.mu.Unlock()
	if onClear != nil {
		onClear()
	}
	return err
}

func (c *handoffDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.write = deadline
	var onClear func()
	var err error
	if deadline.IsZero() {
		c.writeClearCalls++
		onClear = c.onClear
		err = c.clearErr
	}
	c.mu.Unlock()
	if onClear != nil {
		onClear()
	}
	return err
}

func (c *handoffDeadlineConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	var onClear func()
	var err error
	if deadline.IsZero() {
		c.deadlineClearCalls++
		onClear = c.onClear
		err = c.clearErr
	}
	c.mu.Unlock()
	if onClear != nil {
		onClear()
	}
	return err
}

func (c *handoffDeadlineConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	return nil
}

func (c *handoffDeadlineConn) assertCleared(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.read.IsZero() || !c.write.IsZero() {
		t.Fatalf("deadlines = read:%v write:%v, want zero", c.read, c.write)
	}
}

func (c *handoffDeadlineConn) assertDeadlineClearCalls(t *testing.T, wantDeadline, wantClose int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readClearCalls != 1 || c.writeClearCalls != 1 ||
		c.deadlineClearCalls != wantDeadline || c.closeCalls != wantClose {
		t.Fatalf(
			"deadline clear calls = read:%d write:%d deadline:%d close:%d, want read:1 write:1 deadline:%d close:%d",
			c.readClearCalls,
			c.writeClearCalls,
			c.deadlineClearCalls,
			c.closeCalls,
			wantDeadline,
			wantClose,
		)
	}
}

type handoffReadStep struct {
	count int
	err   error
}

type handoffScriptedBatchConn struct {
	mu    sync.Mutex
	steps []handoffReadStep
	calls int
	read  func(context.Context, []externalV2BulkPacketBatchMessage) (int, error)
}

type handoffDelayedDeadlineContext struct {
	context.Context
	deadline time.Time
	done     <-chan struct{}
}

func (c handoffDelayedDeadlineContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}

func (c handoffDelayedDeadlineContext) Done() <-chan struct{} {
	return c.done
}

func (*handoffScriptedBatchConn) WriteBatch(context.Context, []externalV2BulkPacketBatchMessage) (int, error) {
	return 0, errors.New("unexpected handoff test write")
}

func (c *handoffScriptedBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.read != nil {
		return c.read(ctx, messages)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.steps) == 0 {
		return 0, errors.New("handoff test exhausted read script")
	}
	step := c.steps[0]
	c.steps = c.steps[1:]
	return step.count, step.err
}

func (*handoffScriptedBatchConn) Stats() externalV2BulkPacketBatchStats {
	return externalV2BulkPacketBatchStats{}
}

func TestDrainExternalV2BulkPacketHandoffConsumesUntilQuiet(t *testing.T) {
	conn := &handoffDeadlineConn{}
	reader := &handoffScriptedBatchConn{steps: []handoffReadStep{
		{count: 3}, {count: 2}, {err: context.DeadlineExceeded},
	}}
	path := externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}
	got, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), path, externalV2BulkPacketHandoffDrainDeps{
		quietWindow:  time.Millisecond,
		hardTimeout:  50 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Lanes != 1 || got.Datagrams != 5 || got.Duration <= 0 {
		t.Fatalf("drain result = %+v, want one lane and five datagrams", got)
	}
	if reader.calls != 3 {
		t.Fatalf("read calls = %d, want 3", reader.calls)
	}
	conn.assertCleared(t)
	conn.assertDeadlineClearCalls(t, 0, 0)
}

func TestDrainExternalV2BulkPacketHandoffRunsLanesConcurrently(t *testing.T) {
	release := make(chan struct{})
	started := make(chan int, 2)
	conns := []net.PacketConn{&handoffDeadlineConn{}, &handoffDeadlineConn{}}
	var joined atomic.Int32
	var clearedBeforeJoin atomic.Bool
	for _, conn := range conns {
		conn.(*handoffDeadlineConn).onClear = func() {
			if joined.Load() != int32(len(conns)) {
				clearedBeforeJoin.Store(true)
			}
		}
	}
	readers := map[net.PacketConn]externalV2BulkPacketBatchConn{}
	for lane, conn := range conns {
		lane := lane
		calls := 0
		readers[conn] = &handoffScriptedBatchConn{read: func(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
			calls++
			if calls == 1 {
				started <- lane
				select {
				case <-release:
					return 1, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}
			joined.Add(1)
			return 0, context.DeadlineExceeded
		}}
	}
	path := externalV2BulkPacketPath{Conns: conns}
	done := make(chan error, 1)
	go func() {
		_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), path, externalV2BulkPacketHandoffDrainDeps{
			quietWindow:  time.Second,
			hardTimeout:  2 * time.Second,
			newBatchConn: func(conn net.PacketConn) externalV2BulkPacketBatchConn { return readers[conn] },
		})
		done <- err
	}()
	seen := map[int]bool{}
	startDeadline := time.NewTimer(250 * time.Millisecond)
	defer startDeadline.Stop()
	for range cap(started) {
		select {
		case lane := <-started:
			seen[lane] = true
		case <-startDeadline.C:
			close(release)
			t.Fatal("timed out waiting for both handoff lanes to start")
		}
	}
	if !seen[0] || !seen[1] {
		t.Fatalf("started lanes = %v, want 0 and 1", seen)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if clearedBeforeJoin.Load() {
		t.Fatal("cleared deadlines before every lane joined")
	}
	for _, conn := range conns {
		deadlineConn := conn.(*handoffDeadlineConn)
		deadlineConn.assertCleared(t)
		deadlineConn.assertDeadlineClearCalls(t, 0, 0)
	}
}

func TestDrainExternalV2BulkPacketHandoffHardDeadlineIsFatal(t *testing.T) {
	conn := &handoffDeadlineConn{}
	reader := &handoffScriptedBatchConn{read: func(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			return 1, nil
		}
	}}
	path := externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}
	_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), path, externalV2BulkPacketHandoffDrainDeps{
		quietWindow:  time.Millisecond,
		hardTimeout:  5 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err == nil || !strings.Contains(err.Error(), "bulk packet handoff lane 0: hard deadline") {
		t.Fatalf("drain error = %v, want lane hard-deadline failure", err)
	}
	conn.assertCleared(t)
	conn.assertDeadlineClearCalls(t, 0, 0)
}

func TestDrainExternalV2BulkPacketHandoffHardDeadlineWinsWhenTimerDeliveryLags(t *testing.T) {
	hardDeadline := time.Now().Add(10 * time.Millisecond)
	drainCtx := handoffDelayedDeadlineContext{
		Context:  context.Background(),
		deadline: hardDeadline,
		done:     make(chan struct{}),
	}
	reader := &handoffScriptedBatchConn{read: func(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
		<-ctx.Done()
		time.Sleep(time.Until(hardDeadline) + time.Millisecond)
		return 0, ctx.Err()
	}}

	_, err := drainExternalV2BulkPacketHandoffLane(drainCtx, time.Millisecond, reader)
	if err == nil || !strings.Contains(err.Error(), "hard deadline") {
		t.Fatalf("drain error = %v, want hard-deadline failure", err)
	}
}

func TestDrainExternalV2BulkPacketHandoffReadFailureJoinsOtherLanes(t *testing.T) {
	readFailure := errors.New("injected handoff read failure")
	otherStarted := make(chan struct{})
	otherJoined := make(chan struct{})
	releaseOther := make(chan struct{})
	conns := []net.PacketConn{&handoffDeadlineConn{}, &handoffDeadlineConn{}}
	readers := map[net.PacketConn]externalV2BulkPacketBatchConn{
		conns[0]: &handoffScriptedBatchConn{steps: []handoffReadStep{{err: readFailure}}},
		conns[1]: &handoffScriptedBatchConn{read: func(ctx context.Context, _ []externalV2BulkPacketBatchMessage) (int, error) {
			close(otherStarted)
			select {
			case <-releaseOther:
				close(otherJoined)
				return 0, context.DeadlineExceeded
			case <-ctx.Done():
				close(otherJoined)
				return 0, ctx.Err()
			}
		}},
	}
	done := make(chan error, 1)
	go func() {
		_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), externalV2BulkPacketPath{Conns: conns}, externalV2BulkPacketHandoffDrainDeps{
			quietWindow:  100 * time.Millisecond,
			hardTimeout:  200 * time.Millisecond,
			newBatchConn: func(conn net.PacketConn) externalV2BulkPacketBatchConn { return readers[conn] },
		})
		done <- err
	}()
	<-otherStarted
	select {
	case err := <-done:
		t.Fatalf("drain returned before other lane joined: %v", err)
	default:
	}
	close(releaseOther)
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "bulk packet handoff lane 0") ||
		!strings.Contains(err.Error(), "read queued datagrams") || !errors.Is(err, readFailure) {
		t.Fatalf("drain error = %v, want lane read failure", err)
	}
	select {
	case <-otherJoined:
	default:
		t.Fatal("other lane did not join before drain returned")
	}
	for _, conn := range conns {
		deadlineConn := conn.(*handoffDeadlineConn)
		deadlineConn.assertCleared(t)
		deadlineConn.assertDeadlineClearCalls(t, 0, 0)
	}
}

func TestDrainExternalV2BulkPacketHandoffRestoresDeadlinesAfterFailure(t *testing.T) {
	restoreFailure := errors.New("injected handoff deadline restoration failure")
	conn := &handoffDeadlineConn{clearErr: restoreFailure}
	reader := &handoffScriptedBatchConn{steps: []handoffReadStep{{err: context.DeadlineExceeded}}}
	_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}, externalV2BulkPacketHandoffDrainDeps{
		quietWindow:  time.Millisecond,
		hardTimeout:  50 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err == nil || !strings.Contains(err.Error(), "restore deadlines") ||
		!strings.Contains(err.Error(), "bulk packet lane 0 deadline cleanup") || !errors.Is(err, restoreFailure) {
		t.Fatalf("drain error = %v, want lane deadline restoration failure", err)
	}
	conn.assertCleared(t)
	conn.assertDeadlineClearCalls(t, 1, 1)
}

func TestDrainExternalV2BulkPacketHandoffStripsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &handoffDeadlineConn{}
	reader := &handoffScriptedBatchConn{steps: []handoffReadStep{{err: context.DeadlineExceeded}}}
	_, err := drainExternalV2BulkPacketHandoffWithDeps(ctx, externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}, externalV2BulkPacketHandoffDrainDeps{
		quietWindow:  time.Millisecond,
		hardTimeout:  50 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err != nil {
		t.Fatalf("drain with canceled caller context: %v", err)
	}
	conn.assertCleared(t)
	conn.assertDeadlineClearCalls(t, 0, 0)
}

func TestDrainExternalV2BulkPacketHandoffRejectsInvalidReadCount(t *testing.T) {
	for _, tt := range []struct {
		name  string
		count func(int) int
	}{
		{name: "negative", count: func(int) int { return -1 }},
		{name: "overlarge", count: func(messages int) int { return messages + 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := &handoffDeadlineConn{}
			calls := 0
			reader := &handoffScriptedBatchConn{read: func(_ context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
				calls++
				if calls > 1 {
					return 0, context.DeadlineExceeded
				}
				return tt.count(len(messages)), nil
			}}
			got, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}, externalV2BulkPacketHandoffDrainDeps{
				quietWindow:  time.Millisecond,
				hardTimeout:  50 * time.Millisecond,
				newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
			})
			if err == nil || !strings.Contains(err.Error(), "bulk packet handoff lane 0: read queued datagrams") ||
				!strings.Contains(err.Error(), "invalid bulk packet batch read count") {
				t.Fatalf("drain error = %v, want invalid lane read count", err)
			}
			if got.Datagrams != 0 {
				t.Fatalf("drained datagrams = %d, want zero after invalid read count", got.Datagrams)
			}
			conn.assertCleared(t)
			conn.assertDeadlineClearCalls(t, 0, 0)
		})
	}
}

func TestDrainExternalV2BulkPacketHandoffJoinsReadAndRestorationFailures(t *testing.T) {
	readFailure := errors.New("injected handoff read failure")
	restoreFailure := errors.New("injected handoff deadline restoration failure")
	conn := &handoffDeadlineConn{clearErr: restoreFailure}
	reader := &handoffScriptedBatchConn{steps: []handoffReadStep{{err: readFailure}}}
	_, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), externalV2BulkPacketPath{Conns: []net.PacketConn{conn}}, externalV2BulkPacketHandoffDrainDeps{
		quietWindow:  time.Millisecond,
		hardTimeout:  50 * time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn { return reader },
	})
	if err == nil || !errors.Is(err, readFailure) || !errors.Is(err, restoreFailure) ||
		!strings.Contains(err.Error(), "read queued datagrams") || !strings.Contains(err.Error(), "restore deadlines") {
		t.Fatalf("drain error = %v, want joined read and deadline restoration failures", err)
	}
	conn.assertCleared(t)
	conn.assertDeadlineClearCalls(t, 1, 1)
}

func TestDrainExternalV2BulkPacketHandoffValidatesInputs(t *testing.T) {
	validPath := externalV2BulkPacketPath{Conns: []net.PacketConn{&handoffDeadlineConn{}}}
	validDeps := externalV2BulkPacketHandoffDrainDeps{
		quietWindow: time.Millisecond,
		hardTimeout: time.Millisecond,
		newBatchConn: func(net.PacketConn) externalV2BulkPacketBatchConn {
			return &handoffScriptedBatchConn{steps: []handoffReadStep{{err: context.DeadlineExceeded}}}
		},
	}
	for _, tt := range []struct {
		name string
		path externalV2BulkPacketPath
		deps externalV2BulkPacketHandoffDrainDeps
	}{
		{name: "empty path", deps: validDeps},
		{name: "zero quiet window", path: validPath, deps: externalV2BulkPacketHandoffDrainDeps{hardTimeout: time.Millisecond, newBatchConn: validDeps.newBatchConn}},
		{name: "zero hard timeout", path: validPath, deps: externalV2BulkPacketHandoffDrainDeps{quietWindow: time.Millisecond, newBatchConn: validDeps.newBatchConn}},
		{name: "nil batch conn factory", path: validPath, deps: externalV2BulkPacketHandoffDrainDeps{quietWindow: time.Millisecond, hardTimeout: time.Millisecond}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := drainExternalV2BulkPacketHandoffWithDeps(context.Background(), tt.path, tt.deps); err == nil {
				t.Fatal("drain error = nil, want input validation error")
			}
		})
	}
}
