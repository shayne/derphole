// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//lint:ignore SA1019 x/sys has no recvmsg_x wrapper; Darwin batching requires this stable XNU syscall.
const externalV2BulkPacketDarwinRecvmsgX = unix.SYS_RECVMSG_X //nolint:staticcheck // See the lint:ignore rationale above.

type externalV2BulkPacketDarwinMsgHdr struct {
	Name       *byte
	NameLen    uint32
	Iov        *unix.Iovec
	IovLen     int32
	Control    *byte
	ControlLen uint32
	Flags      int32
	DataLen    uint64
}

type externalV2BulkPacketDarwinBatchConn struct {
	conn    net.PacketConn
	raw     syscall.RawConn
	stats   *externalV2BulkPacketAtomicBatchStats
	headers [externalV2BulkPacketMaxBatch]externalV2BulkPacketDarwinMsgHdr
	iovs    [externalV2BulkPacketMaxBatch]unix.Iovec
}

func newExternalV2BulkPacketBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	batch := &externalV2BulkPacketDarwinBatchConn{
		conn:  conn,
		stats: newExternalV2BulkPacketAtomicBatchStats("portable-single"),
	}
	if syscallConn, ok := conn.(syscall.Conn); ok {
		batch.raw, _ = syscallConn.SyscallConn()
	}
	return batch
}

func (c *externalV2BulkPacketDarwinBatchConn) WriteBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	written := 0
	for index := range messages {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		payload, err := externalV2BulkPacketFlattenMessage(messages[index].Buffers)
		if err != nil {
			return written, err
		}
		if err := c.conn.SetWriteDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now())); err != nil {
			return written, err
		}
		n, err := c.conn.WriteTo(payload, messages[index].Addr)
		if n > 0 {
			c.stats.observeSend(1)
		}
		if err != nil {
			return written, err
		}
		if n != len(payload) {
			return written, io.ErrShortWrite
		}
		messages[index].N = n
		written++
	}
	return written, nil
}

func (c *externalV2BulkPacketDarwinBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(messages) == 0 {
		return 0, nil
	}
	if c.raw == nil {
		return c.readPortable(ctx, messages)
	}
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	if err := c.prepareRecvmsgX(messages); err != nil {
		return 0, err
	}
	return c.readRecvmsgXLoop(ctx, messages)
}

func (c *externalV2BulkPacketDarwinBatchConn) readRecvmsgXLoop(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	for {
		if err := c.conn.SetReadDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now())); err != nil {
			return 0, err
		}
		count, err := c.recvmsgX(messages)
		if err == nil {
			c.stats.setBackend("darwin-recvmsg-x")
			c.stats.observeReceive(count)
			return count, nil
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			continue
		}
		return 0, err
	}
}

func (c *externalV2BulkPacketDarwinBatchConn) prepareRecvmsgX(messages []externalV2BulkPacketBatchMessage) error {
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 {
			return errors.New("darwin bulk packet receive requires one non-empty buffer")
		}
		buffer := messages[index].Buffers[0]
		c.iovs[index] = unix.Iovec{Base: &buffer[0], Len: uint64(len(buffer))}
		c.headers[index] = externalV2BulkPacketDarwinMsgHdr{
			Iov:    &c.iovs[index],
			IovLen: 1,
		}
	}
	return nil
}

func (c *externalV2BulkPacketDarwinBatchConn) recvmsgX(messages []externalV2BulkPacketBatchMessage) (int, error) {
	count := 0
	var syscallErr error
	err := c.raw.Read(func(fd uintptr) bool {
		for {
			received, _, errno := unix.Syscall6(
				externalV2BulkPacketDarwinRecvmsgX,
				fd,
				uintptr(unsafe.Pointer(&c.headers[0])),
				uintptr(len(messages)),
				uintptr(unix.MSG_DONTWAIT),
				0,
				0,
			)
			switch errno {
			case 0:
				count = int(received)
				return true
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				return false
			default:
				syscallErr = errno
				return true
			}
		}
	})
	runtime.KeepAlive(messages)
	runtime.KeepAlive(c.headers)
	runtime.KeepAlive(c.iovs)
	if err != nil {
		return 0, err
	}
	if syscallErr != nil {
		return 0, syscallErr
	}
	for index := 0; index < count; index++ {
		messages[index].N = int(c.headers[index].DataLen)
		messages[index].NN = 0
		messages[index].Flags = int(c.headers[index].Flags)
		messages[index].Addr = nil
	}
	return count, nil
}

func (c *externalV2BulkPacketDarwinBatchConn) readPortable(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	buffer := messages[0].Buffers
	if len(buffer) != 1 || len(buffer[0]) == 0 {
		return 0, errors.New("portable bulk packet receive requires one non-empty buffer")
	}
	if err := c.conn.SetReadDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now())); err != nil {
		return 0, err
	}
	n, addr, err := c.conn.ReadFrom(buffer[0])
	if err != nil {
		return 0, err
	}
	messages[0].N = n
	messages[0].Addr = addr
	c.stats.observeReceive(1)
	return 1, nil
}

func (c *externalV2BulkPacketDarwinBatchConn) Stats() externalV2BulkPacketBatchStats {
	return c.stats.snapshot()
}
