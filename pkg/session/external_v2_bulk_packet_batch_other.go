// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type externalV2BulkPacketPortableBatchConn struct {
	conn  net.PacketConn
	stats *externalV2BulkPacketAtomicBatchStats
}

func newExternalV2BulkPacketPortableBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	return &externalV2BulkPacketPortableBatchConn{
		conn:  conn,
		stats: newExternalV2BulkPacketAtomicBatchStats("portable-single"),
	}
}

func (c *externalV2BulkPacketPortableBatchConn) WriteBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	written := 0
	for index := range messages {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		payload, err := externalV2BulkPacketFlattenMessage(messages[index].Buffers)
		if err != nil {
			return written, err
		}
		if err := c.armWriteDeadline(ctx); err != nil {
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

func (c *externalV2BulkPacketPortableBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	buffer, empty, err := externalV2BulkPacketPortableReadBuffer(messages)
	if err != nil || empty {
		return 0, err
	}
	for {
		n, addr, retry, err := c.readOne(ctx, buffer)
		if err != nil {
			return 0, err
		}
		if retry {
			continue
		}
		externalV2BulkPacketCommitPortableRead(&messages[0], n, addr)
		c.stats.observeReceive(1)
		return 1, nil
	}
}

func externalV2BulkPacketPortableReadBuffer(messages []externalV2BulkPacketBatchMessage) ([]byte, bool, error) {
	if len(messages) == 0 {
		return nil, true, nil
	}
	if len(messages[0].Buffers) != 1 || len(messages[0].Buffers[0]) == 0 {
		return nil, false, errors.New("portable bulk packet receive requires one non-empty buffer")
	}
	return messages[0].Buffers[0], false, nil
}

func (c *externalV2BulkPacketPortableBatchConn) readOne(ctx context.Context, buffer []byte) (int, net.Addr, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, false, err
	}
	if err := c.armReadDeadline(ctx); err != nil {
		return 0, nil, false, err
	}
	n, addr, err := c.conn.ReadFrom(buffer)
	if err == nil {
		return n, addr, false, nil
	}
	retry, err := externalV2BulkPacketRetryReadError(ctx, err)
	return 0, nil, retry, err
}

func externalV2BulkPacketCommitPortableRead(message *externalV2BulkPacketBatchMessage, n int, addr net.Addr) {
	message.N = n
	message.NN = 0
	message.Flags = 0
	message.Addr = addr
}

func (c *externalV2BulkPacketPortableBatchConn) Stats() externalV2BulkPacketBatchStats {
	return c.stats.snapshot()
}

func (c *externalV2BulkPacketPortableBatchConn) armReadDeadline(ctx context.Context) error {
	return c.conn.SetReadDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now()))
}

func (c *externalV2BulkPacketPortableBatchConn) armWriteDeadline(ctx context.Context) error {
	return externalV2BulkPacketArmWriteDeadline(ctx, c.conn)
}
