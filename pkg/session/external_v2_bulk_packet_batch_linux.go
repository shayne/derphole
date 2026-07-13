// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package session

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const externalV2BulkPacketMaxIPv4Payload = 1<<16 - 1 - 20 - 8

type externalV2BulkPacketLinuxBatchConn struct {
	conn       net.PacketConn
	packetConn *ipv4.PacketConn
	stats      *externalV2BulkPacketAtomicBatchStats
	gsoCapable atomic.Bool
}

func newExternalV2BulkPacketBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	batch := &externalV2BulkPacketLinuxBatchConn{
		conn:       conn,
		packetConn: ipv4.NewPacketConn(conn),
		stats:      newExternalV2BulkPacketAtomicBatchStats("linux-sendmmsg"),
	}
	batch.gsoCapable.Store(externalV2BulkPacketLinuxGSOCapable(conn))
	return batch
}

func (c *externalV2BulkPacketLinuxBatchConn) WriteBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	empty, err := externalV2BulkPacketPrepareWrite(ctx, c.conn, len(messages))
	if err != nil {
		return 0, err
	}
	if empty {
		return 0, nil
	}
	return c.writePreparedBatch(messages)
}

func (c *externalV2BulkPacketLinuxBatchConn) writePreparedBatch(messages []externalV2BulkPacketBatchMessage) (int, error) {
	if !c.gsoCapable.Load() {
		return c.writeSendMMsg(messages)
	}
	if !externalV2BulkPacketCanGSO(messages) {
		return c.writeSendMMsg(messages)
	}
	if handled, written, err := c.tryWriteGSO(messages); handled {
		return written, err
	}
	return c.writeSendMMsg(messages)
}

func externalV2BulkPacketPrepareWrite(ctx context.Context, conn net.PacketConn, count int) (bool, error) {
	if count == 0 {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, conn.SetWriteDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now()))
}

func (c *externalV2BulkPacketLinuxBatchConn) tryWriteGSO(messages []externalV2BulkPacketBatchMessage) (bool, int, error) {
	c.stats.gsoAttempted.Store(true)
	written, err := c.writeGSO(messages)
	if err == nil || written == 1 {
		c.observeGSOSuccess(len(messages))
		return true, len(messages), nil
	}
	if !externalV2BulkPacketShouldDisableGSO(err) {
		return true, 0, err
	}
	c.disableGSO()
	return false, 0, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) observeGSOSuccess(count int) {
	c.stats.gsoActive.Store(true)
	c.stats.gsoSegments.Add(uint64(count))
	c.stats.setBackend("linux-gso")
	c.stats.observeSend(count)
}

func (c *externalV2BulkPacketLinuxBatchConn) disableGSO() {
	c.gsoCapable.Store(false)
	c.stats.gsoActive.Store(false)
	c.stats.setBackend("linux-sendmmsg")
}

func (c *externalV2BulkPacketLinuxBatchConn) writeSendMMsg(messages []externalV2BulkPacketBatchMessage) (int, error) {
	xMessages := make([]ipv4.Message, len(messages))
	for index := range messages {
		xMessages[index] = ipv4.Message{
			Buffers: messages[index].Buffers,
			OOB:     messages[index].OOB,
			Addr:    messages[index].Addr,
		}
	}
	written, err := c.packetConn.WriteBatch(xMessages, 0)
	if written > 0 {
		c.stats.observeSend(written)
		for index := 0; index < written; index++ {
			messages[index].N = externalV2BulkPacketMessageLength(messages[index].Buffers)
		}
	}
	return written, err
}

func (c *externalV2BulkPacketLinuxBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	messages, rxMessages, err := externalV2BulkPacketPrepareRead(messages)
	if err != nil || len(messages) == 0 {
		return 0, err
	}
	return c.readPreparedBatch(ctx, messages, rxMessages)
}

func externalV2BulkPacketPrepareRead(messages []externalV2BulkPacketBatchMessage) ([]externalV2BulkPacketBatchMessage, []ipv4.Message, error) {
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	rxMessages := make([]ipv4.Message, len(messages))
	for index := range messages {
		if len(messages[index].Buffers) == 0 {
			return nil, nil, errors.New("bulk packet receive message has no buffer")
		}
		rxMessages[index] = ipv4.Message{Buffers: messages[index].Buffers, OOB: messages[index].OOB}
	}
	return messages, rxMessages, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) readPreparedBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage, rxMessages []ipv4.Message) (int, error) {
	for {
		read, retry, err := c.readBatchAttempt(ctx, rxMessages)
		if err != nil {
			return 0, err
		}
		if retry {
			continue
		}
		return c.finishReadBatch(messages, rxMessages, read)
	}
}

func (c *externalV2BulkPacketLinuxBatchConn) finishReadBatch(messages []externalV2BulkPacketBatchMessage, rxMessages []ipv4.Message, read int) (int, error) {
	if err := externalV2BulkPacketCopyReadBatch(messages, rxMessages, read); err != nil {
		return 0, err
	}
	c.stats.setBackend("linux-recvmmsg")
	c.stats.observeReceive(read)
	return read, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) readBatchAttempt(ctx context.Context, rxMessages []ipv4.Message) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if err := c.conn.SetReadDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now())); err != nil {
		return 0, false, err
	}
	read, err := c.packetConn.ReadBatch(rxMessages, 0)
	if err == nil {
		return read, false, nil
	}
	return externalV2BulkPacketClassifyReadError(ctx, err)
}

func externalV2BulkPacketClassifyReadError(ctx context.Context, err error) (int, bool, error) {
	networkError, ok := err.(net.Error)
	if !ok {
		return 0, false, err
	}
	if !networkError.Timeout() {
		return 0, false, err
	}
	if ctx.Err() != nil {
		return 0, false, ctx.Err()
	}
	return 0, true, nil
}

func externalV2BulkPacketCopyReadBatch(messages []externalV2BulkPacketBatchMessage, rxMessages []ipv4.Message, read int) error {
	for index := 0; index < read; index++ {
		if rxMessages[index].Flags&unix.MSG_TRUNC != 0 {
			return errors.New("bulk packet receive batch contained a truncated datagram")
		}
		messages[index].N = rxMessages[index].N
		messages[index].NN = rxMessages[index].NN
		messages[index].Flags = rxMessages[index].Flags
		messages[index].Addr = rxMessages[index].Addr
	}
	return nil
}

func (c *externalV2BulkPacketLinuxBatchConn) Stats() externalV2BulkPacketBatchStats {
	return c.stats.snapshot()
}

func (c *externalV2BulkPacketLinuxBatchConn) writeGSO(messages []externalV2BulkPacketBatchMessage) (int, error) {
	control := make([]byte, 0, unix.CmsgSpace(2))
	externalV2BulkPacketSetGSOSize(&control, uint16(externalV2BulkPacketMessageLength(messages[0].Buffers)))
	buffers := make([][]byte, 0, len(messages))
	for _, message := range messages {
		buffers = append(buffers, message.Buffers[0])
	}
	return c.packetConn.WriteBatch([]ipv4.Message{{
		Buffers: buffers,
		OOB:     control,
		Addr:    messages[0].Addr,
	}}, 0)
}

func externalV2BulkPacketCanGSO(messages []externalV2BulkPacketBatchMessage) bool {
	if !externalV2BulkPacketGSOCountValid(len(messages)) {
		return false
	}
	segmentSize, destination, ok := externalV2BulkPacketGSOTemplate(messages[0])
	if !ok {
		return false
	}
	total, ok := externalV2BulkPacketGSOMessageTotal(messages, destination, segmentSize)
	if !ok {
		return false
	}
	return total <= externalV2BulkPacketMaxIPv4Payload
}

func externalV2BulkPacketGSOMessageTotal(messages []externalV2BulkPacketBatchMessage, destination string, segmentSize int) (int, bool) {
	total := 0
	shortSeen := false
	for index, message := range messages {
		length, ok := externalV2BulkPacketGSOMessageLength(message, destination, segmentSize)
		if !ok {
			return 0, false
		}
		if !externalV2BulkPacketGSOOrderValid(length, segmentSize, shortSeen, index == len(messages)-1) {
			return 0, false
		}
		shortSeen = length < segmentSize
		total += length
	}
	return total, true
}

func externalV2BulkPacketGSOCountValid(count int) bool {
	return count >= 2 && count <= externalV2BulkPacketMaxBatch
}

func externalV2BulkPacketGSOTemplate(message externalV2BulkPacketBatchMessage) (int, string, bool) {
	if len(message.Buffers) != 1 {
		return 0, "", false
	}
	if message.Addr == nil {
		return 0, "", false
	}
	segmentSize := len(message.Buffers[0])
	return segmentSize, message.Addr.String(), segmentSize > 0
}

func externalV2BulkPacketGSOMessageLength(message externalV2BulkPacketBatchMessage, destination string, segmentSize int) (int, bool) {
	if !externalV2BulkPacketGSOTargetMatches(message, destination) {
		return 0, false
	}
	length := len(message.Buffers[0])
	return length, length > 0 && length <= segmentSize
}

func externalV2BulkPacketGSOTargetMatches(message externalV2BulkPacketBatchMessage, destination string) bool {
	if len(message.Buffers) != 1 {
		return false
	}
	if len(message.OOB) != 0 {
		return false
	}
	if message.Addr == nil {
		return false
	}
	return message.Addr.String() == destination
}

func externalV2BulkPacketGSOOrderValid(length, segmentSize int, shortSeen, last bool) bool {
	if shortSeen {
		return false
	}
	if length < segmentSize {
		return last
	}
	return true
}

func externalV2BulkPacketLinuxGSOCapable(conn net.PacketConn) bool {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return false
	}
	capable := false
	if err := raw.Control(func(fd uintptr) {
		_, socketErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		capable = socketErr == nil
	}); err != nil {
		return false
	}
	return capable
}

func externalV2BulkPacketShouldDisableGSO(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EIO)
}

func externalV2BulkPacketSetGSOSize(control *[]byte, size uint16) {
	*control = (*control)[:0]
	if cap(*control) < unix.CmsgSpace(2) {
		return
	}
	*control = (*control)[:cap(*control)]
	header := (*unix.Cmsghdr)(unsafe.Pointer(&(*control)[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16((*control)[unix.SizeofCmsghdr:], size)
	*control = (*control)[:unix.CmsgSpace(2)]
}
