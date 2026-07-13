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
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	externalV2BulkPacketMaxIPv4Payload = 1<<16 - 1 - 20 - 8
	// Keep each software-segmented skb to a few qdisc quanta so a single local
	// queue drop cannot discard a large fraction of the sender window. All GSO
	// messages still share one sendmmsg call per logical batch.
	externalV2BulkPacketLinuxGSOSegmentsPerMessage     = 3
	externalV2BulkPacketLinuxMaximumGSOMessagesPerCall = (externalV2BulkPacketMaxBatch + externalV2BulkPacketLinuxGSOSegmentsPerMessage - 1) / externalV2BulkPacketLinuxGSOSegmentsPerMessage
)

type externalV2BulkPacketLinuxGSOScratch struct {
	messages  [externalV2BulkPacketLinuxMaximumGSOMessagesPerCall]ipv4.Message
	buffers   [externalV2BulkPacketMaxBatch][]byte
	groupEnds [externalV2BulkPacketLinuxMaximumGSOMessagesPerCall]int
	control   []byte
}

var externalV2BulkPacketLinuxGSOScratchPool = sync.Pool{New: func() any {
	return &externalV2BulkPacketLinuxGSOScratch{control: make([]byte, 0, unix.CmsgSpace(2))}
}}

type externalV2BulkPacketLinuxBatchConn struct {
	conn              net.PacketConn
	packetConn        *ipv4.PacketConn
	rawConn           syscall.RawConn
	stats             *externalV2BulkPacketAtomicBatchStats
	gsoCapable        atomic.Bool
	readHeaders       [externalV2BulkPacketMaxBatch]externalV2BulkPacketMMsgHdr
	readIovecs        [externalV2BulkPacketMaxBatch]unix.Iovec
	readDeadline      time.Time
	readDeadlineArmed bool
}

type externalV2BulkPacketMMsgHdr struct {
	hdr unix.Msghdr
	len uint32
}

func newExternalV2BulkPacketBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	if _, ok := conn.(net.Conn); !ok {
		return newExternalV2BulkPacketPortableBatchConn(conn)
	}
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return newExternalV2BulkPacketPortableBatchConn(conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return newExternalV2BulkPacketPortableBatchConn(conn)
	}
	batch := &externalV2BulkPacketLinuxBatchConn{
		conn:       conn,
		packetConn: ipv4.NewPacketConn(conn),
		rawConn:    rawConn,
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
	return false, externalV2BulkPacketArmWriteDeadline(ctx, conn)
}

func (c *externalV2BulkPacketLinuxBatchConn) tryWriteGSO(messages []externalV2BulkPacketBatchMessage) (bool, int, error) {
	c.stats.gsoAttempted.Store(true)
	written, err := c.writeGSO(messages)
	if written > 0 {
		c.observeGSOSuccess(written)
		return true, written, err
	}
	if err == nil {
		return true, 0, nil
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
	messages, headers, err := externalV2BulkPacketPrepareRead(messages, c.readHeaders[:], c.readIovecs[:])
	if err != nil || len(messages) == 0 {
		return 0, err
	}
	return c.readPreparedBatch(ctx, messages, headers)
}

func externalV2BulkPacketPrepareRead(
	messages []externalV2BulkPacketBatchMessage,
	headers []externalV2BulkPacketMMsgHdr,
	iovecs []unix.Iovec,
) ([]externalV2BulkPacketBatchMessage, []externalV2BulkPacketMMsgHdr, error) {
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	if len(headers) < len(messages) || len(iovecs) < len(messages) {
		return nil, nil, errors.New("bulk packet receive scratch is too small")
	}
	headers = headers[:len(messages)]
	iovecs = iovecs[:len(messages)]
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 {
			return nil, nil, errors.New("bulk packet connected receive requires one non-empty buffer")
		}
		buffer := messages[index].Buffers[0]
		iovecs[index].Base = &buffer[0]
		iovecs[index].SetLen(len(buffer))
		headers[index] = externalV2BulkPacketMMsgHdr{hdr: unix.Msghdr{
			Iov: &iovecs[index], Iovlen: 1,
		}}
		messages[index].Addr = nil
		messages[index].N = 0
		messages[index].NN = 0
		messages[index].Flags = 0
	}
	return messages, headers, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) readPreparedBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage, headers []externalV2BulkPacketMMsgHdr) (int, error) {
	for {
		read, retry, err := c.readBatchAttempt(ctx, headers)
		if err != nil {
			return 0, err
		}
		if retry {
			continue
		}
		return c.finishReadBatch(messages, headers, read)
	}
}

func (c *externalV2BulkPacketLinuxBatchConn) finishReadBatch(messages []externalV2BulkPacketBatchMessage, headers []externalV2BulkPacketMMsgHdr, read int) (int, error) {
	if err := externalV2BulkPacketCopyReadBatch(messages, headers, read); err != nil {
		return 0, err
	}
	c.stats.setBackend("linux-recvmmsg")
	c.stats.observeReceive(read)
	return read, nil
}

func (c *externalV2BulkPacketLinuxBatchConn) readBatchAttempt(ctx context.Context, headers []externalV2BulkPacketMMsgHdr) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	deadline := externalV2BulkPacketBatchDeadline(ctx, time.Now())
	if !c.readDeadlineArmed || deadline.Before(c.readDeadline) {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return 0, false, err
		}
		c.readDeadline = deadline
		c.readDeadlineArmed = true
	}
	read, err := externalV2BulkPacketRecvMMsg(c.rawConn, headers)
	if err == nil {
		return read, false, nil
	}
	c.readDeadlineArmed = false
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	return externalV2BulkPacketClassifyReadError(ctx, err)
}

func externalV2BulkPacketRecvMMsg(rawConn syscall.RawConn, headers []externalV2BulkPacketMMsgHdr) (int, error) {
	if rawConn == nil || len(headers) == 0 {
		return 0, errors.New("bulk packet recvmmsg has no socket or buffers")
	}
	read := 0
	var receiveErr error
	err := rawConn.Read(func(fd uintptr) bool {
		count, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&headers[0])),
			uintptr(len(headers)),
			0,
			0,
			0,
		)
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false
		}
		if errno != 0 {
			receiveErr = errno
		} else {
			read = int(count)
		}
		return true
	})
	runtime.KeepAlive(headers)
	if err != nil {
		return 0, err
	}
	return read, receiveErr
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

func externalV2BulkPacketCopyReadBatch(messages []externalV2BulkPacketBatchMessage, headers []externalV2BulkPacketMMsgHdr, read int) error {
	for index := 0; index < read; index++ {
		if int(headers[index].hdr.Flags)&unix.MSG_TRUNC != 0 {
			return errors.New("bulk packet receive batch contained a truncated datagram")
		}
		messages[index].N = int(headers[index].len)
		messages[index].NN = 0
		messages[index].Flags = int(headers[index].hdr.Flags)
		messages[index].Addr = nil
	}
	return nil
}

func (c *externalV2BulkPacketLinuxBatchConn) Stats() externalV2BulkPacketBatchStats {
	return c.stats.snapshot()
}

func (c *externalV2BulkPacketLinuxBatchConn) writeGSO(messages []externalV2BulkPacketBatchMessage) (int, error) {
	scratch := externalV2BulkPacketLinuxGSOScratchPool.Get().(*externalV2BulkPacketLinuxGSOScratch)
	groups, groupEnds := externalV2BulkPacketPrepareLinuxGSOGroups(messages, scratch)
	defer func() {
		for index := range len(groups) {
			scratch.messages[index] = ipv4.Message{}
			scratch.groupEnds[index] = 0
		}
		for index := range len(messages) {
			scratch.buffers[index] = nil
		}
		externalV2BulkPacketLinuxGSOScratchPool.Put(scratch)
	}()
	writtenGroups, err := c.packetConn.WriteBatch(groups, 0)
	written := externalV2BulkPacketLinuxGSOWritten(writtenGroups, groupEnds)
	for index := range written {
		messages[index].N = externalV2BulkPacketMessageLength(messages[index].Buffers)
	}
	return written, err
}

func externalV2BulkPacketPrepareLinuxGSOGroups(messages []externalV2BulkPacketBatchMessage, scratch *externalV2BulkPacketLinuxGSOScratch) ([]ipv4.Message, []int) {
	if scratch.control == nil {
		scratch.control = make([]byte, 0, unix.CmsgSpace(2))
	}
	externalV2BulkPacketSetGSOSize(&scratch.control, uint16(externalV2BulkPacketMessageLength(messages[0].Buffers)))
	groupCount := 0
	for start := 0; start < len(messages); start += externalV2BulkPacketLinuxGSOSegmentsPerMessage {
		end := min(start+externalV2BulkPacketLinuxGSOSegmentsPerMessage, len(messages))
		for index := start; index < end; index++ {
			scratch.buffers[index] = messages[index].Buffers[0]
		}
		scratch.messages[groupCount] = ipv4.Message{
			Buffers: scratch.buffers[start:end],
			OOB:     scratch.control,
			Addr:    messages[start].Addr,
		}
		scratch.groupEnds[groupCount] = end
		groupCount++
	}
	return scratch.messages[:groupCount], scratch.groupEnds[:groupCount]
}

func externalV2BulkPacketLinuxGSOWritten(writtenGroups int, groupEnds []int) int {
	if writtenGroups <= 0 || len(groupEnds) == 0 {
		return 0
	}
	return groupEnds[min(writtenGroups, len(groupEnds))-1]
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
