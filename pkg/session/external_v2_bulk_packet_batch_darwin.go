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
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	//lint:ignore SA1019 x/sys has no recvmsg_x wrapper; Darwin batching requires this stable XNU syscall.
	externalV2BulkPacketDarwinRecvmsgX = unix.SYS_RECVMSG_X //nolint:staticcheck // See the lint:ignore rationale above.
	//lint:ignore SA1019 x/sys has no sendmsg_x wrapper; Darwin batching requires this stable XNU syscall.
	externalV2BulkPacketDarwinSendmsgX = unix.SYS_SENDMSG_X //nolint:staticcheck // See the lint:ignore rationale above.

	externalV2BulkPacketDarwinReceiveCoalesceDelay = time.Millisecond
)

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

type externalV2BulkPacketDarwinSockaddr struct {
	storage unix.RawSockaddrInet6
}

type externalV2BulkPacketDarwinBatchConn struct {
	conn         net.PacketConn
	raw          syscall.RawConn
	stats        *externalV2BulkPacketAtomicBatchStats
	candidateErr error
	writeMu      sync.Mutex

	connectAttempted     bool
	connectEnabled       bool
	fixedPeer            net.Addr
	connected            bool
	connectedAddr        string
	receiveCoalescing    bool
	receiveCoalesceDelay time.Duration
	headers              [externalV2BulkPacketMaxBatch]externalV2BulkPacketDarwinMsgHdr
	iovs                 [externalV2BulkPacketMaxBatch]unix.Iovec
	addrs                [externalV2BulkPacketMaxBatch]externalV2BulkPacketDarwinSockaddr
}

func newExternalV2BulkPacketBatchConn(conn net.PacketConn) externalV2BulkPacketBatchConn {
	candidate, candidateErr := externalV2BulkPacketConfiguredCandidate()
	batch := &externalV2BulkPacketDarwinBatchConn{
		conn:         conn,
		stats:        newExternalV2BulkPacketAtomicBatchStats("portable-single"),
		candidateErr: candidateErr,
	}
	if candidateErr == nil {
		batch.stats.setCandidateID(candidate.ID)
	}
	if syscallConn, ok := conn.(syscall.Conn); ok {
		batch.raw, _ = syscallConn.SyscallConn()
	}
	return batch
}

func (c *externalV2BulkPacketDarwinBatchConn) WriteBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.candidateErr != nil {
		return 0, c.candidateErr
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(messages) == 0 {
		return 0, nil
	}
	if c.raw == nil {
		return c.writePortable(ctx, messages)
	}
	if len(messages) > externalV2BulkPacketMaxBatch {
		messages = messages[:externalV2BulkPacketMaxBatch]
	}
	return c.writeSendmsgX(ctx, messages)
}

func (c *externalV2BulkPacketDarwinBatchConn) enableFixedPeerConnect(peer net.Addr) error {
	if peer == nil {
		return errors.New("bulk packet fixed peer is nil")
	}
	c.connectEnabled = true
	c.fixedPeer = peer
	return nil
}

func (c *externalV2BulkPacketDarwinBatchConn) enableReceiveCoalescing() {
	if c.raw == nil {
		return
	}
	c.receiveCoalescing = true
	c.receiveCoalesceDelay = externalV2BulkPacketDarwinReceiveCoalesceDelay
}

func (c *externalV2BulkPacketDarwinBatchConn) writeSendmsgX(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	prepared, err := c.prepareSendmsgX(messages)
	if err != nil {
		return 0, err
	}
	if !prepared {
		return c.writePortable(ctx, messages)
	}
	if err := externalV2BulkPacketArmWriteDeadline(ctx, c.conn); err != nil {
		return 0, err
	}
	written, err := c.sendmsgX(messages)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return c.writePortable(ctx, messages)
	}
	if written > 0 {
		c.stats.observeNativeAccepted(messages, written, 0, 0)
		c.stats.setBackend("darwin-sendmsg-x")
		c.stats.observeSend(written)
		for index := 0; index < written; index++ {
			messages[index].N = len(messages[index].Buffers[0])
		}
	}
	return written, err
}

func (c *externalV2BulkPacketDarwinBatchConn) writePortable(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	written := 0
	for index := range messages {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		payload, err := externalV2BulkPacketFlattenMessage(messages[index].Buffers)
		if err != nil {
			return written, err
		}
		if err := externalV2BulkPacketArmWriteDeadline(ctx, c.conn); err != nil {
			return written, err
		}
		c.stats.observeNativeAttempt()
		n, err := c.conn.WriteTo(payload, messages[index].Addr)
		c.stats.observeNativeSyscall()
		if n == len(payload) {
			c.stats.observeNativeAccepted(messages[index:index+1], 1, 0, 0)
			c.stats.setBackend("portable-single")
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

func (c *externalV2BulkPacketDarwinBatchConn) prepareSendmsgX(messages []externalV2BulkPacketBatchMessage) (bool, error) {
	connected := c.connectFixedPeer(messages)
	for index := range messages {
		if len(messages[index].Buffers) != 1 || len(messages[index].Buffers[0]) == 0 || len(messages[index].OOB) != 0 {
			return false, nil
		}
		var name *byte
		var nameLen uint32
		if !connected {
			var supported bool
			var err error
			name, nameLen, supported, err = c.addrs[index].set(messages[index].Addr)
			if err != nil {
				return false, err
			}
			if !supported {
				return false, nil
			}
		}
		buffer := messages[index].Buffers[0]
		c.iovs[index] = unix.Iovec{Base: &buffer[0], Len: uint64(len(buffer))}
		c.headers[index] = externalV2BulkPacketDarwinMsgHdr{
			Name:    name,
			NameLen: nameLen,
			Iov:     &c.iovs[index],
			IovLen:  1,
		}
	}
	return true, nil
}

func (c *externalV2BulkPacketDarwinBatchConn) connectFixedPeer(messages []externalV2BulkPacketBatchMessage) bool {
	if !c.connectEnabled || c.raw == nil || c.fixedPeer == nil || len(messages) == 0 {
		return false
	}
	peer := c.fixedPeer.String()
	for index := range messages {
		if messages[index].Addr == nil || messages[index].Addr.String() != peer {
			return false
		}
	}
	if c.connected {
		return c.connectedAddr == peer
	}
	if c.connectAttempted {
		return false
	}
	c.connectAttempted = true
	sockaddr, ok := externalV2BulkPacketDarwinConnectSockaddr(c.fixedPeer)
	if !ok {
		return false
	}
	var connectErr error
	if err := c.raw.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), sockaddr)
	}); err != nil {
		return false
	}
	if connectErr != nil && !errors.Is(connectErr, unix.EISCONN) {
		return false
	}
	c.connected = true
	c.connectedAddr = peer
	return true
}

func externalV2BulkPacketDarwinConnectSockaddr(addr net.Addr) (unix.Sockaddr, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port < 0 || udpAddr.Port > 1<<16-1 {
		return nil, false
	}
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		sockaddr := &unix.SockaddrInet4{Port: udpAddr.Port}
		copy(sockaddr.Addr[:], ip4)
		return sockaddr, true
	}
	ip6 := udpAddr.IP.To16()
	if ip6 == nil {
		return nil, false
	}
	sockaddr := &unix.SockaddrInet6{Port: udpAddr.Port}
	copy(sockaddr.Addr[:], ip6)
	if udpAddr.Zone != "" {
		iface, err := net.InterfaceByName(udpAddr.Zone)
		if err != nil {
			return nil, false
		}
		sockaddr.ZoneId = uint32(iface.Index)
	}
	return sockaddr, true
}

func (a *externalV2BulkPacketDarwinSockaddr) set(addr net.Addr) (*byte, uint32, bool, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return nil, 0, false, nil
	}
	if udpAddr.Port < 0 || udpAddr.Port > 1<<16-1 {
		return nil, 0, false, unix.EINVAL
	}
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		raw := (*unix.RawSockaddrInet4)(unsafe.Pointer(&a.storage))
		*raw = unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET}
		externalV2BulkPacketDarwinSetPort(&raw.Port, udpAddr.Port)
		copy(raw.Addr[:], ip4)
		return (*byte)(unsafe.Pointer(raw)), uint32(raw.Len), true, nil
	}
	ip6 := udpAddr.IP.To16()
	if ip6 == nil {
		return nil, 0, false, unix.EINVAL
	}
	raw := &a.storage
	*raw = unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6}
	externalV2BulkPacketDarwinSetPort(&raw.Port, udpAddr.Port)
	copy(raw.Addr[:], ip6)
	if udpAddr.Zone != "" {
		iface, err := net.InterfaceByName(udpAddr.Zone)
		if err != nil {
			return nil, 0, false, err
		}
		raw.Scope_id = uint32(iface.Index)
	}
	return (*byte)(unsafe.Pointer(raw)), uint32(raw.Len), true, nil
}

func externalV2BulkPacketDarwinSetPort(port *uint16, value int) {
	bytes := (*[2]byte)(unsafe.Pointer(port))
	bytes[0] = byte(value >> 8)
	bytes[1] = byte(value)
}

func (c *externalV2BulkPacketDarwinBatchConn) sendmsgX(messages []externalV2BulkPacketBatchMessage) (int, error) {
	written := 0
	var syscallErr error
	err := c.raw.Write(func(fd uintptr) bool {
		for {
			c.stats.observeNativeAttempt()
			count, _, errno := unix.Syscall6(
				externalV2BulkPacketDarwinSendmsgX,
				fd,
				uintptr(unsafe.Pointer(&c.headers[0])),
				uintptr(len(messages)),
				uintptr(unix.MSG_DONTWAIT),
				0,
				0,
			)
			c.stats.observeNativeSyscall()
			switch errno {
			case 0:
				written = int(count)
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
	runtime.KeepAlive(c.addrs)
	if err != nil {
		return 0, err
	}
	if syscallErr != nil {
		return 0, syscallErr
	}
	return written, nil
}

func (c *externalV2BulkPacketDarwinBatchConn) ReadBatch(ctx context.Context, messages []externalV2BulkPacketBatchMessage) (int, error) {
	if c.candidateErr != nil {
		return 0, c.candidateErr
	}
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
			return c.observeRecvmsgX(count), nil
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

func (c *externalV2BulkPacketDarwinBatchConn) observeRecvmsgX(count int) int {
	c.stats.setBackend("darwin-recvmsg-x")
	c.stats.observeReceive(count)
	return count
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
	delayed := false
	err := c.raw.Read(func(fd uintptr) bool {
		if c.receiveCoalescing && !delayed {
			// Darwin wakes the socket at the first datagram even when recvmsg_x can
			// drain a full vector. Give the kernel one bounded scheduling interval
			// to fill that vector; this is enabled only for bulk file receivers.
			delayed = true
			time.Sleep(c.receiveCoalesceDelay)
		}
		count, syscallErr = c.recvmsgXFD(fd, messages)
		return !errors.Is(syscallErr, unix.EAGAIN)
	})
	return c.finishRecvmsgX(messages, count, errors.Join(err, syscallErr))
}

func (c *externalV2BulkPacketDarwinBatchConn) recvmsgXFD(fd uintptr, messages []externalV2BulkPacketBatchMessage) (int, error) {
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
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		return int(received), nil
	}
}

func (c *externalV2BulkPacketDarwinBatchConn) finishRecvmsgX(messages []externalV2BulkPacketBatchMessage, count int, err error) (int, error) {
	runtime.KeepAlive(messages)
	runtime.KeepAlive(c.headers)
	runtime.KeepAlive(c.iovs)
	if err != nil {
		return 0, err
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
	for {
		if err := c.conn.SetReadDeadline(externalV2BulkPacketBatchDeadline(ctx, time.Now())); err != nil {
			return 0, err
		}
		n, addr, err := c.conn.ReadFrom(buffer[0])
		if err != nil {
			retry, readErr := externalV2BulkPacketRetryReadError(ctx, err)
			if retry {
				continue
			}
			return 0, readErr
		}
		messages[0].N = n
		messages[0].Addr = addr
		c.stats.observeReceive(1)
		return 1, nil
	}
}

func (c *externalV2BulkPacketDarwinBatchConn) Stats() externalV2BulkPacketBatchStats {
	return c.stats.snapshot()
}
