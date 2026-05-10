// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type darwinMsgHdrX struct {
	Name       *byte
	Namelen    uint32
	Iov        *unix.Iovec
	Iovlen     int32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

type darwinBatcher struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	caps TransportCaps
	pool sync.Pool
}

type darwinBatch struct {
	hdrs  []darwinMsgHdrX
	iovs  []unix.Iovec
	names []unix.RawSockaddrAny
}

func newPlatformBatcher(conn net.PacketConn, requested string) packetBatcher {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil
	}
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil
	}
	b := &darwinBatcher{
		conn: udpConn,
		raw:  rawConn,
		caps: tuneSocketCaps(udpConn, TransportCaps{
			Kind:          probeTransportBatched,
			RequestedKind: requested,
			BatchSize:     probeIdealBatchSize,
		}),
	}
	b.pool.New = func() any {
		return &darwinBatch{
			hdrs:  make([]darwinMsgHdrX, probeIdealBatchSize),
			iovs:  make([]unix.Iovec, probeIdealBatchSize),
			names: make([]unix.RawSockaddrAny, probeIdealBatchSize),
		}
	}
	return b
}

func (b *darwinBatcher) Capabilities() TransportCaps { return b.caps }
func (b *darwinBatcher) MaxBatch() int               { return probeIdealBatchSize }

func (b *darwinBatcher) WriteBatch(ctx context.Context, peer net.Addr, packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil || b.raw == nil {
		return 0, errors.New("nil packet conn")
	}
	deadline, err := batchWriteDeadline(ctx)
	if err != nil {
		return 0, err
	}
	if err := b.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer b.conn.SetWriteDeadline(time.Time{})

	batch := b.getBatch()
	defer b.putBatch(batch)

	name, namelen, err := darwinSockaddrForAddr(b.conn.LocalAddr(), peer, &batch.names[0])
	if err != nil {
		return 0, err
	}
	sent := 0
	for sent < len(packets) {
		chunk := len(packets) - sent
		if chunk > len(batch.hdrs) {
			chunk = len(batch.hdrs)
		}
		for i := 0; i < chunk; i++ {
			packet := packets[sent+i]
			batch.iovs[i] = unix.Iovec{Len: uint64(len(packet))}
			if len(packet) > 0 {
				batch.iovs[i].Base = &packet[0]
			}
			batch.hdrs[i] = darwinMsgHdrX{
				Name:    name,
				Namelen: namelen,
				Iov:     &batch.iovs[i],
				Iovlen:  1,
			}
		}
		n, err := darwinSendmsgX(b.raw, batch.hdrs[:chunk])
		sent += n
		if err != nil {
			runtime.KeepAlive(packets)
			return sent, err
		}
		if n == 0 {
			runtime.KeepAlive(packets)
			return sent, errors.New("sendmsg_x made no progress")
		}
	}
	runtime.KeepAlive(packets)
	return sent, nil
}

func (b *darwinBatcher) ReadBatch(ctx context.Context, timeout time.Duration, bufs []batchReadBuffer) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if b == nil || b.conn == nil || b.raw == nil {
		return 0, errors.New("nil packet conn")
	}
	deadline, err := batchReadDeadline(ctx, timeout)
	if err != nil {
		return 0, err
	}
	if err := b.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	defer b.conn.SetReadDeadline(time.Time{})

	batch := b.getBatch()
	defer b.putBatch(batch)

	limit := len(bufs)
	if limit > len(batch.hdrs) {
		limit = len(batch.hdrs)
	}
	nameLen := uint32(unsafe.Sizeof(batch.names[0]))
	for i := 0; i < limit; i++ {
		batch.names[i] = unix.RawSockaddrAny{}
		batch.iovs[i] = unix.Iovec{Len: uint64(len(bufs[i].Bytes))}
		if len(bufs[i].Bytes) > 0 {
			batch.iovs[i].Base = &bufs[i].Bytes[0]
		}
		batch.hdrs[i] = darwinMsgHdrX{
			Name:    (*byte)(unsafe.Pointer(&batch.names[i])),
			Namelen: nameLen,
			Iov:     &batch.iovs[i],
			Iovlen:  1,
		}
	}

	n, err := darwinRecvmsgX(b.raw, batch.hdrs[:limit])
	if err != nil {
		return 0, err
	}
	for i := 0; i < n; i++ {
		size := int(batch.hdrs[i].Datalen)
		if size > len(bufs[i].Bytes) {
			size = len(bufs[i].Bytes)
		}
		bufs[i].N = size
		bufs[i].Addr = darwinUDPAddrFromRaw(&batch.names[i])
	}
	for i := n; i < len(bufs); i++ {
		bufs[i].N = 0
		bufs[i].Addr = nil
	}
	return n, nil
}

func (b *darwinBatcher) getBatch() *darwinBatch {
	return b.pool.Get().(*darwinBatch)
}

func (b *darwinBatcher) putBatch(batch *darwinBatch) {
	for i := range batch.hdrs {
		batch.hdrs[i] = darwinMsgHdrX{}
		batch.iovs[i] = unix.Iovec{}
		batch.names[i] = unix.RawSockaddrAny{}
	}
	b.pool.Put(batch)
}

func darwinSendmsgX(raw syscall.RawConn, hdrs []darwinMsgHdrX) (int, error) {
	if len(hdrs) == 0 {
		return 0, nil
	}
	var sent int
	var callErr error
	err := raw.Write(func(fd uintptr) bool {
		//lint:ignore SA1019 Go does not expose Darwin sendmsg_x; this is the platform batch path.
		n, _, errno := syscall.Syscall6(unix.SYS_SENDMSG_X, fd, uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)), 0, 0, 0)
		if errno == 0 {
			sent = int(n)
			return true
		}
		if darwinWouldBlock(errno) {
			return false
		}
		callErr = errno
		return true
	})
	if err != nil {
		return sent, err
	}
	return sent, callErr
}

func darwinRecvmsgX(raw syscall.RawConn, hdrs []darwinMsgHdrX) (int, error) {
	if len(hdrs) == 0 {
		return 0, nil
	}
	var received int
	var callErr error
	err := raw.Read(func(fd uintptr) bool {
		//lint:ignore SA1019 Go does not expose Darwin recvmsg_x; this is the platform batch path.
		n, _, errno := syscall.Syscall6(unix.SYS_RECVMSG_X, fd, uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)), 0, 0, 0)
		if errno == 0 {
			received = int(n)
			return true
		}
		if errno == syscall.EINTR {
			callErr = errno
			return true
		}
		if darwinWouldBlock(errno) {
			return false
		}
		callErr = errno
		return true
	})
	if err != nil {
		return received, err
	}
	if callErr == syscall.EINTR {
		return darwinRecvmsgX(raw, hdrs)
	}
	return received, callErr
}

func darwinWouldBlock(errno syscall.Errno) bool {
	return errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK
}

func darwinSockaddrForAddr(local net.Addr, addr net.Addr, storage *unix.RawSockaddrAny) (*byte, uint32, error) {
	if storage == nil {
		return nil, 0, errors.New("nil sockaddr storage")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return nil, 0, errors.New("darwin batcher requires UDP peer address")
	}
	ap := udpAddr.AddrPort()
	if !ap.IsValid() {
		return nil, 0, errors.New("invalid UDP peer address")
	}
	addrOnly := ap.Addr().Unmap()
	if addrOnly.Is4() {
		if localUDPAddrIs6(local) {
			sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(storage))
			*sa = unix.RawSockaddrInet6{
				Len:    uint8(unsafe.Sizeof(*sa)),
				Family: unix.AF_INET6,
			}
			darwinSetSockaddrPort(&sa.Port, ap.Port())
			v4 := addrOnly.As4()
			sa.Addr[10] = 0xff
			sa.Addr[11] = 0xff
			copy(sa.Addr[12:], v4[:])
			return (*byte)(unsafe.Pointer(sa)), uint32(sa.Len), nil
		}
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(storage))
		*sa = unix.RawSockaddrInet4{
			Len:    uint8(unsafe.Sizeof(*sa)),
			Family: unix.AF_INET,
		}
		darwinSetSockaddrPort(&sa.Port, ap.Port())
		v4 := addrOnly.As4()
		copy(sa.Addr[:], v4[:])
		return (*byte)(unsafe.Pointer(sa)), uint32(sa.Len), nil
	}
	if addrOnly.Is6() {
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(storage))
		*sa = unix.RawSockaddrInet6{
			Len:      uint8(unsafe.Sizeof(*sa)),
			Family:   unix.AF_INET6,
			Scope_id: zoneID(addrOnly),
		}
		darwinSetSockaddrPort(&sa.Port, ap.Port())
		v6 := addrOnly.As16()
		copy(sa.Addr[:], v6[:])
		return (*byte)(unsafe.Pointer(sa)), uint32(sa.Len), nil
	}
	return nil, 0, errors.New("unsupported UDP peer address")
}

func darwinUDPAddrFromRaw(storage *unix.RawSockaddrAny) net.Addr {
	if storage == nil {
		return nil
	}
	switch storage.Addr.Family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(storage))
		return &net.UDPAddr{
			IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
			Port: darwinSockaddrPort(sa.Port),
		}
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(storage))
		ip := make(net.IP, net.IPv6len)
		copy(ip, sa.Addr[:])
		addr := &net.UDPAddr{
			IP:   ip,
			Port: darwinSockaddrPort(sa.Port),
		}
		if sa.Scope_id != 0 {
			addr.Zone = strconv.FormatUint(uint64(sa.Scope_id), 10)
		}
		return addr
	default:
		return nil
	}
}

func darwinSetSockaddrPort(dst *uint16, port uint16) {
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(dst))[:], port)
}

func darwinSockaddrPort(src uint16) int {
	return int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&src))[:]))
}

func platformSetSocketBuffers(conn net.PacketConn, caps *TransportCaps, size int) {
	if conn == nil {
		return
	}
	type readBufferSetter interface {
		SetReadBuffer(int) error
	}
	type writeBufferSetter interface {
		SetWriteBuffer(int) error
	}
	if setter, ok := conn.(readBufferSetter); ok {
		_ = setter.SetReadBuffer(size)
	}
	if setter, ok := conn.(writeBufferSetter); ok {
		_ = setter.SetWriteBuffer(size)
	}
	_ = caps
}

func platformSetSocketPacing(conn net.PacketConn, bytesPerSecond uint64) bool {
	return false
}
