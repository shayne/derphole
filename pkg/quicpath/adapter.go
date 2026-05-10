// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

type PeerDatagramConn interface {
	SendDatagram([]byte) error
	RecvDatagram(context.Context) ([]byte, net.Addr, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	ReleaseDatagram([]byte)
	Close() error
}

type Adapter struct {
	peer PeerDatagramConn

	mu            sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
	closedCh  chan struct{}
}

func NewAdapter(peer PeerDatagramConn) *Adapter {
	return &Adapter{
		peer:     peer,
		closedCh: make(chan struct{}),
	}
}

func (a *Adapter) ReadFrom(p []byte) (int, net.Addr, error) {
	ctx, cancel := a.readContext()
	defer cancel()

	payload, addr, err := a.peer.RecvDatagram(ctx)
	if err != nil {
		return 0, nil, a.translateError(err)
	}
	if remote := a.peer.RemoteAddr(); remote != nil {
		addr = remote
	}
	n := copy(p, payload)
	a.peer.ReleaseDatagram(payload)
	return n, addr, nil
}

func (a *Adapter) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := a.writeReady(); err != nil {
		return 0, err
	}
	if err := a.peer.SendDatagram(p); err != nil {
		return 0, a.translateError(err)
	}
	return len(p), nil
}

func (a *Adapter) Close() error {
	var err error
	a.closeOnce.Do(func() {
		close(a.closedCh)
		err = a.peer.Close()
	})
	return err
}

func (a *Adapter) LocalAddr() net.Addr { return a.peer.LocalAddr() }

func (a *Adapter) SetReadBuffer(bytes int) error {
	type readBufferConn interface {
		SetReadBuffer(int) error
	}
	if conn, ok := a.peer.(readBufferConn); ok {
		return conn.SetReadBuffer(bytes)
	}
	return nil
}

func (a *Adapter) SetWriteBuffer(bytes int) error {
	type writeBufferConn interface {
		SetWriteBuffer(int) error
	}
	if conn, ok := a.peer.(writeBufferConn); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return nil
}

func (a *Adapter) SetDeadline(t time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readDeadline = t
	a.writeDeadline = t
	return nil
}

func (a *Adapter) SetReadDeadline(t time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readDeadline = t
	return nil
}

func (a *Adapter) SetWriteDeadline(t time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.writeDeadline = t
	return nil
}

func (a *Adapter) readContext() (context.Context, context.CancelFunc) {
	a.mu.RLock()
	deadline := a.readDeadline
	a.mu.RUnlock()

	if deadline.IsZero() {
		return context.Background(), func() {}
	}
	return context.WithDeadline(context.Background(), deadline)
}

func (a *Adapter) writeReady() error {
	select {
	case <-a.closedCh:
		return net.ErrClosed
	default:
	}

	a.mu.RLock()
	deadline := a.writeDeadline
	a.mu.RUnlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (a *Adapter) translateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		select {
		case <-a.closedCh:
			return net.ErrClosed
		default:
			return err
		}
	case errors.Is(err, context.DeadlineExceeded):
		return os.ErrDeadlineExceeded
	default:
		return err
	}
}
