// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"errors"
	"io"
	"time"

	"github.com/shayne/derphole/pkg/directquic"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/transport"
)

var errExternalDirectQUICNotImplemented = errors.New("direct QUIC transport is not implemented")

const externalDirectQUICCopyBufferSize = 1 << 20

func sendExternalViaDirectQUIC(ctx context.Context, cfg SendConfig) error {
	return errExternalDirectQUICNotImplemented
}

func listenExternalViaDirectQUIC(ctx context.Context, cfg ListenConfig) (string, error) {
	return "", errExternalDirectQUICNotImplemented
}

func externalDirectQUICSendOverManager(ctx context.Context, src io.Reader, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer func() { _ = adapter.Close() }()

	endpoint, err := directquic.Dial(ctx, directquic.DialConfig{
		PacketConn: adapter,
		RemoteAddr: peerConn.RemoteAddr(),
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		return err
	}
	defer func() { _ = endpoint.Close() }()

	before := endpoint.Stats().BytesSent
	stream, err := endpoint.OpenSendStream(ctx)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(stream, externalDirectQUICCopyBufferSize)
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	if _, err := io.CopyBuffer(writer, src, buf); err != nil {
		_ = stream.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = stream.Close()
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	if endpoint.Stats().BytesSent > before {
		if err := externalDirectQUICWaitForCommittedBytes(ctx, func() int64 {
			return endpoint.Stats().BytesSent
		}, before); err != nil {
			return err
		}
	}
	return nil
}

func externalDirectQUICReceiveOverManager(ctx context.Context, dst io.Writer, manager *transport.Manager, identity quicpath.SessionIdentity, peer [32]byte) error {
	peerConn := manager.PeerDatagramConn(ctx)
	adapter := quicpath.NewAdapter(peerConn)
	defer func() { _ = adapter.Close() }()

	endpoint, err := directquic.Listen(ctx, directquic.ListenConfig{
		PacketConn: adapter,
		Identity:   identity,
		PeerPublic: peer,
	})
	if err != nil {
		return err
	}
	defer func() { _ = endpoint.Close() }()

	stream, err := endpoint.AcceptReceiveStream(ctx)
	if err != nil {
		return err
	}
	buf := make([]byte, externalDirectQUICCopyBufferSize)
	_, copyErr := io.CopyBuffer(dst, stream, buf)
	closeErr := stream.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func externalDirectQUICWaitForCommittedBytes(ctx context.Context, committed func() int64, before int64) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if committed() > before {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
