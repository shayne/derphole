// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"
)

const externalQUICStreamOpenByte = byte(1)

func openExternalQUICStreamForConn(ctx context.Context, conn *quic.Conn, openStream bool) (*quic.Stream, error) {
	if openStream {
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		cancelDeadline := cancelExternalQUICStreamDeadlineOnContextDone(ctx, stream)
		defer cancelDeadline()
		if _, err := stream.Write([]byte{externalQUICStreamOpenByte}); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, nil
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	cancelDeadline := cancelExternalQUICStreamDeadlineOnContextDone(ctx, stream)
	defer cancelDeadline()
	var opened [1]byte
	if _, err := io.ReadFull(stream, opened[:]); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if opened[0] != externalQUICStreamOpenByte {
		_ = stream.Close()
		return nil, fmt.Errorf("QUIC stream open byte = %d, want %d", opened[0], externalQUICStreamOpenByte)
	}
	return stream, nil
}

func cancelExternalQUICStreamDeadlineOnContextDone(ctx context.Context, stream *quic.Stream) func() {
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = stream.SetDeadline(time.Now())
		close(callbackDone)
	})
	return func() {
		if stop() {
			close(callbackDone)
		}
		<-callbackDone
		_ = stream.SetDeadline(time.Time{})
	}
}
