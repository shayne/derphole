// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"

	"github.com/shayne/derphole/pkg/derpssh/protocol"
)

type routedInputSink struct {
	sendData func(context.Context, []byte) error
	sendChat func(context.Context, string) error
}

func pumpRoutedInput(ctx context.Context, src io.Reader, sink routedInputSink) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if sink.sendData != nil {
				chunk := append([]byte(nil), buf[:n]...)
				if writeErr := sink.sendData(ctx, chunk); writeErr != nil {
					return writeErr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func hostInputSink(host *HostRuntime) routedInputSink {
	return routedInputSink{
		sendData: func(ctx context.Context, data []byte) error {
			if _, err := host.cfg.PTYInput.Write(data); err != nil {
				_ = host.writeControlCtx(ctx, protocol.Message{
					Type:  protocol.MessageClose,
					Close: &protocol.Close{Reason: err.Error()},
				})
				return err
			}
			return nil
		},
	}
}
