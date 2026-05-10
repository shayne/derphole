// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream

import (
	"context"
	"net"
)

func ListenOnce(ctx context.Context, addr string) (net.Conn, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ln.Close() }()

	type result struct {
		conn net.Conn
		err  error
	}

	acceptCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- result{conn: conn, err: err}
	}()

	select {
	case res := <-acceptCh:
		if res.err != nil {
			return nil, res.err
		}
		return res.conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func Connect(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}
