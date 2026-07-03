// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
)

func TestDerptunAppMuxCarriesStream(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverToken, clientToken := derptunServerAndClientTokens(t)
	accepted := make(chan struct{})
	serverDone := make(chan string, 1)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunAppServe(ctx, DerptunAppServeConfig{
			ServerToken: serverToken,
			ForceRelay:  true,
			OnMux: func(ctx context.Context, mux *derptun.Mux) error {
				overlayConn, err := mux.Accept(ctx)
				if err != nil {
					return err
				}
				close(accepted)
				defer func() { _ = overlayConn.Close() }()
				if err := overlayConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					return err
				}
				line, err := bufio.NewReader(overlayConn).ReadString('\n')
				if err != nil {
					serverDone <- "read: " + err.Error()
					return err
				}
				_, err = io.WriteString(overlayConn, "echo: "+line)
				if err != nil {
					serverDone <- "write: " + err.Error()
					return err
				} else {
					serverDone <- "wrote: " + line
				}
				<-ctx.Done()
				return ctx.Err()
			},
		})
	}()
	conn, cleanup, err := DerptunAppDialStream(ctx, DerptunAppDialConfig{
		ClientToken: clientToken,
		ForceRelay:  true,
	})
	if err != nil {
		t.Fatalf("DerptunAppDialStream() error = %v", err)
	}
	defer cleanup()
	defer func() { _ = conn.Close() }()

	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatalf("DerptunAppServe did not accept stream: %v", ctx.Err())
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		select {
		case serverState := <-serverDone:
			t.Fatalf("ReadString() error = %v after server %s", err, serverState)
		default:
			t.Fatalf("ReadString() error = %v before server read/write completed", err)
		}
	}
	if line != "echo: hello\n" {
		t.Fatalf("line = %q, want echo: hello", line)
	}
	cancel()
	if err := <-serveErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("DerptunAppServe() after cancel error = %v, want nil or context cancellation", err)
	}
}
