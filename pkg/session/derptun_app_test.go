// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDerptunAppMuxStillBridgesStdio(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()
	var out strings.Builder
	err := DerptunConnect(ctx, DerptunConnectConfig{
		ClientToken: clientToken,
		StdioIn:     strings.NewReader("hello\n"),
		StdioOut:    &out,
		ForceRelay:  true,
	})
	if err != nil {
		t.Fatalf("DerptunConnect() error = %v", err)
	}
	if out.String() != "echo: hello\n" {
		t.Fatalf("stdout = %q, want echo: hello", out.String())
	}
	cancel()
	<-serveErr
}
