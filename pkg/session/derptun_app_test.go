// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/tailcfg"
)

func TestDerptunAppMuxCarriesStream(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverToken, clientToken := derptunServerAndClientTokens(t)
	runDerptunAppMuxStreamExchange(t, ctx, serverToken, clientToken, true, nil, nil)
}

func TestDerptunAppCustomDERPSTUNTimeoutFallsBackToRelay(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv(derpbind.CustomDERPServerEnv, "https://127.0.0.1:8443/derp")
	clearDERPProxyEnvironment(t)

	serverToken, err := derptun.GenerateServerTokenFromEnvironment(derptun.ServerTokenOptions{Now: time.Now(), Days: 1})
	if err != nil {
		t.Fatalf("GenerateServerTokenFromEnvironment() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: time.Now(), ServerToken: serverToken, Days: 1})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	t.Setenv(derpbind.CustomDERPServerEnv, "")
	route, err := derpbind.NewCustomRoute("127.0.0.1", 8443, derpbind.DefaultSTUNPort)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}

	prevInterfaceAddrs := publicInterfaceAddrs
	publicInterfaceAddrs = func() ([]net.Addr, error) { return nil, nil }
	t.Cleanup(func() { publicInterfaceAddrs = prevInterfaceAddrs })
	prevGather := gatherTraversalCandidates
	var gatheredMu sync.Mutex
	var gatheredMaps []*tailcfg.DERPMap
	gatherTraversalCandidates = func(_ context.Context, _ net.PacketConn, dm *tailcfg.DERPMap, _ func() (netip.AddrPort, bool)) ([]string, error) {
		gatheredMu.Lock()
		gatheredMaps = append(gatheredMaps, dm)
		gatheredMu.Unlock()
		return nil, context.DeadlineExceeded
	}
	t.Cleanup(func() { gatherTraversalCandidates = prevGather })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var serverStatus syncBuffer
	var clientStatus syncBuffer
	runDerptunAppMuxStreamExchange(
		t,
		ctx,
		serverToken,
		clientToken,
		false,
		telemetry.New(&serverStatus, telemetry.LevelVerbose),
		telemetry.New(&clientStatus, telemetry.LevelVerbose),
	)

	gatheredMu.Lock()
	maps := append([]*tailcfg.DERPMap(nil), gatheredMaps...)
	gatheredMu.Unlock()
	if len(maps) == 0 {
		t.Fatal("custom STUN gather calls = 0, want at least one timed-out gather")
	}
	for _, dm := range maps {
		assertCustomDERPMap(t, dm, route)
	}
	for name, status := range map[string]string{"server": serverStatus.String(), "client": clientStatus.String()} {
		if !strings.Contains(status, string(StateRelay)) || strings.Contains(status, string(StateDirect)) {
			t.Fatalf("%s status = %q, want relay completion without direct promotion", name, status)
		}
	}
}

func runDerptunAppMuxStreamExchange(
	t *testing.T,
	ctx context.Context,
	serverToken string,
	clientToken string,
	forceRelay bool,
	serverEmitter *telemetry.Emitter,
	clientEmitter *telemetry.Emitter,
) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	accepted := make(chan struct{})
	serverDone := make(chan string, 1)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunAppServe(ctx, DerptunAppServeConfig{
			ServerToken: serverToken,
			Emitter:     serverEmitter,
			ForceRelay:  forceRelay,
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
		Emitter:     clientEmitter,
		ForceRelay:  forceRelay,
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
