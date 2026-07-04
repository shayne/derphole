// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"go4.org/mem"
	"tailscale.com/types/key"
)

func derptunServerAndClientTokens(t *testing.T) (string, string) {
	t.Helper()
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		Now:         now,
		ServerToken: server,
		Days:        1,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return server, client
}

func TestDerptunOpenForwardsTCPToServedTarget(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{ClientToken: clientToken, ListenAddr: "127.0.0.1:0", BindAddrSink: bindCh})
	}()
	bindAddr := <-bindCh
	conn, err := net.Dial("tcp", bindAddr)
	if err != nil {
		t.Fatalf("Dial(open listener) error = %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if line != "echo: ping\n" {
		t.Fatalf("line = %q, want echo: ping", line)
	}
	cancel()
	<-serveErr
	<-openErr
}

func TestDerptunOpenForwardsConcurrentTCPConnections(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend, accepted := startHoldingTCPServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{ClientToken: clientToken, ListenAddr: "127.0.0.1:0", BindAddrSink: bindCh, ForceRelay: true})
	}()
	bindAddr := <-bindCh

	firstConn, err := net.Dial("tcp", bindAddr)
	if err != nil {
		t.Fatalf("first Dial(open listener) error = %v", err)
	}
	defer firstConn.Close()
	if _, err := firstConn.Write([]byte("x")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	waitForBackendAccept(t, ctx, accepted, "first connection")

	secondConn, err := net.Dial("tcp", bindAddr)
	if err != nil {
		t.Fatalf("second Dial(open listener) error = %v", err)
	}
	defer secondConn.Close()
	if _, err := secondConn.Write([]byte("x")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	waitForBackendAccept(t, ctx, accepted, "second connection")

	cancel()
	<-serveErr
	<-openErr
}

func TestDerptunOpenStripesTCPConnectionsAcrossQUICConnections(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	backend, backendDone := startEchoServer(t, ctx)
	defer backendDone()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	var serveStatus syncBuffer
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{
			ServerToken: serverToken,
			TargetAddr:  backend,
			Emitter:     telemetry.New(&serveStatus, telemetry.LevelVerbose),
			ForceRelay:  true,
		})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{
			ClientToken:  clientToken,
			ListenAddr:   "127.0.0.1:0",
			BindAddrSink: bindCh,
			ForceRelay:   true,
		})
	}()
	bindAddr := <-bindCh

	for _, payload := range []string{"first", "second"} {
		reply, err := roundTripTCP(ctx, bindAddr, payload)
		if err != nil {
			t.Fatalf("roundTripTCP(%q) error = %v; serve=%q", payload, err, serveStatus.String())
		}
		if reply != payload {
			t.Fatalf("reply = %q, want %q", reply, payload)
		}
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer waitCancel()
	if err := waitForSessionTestStatusOccurrences(waitCtx, &serveStatus, "derptun-quic-connection-accepted", 9); err != nil {
		t.Fatalf("serve status = %q, want control plus striped per-flow QUIC connections: %v", serveStatus.String(), err)
	}

	cancel()
	<-serveErr
	<-openErr
}

func TestDerptunOpenUsesV2RawDirectDataPlane(t *testing.T) {
	t.Setenv("DERPHOLE_FAKE_TRANSPORT", "1")
	t.Setenv("DERPHOLE_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	backend, backendDone := startEchoServer(t, ctx)
	defer backendDone()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	var serveStatus syncBuffer
	var openStatus syncBuffer
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{
			ServerToken: serverToken,
			TargetAddr:  backend,
			Emitter:     telemetry.New(&serveStatus, telemetry.LevelVerbose),
		})
	}()

	bindCh := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- DerptunOpen(ctx, DerptunOpenConfig{
			ClientToken:  clientToken,
			ListenAddr:   "127.0.0.1:0",
			BindAddrSink: bindCh,
			Emitter:      telemetry.New(&openStatus, telemetry.LevelVerbose),
		})
	}()
	bindAddr := <-bindCh

	reply, err := roundTripTCP(ctx, bindAddr, "raw-direct")
	if err != nil {
		t.Fatalf("roundTripTCP() error = %v; serve=%q open=%q", err, serveStatus.String(), openStatus.String())
	}
	if reply != "raw-direct" {
		t.Fatalf("reply = %q, want raw-direct; serve=%q open=%q", reply, serveStatus.String(), openStatus.String())
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	if err := waitForSessionTestStatusContains(waitCtx, &serveStatus, "v2-data-plane=raw-direct"); err != nil {
		t.Fatalf("serve status = %q, want raw-direct data plane: %v", serveStatus.String(), err)
	}
	if err := waitForSessionTestStatusContains(waitCtx, &openStatus, "v2-data-plane=raw-direct"); err != nil {
		t.Fatalf("open status = %q, want raw-direct data plane: %v", openStatus.String(), err)
	}

	cancel()
	<-serveErr
	<-openErr
}

func TestDerptunConnectBridgesStdio(t *testing.T) {
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
	start := time.Now()
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
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("DerptunConnect() elapsed = %v, want under 5s", elapsed)
	}
	cancel()
	<-serveErr
}

func TestDerptunServeAcceptsRepeatedConnectRestarts(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backend := startLineEchoServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()

	for _, line := range []string{"first\n", "second\n"} {
		var out strings.Builder
		connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second)
		err := DerptunConnect(connectCtx, DerptunConnectConfig{
			ClientToken: clientToken,
			StdioIn:     strings.NewReader(line),
			StdioOut:    &out,
			ForceRelay:  true,
		})
		connectCancel()
		if err != nil {
			t.Fatalf("DerptunConnect(%q) error = %v", strings.TrimSpace(line), err)
		}
		if got, want := out.String(), "echo: "+line; got != want {
			t.Fatalf("DerptunConnect(%q) stdout = %q, want %q", strings.TrimSpace(line), got, want)
		}
	}

	cancel()
	<-serveErr
}

func TestDerptunServeRejectsConcurrentConnector(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backend, accepted := startHoldingTCPServer(t)
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- DerptunServe(ctx, DerptunServeConfig{ServerToken: serverToken, TargetAddr: backend, ForceRelay: true})
	}()

	firstInput, firstInputWriter := io.Pipe()
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- DerptunConnect(ctx, DerptunConnectConfig{
			ClientToken: clientToken,
			StdioIn:     firstInput,
			StdioOut:    io.Discard,
			ForceRelay:  true,
		})
	}()
	if _, err := firstInputWriter.Write([]byte("first\n")); err != nil {
		t.Fatalf("first connector Write() error = %v", err)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("first connector did not reach backend")
	}

	secondCtx, secondCancel := context.WithTimeout(ctx, 5*time.Second)
	defer secondCancel()
	err := DerptunConnect(secondCtx, DerptunConnectConfig{
		ClientToken: clientToken,
		StdioIn:     strings.NewReader("second\n"),
		StdioOut:    io.Discard,
		ForceRelay:  true,
	})
	if err == nil {
		t.Fatal("second DerptunConnect() error = nil, want claimed rejection")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("second DerptunConnect() error = %v, want deterministic claimed rejection", err)
	}
	if !strings.Contains(err.Error(), "session already claimed") {
		t.Fatalf("second DerptunConnect() error = %v, want session already claimed", err)
	}

	cancel()
	_ = firstInputWriter.Close()
	<-firstErr
	<-serveErr
}

func TestDerptunRejectsWrongTokenRoles(t *testing.T) {
	serverToken, clientToken := derptunServerAndClientTokens(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := DerptunServe(ctx, DerptunServeConfig{ServerToken: clientToken, TargetAddr: "127.0.0.1:22"}); !errors.Is(err, derptun.ErrInvalidToken) {
		t.Fatalf("DerptunServe(client) error = %v, want ErrInvalidToken", err)
	}
	if err := DerptunConnect(ctx, DerptunConnectConfig{ClientToken: serverToken, StdioIn: strings.NewReader("x"), StdioOut: io.Discard}); !errors.Is(err, derptun.ErrInvalidToken) {
		t.Fatalf("DerptunConnect(server) error = %v, want ErrInvalidToken", err)
	}
	if err := DerptunConnect(ctx, DerptunConnectConfig{ClientToken: "dtc1_legacy", StdioIn: strings.NewReader("x"), StdioOut: io.Discard}); !errors.Is(err, derptun.ErrInvalidToken) {
		t.Fatalf("DerptunConnect(old client token) error = %v, want ErrInvalidToken", err)
	}
}

func TestDerptunServerTokenForClaimRejectsTamperedClientProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	validClaim := derptunClaimForClient(t, clientCred, 91)
	if _, reject, err := derptunServerTokenForClaim(serverCred, validClaim, now); err != nil {
		t.Fatalf("valid derptunServerTokenForClaim() error = %v reject=%+v", err, reject)
	}

	for _, tt := range []struct {
		name   string
		mutate func(*rendezvous.Claim)
	}{
		{
			name: "extended expiry",
			mutate: func(claim *rendezvous.Claim) {
				claim.Client.ExpiresUnix += int64(24 * time.Hour / time.Second)
			},
		},
		{
			name: "moved session",
			mutate: func(claim *rendezvous.Claim) {
				claim.SessionID[0]++
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			claim := derptunClaimForClient(t, clientCred, 92)
			tt.mutate(&claim)
			clientTok, err := clientCred.SessionToken()
			if err != nil {
				t.Fatalf("SessionToken() error = %v", err)
			}
			claim.BearerMAC = rendezvous.ComputeBearerMAC(clientTok.BearerSecret, claim)

			_, reject, err := derptunServerTokenForClaim(serverCred, claim, now)
			if err == nil {
				t.Fatal("derptunServerTokenForClaim(tampered) error = nil, want rejection")
			}
			if reject.Reject == nil || reject.Reject.Code != rendezvous.RejectBadMAC {
				t.Fatalf("Reject = %+v, want %q", reject.Reject, rendezvous.RejectBadMAC)
			}
		})
	}
}

func TestDerptunServerTokenForClaimRejectsMissingClientProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	claim := derptunClaimForClient(t, clientCred, 93)
	claim.Client = nil
	clientTok, err := clientCred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(clientTok.BearerSecret, claim)

	_, reject, err := derptunServerTokenForClaim(serverCred, claim, now)
	if !errors.Is(err, rendezvous.ErrDenied) {
		t.Fatalf("derptunServerTokenForClaim() error = %v, want ErrDenied", err)
	}
	if reject.Reject == nil || reject.Reject.Code != rendezvous.RejectClaimMalformed {
		t.Fatalf("Reject = %+v, want %q", reject.Reject, rendezvous.RejectClaimMalformed)
	}
}

func TestDerptunServerTokenForClaimRejectsExpiredServerCredential(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	serverCred.ExpiresUnix = now.Add(-time.Second).Unix()
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	claim := derptunClaimForClient(t, clientCred, 94)

	_, reject, err := derptunServerTokenForClaim(serverCred, claim, now)
	if !errors.Is(err, derptun.ErrExpired) {
		t.Fatalf("derptunServerTokenForClaim() error = %v, want derptun.ErrExpired", err)
	}
	if reject.Reject == nil || reject.Reject.Code != rendezvous.RejectExpired {
		t.Fatalf("Reject = %+v, want %q", reject.Reject, rendezvous.RejectExpired)
	}
}

func TestDerptunServerAndClientDeriveSameTransportDiscoveryKey(t *testing.T) {
	now := time.Now()
	serverToken, clientToken := derptunServerAndClientTokens(t)
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	claim := derptunClaimForClient(t, clientCred, 97)
	serverTok, reject, err := derptunServerTokenForClaim(serverCred, claim, now)
	if err != nil {
		t.Fatalf("derptunServerTokenForClaim() error = %v reject=%+v", err, reject)
	}
	clientTok, err := clientCred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	serverDERP, err := serverCred.DERPKey()
	if err != nil {
		t.Fatalf("DERPKey() error = %v", err)
	}
	clientDERP := key.NodePublicFromRaw32(mem.B(claim.DERPPublic[:]))

	serverKey := externalTransportDiscoveryKey(serverTok, serverDERP.Public(), clientDERP)
	clientKey := externalTransportDiscoveryKey(clientTok, clientDERP, serverDERP.Public())
	if serverKey != clientKey {
		t.Fatalf("server key = %x, client key = %x", serverKey, clientKey)
	}
}

func TestDerptunServerTokenForClaimRejectsClientExpiryPastServerExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	serverCred.ExpiresUnix = now.Add(time.Hour).Unix()
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	claim := derptunClaimForClient(t, clientCred, 95)

	_, reject, err := derptunServerTokenForClaim(serverCred, claim, now)
	if !errors.Is(err, derptun.ErrExpired) {
		t.Fatalf("derptunServerTokenForClaim() error = %v, want derptun.ErrExpired", err)
	}
	if reject.Reject == nil || reject.Reject.Code != rendezvous.RejectExpired {
		t.Fatalf("Reject = %+v, want %q", reject.Reject, rendezvous.RejectExpired)
	}
}

func TestHandleDerptunServeRuntimeClaimRejectsSourceMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	claim := derptunClaimForClient(t, clientCred, 96)
	payload, err := json.Marshal(envelope{Type: envelopeClaim, Claim: &claim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	runtime := &derptunServeRuntime{server: serverCred}
	gate := &derptunClientGate{}
	active, err := handleDerptunServeRuntimeClaim(
		context.Background(),
		derptunServeSessionConfig{ForceRelay: true, TargetAddr: "127.0.0.1:1"},
		runtime,
		gate,
		nil,
		derpbind.Packet{From: key.NewNode().Public(), Payload: payload},
	)
	if err != nil {
		t.Fatalf("handleDerptunServeRuntimeClaim() error = %v, want nil for ignored source mismatch", err)
	}
	if active != nil {
		t.Fatalf("active = %+v, want nil", active)
	}
	if gate.active != nil {
		t.Fatalf("gate active = %+v, want nil", gate.active)
	}
}

func TestHandleDerptunServeRuntimeClaimRejectsUnsignedEnvelope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}

	srv := newSessionTestDERPServer(t)
	node := srv.Map.Regions[1].Nodes[0]
	derpClient, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(server) error = %v", err)
	}
	defer derpClient.Close()
	peerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(peer) error = %v", err)
	}
	defer peerDERP.Close()

	probeConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer probeConn.Close()

	claim := derptunClaimForClient(t, clientCred, 96)
	claim.DERPPublic = derpPublicKeyRaw32(peerDERP.PublicKey())
	tok, err := clientCred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	payload, err := json.Marshal(envelope{Type: envelopeClaim, Claim: &claim})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	gate := &derptunClientGate{}
	runtime := &derptunServeRuntime{
		server:     serverCred,
		identity:   quicpath.SessionIdentity{},
		dm:         srv.Map,
		derpClient: derpClient,
		probeConn:  probeConn,
		pm:         newBoundPublicPortmap(probeConn, nil),
	}
	active, err := handleDerptunServeRuntimeClaim(
		ctx,
		derptunServeSessionConfig{ForceRelay: true, TargetAddr: "127.0.0.1:1"},
		runtime,
		gate,
		nil,
		derpbind.Packet{From: peerDERP.PublicKey(), Payload: payload},
	)
	if active != nil {
		defer func() { _ = active.stop(context.Background()) }()
	}
	if err != nil {
		t.Fatalf("handleDerptunServeRuntimeClaim() error = %v, want nil for ignored unsigned claim", err)
	}
	if active != nil {
		t.Fatalf("active = %+v, want nil", active)
	}
	if gate.active != nil {
		t.Fatalf("gate active = %+v, want nil", gate.active)
	}
}

func TestRecoverStaleDerptunActiveReleasesUnresponsiveClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	now := time.Now()
	tok := derptunTestToken(now.Add(time.Minute))
	gate := &derptunClientGate{}
	first := derptunTestClaim(tok, 11)
	if _, err := gate.Accept(now, tok, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: time.Second})
	defer mux.Close()
	mux.ReplaceCarrier(newSessionNoReplyCarrier())

	activeCtx, activeCancel := context.WithCancel(ctx)
	active := &derptunServeActive{
		claim:  first,
		mux:    mux,
		cancel: activeCancel,
		done:   make(chan error, 1),
	}
	go func() {
		<-activeCtx.Done()
		active.done <- activeCtx.Err()
	}()

	second := derptunTestClaim(tok, 22)
	if _, err := gate.Accept(now, tok, second); !errors.Is(err, rendezvous.ErrClaimed) {
		t.Fatalf("second Accept() error = %v, want %v", err, rendezvous.ErrClaimed)
	}

	recovered, err := recoverStaleDerptunActive(ctx, nil, gate, active, 50*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("recoverStaleDerptunActive() error = %v", err)
	}
	if !recovered {
		t.Fatal("recoverStaleDerptunActive() recovered = false, want true")
	}

	decision, err := gate.Accept(now, tok, second)
	if err != nil {
		t.Fatalf("second Accept() after recovery error = %v", err)
	}
	if !decision.Accepted {
		t.Fatal("second Accept() after recovery rejected, want accepted")
	}
}

func TestRecoverStaleDerptunActiveKeepsResponsiveClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	now := time.Now()
	tok := derptunTestToken(now.Add(time.Minute))
	gate := &derptunClientGate{}
	first := derptunTestClaim(tok, 33)
	if _, err := gate.Accept(now, tok, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	clientMux, serverMux := newSessionMuxPair(t, time.Second)
	defer clientMux.Close()
	defer serverMux.Close()
	active := &derptunServeActive{
		claim:  first,
		mux:    serverMux,
		cancel: func() {},
		done:   make(chan error, 1),
	}

	recovered, err := recoverStaleDerptunActive(ctx, nil, gate, active, 200*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("recoverStaleDerptunActive() error = %v", err)
	}
	if recovered {
		t.Fatal("recoverStaleDerptunActive() recovered = true, want false")
	}

	second := derptunTestClaim(tok, 44)
	if _, err := gate.Accept(now, tok, second); !errors.Is(err, rendezvous.ErrClaimed) {
		t.Fatalf("second Accept() error = %v, want %v", err, rendezvous.ErrClaimed)
	}
}

func TestRecoverStaleDerptunActiveReleasesClosedTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	now := time.Now()
	tok := derptunTestToken(now.Add(time.Minute))
	gate := &derptunClientGate{}
	first := derptunTestClaim(tok, 77)
	if _, err := gate.Accept(now, tok, first); err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	quicDone := make(chan struct{})
	close(quicDone)
	active := &derptunServeActive{
		claim:    first,
		quicDone: quicDone,
		cancel:   func() {},
		done:     make(chan error, 1),
	}
	active.done <- context.Canceled

	recovered, err := recoverStaleDerptunActive(ctx, nil, gate, active, 200*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("recoverStaleDerptunActive() error = %v", err)
	}
	if !recovered {
		t.Fatal("recoverStaleDerptunActive() recovered = false, want true")
	}

	second := derptunTestClaim(tok, 88)
	decision, err := gate.Accept(now, tok, second)
	if err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	if !decision.Accepted {
		t.Fatal("second Accept() rejected after closed transport recovery")
	}
}

func TestServeQUICListenerForwardsConcurrentStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend, accepted := startHoldingTCPServer(t)
	serverIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(server) error = %v", err)
	}
	clientIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(client) error = %v", err)
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer packetConn.Close()
	listener, err := quic.Listen(packetConn, quicpath.ServerTLSConfig(serverIdentity, clientIdentity.Public), derptunQUICConfig())
	if err != nil {
		t.Fatalf("quic.Listen() error = %v", err)
	}
	defer listener.Close()
	clientPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(client) error = %v", err)
	}
	defer clientPacketConn.Close()

	serveErr := make(chan error, 1)
	go func() {
		quicConn, err := listener.Accept(ctx)
		if err != nil {
			serveErr <- err
			return
		}
		serveErr <- serveQUICListener(ctx, quicConn, backend, nil)
	}()

	clientConn, err := quic.Dial(ctx, clientPacketConn, packetConn.LocalAddr(), quicpath.ClientTLSConfig(clientIdentity, serverIdentity.Public), derptunQUICConfig())
	if err != nil {
		t.Fatalf("quic.Dial() error = %v", err)
	}
	defer func() { _ = clientConn.CloseWithError(0, "") }()

	firstStream, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("first OpenStreamSync() error = %v", err)
	}
	defer firstStream.Close()
	if _, err := firstStream.Write([]byte("x")); err != nil {
		t.Fatalf("first stream Write() error = %v", err)
	}
	waitForBackendAccept(t, ctx, accepted, "first native QUIC stream")

	secondStream, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("second OpenStreamSync() error = %v", err)
	}
	defer secondStream.Close()
	if _, err := secondStream.Write([]byte("x")); err != nil {
		t.Fatalf("second stream Write() error = %v", err)
	}
	waitForBackendAccept(t, ctx, accepted, "second native QUIC stream")

	cancel()
	if err := <-serveErr; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("serveQUICListener() error = %v", err)
	}
}

func TestDerptunQUICConfigDetectsDeadPeersPromptly(t *testing.T) {
	cfg := derptunQUICConfig()
	if cfg.KeepAlivePeriod > 2*time.Second {
		t.Fatalf("KeepAlivePeriod = %v, want <= 2s", cfg.KeepAlivePeriod)
	}
	if cfg.MaxIdleTimeout > 10*time.Second {
		t.Fatalf("MaxIdleTimeout = %v, want <= 10s", cfg.MaxIdleTimeout)
	}
}

func TestDerptunNativeTCPUsesMeasuredStripeCount(t *testing.T) {
	if derptunNativeTCPStripeCount != 12 {
		t.Fatalf("derptunNativeTCPStripeCount = %d, want 12", derptunNativeTCPStripeCount)
	}
}

func TestDerptunStripedStreamConnStaysOpenUntilClose(t *testing.T) {
	localLane, remoteLane := net.Pipe()
	defer remoteLane.Close()

	conn := newDerptunStripedStreamConn([]derptunNativeDialedLane{{conn: localLane}})
	defer conn.Close()

	payload := []byte("payload")
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeDone <- err
	}()

	if err := remoteLane.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	chunk, err := readExternalStripedChunk(remoteLane, externalCopyBufferSize, newExternalStripedChunkPool(externalCopyBufferSize))
	if err != nil {
		t.Fatalf("readExternalStripedChunk() error = %v", err)
	}
	if !bytes.Equal(chunk.data, payload) {
		t.Fatalf("chunk.data = %q, want %q", chunk.data, payload)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write() did not return")
	}
}

func TestBridgeDerptunStdioClosesInputWhenRemoteEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	local, remote := net.Pipe()
	input, inputWriter := io.Pipe()
	defer inputWriter.Close()

	done := make(chan error, 1)
	go func() {
		done <- bridgeDerptunStdio(ctx, local, input, io.Discard)
	}()

	if err := remote.Close(); err != nil {
		t.Fatalf("remote Close() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bridgeDerptunStdio() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("bridgeDerptunStdio() did not return after remote close")
	}
	if _, err := inputWriter.Write([]byte("still-open")); err == nil {
		t.Fatal("input writer remained open after bridge returned")
	}
}

func TestBridgeDerptunStdioReadsReplyBeforeRemoteClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	local, remote := net.Pipe()
	defer local.Close()
	go func() {
		defer remote.Close()
		line, err := bufio.NewReader(remote).ReadString('\n')
		if err == nil {
			_, _ = io.WriteString(remote, "echo: "+line)
		}
	}()

	var out bytes.Buffer
	if err := bridgeDerptunStdio(ctx, local, strings.NewReader("hello\n"), &out); err != nil {
		t.Fatalf("bridgeDerptunStdio() error = %v", err)
	}
	if got, want := out.String(), "echo: hello\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func startLineEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					_, _ = io.WriteString(conn, "echo: "+line)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func startHoldingTCPServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan struct{}, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String(), accepted
}

func waitForBackendAccept(t *testing.T, ctx context.Context, accepted <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatalf("%s did not reach backend: %v", label, ctx.Err())
	}
}

func waitForSessionTestStatusOccurrences(ctx context.Context, status *syncBuffer, needle string, want int) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if strings.Count(status.String(), needle) >= want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func derptunTestToken(expires time.Time) token.Token {
	return token.Token{
		Version:      token.SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8},
		ExpiresUnix:  expires.Unix(),
		BearerSecret: [32]byte{9, 8, 7, 6, 5, 4, 3, 2},
		Capabilities: token.CapabilityDerptunTCP,
	}
}

func derptunTestClaim(tok token.Token, marker byte) rendezvous.Claim {
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   [32]byte{marker},
		QUICPublic:   [32]byte{marker + 1},
		Candidates:   []string{"203.0.113.10:12345"},
		Capabilities: tok.Capabilities,
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}

func derptunClaimForClient(t *testing.T, cred derptun.ClientCredential, marker byte) rendezvous.Claim {
	t.Helper()
	tok, err := cred.SessionToken()
	if err != nil {
		t.Fatalf("SessionToken() error = %v", err)
	}
	claim := rendezvous.Claim{
		Version:      tok.Version,
		SessionID:    tok.SessionID,
		DERPPublic:   [32]byte{marker},
		QUICPublic:   [32]byte{marker + 1},
		Candidates:   []string{"203.0.113.10:12345"},
		Capabilities: tok.Capabilities,
		Client: &rendezvous.ClientProof{
			ClientID:    cred.ClientID,
			TokenID:     cred.TokenID,
			ClientName:  cred.ClientName,
			ExpiresUnix: cred.ExpiresUnix,
			ProofMAC:    cred.ProofMAC,
		},
	}
	claim.BearerMAC = rendezvous.ComputeBearerMAC(tok.BearerSecret, claim)
	return claim
}

func newSessionMuxPair(t *testing.T, reconnectTimeout time.Duration) (*derptun.Mux, *derptun.Mux) {
	t.Helper()

	clientCarrier, serverCarrier := net.Pipe()
	clientMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: reconnectTimeout})
	serverMux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: reconnectTimeout})
	clientMux.ReplaceCarrier(clientCarrier)
	serverMux.ReplaceCarrier(serverCarrier)
	return clientMux, serverMux
}

type sessionNoReplyCarrier struct {
	closed chan struct{}
	once   sync.Once
}

func newSessionNoReplyCarrier() *sessionNoReplyCarrier {
	return &sessionNoReplyCarrier{closed: make(chan struct{})}
}

func (c *sessionNoReplyCarrier) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *sessionNoReplyCarrier) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *sessionNoReplyCarrier) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}
