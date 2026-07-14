// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestCustomDERPOneShotForceRelayRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv(derpbind.CustomDERPServerEnv, "https://custom.test.invalid")
	clearDERPProxyEnvironment(t)
	publicFetches := rejectCustomProductPublicMapFetches(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var listenerOut bytes.Buffer
	var listenerDebug, senderDebug syncBuffer
	tokens := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerDebug, telemetry.LevelVerbose),
			TokenSink:     tokens,
			StdioOut:      &listenerOut,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	var encoded string
	select {
	case encoded = <-tokens:
	case err := <-listenErr:
		t.Fatalf("Listen() returned before token: %v", err)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for token: %v", ctx.Err())
	}
	assertCustomProductToken(t, encoded)

	t.Setenv(derpbind.CustomDERPServerEnv, "")
	if err := Send(ctx, SendConfig{
		Token:         encoded,
		Emitter:       telemetry.New(&senderDebug, telemetry.LevelVerbose),
		StdioIn:       strings.NewReader("custom one-shot payload"),
		ForceRelay:    true,
		UsePublicDERP: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if got := listenerOut.String(); got != "custom one-shot payload" {
		t.Fatalf("received payload = %q, want custom one-shot payload", got)
	}
	assertCustomProductDiagnostics(t, "listener", listenerDebug.String())
	assertCustomProductDiagnostics(t, "sender", senderDebug.String())
	if got := publicFetches.Load(); got != 0 {
		t.Fatalf("public DERP map fetches = %d, want 0", got)
	}
}

func TestCustomDERPDerptunAppForceRelayRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv(derpbind.CustomDERPServerEnv, "https://custom.test.invalid")
	clearDERPProxyEnvironment(t)
	publicFetches := rejectCustomProductPublicMapFetches(t)

	now := time.Now()
	serverToken, err := derptun.GenerateServerTokenFromEnvironment(derptun.ServerTokenOptions{Now: now, Days: 1})
	if err != nil {
		t.Fatalf("GenerateServerTokenFromEnvironment() error = %v", err)
	}
	clientToken, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: serverToken, Days: 1})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if !strings.HasPrefix(serverToken, derptun.CustomServerTokenPrefix) || !strings.HasPrefix(clientToken, derptun.CustomClientTokenPrefix) {
		t.Fatalf("custom credential prefixes = %q/%q, want %q/%q", serverToken[:len(derptun.CustomServerTokenPrefix)], clientToken[:len(derptun.CustomClientTokenPrefix)], derptun.CustomServerTokenPrefix, derptun.CustomClientTokenPrefix)
	}
	serverCred, err := derptun.DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	serverSession, err := serverCred.SessionToken()
	if err != nil {
		t.Fatalf("server SessionToken() error = %v", err)
	}
	clientCred, err := derptun.DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	clientSession, err := clientCred.SessionToken()
	if err != nil {
		t.Fatalf("client SessionToken() error = %v", err)
	}
	assertCustomProductSessionToken(t, serverSession)
	assertCustomProductSessionToken(t, clientSession)

	t.Setenv(derpbind.CustomDERPServerEnv, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var serverDebug, clientDebug syncBuffer
	runDerptunAppMuxStreamExchange(
		t,
		ctx,
		serverToken,
		clientToken,
		true,
		telemetry.New(&serverDebug, telemetry.LevelVerbose),
		telemetry.New(&clientDebug, telemetry.LevelVerbose),
	)
	assertCustomProductDiagnostics(t, "derptun app server", serverDebug.String())
	assertCustomProductDiagnostics(t, "derptun app client", clientDebug.String())
	if got := publicFetches.Load(); got != 0 {
		t.Fatalf("public DERP map fetches = %d, want 0", got)
	}
}

func TestCustomDERPUnresolvableEmbeddedRouteFailsClosed(t *testing.T) {
	clearDERPProxyEnvironment(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "")
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")
	t.Setenv(derpbind.CustomDERPServerEnv, "https://consumer-secret.invalid:9443/derp")

	oldFetch := fetchSessionDERPMap
	var publicFetches atomic.Int64
	fetchSessionDERPMap = func(context.Context, string) (*tailcfg.DERPMap, error) {
		publicFetches.Add(1)
		return customProductPublicFallbackMap(), nil
	}
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })

	route, err := derpbind.NewCustomRoute("unresolvable.custom.test.invalid", derpbind.DefaultDERPPort, derpbind.DefaultSTUNPort)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	encoded := encodeCustomProductTestToken(t, route)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = Send(ctx, SendConfig{
		Token:         encoded,
		StdioIn:       strings.NewReader("must not fall back"),
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err == nil {
		t.Fatal("Send() error = nil, want custom destination failure")
	}
	assertSanitizedCustomConnectError(t, err, "unresolvable.custom.test.invalid:443")
	if got := publicFetches.Load(); got != 0 {
		t.Fatalf("public DERP map fetches = %d, want 0", got)
	}
}

func TestCustomDERPDurableServerUnresolvableRouteFailsClosed(t *testing.T) {
	clearDERPProxyEnvironment(t)
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "")
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")
	t.Setenv(derpbind.CustomDERPServerEnv, "https://consumer-secret.invalid:9443/derp")

	oldFetch := fetchSessionDERPMap
	var publicFetches atomic.Int64
	fetchSessionDERPMap = func(context.Context, string) (*tailcfg.DERPMap, error) {
		publicFetches.Add(1)
		return customProductPublicFallbackMap(), nil
	}
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })

	route, err := derpbind.NewCustomRoute("unresolvable.durable.test.invalid", derpbind.DefaultDERPPort, derpbind.DefaultSTUNPort)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	serverToken, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: time.Now(), Days: 1, DERPRoute: route})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	cred, tok, _, err := loadDerptunServeIdentity(serverToken)
	if err != nil {
		t.Fatalf("loadDerptunServeIdentity() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = openDerptunServeDERP(ctx, tok, cred, nil)
	if err == nil {
		t.Fatal("openDerptunServeDERP() error = nil, want custom destination failure")
	}
	assertSanitizedCustomConnectError(t, err, "unresolvable.durable.test.invalid:443")
	if got := publicFetches.Load(); got != 0 {
		t.Fatalf("public DERP map fetches = %d, want 0", got)
	}
}

func TestCustomDERPPublicTokenStillUsesPublicProvider(t *testing.T) {
	clearDERPProxyEnvironment(t)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "http://127.0.0.1:1/derp")
	t.Setenv(derpbind.CustomDERPServerEnv, "https://consumer-conflict.invalid:9443/derp")

	oldFetch := fetchSessionDERPMap
	var publicFetches atomic.Int64
	fetchSessionDERPMap = func(context.Context, string) (*tailcfg.DERPMap, error) {
		publicFetches.Add(1)
		return customProductPublicFallbackMap(), nil
	}
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })

	encoded := encodeCustomProductTestToken(t, derpbind.Route{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Send(ctx, SendConfig{
		Token:         encoded,
		StdioIn:       strings.NewReader("public provider proof"),
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err == nil {
		t.Fatal("Send() error = nil, want test public DERP connection failure")
	}
	if got := publicFetches.Load(); got != 1 {
		t.Fatalf("public DERP map fetches = %d, want 1", got)
	}
}

func rejectCustomProductPublicMapFetches(t *testing.T) *atomic.Int64 {
	t.Helper()
	oldFetch := fetchSessionDERPMap
	var calls atomic.Int64
	fetchSessionDERPMap = func(context.Context, string) (*tailcfg.DERPMap, error) {
		calls.Add(1)
		return nil, errors.New("unexpected public DERP map fetch")
	}
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })
	return &calls
}

func assertCustomProductToken(t *testing.T, encoded string) {
	t.Helper()
	tok, err := token.Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	assertCustomProductSessionToken(t, tok)
}

func assertCustomProductSessionToken(t *testing.T, tok token.Token) {
	t.Helper()
	wantRoute := derpbind.Route{
		Host:     "custom.test.invalid",
		DERPPort: derpbind.DefaultDERPPort,
		STUNPort: derpbind.DefaultSTUNPort,
	}
	if tok.Version != token.CustomDERPVersion || tok.DERPRoute != wantRoute {
		t.Fatalf("token version/route = %d/%+v, want v%d %+v", tok.Version, tok.DERPRoute, token.CustomDERPVersion, wantRoute)
	}
}

func assertCustomProductDiagnostics(t *testing.T, peer, got string) {
	t.Helper()
	if !strings.Contains(got, "derp-route=custom") || !strings.Contains(got, string(StateRelay)) {
		t.Fatalf("%s diagnostics = %q, want custom route and connected relay", peer, got)
	}
	for _, publicName := range []string{"tailscale.com", "derp1", "derp2", "derp3", "derp4"} {
		if strings.Contains(strings.ToLower(got), publicName) {
			t.Fatalf("%s diagnostics name public DERP %q: %q", peer, publicName, got)
		}
	}
}

func encodeCustomProductTestToken(t *testing.T, route derpbind.Route) string {
	t.Helper()
	regionID := uint16(1)
	if route.IsCustom() {
		regionID = derpbind.CustomDERPRegionID
	}
	tok := token.Token{
		Version:         token.VersionForRoute(route),
		SessionID:       [16]byte{1},
		ExpiresUnix:     time.Now().Add(time.Hour).Unix(),
		BootstrapRegion: regionID,
		DERPPublic:      derpPublicKeyRaw32(key.NewNode().Public()),
		QUICPublic:      [32]byte{2},
		BearerSecret:    [32]byte{3},
		Capabilities:    token.CapabilityStdio | token.CapabilityTransferV2,
		DERPRoute:       route,
	}
	encoded, err := token.Encode(tok)
	if err != nil {
		t.Fatalf("token.Encode() error = %v", err)
	}
	return encoded
}

func customProductPublicFallbackMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {
			RegionID:   1,
			RegionCode: "public-fallback",
			RegionName: "Public Fallback",
			Nodes: []*tailcfg.DERPNode{{
				Name:     "public-fallback-1",
				RegionID: 1,
				HostName: "public-fallback.test.invalid",
			}},
		},
	}}
}

func assertSanitizedCustomConnectError(t *testing.T, err error, authority string) {
	t.Helper()
	got := err.Error()
	if !strings.Contains(got, "connect custom DERP "+authority) {
		t.Fatalf("custom connect error = %q, want sanitized authority %q", got, authority)
	}
	if !strings.Contains(got, "dial") && !strings.Contains(got, "lookup") && !strings.Contains(got, "timeout") {
		t.Fatalf("custom connect error = %q, want useful connection-stage detail", got)
	}
	for _, forbidden := range []string{"consumer-secret", "public-fallback", "tailscale.com", "https://", "http://", "/derp"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("custom connect error exposes destination detail %q: %q", forbidden, got)
		}
	}
}
