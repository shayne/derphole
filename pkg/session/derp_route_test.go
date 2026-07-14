// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"tailscale.com/tailcfg"
)

func TestDERPBootstrapPublicUsesPublicProvider(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "")
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")

	node := &tailcfg.DERPNode{
		Name:     "public-test",
		RegionID: 41,
		HostName: "public.example.com",
		DERPPort: 8443,
	}
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		41: {RegionID: 41, Nodes: []*tailcfg.DERPNode{node}},
	}}

	oldFetch := fetchSessionDERPMap
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })
	var calls int
	fetchSessionDERPMap = func(_ context.Context, gotURL string) (*tailcfg.DERPMap, error) {
		calls++
		if gotURL != publicDERPMapURL() {
			t.Fatalf("fetch URL = %q, want %q", gotURL, publicDERPMapURL())
		}
		return dm, nil
	}

	got, err := resolveDERPBootstrap(context.Background(), derpbind.Route{}, 41, "missing public node")
	if err != nil {
		t.Fatalf("resolveDERPBootstrap() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("fetch calls = %d, want 1", calls)
	}
	if got.route.IsCustom() {
		t.Fatalf("bootstrap route = %+v, want public", got.route)
	}
	if got.dm != dm {
		t.Fatal("bootstrap DERP map did not preserve provider result")
	}
	if got.node != node {
		t.Fatal("bootstrap node did not preserve requested region selection")
	}
	if want := publicDERPServerURL(node); got.serverURL != want {
		t.Fatalf("bootstrap server URL = %q, want %q", got.serverURL, want)
	}
}

func TestDERPBootstrapCustomBuildsOneNodeMapWithoutPublicProvider(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "https://map.invalid/must-not-fetch")
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")

	oldFetch := fetchSessionDERPMap
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })
	fetchSessionDERPMap = func(_ context.Context, gotURL string) (*tailcfg.DERPMap, error) {
		t.Fatalf("fetchSessionDERPMap called for custom route with %q", gotURL)
		return nil, nil
	}

	route, err := derpbind.NewCustomRoute("derp.example.com", 8443, 3479)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	got, err := resolveDERPBootstrap(context.Background(), route, 123, "missing custom node")
	if err != nil {
		t.Fatalf("resolveDERPBootstrap() error = %v", err)
	}
	if got.route != route {
		t.Fatalf("bootstrap route = %+v, want %+v", got.route, route)
	}
	if got.dm == nil || !got.dm.OmitDefaultRegions || len(got.dm.Regions) != 1 {
		t.Fatalf("bootstrap map = %+v, want one custom-only region", got.dm)
	}
	region := got.dm.Regions[derpbind.CustomDERPRegionID]
	if region == nil || len(region.Nodes) != 1 {
		t.Fatalf("custom region = %+v, want one node", region)
	}
	if got.node != region.Nodes[0] || got.node.RegionID != derpbind.CustomDERPRegionID {
		t.Fatalf("bootstrap node = %+v, want custom region node", got.node)
	}
	if got.serverURL != route.ServerURL() {
		t.Fatalf("bootstrap server URL = %q, want %q", got.serverURL, route.ServerURL())
	}
}

func TestDERPBootstrapServerURLOverrideChangesOnlyDialURL(t *testing.T) {
	const override = "http://127.0.0.1:12345/derp"
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", override)

	t.Run("public", func(t *testing.T) {
		node := &tailcfg.DERPNode{Name: "public-test", RegionID: 7, HostName: "public.example.com"}
		dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
			7: {RegionID: 7, Nodes: []*tailcfg.DERPNode{node}},
		}}
		oldFetch := fetchSessionDERPMap
		t.Cleanup(func() { fetchSessionDERPMap = oldFetch })
		fetchSessionDERPMap = func(_ context.Context, _ string) (*tailcfg.DERPMap, error) {
			return dm, nil
		}

		got, err := resolveDERPBootstrap(context.Background(), derpbind.Route{}, 7, "missing")
		if err != nil {
			t.Fatalf("resolveDERPBootstrap() error = %v", err)
		}
		if got.dm != dm || got.node != node || got.serverURL != override {
			t.Fatalf("bootstrap = %+v, want preserved public map/node and override URL", got)
		}
	})

	t.Run("custom", func(t *testing.T) {
		t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "https://map.invalid/must-not-fetch")
		oldFetch := fetchSessionDERPMap
		t.Cleanup(func() { fetchSessionDERPMap = oldFetch })
		fetchSessionDERPMap = func(_ context.Context, gotURL string) (*tailcfg.DERPMap, error) {
			t.Fatalf("fetchSessionDERPMap called for custom route with %q", gotURL)
			return nil, nil
		}
		route, err := derpbind.NewCustomRoute("custom.example.com", 8443, 3478)
		if err != nil {
			t.Fatalf("NewCustomRoute() error = %v", err)
		}

		got, err := resolveDERPBootstrap(context.Background(), route, 7, "missing")
		if err != nil {
			t.Fatalf("resolveDERPBootstrap() error = %v", err)
		}
		if got.route != route || got.node == nil || got.node.HostName != route.Host || got.serverURL != override {
			t.Fatalf("bootstrap = %+v, want custom route/map and override URL", got)
		}
	})
}

func TestDERPBootstrapRejectsInvalidCustomRouteWithoutPublicProvider(t *testing.T) {
	oldFetch := fetchSessionDERPMap
	t.Cleanup(func() { fetchSessionDERPMap = oldFetch })
	fetchSessionDERPMap = func(_ context.Context, gotURL string) (*tailcfg.DERPMap, error) {
		t.Fatalf("fetchSessionDERPMap called for invalid custom route with %q", gotURL)
		return nil, nil
	}

	_, err := resolveDERPBootstrap(context.Background(), derpbind.Route{Host: "secret.example.com"}, 0, "missing")
	if err == nil {
		t.Fatal("resolveDERPBootstrap() error = nil, want invalid route error")
	}
}

func TestDERPRouteDebugEmitsOnlySanitizedCustomAuthorities(t *testing.T) {
	route, err := derpbind.NewCustomRoute("derp.example.com", 443, 3478)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	var out bytes.Buffer
	emitter := telemetry.New(&out, telemetry.LevelVerbose)

	emitDERPRouteDebug(emitter, derpbind.Route{})
	emitDERPRouteDebug(emitter, route)

	if got, want := out.String(), "derp-route=custom derp=derp.example.com:443 stun=derp.example.com:3478\n"; got != want {
		t.Fatalf("route diagnostics = %q, want %q", got, want)
	}
}

func TestDERPBootstrapCustomConnectFailureIncludesRouteAuthority(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")
	route, err := derpbind.NewCustomRoute("derp.example.com", 8443, 3478)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	bootstrap, err := resolveDERPBootstrap(context.Background(), route, 0, "missing")
	if err != nil {
		t.Fatalf("resolveDERPBootstrap() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = openSessionDERPClient(ctx, bootstrap, nil)
	if err == nil {
		t.Fatal("openSessionDERPClient() error = nil, want connect error")
	}
	if got, want := err.Error(), "connect custom DERP derp.example.com:8443:"; !strings.Contains(got, want) {
		t.Fatalf("openSessionDERPClient() error = %q, want %q", got, want)
	}
}

func TestCustomDERPRouteCreatorsEmbedCanonicalAuthority(t *testing.T) {
	creators := []struct {
		name   string
		create func(context.Context) (string, *relaySession, error)
	}{
		{
			name: "public session",
			create: func(ctx context.Context) (string, *relaySession, error) {
				return issuePublicSessionWithCapabilities(ctx, token.CapabilityStdio)
			},
		},
		{
			name: "public QUIC session",
			create: func(ctx context.Context) (string, *relaySession, error) {
				return issuePublicQUICSession(ctx, token.CapabilityStdio|token.CapabilityTransferV2, nil)
			},
		},
	}

	for _, tt := range creators {
		t.Run(tt.name, func(t *testing.T) {
			srv := newSessionTestDERPServer(t)
			t.Setenv(derpbind.CustomDERPServerEnv, "https://Creator.Invalid.:8443/derp")
			t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
			t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
			clearDERPProxyEnvironment(t)

			raw, session, err := tt.create(context.Background())
			if err != nil {
				t.Fatalf("create session error = %v", err)
			}
			closeTestRelaySession(session)

			got, err := token.Decode(raw, time.Now())
			if err != nil {
				t.Fatalf("token.Decode() error = %v", err)
			}
			wantRoute, err := derpbind.NewCustomRoute("creator.invalid", 8443, derpbind.DefaultSTUNPort)
			if err != nil {
				t.Fatalf("NewCustomRoute() error = %v", err)
			}
			if got.Version != token.CustomDERPVersion {
				t.Fatalf("token version = %d, want %d", got.Version, token.CustomDERPVersion)
			}
			if got.DERPRoute != wantRoute {
				t.Fatalf("token DERP route = %+v, want %+v", got.DERPRoute, wantRoute)
			}
			if got.BootstrapRegion != derpbind.CustomDERPRegionID {
				t.Fatalf("token bootstrap region = %d, want %d", got.BootstrapRegion, derpbind.CustomDERPRegionID)
			}
			if session.token.DERPRoute != wantRoute || session.derpMap == nil || session.derpMap.Regions[derpbind.CustomDERPRegionID] == nil {
				t.Fatalf("session route state = token %+v map %+v, want embedded custom route", session.token.DERPRoute, session.derpMap)
			}
		})
	}
}

func TestCustomDERPRouteConsumersUseCreatorAuthority(t *testing.T) {
	consumers := []struct {
		name         string
		capabilities uint32
		open         func(context.Context, string) error
	}{
		{
			name:         "external v2 send",
			capabilities: token.CapabilityStdio | token.CapabilityTransferV2,
			open: func(ctx context.Context, raw string) error {
				rt, err := newExternalV2SendRuntime(ctx, SendConfig{Token: raw})
				if rt != nil {
					rt.Close()
				}
				return err
			},
		},
		{
			name:         "external v2 offer receive",
			capabilities: token.CapabilityStdioOffer | token.CapabilityTransferV2,
			open: func(ctx context.Context, raw string) error {
				rt, err := newExternalV2OfferReceiveRuntime(ctx, ReceiveConfig{Token: raw})
				if rt != nil {
					rt.Close()
				}
				return err
			},
		},
	}

	for _, tt := range consumers {
		t.Run(tt.name, func(t *testing.T) {
			srv := newSessionTestDERPServer(t)
			t.Setenv(derpbind.CustomDERPServerEnv, "https://creator.invalid:8443")
			t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
			t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
			clearDERPProxyEnvironment(t)

			raw, session, err := issuePublicQUICSession(context.Background(), tt.capabilities, nil)
			if err != nil {
				t.Fatalf("issuePublicQUICSession() error = %v", err)
			}
			closeTestRelaySession(session)

			t.Setenv(derpbind.CustomDERPServerEnv, "https://consumer-conflict.invalid")
			t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")
			var mapRequests atomic.Int64
			mapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mapRequests.Add(1)
				http.Error(w, "custom consumers must not fetch a DERP map", http.StatusInternalServerError)
			}))
			t.Cleanup(mapServer.Close)
			t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", mapServer.URL)

			connectTargets := make(chan string, 1)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connectTargets <- r.Host
				http.Error(w, "stop after recording CONNECT authority", http.StatusBadGateway)
			}))
			t.Cleanup(proxy.Close)
			t.Setenv("HTTPS_PROXY", proxy.URL)
			t.Setenv("https_proxy", proxy.URL)
			t.Setenv("NO_PROXY", "")
			t.Setenv("no_proxy", "")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = tt.open(ctx, raw)
			if err == nil {
				t.Fatal("consumer runtime error = nil, want proxy rejection")
			}
			select {
			case got := <-connectTargets:
				if got != "creator.invalid:8443" {
					t.Fatalf("consumer CONNECT authority = %q, want creator.invalid:8443", got)
				}
			default:
				t.Fatalf("consumer did not request creator authority; error = %v", err)
			}
			if got := mapRequests.Load(); got != 0 {
				t.Fatalf("public DERP map requests = %d, want 0", got)
			}
			if got := err.Error(); !strings.Contains(got, "connect custom DERP creator.invalid:8443:") || strings.Contains(got, "consumer-conflict.invalid") {
				t.Fatalf("consumer error = %q, want only creator authority", got)
			}
		})
	}
}

func TestCustomDERPRouteInvalidCreatorConfigurationFailsBeforeNetwork(t *testing.T) {
	creators := []struct {
		name   string
		create func(context.Context) (string, *relaySession, error)
	}{
		{
			name: "public session",
			create: func(ctx context.Context) (string, *relaySession, error) {
				return issuePublicSessionWithCapabilities(ctx, token.CapabilityStdio)
			},
		},
		{
			name: "public QUIC session",
			create: func(ctx context.Context) (string, *relaySession, error) {
				return issuePublicQUICSession(ctx, token.CapabilityStdio|token.CapabilityTransferV2, nil)
			},
		},
	}

	for _, tt := range creators {
		t.Run(tt.name, func(t *testing.T) {
			var mapRequests atomic.Int64
			dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
				1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "network-spy", RegionID: 1, HostName: "127.0.0.1"}}},
			}}
			mapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mapRequests.Add(1)
				_ = json.NewEncoder(w).Encode(dm)
			}))
			t.Cleanup(mapServer.Close)
			var dialRequests atomic.Int64
			dialServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				dialRequests.Add(1)
				http.Error(w, "network should not be reached", http.StatusInternalServerError)
			}))
			t.Cleanup(dialServer.Close)

			t.Setenv(derpbind.CustomDERPServerEnv, "https://user:super-secret@creator.invalid")
			t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", mapServer.URL)
			t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", dialServer.URL+"/derp")
			clearDERPProxyEnvironment(t)

			_, session, err := tt.create(context.Background())
			if session != nil {
				closeTestRelaySession(session)
			}
			if err == nil || !strings.Contains(err.Error(), "invalid "+derpbind.CustomDERPServerEnv) {
				t.Fatalf("create session error = %v, want invalid custom DERP configuration", err)
			}
			if strings.Contains(err.Error(), "super-secret") {
				t.Fatalf("create session error leaked userinfo: %v", err)
			}
			if got := mapRequests.Load(); got != 0 {
				t.Fatalf("DERP map requests = %d, want 0", got)
			}
			if got := dialRequests.Load(); got != 0 {
				t.Fatalf("DERP dial requests = %d, want 0", got)
			}
		})
	}
}

func TestCustomDERPRouteClearedConfigurationKeepsPublicV5TokenShape(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv(derpbind.CustomDERPServerEnv, "")
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", srv.DERPURL)
	clearDERPProxyEnvironment(t)

	raw, session, err := issuePublicQUICSession(context.Background(), token.CapabilityStdio|token.CapabilityTransferV2, nil)
	if err != nil {
		t.Fatalf("issuePublicQUICSession() error = %v", err)
	}
	closeTestRelaySession(session)

	got, err := token.Decode(raw, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if got.Version != token.SupportedVersion || got.DERPRoute.IsCustom() {
		t.Fatalf("token version/route = %d/%+v, want public v5", got.Version, got.DERPRoute)
	}
	if got.BootstrapRegion != 1 {
		t.Fatalf("token bootstrap region = %d, want 1", got.BootstrapRegion)
	}
	wire, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("base64 decode token error = %v", err)
	}
	if len(wire) != 131 {
		t.Fatalf("public token wire length = %d, want existing v5 length 131", len(wire))
	}
}

func clearDERPProxyEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(name, "")
	}
}

func closeTestRelaySession(session *relaySession) {
	if session == nil {
		return
	}
	closePublicSessionTransport(session)
	if session.derp != nil {
		_ = session.derp.Close()
	}
}
