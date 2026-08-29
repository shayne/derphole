// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	var calls int
	storedAt := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	resolve := func(_ context.Context, gotURL string) (derpbind.MapResult, error) {
		calls++
		if gotURL != publicDERPMapURL() {
			t.Fatalf("fetch URL = %q, want %q", gotURL, publicDERPMapURL())
		}
		return derpbind.MapResult{
			Map:      dm,
			Source:   derpbind.MapSourceNetwork,
			URL:      gotURL,
			StoredAt: storedAt,
		}, nil
	}

	got, err := resolveDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 41, "missing public node", resolve)
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
	if got.mapSource != derpbind.MapSourceNetwork || !got.mapStoredAt.Equal(storedAt) {
		t.Fatalf("bootstrap map metadata = %q/%v, want %q/%v", got.mapSource, got.mapStoredAt, derpbind.MapSourceNetwork, storedAt)
	}
}

func TestDERPBootstrapCustomBuildsOneNodeMapWithoutPublicProvider(t *testing.T) {
	t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "https://map.invalid/must-not-fetch")
	t.Setenv("DERPHOLE_TEST_DERP_SERVER_URL", "")

	resolve := func(_ context.Context, gotURL string) (derpbind.MapResult, error) {
		t.Fatalf("resolveSessionDERPMap called for custom route with %q", gotURL)
		return derpbind.MapResult{}, nil
	}

	route, err := derpbind.NewCustomRoute("derp.example.com", 8443, 3479)
	if err != nil {
		t.Fatalf("NewCustomRoute() error = %v", err)
	}
	got, err := resolveDERPBootstrapWithResolver(context.Background(), route, 123, "missing custom node", resolve)
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
	if got.mapSource != derpbind.MapSourceEmbedded || !got.mapStoredAt.IsZero() {
		t.Fatalf("bootstrap map metadata = %q/%v, want embedded with no timestamp", got.mapSource, got.mapStoredAt)
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
		resolve := func(_ context.Context, gotURL string) (derpbind.MapResult, error) {
			return derpbind.MapResult{Map: dm, Source: derpbind.MapSourceNetwork, URL: gotURL}, nil
		}

		got, err := resolveDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 7, "missing", resolve)
		if err != nil {
			t.Fatalf("resolveDERPBootstrap() error = %v", err)
		}
		if got.dm != dm || got.node != node || got.serverURL != override {
			t.Fatalf("bootstrap = %+v, want preserved public map/node and override URL", got)
		}
	})

	t.Run("custom", func(t *testing.T) {
		t.Setenv("DERPHOLE_TEST_DERP_MAP_URL", "https://map.invalid/must-not-fetch")
		resolve := func(_ context.Context, gotURL string) (derpbind.MapResult, error) {
			t.Fatalf("resolveSessionDERPMap called for custom route with %q", gotURL)
			return derpbind.MapResult{}, nil
		}
		route, err := derpbind.NewCustomRoute("custom.example.com", 8443, 3478)
		if err != nil {
			t.Fatalf("NewCustomRoute() error = %v", err)
		}

		got, err := resolveDERPBootstrapWithResolver(context.Background(), route, 7, "missing", resolve)
		if err != nil {
			t.Fatalf("resolveDERPBootstrap() error = %v", err)
		}
		if got.route != route || got.node == nil || got.node.HostName != route.Host || got.serverURL != override {
			t.Fatalf("bootstrap = %+v, want custom route/map and override URL", got)
		}
	})
}

func TestDERPBootstrapRejectsInvalidCustomRouteWithoutPublicProvider(t *testing.T) {
	resolve := func(_ context.Context, gotURL string) (derpbind.MapResult, error) {
		t.Fatalf("resolveSessionDERPMap called for invalid custom route with %q", gotURL)
		return derpbind.MapResult{}, nil
	}

	_, err := resolveDERPBootstrapWithResolver(context.Background(), derpbind.Route{Host: "secret.example.com"}, 0, "missing", resolve)
	if err == nil {
		t.Fatal("resolveDERPBootstrap() error = nil, want invalid route error")
	}
}

func TestNewDERPBootstrapSelectsMeasuredRegion(t *testing.T) {
	dm := regionChoiceTestMap(9, 3)
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: dm, Source: derpbind.MapSourceNetwork}, nil
	}

	bootstrap, err := resolveNewDERPBootstrapWithResolverAndPicker(
		context.Background(),
		derpbind.Route{},
		"missing",
		resolve,
		func(context.Context, *tailcfg.DERPMap) (derpbind.RegionSelection, error) {
			return derpbind.RegionSelection{RegionID: 9, Latency: 18 * time.Millisecond, Measured: true}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolveNewDERPBootstrapWithPicker(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.node.RegionID != 9 {
		t.Fatalf("bootstrap node = %+v, want measured region 9", bootstrap.node)
	}
	want := derpbind.RegionSelection{RegionID: 9, Latency: 18 * time.Millisecond, Measured: true}
	if bootstrap.selection != want {
		t.Fatalf("selection = %+v, want %+v", bootstrap.selection, want)
	}
}

func TestNewDERPBootstrapPickerFailureUsesSortedFallback(t *testing.T) {
	dm := regionChoiceTestMap(9, 3)
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: dm, Source: derpbind.MapSourceCompiled}, nil
	}

	bootstrap, err := resolveNewDERPBootstrapWithResolverAndPicker(
		context.Background(),
		derpbind.Route{},
		"missing",
		resolve,
		func(context.Context, *tailcfg.DERPMap) (derpbind.RegionSelection, error) {
			return derpbind.RegionSelection{}, errors.New("probe failed")
		},
	)
	if err != nil {
		t.Fatalf("resolveNewDERPBootstrapWithPicker(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.node.RegionID != 3 {
		t.Fatalf("bootstrap node = %+v, want sorted fallback region 3", bootstrap.node)
	}
	if bootstrap.selection != (derpbind.RegionSelection{RegionID: 3}) {
		t.Fatalf("selection = %+v, want deterministic region 3", bootstrap.selection)
	}
}

func TestNewDERPBootstrapCustomSkipsRegionPicker(t *testing.T) {
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		t.Fatal("custom bootstrap called public resolver")
		return derpbind.MapResult{}, nil
	}
	route, err := derpbind.NewCustomRoute("custom.example.test", 8443, 3478)
	if err != nil {
		t.Fatalf("NewCustomRoute: %v", err)
	}

	bootstrap, err := resolveNewDERPBootstrapWithResolverAndPicker(
		context.Background(),
		route,
		"missing",
		resolve,
		func(context.Context, *tailcfg.DERPMap) (derpbind.RegionSelection, error) {
			t.Fatal("custom bootstrap invoked region picker")
			return derpbind.RegionSelection{}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolveNewDERPBootstrapWithPicker(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.node.RegionID != derpbind.CustomDERPRegionID {
		t.Fatalf("bootstrap node = %+v, want custom region", bootstrap.node)
	}
	if bootstrap.selection != (derpbind.RegionSelection{}) {
		t.Fatalf("custom selection = %+v, want zero value", bootstrap.selection)
	}
}

func TestDERPBootstrapConsumersKeepEncodedOrDeterministicRegion(t *testing.T) {
	dm := regionChoiceTestMap(9, 3)
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: dm, Source: derpbind.MapSourceNetwork}, nil
	}

	encoded, err := resolveDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 9, "missing", resolve)
	if err != nil {
		t.Fatalf("resolveDERPBootstrap(encoded): %v", err)
	}
	if encoded.node == nil || encoded.node.RegionID != 9 || encoded.selection != (derpbind.RegionSelection{}) {
		t.Fatalf("encoded bootstrap = %+v, want region 9 without new selection", encoded)
	}
	durable, err := resolveDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 0, "missing", resolve)
	if err != nil {
		t.Fatalf("resolveDERPBootstrap(durable): %v", err)
	}
	if durable.node == nil || durable.node.RegionID != 3 || durable.selection != (derpbind.RegionSelection{}) {
		t.Fatalf("durable bootstrap = %+v, want sorted region 3 without new selection", durable)
	}
}

func TestDurableDERPBootstrapRegionZeroUsesStableCompiledMap(t *testing.T) {
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		t.Fatal("region-zero durable bootstrap called live map resolver")
		return derpbind.MapResult{}, nil
	}

	bootstrap, err := resolveDurableDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 0, "missing", resolve)
	if err != nil {
		t.Fatalf("resolveDurableDERPBootstrap(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.dm == nil {
		t.Fatalf("durable bootstrap = %+v, want compiled map and node", bootstrap)
	}
	if bootstrap.mapSource != derpbind.MapSourceCompiled {
		t.Fatalf("map source = %q, want %q", bootstrap.mapSource, derpbind.MapSourceCompiled)
	}
	if bootstrap.selection != (derpbind.RegionSelection{}) {
		t.Fatalf("selection = %+v, want zero value", bootstrap.selection)
	}
}

func TestDurableRegionZeroRendezvousIgnoresDivergentLiveMaps(t *testing.T) {
	serverResolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: regionChoiceTestMap(3), Source: derpbind.MapSourceNetwork}, nil
	}
	clientResolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: regionChoiceTestMap(9), Source: derpbind.MapSourceStaleCache}, nil
	}

	server, err := resolveDurableDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 0, "missing", serverResolve)
	if err != nil {
		t.Fatalf("server durable bootstrap: %v", err)
	}
	client, err := resolveDurableDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 0, "missing", clientResolve)
	if err != nil {
		t.Fatalf("client durable bootstrap: %v", err)
	}
	if server.node == nil || client.node == nil || server.node.RegionID != client.node.RegionID {
		t.Fatalf("durable regions = %+v/%+v, want identical compiled rendezvous", server.node, client.node)
	}
	if server.mapSource != derpbind.MapSourceCompiled || client.mapSource != derpbind.MapSourceCompiled {
		t.Fatalf("durable sources = %q/%q, want compiled", server.mapSource, client.mapSource)
	}
}

func TestDurableDERPBootstrapEncodedRegionUsesResolver(t *testing.T) {
	dm := regionChoiceTestMap(9, 3)
	var calls atomic.Int32
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		calls.Add(1)
		return derpbind.MapResult{Map: dm, Source: derpbind.MapSourceFreshCache}, nil
	}

	bootstrap, err := resolveDurableDERPBootstrapWithResolver(context.Background(), derpbind.Route{}, 9, "missing", resolve)
	if err != nil {
		t.Fatalf("resolveDurableDERPBootstrap(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.node.RegionID != 9 {
		t.Fatalf("durable bootstrap node = %+v, want encoded region 9", bootstrap.node)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls = %d, want 1", got)
	}
}

func TestDERPBootstrapMissingEncodedRegionUsesExactCompiledFallback(t *testing.T) {
	live := regionChoiceTestMap(3)
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: live, Source: derpbind.MapSourceNetwork}, nil
	}

	bootstrap, err := resolveDERPBootstrapWithResolver(
		context.Background(),
		derpbind.Route{},
		1,
		"missing",
		resolve,
	)
	if err != nil {
		t.Fatalf("resolveDERPBootstrapWithResolver(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.node.RegionID != 1 {
		t.Fatalf("bootstrap node = %+v, want exact compiled region 1", bootstrap.node)
	}
	if bootstrap.mapSource != derpbind.MapSourceCompiled {
		t.Fatalf("map source = %q, want %q", bootstrap.mapSource, derpbind.MapSourceCompiled)
	}

	_, err = resolveDERPBootstrapWithResolver(
		context.Background(),
		derpbind.Route{},
		41,
		"missing",
		resolve,
	)
	if err == nil {
		t.Fatal("missing region 41 error = nil, want no cross-region substitution")
	}
}

func TestNewDERPBootstrapRestrictsPickerToLegacyCompatibleRegions(t *testing.T) {
	dm := regionChoiceTestMap(99, 3)
	resolve := func(context.Context, string) (derpbind.MapResult, error) {
		return derpbind.MapResult{Map: dm, Source: derpbind.MapSourceNetwork}, nil
	}

	bootstrap, err := resolveNewDERPBootstrapWithResolverAndPicker(
		context.Background(),
		derpbind.Route{},
		"missing",
		resolve,
		func(_ context.Context, candidate *tailcfg.DERPMap) (derpbind.RegionSelection, error) {
			if derpbind.NodeForRegion(candidate, 99) != nil {
				t.Fatal("picker received post-compatibility region 99")
			}
			if derpbind.NodeForRegion(candidate, 3) == nil {
				t.Fatal("picker did not receive compatible region 3")
			}
			return derpbind.RegionSelection{RegionID: 99, Measured: true}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolveNewDERPBootstrapWithResolverAndPicker(): %v", err)
	}
	if bootstrap.node == nil || bootstrap.node.RegionID != 3 {
		t.Fatalf("bootstrap node = %+v, want compatible fallback region 3", bootstrap.node)
	}
	if bootstrap.selection != (derpbind.RegionSelection{RegionID: 3}) {
		t.Fatalf("selection = %+v, want deterministic compatible region 3", bootstrap.selection)
	}
}

func TestDERPMapDebugReportsCacheWriteDegradation(t *testing.T) {
	bootstrap := derpBootstrap{
		node:             &tailcfg.DERPNode{RegionID: 7},
		mapSource:        derpbind.MapSourceNetwork,
		cacheWriteFailed: true,
	}
	if got, want := formatDERPMapDebug(bootstrap, time.Now()), "derp-map-source=network region=7 cache-write=failed"; got != want {
		t.Fatalf("formatDERPMapDebug() = %q, want %q", got, want)
	}
}

func TestDerptunServeBootstrapDebugIncludesMapProvenance(t *testing.T) {
	var out bytes.Buffer
	emitter := telemetry.New(&out, telemetry.LevelVerbose)
	emitDerptunServeBootstrapDebug(emitter, derpBootstrap{
		node:      &tailcfg.DERPNode{RegionID: 3},
		mapSource: derpbind.MapSourceCompiled,
	})
	if got, want := out.String(), "derp-map-source=compiled-fallback region=3\n"; got != want {
		t.Fatalf("server diagnostics = %q, want %q", got, want)
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

func TestDERPMapDebugFormatsRedactedMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	node7 := &tailcfg.DERPNode{RegionID: 7}
	tests := []struct {
		name string
		boot derpBootstrap
		want string
	}{
		{
			name: "network",
			boot: derpBootstrap{node: node7, mapSource: derpbind.MapSourceNetwork},
			want: "derp-map-source=network region=7",
		},
		{
			name: "stale cache",
			boot: derpBootstrap{
				node:        node7,
				mapSource:   derpbind.MapSourceStaleCache,
				mapStoredAt: now.Add(-74 * time.Minute),
			},
			want: "derp-map-source=stale-cache region=7 age=1h14m0s",
		},
		{
			name: "future cache age clamped",
			boot: derpBootstrap{
				node:        node7,
				mapSource:   derpbind.MapSourceFreshCache,
				mapStoredAt: now.Add(time.Minute),
			},
			want: "derp-map-source=fresh-cache region=7 age=0s",
		},
		{
			name: "embedded route omitted",
			boot: derpBootstrap{node: &tailcfg.DERPNode{RegionID: derpbind.CustomDERPRegionID}, mapSource: derpbind.MapSourceEmbedded},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDERPMapDebug(tt.boot, now)
			if got != tt.want {
				t.Fatalf("formatDERPMapDebug() = %q, want %q", got, tt.want)
			}
			for _, secret := range []string{"https://map.example.test/private", `"etag-canary"`} {
				if strings.Contains(got, secret) {
					t.Fatalf("diagnostics %q contain secret canary %q", got, secret)
				}
			}
		})
	}
}

func TestDERPSelectionDebugFormatsCreationOnlyMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		boot derpBootstrap
		want string
	}{
		{
			name: "measured",
			boot: derpBootstrap{
				node:      &tailcfg.DERPNode{RegionID: 7},
				selection: derpbind.RegionSelection{RegionID: 7, Latency: 18 * time.Millisecond, Measured: true},
			},
			want: "derp-bootstrap-region=7 selection=measured latency=18ms",
		},
		{
			name: "deterministic fallback",
			boot: derpBootstrap{
				node:      &tailcfg.DERPNode{RegionID: 3},
				selection: derpbind.RegionSelection{RegionID: 3},
			},
			want: "derp-bootstrap-region=3 selection=deterministic-fallback",
		},
		{name: "token consumer omitted", boot: derpBootstrap{node: &tailcfg.DERPNode{RegionID: 9}}},
		{
			name: "custom route omitted",
			boot: derpBootstrap{
				route:     derpbind.Route{Host: "custom.example.test"},
				node:      &tailcfg.DERPNode{RegionID: derpbind.CustomDERPRegionID},
				selection: derpbind.RegionSelection{RegionID: derpbind.CustomDERPRegionID},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDERPSelectionDebug(tt.boot); got != tt.want {
				t.Fatalf("formatDERPSelectionDebug() = %q, want %q", got, tt.want)
			}
		})
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

func regionChoiceTestMap(regionIDs ...int) *tailcfg.DERPMap {
	dm := &tailcfg.DERPMap{Regions: make(map[int]*tailcfg.DERPRegion, len(regionIDs))}
	for _, regionID := range regionIDs {
		dm.Regions[regionID] = &tailcfg.DERPRegion{
			RegionID: regionID,
			Nodes: []*tailcfg.DERPNode{{
				Name:     "test",
				RegionID: regionID,
				HostName: "derp.example.test",
			}},
		}
	}
	return dm
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
