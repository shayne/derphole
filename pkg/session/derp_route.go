// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/tailcfg"
)

type derpBootstrap struct {
	route            derpbind.Route
	dm               *tailcfg.DERPMap
	node             *tailcfg.DERPNode
	serverURL        string
	mapSource        derpbind.MapSource
	mapStoredAt      time.Time
	cacheWriteFailed bool
	selection        derpbind.RegionSelection
}

type derpMapResolver func(context.Context, string) (derpbind.MapResult, error)

type regionPicker func(context.Context, *tailcfg.DERPMap) (derpbind.RegionSelection, error)

func resolveDERPBootstrap(ctx context.Context, route derpbind.Route, regionID int, missingNodeError string) (derpBootstrap, error) {
	return resolveDERPBootstrapWithResolver(ctx, route, regionID, missingNodeError, derpbind.ResolveMap)
}

func resolveDERPBootstrapWithResolver(
	ctx context.Context,
	route derpbind.Route,
	regionID int,
	missingNodeError string,
	resolve derpMapResolver,
) (derpBootstrap, error) {
	if route.IsCustom() {
		return resolveCustomDERPBootstrap(route, missingNodeError)
	}
	return resolvePublicDERPBootstrap(ctx, regionID, missingNodeError, resolve)
}

func resolveCustomDERPBootstrap(route derpbind.Route, missingNodeError string) (derpBootstrap, error) {
	if err := route.Validate(); err != nil {
		return derpBootstrap{}, err
	}
	dm := route.DERPMap()
	node := derpbind.NodeForRegion(dm, derpbind.CustomDERPRegionID)
	if node == nil {
		return derpBootstrap{}, errors.New(missingNodeError)
	}
	serverURL := route.ServerURL()
	if override := os.Getenv("DERPHOLE_TEST_DERP_SERVER_URL"); override != "" {
		serverURL = override
	}
	return derpBootstrap{
		route:     route,
		dm:        dm,
		node:      node,
		serverURL: serverURL,
		mapSource: derpbind.MapSourceEmbedded,
	}, nil
}

func resolvePublicDERPBootstrap(
	ctx context.Context,
	regionID int,
	missingNodeError string,
	resolve derpMapResolver,
) (derpBootstrap, error) {
	result, err := resolve(ctx, publicDERPMapURL())
	if err != nil {
		return derpBootstrap{}, err
	}
	result, node, err := resolvedPublicDERPNode(result, regionID)
	if err != nil {
		return derpBootstrap{}, err
	}
	if node == nil {
		return derpBootstrap{}, errors.New(missingNodeError)
	}
	return derpBootstrap{
		dm:               result.Map,
		node:             node,
		serverURL:        publicDERPServerURL(node),
		mapSource:        result.Source,
		mapStoredAt:      result.StoredAt,
		cacheWriteFailed: result.CacheWriteFailed,
	}, nil
}

func resolvedPublicDERPNode(
	result derpbind.MapResult,
	regionID int,
) (derpbind.MapResult, *tailcfg.DERPNode, error) {
	if regionID == 0 {
		return result, derpbind.FirstNode(result.Map), nil
	}
	if node := derpbind.NodeForRegion(result.Map, regionID); node != nil {
		return result, node, nil
	}
	compiled, err := derpbind.CompiledMap()
	if err != nil {
		return derpbind.MapResult{}, nil, err
	}
	compiled, err = derpbind.OneShotCompatibleMap(compiled)
	if err != nil {
		return derpbind.MapResult{}, nil, err
	}
	node := derpbind.NodeForRegion(compiled, regionID)
	if node != nil {
		result = derpbind.MapResult{Map: compiled, Source: derpbind.MapSourceCompiled}
	}
	return result, node, nil
}

// resolveDurableDERPBootstrap preserves the original region-zero rendezvous
// behavior for durable Derptun credentials. Their two endpoints may resolve at
// different times, so choosing from a live or independently cached map could
// send them to different relays. New credentials encode a concrete region and
// use the normal resolver path.
func resolveDurableDERPBootstrap(
	ctx context.Context,
	route derpbind.Route,
	regionID int,
	missingNodeError string,
) (derpBootstrap, error) {
	return resolveDurableDERPBootstrapWithResolver(
		ctx,
		route,
		regionID,
		missingNodeError,
		derpbind.ResolveMap,
	)
}

func resolveDurableDERPBootstrapWithResolver(
	ctx context.Context,
	route derpbind.Route,
	regionID int,
	missingNodeError string,
	resolve derpMapResolver,
) (derpBootstrap, error) {
	if route.IsCustom() || regionID != 0 {
		return resolveDERPBootstrapWithResolver(ctx, route, regionID, missingNodeError, resolve)
	}

	dm, err := derpbind.CompiledMap()
	if err != nil {
		return derpBootstrap{}, err
	}
	node := derpbind.FirstNode(dm)
	if node == nil {
		return derpBootstrap{}, errors.New(missingNodeError)
	}
	return derpBootstrap{
		dm:        dm,
		node:      node,
		serverURL: publicDERPServerURL(node),
		mapSource: derpbind.MapSourceCompiled,
	}, nil
}

func resolveNewDERPBootstrap(ctx context.Context, route derpbind.Route, missingNodeError string) (derpBootstrap, error) {
	return resolveNewDERPBootstrapWithResolverAndPicker(
		ctx,
		route,
		missingNodeError,
		derpbind.ResolveMap,
		derpbind.PickRegion,
	)
}

func resolveNewDERPBootstrapWithResolverAndPicker(
	ctx context.Context,
	route derpbind.Route,
	missingNodeError string,
	resolve derpMapResolver,
	pick regionPicker,
) (derpBootstrap, error) {
	if route.IsCustom() {
		return resolveDERPBootstrapWithResolver(ctx, route, derpbind.CustomDERPRegionID, missingNodeError, resolve)
	}

	bootstrap, err := resolveDERPBootstrapWithResolver(ctx, route, 0, missingNodeError, resolve)
	if err != nil {
		return derpBootstrap{}, err
	}
	compatible, err := derpbind.OneShotCompatibleMap(bootstrap.dm)
	if err != nil {
		return derpBootstrap{}, err
	}
	selectionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	selection, err := pick(selectionCtx, compatible)
	if err != nil {
		selection = derpbind.RegionSelection{}
	}
	compatibleNode := derpbind.NodeForRegion(compatible, selection.RegionID)
	node := derpbind.NodeForRegion(bootstrap.dm, selection.RegionID)
	if selection.RegionID == 0 || compatibleNode == nil || node == nil {
		node = derpbind.FirstNode(compatible)
		if node == nil {
			return derpBootstrap{}, errors.New(missingNodeError)
		}
		selection = derpbind.RegionSelection{RegionID: node.RegionID}
	}
	bootstrap.node = node
	bootstrap.serverURL = publicDERPServerURL(node)
	bootstrap.selection = selection
	return bootstrap, nil
}

func openSessionDERPClient(ctx context.Context, bootstrap derpBootstrap, emitter *telemetry.Emitter) (*derpbind.Client, error) {
	emitDERPRouteDebug(emitter, bootstrap.route)
	emitDERPMapDebug(emitter, bootstrap)
	emitDERPSelectionDebug(emitter, bootstrap)
	client, err := derpbind.NewClient(ctx, bootstrap.node, bootstrap.serverURL)
	if err != nil {
		return nil, derpbind.WrapCustomDERPConnectError(bootstrap.route, bootstrap.serverURL, err)
	}
	emitDERPProxyDebug(emitter, client)
	return client, nil
}

func emitDERPSelectionDebug(emitter *telemetry.Emitter, bootstrap derpBootstrap) {
	if emitter == nil {
		return
	}
	if message := formatDERPSelectionDebug(bootstrap); message != "" {
		emitter.Debug(message)
	}
}

func formatDERPSelectionDebug(bootstrap derpBootstrap) string {
	if bootstrap.route.IsCustom() || bootstrap.selection.RegionID == 0 {
		return ""
	}
	if bootstrap.selection.Measured {
		return fmt.Sprintf(
			"derp-bootstrap-region=%d selection=measured latency=%s",
			bootstrap.selection.RegionID,
			bootstrap.selection.Latency,
		)
	}
	return fmt.Sprintf(
		"derp-bootstrap-region=%d selection=deterministic-fallback",
		bootstrap.selection.RegionID,
	)
}

func emitDERPMapDebug(emitter *telemetry.Emitter, bootstrap derpBootstrap) {
	if emitter == nil {
		return
	}
	if message := formatDERPMapDebug(bootstrap, time.Now()); message != "" {
		emitter.Debug(message)
	}
}

func formatDERPMapDebug(bootstrap derpBootstrap, now time.Time) string {
	if bootstrap.mapSource == "" || bootstrap.mapSource == derpbind.MapSourceEmbedded || bootstrap.node == nil {
		return ""
	}
	message := fmt.Sprintf("derp-map-source=%s region=%d", bootstrap.mapSource, bootstrap.node.RegionID)
	if mapSourceHasAge(bootstrap.mapSource) && !bootstrap.mapStoredAt.IsZero() {
		age := now.Sub(bootstrap.mapStoredAt)
		if age < 0 {
			age = 0
		}
		message = fmt.Sprintf("%s age=%s", message, age.Round(time.Second))
	}
	if bootstrap.cacheWriteFailed {
		message += " cache-write=failed"
	}
	return message
}

func mapSourceHasAge(source derpbind.MapSource) bool {
	return source == derpbind.MapSourceFreshCache ||
		source == derpbind.MapSourceRevalidated ||
		source == derpbind.MapSourceStaleCache
}

func emitDERPRouteDebug(emitter *telemetry.Emitter, route derpbind.Route) {
	if emitter == nil || !route.IsCustom() {
		return
	}
	emitter.Debug(fmt.Sprintf("derp-route=custom derp=%s stun=%s", route.DERPAuthority(), route.STUNAuthority()))
}
