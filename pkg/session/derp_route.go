// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/tailcfg"
)

type derpBootstrap struct {
	route     derpbind.Route
	dm        *tailcfg.DERPMap
	node      *tailcfg.DERPNode
	serverURL string
}

var fetchSessionDERPMap = derpbind.FetchMap

func resolveDERPBootstrap(ctx context.Context, route derpbind.Route, regionID int, missingNodeError string) (derpBootstrap, error) {
	if !route.IsCustom() {
		dm, err := fetchSessionDERPMap(ctx, publicDERPMapURL())
		if err != nil {
			return derpBootstrap{}, err
		}
		node := firstDERPNode(dm, regionID)
		if node == nil {
			return derpBootstrap{}, errors.New(missingNodeError)
		}
		return derpBootstrap{dm: dm, node: node, serverURL: publicDERPServerURL(node)}, nil
	}

	if err := route.Validate(); err != nil {
		return derpBootstrap{}, err
	}
	dm := route.DERPMap()
	node := firstDERPNode(dm, derpbind.CustomDERPRegionID)
	if node == nil {
		return derpBootstrap{}, errors.New(missingNodeError)
	}
	serverURL := route.ServerURL()
	if override := os.Getenv("DERPHOLE_TEST_DERP_SERVER_URL"); override != "" {
		serverURL = override
	}
	return derpBootstrap{route: route, dm: dm, node: node, serverURL: serverURL}, nil
}

func openSessionDERPClient(ctx context.Context, bootstrap derpBootstrap, emitter *telemetry.Emitter) (*derpbind.Client, error) {
	emitDERPRouteDebug(emitter, bootstrap.route)
	client, err := derpbind.NewClient(ctx, bootstrap.node, bootstrap.serverURL)
	if err != nil {
		return nil, derpbind.WrapCustomDERPConnectError(bootstrap.route, bootstrap.serverURL, err)
	}
	emitDERPProxyDebug(emitter, client)
	return client, nil
}

func emitDERPRouteDebug(emitter *telemetry.Emitter, route derpbind.Route) {
	if emitter == nil || !route.IsCustom() {
		return
	}
	emitter.Debug(fmt.Sprintf("derp-route=custom derp=%s stun=%s", route.DERPAuthority(), route.STUNAuthority()))
}
