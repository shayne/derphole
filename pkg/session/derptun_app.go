// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"net"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
)

type DerptunAppServeConfig struct {
	ServerToken   string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
	OnMux         func(context.Context, *derptun.Mux) error
}

type DerptunAppDialConfig struct {
	ClientToken   string
	Emitter       *telemetry.Emitter
	ForceRelay    bool
	UsePublicDERP bool
}

func DerptunAppServe(ctx context.Context, cfg DerptunAppServeConfig) error {
	return serveDerptunApp(ctx, derptunServeMuxConfig{
		ServerToken:   cfg.ServerToken,
		Emitter:       cfg.Emitter,
		ForceRelay:    cfg.ForceRelay,
		UsePublicDERP: cfg.UsePublicDERP,
		onMux:         cfg.OnMux,
	})
}

func DerptunAppDial(ctx context.Context, cfg DerptunAppDialConfig) (*derptun.Mux, func(), error) {
	runtime, err := newDerptunDialRuntime(ctx, cfg.ClientToken, cfg.Emitter, cfg.ForceRelay)
	if err != nil {
		return nil, nil, err
	}
	claim := runtime.claim()
	decision, err := runtime.sendClaim(ctx, claim)
	if err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	if err := derptunClaimDecisionErr(decision); err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	mux, cleanup, err := runtime.dialMux(ctx, cfg.Emitter, cfg.ForceRelay, decision)
	if err != nil {
		runtime.closeBase()
		return nil, nil, err
	}
	return mux, cleanup, nil
}

func DerptunAppDialStream(ctx context.Context, cfg DerptunAppDialConfig) (net.Conn, func(), error) {
	mux, cleanup, err := DerptunAppDial(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	conn, err := mux.OpenStream(ctx)
	if err != nil {
		cleanup()
		_ = mux.Close()
		return nil, nil, err
	}
	return conn, func() {
		_ = mux.Close()
		cleanup()
	}, nil
}
