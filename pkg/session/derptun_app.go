// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"net"
	"sync"

	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/telemetry"
)

type DerptunAppServeConfig struct {
	ServerToken string
	Emitter     *telemetry.Emitter
	ForceRelay  bool
	OnMux       func(context.Context, *derptun.Mux) error
}

type DerptunAppDialConfig struct {
	ClientToken string
	Emitter     *telemetry.Emitter
	ForceRelay  bool
}

// DerptunAppServe serves one derptun app mux at a time and passes each claimed
// mux to cfg.OnMux. The helper owns the mux and closes it when OnMux returns or
// the session shuts down; cfg.OnMux should keep running until it is done serving
// the peer.
func DerptunAppServe(ctx context.Context, cfg DerptunAppServeConfig) error {
	return serveDerptunSession(ctx, derptunServeSessionConfig{
		ServerToken: cfg.ServerToken,
		Emitter:     cfg.Emitter,
		ForceRelay:  cfg.ForceRelay,
		onMux:       cfg.OnMux,
	})
}

// DerptunAppDial claims a derptun app session and returns a connected mux. The
// returned cleanup function closes the mux and releases the underlying transport
// resources; callers should call cleanup once they are done with the mux.
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
	var cleanupOnce sync.Once
	return mux, func() {
		cleanupOnce.Do(func() {
			_ = mux.Close()
			cleanup()
		})
	}, nil
}

// DerptunAppDialStream claims a derptun app session and opens one stream on the
// returned mux. The returned cleanup function closes the mux and transport; the
// caller still owns the returned stream and may close it independently.
func DerptunAppDialStream(ctx context.Context, cfg DerptunAppDialConfig) (net.Conn, func(), error) {
	mux, cleanup, err := DerptunAppDial(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	conn, err := mux.OpenStream(ctx)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return conn, cleanup, nil
}
