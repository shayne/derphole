// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"syscall/js"

	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
)

const jsDirectReceiveQueueFrames = 512

type jsDirectTransport struct {
	api     js.Value
	readyCh chan struct{}
	failCh  chan error
	recvCh  chan []byte

	mu       sync.Mutex
	funcs    []js.Func
	ready    bool
	failOnce sync.Once
	close    bool
}

func newJSDirectTransport(v js.Value) webrelay.DirectTransport {
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	return &jsDirectTransport{
		api:     v,
		readyCh: make(chan struct{}),
		failCh:  make(chan error, 1),
		recvCh:  make(chan []byte, jsDirectReceiveQueueFrames),
	}
}

func (d *jsDirectTransport) Start(ctx context.Context, role webrelay.DirectRole, peer webrelay.DirectSignalPeer) error {
	if d == nil {
		return errors.New("nil direct transport")
	}
	if err := d.validateAPI(); err != nil {
		return err
	}

	d.installFrameHandler()
	signalSink := d.installSignalSink(ctx, peer)
	d.startWatchers(ctx, peer)
	if _, err := await(ctx, d.api.Call("start", string(role), signalSink)); err != nil {
		d.fail(err)
		return err
	}
	return nil
}

func (d *jsDirectTransport) validateAPI() error {
	for _, name := range []string{"start", "applySignal", "ready", "send", "onFrame"} {
		if !isFunction(d.api.Get(name)) {
			return errors.New("invalid browser direct transport")
		}
	}
	return nil
}

func (d *jsDirectTransport) installFrameHandler() {
	onFrame := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		d.receiveFrameFromJS(args[0])
		return nil
	})
	d.keep(onFrame)
	d.api.Call("onFrame", onFrame)
}

func (d *jsDirectTransport) receiveFrameFromJS(v js.Value) {
	raw, err := bytesFromJS(v)
	if err != nil {
		d.fail(err)
		return
	}
	select {
	case d.recvCh <- raw:
	default:
		d.fail(errors.New("direct receive queue full"))
	}
}

func (d *jsDirectTransport) installSignalSink(ctx context.Context, peer webrelay.DirectSignalPeer) js.Func {
	signalSink := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		go d.sendLocalSignal(ctx, peer, args[0])
		return nil
	})
	d.keep(signalSink)
	return signalSink
}

func (d *jsDirectTransport) startWatchers(ctx context.Context, peer webrelay.DirectSignalPeer) {
	go d.forwardRemoteSignals(ctx, peer)
	go d.waitReady(ctx)
	go d.watchFailed(ctx)
}

func (d *jsDirectTransport) Ready() <-chan struct{} { return d.readyCh }

func (d *jsDirectTransport) Failed() <-chan error { return d.failCh }

func (d *jsDirectTransport) ReceiveFrames() <-chan []byte { return d.recvCh }

func (d *jsDirectTransport) SendFrame(ctx context.Context, frame []byte) error {
	u8 := js.Global().Get("Uint8Array").New(len(frame))
	js.CopyBytesToJS(u8, frame)
	_, err := await(ctx, d.api.Call("send", u8))
	if err != nil {
		d.fail(err)
	}
	return err
}

func (d *jsDirectTransport) Close() error {
	d.mu.Lock()
	if d.close {
		d.mu.Unlock()
		return nil
	}
	d.close = true
	funcs := append([]js.Func(nil), d.funcs...)
	d.funcs = nil
	d.mu.Unlock()

	if closeFn := d.api.Get("close"); isFunction(closeFn) {
		closeFn.Invoke()
	}
	for _, fn := range funcs {
		fn.Release()
	}
	return nil
}

func (d *jsDirectTransport) keep(fn js.Func) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.funcs = append(d.funcs, fn)
}

func (d *jsDirectTransport) waitReady(ctx context.Context) {
	_, err := await(ctx, d.api.Call("ready"))
	if err != nil {
		d.fail(err)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.close || d.ready {
		return
	}
	d.ready = true
	close(d.readyCh)
}

func (d *jsDirectTransport) watchFailed(ctx context.Context) {
	failedFn := d.api.Get("failed")
	if !isFunction(failedFn) {
		return
	}
	value, err := await(ctx, failedFn.Invoke())
	if err != nil {
		d.fail(err)
		return
	}
	if value.IsUndefined() || value.IsNull() {
		d.fail(errors.New("direct path failed"))
		return
	}
	d.fail(jsValueError(value))
}

func (d *jsDirectTransport) fail(err error) {
	if err == nil {
		err = errors.New("direct path failed")
	}
	d.failOnce.Do(func() {
		select {
		case d.failCh <- err:
		default:
		}
	})
}

func (d *jsDirectTransport) sendLocalSignal(ctx context.Context, peer webrelay.DirectSignalPeer, v js.Value) {
	payload, kind, err := marshalJSWebRTCSignal(v)
	if err != nil {
		d.fail(err)
		return
	}
	if err := peer.SendSignal(ctx, kind, 0, payload); err != nil {
		d.fail(err)
	}
}

func (d *jsDirectTransport) forwardRemoteSignals(ctx context.Context, peer webrelay.DirectSignalPeer) {
	for {
		if d.forwardNextRemoteSignal(ctx, peer) {
			return
		}
	}
}

func (d *jsDirectTransport) forwardNextRemoteSignal(ctx context.Context, peer webrelay.DirectSignalPeer) bool {
	select {
	case frame, ok := <-peer.Signals():
		return !ok || d.forwardRemoteSignal(ctx, frame)
	case <-ctx.Done():
		return true
	}
}

func (d *jsDirectTransport) forwardRemoteSignal(ctx context.Context, frame webproto.Frame) bool {
	if !isRemoteWebRTCSignal(frame.Kind) {
		return false
	}
	if _, err := await(ctx, d.api.Call("applySignal", string(frame.Payload))); err != nil {
		d.fail(err)
		return true
	}
	return false
}

func marshalJSWebRTCSignal(v js.Value) ([]byte, webproto.FrameKind, error) {
	kind := jsString(v, "kind")
	signal := webproto.WebRTCSignal{
		Lane:             jsInt(v, "lane"),
		Kind:             kind,
		Type:             jsString(v, "type"),
		SDP:              jsString(v, "sdp"),
		Candidate:        jsString(v, "candidate"),
		SDPMid:           jsString(v, "sdpMid"),
		SDPMLineIndex:    jsInt(v, "sdpMLineIndex"),
		UsernameFragment: jsString(v, "usernameFragment"),
	}
	payload, err := json.Marshal(signal)
	if err != nil {
		return nil, 0, err
	}
	frameKind, ok := jsWebRTCFrameKind(kind)
	if !ok {
		return nil, 0, errors.New("unknown webrtc signal kind")
	}
	return payload, frameKind, nil
}

func jsWebRTCFrameKind(kind string) (webproto.FrameKind, bool) {
	switch kind {
	case "offer":
		return webproto.FrameWebRTCOffer, true
	case "answer":
		return webproto.FrameWebRTCAnswer, true
	case "candidate":
		return webproto.FrameWebRTCIceCandidate, true
	case "ice-complete":
		return webproto.FrameWebRTCIceComplete, true
	default:
		return 0, false
	}
}

func isRemoteWebRTCSignal(kind webproto.FrameKind) bool {
	switch kind {
	case webproto.FrameWebRTCOffer, webproto.FrameWebRTCAnswer, webproto.FrameWebRTCIceCandidate, webproto.FrameWebRTCIceComplete:
		return true
	default:
		return false
	}
}

func bytesFromJS(v js.Value) ([]byte, error) {
	if v.InstanceOf(js.Global().Get("ArrayBuffer")) {
		v = js.Global().Get("Uint8Array").New(v)
	}
	if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, errors.New("direct frame is not a Uint8Array")
	}
	out := make([]byte, v.Get("byteLength").Int())
	js.CopyBytesToGo(out, v)
	return out, nil
}

func jsString(v js.Value, name string) string {
	child := v.Get(name)
	if child.IsUndefined() || child.IsNull() {
		return ""
	}
	return child.String()
}

func jsInt(v js.Value, name string) int {
	child := v.Get(name)
	if child.IsUndefined() || child.IsNull() {
		return 0
	}
	return child.Int()
}

func isFunction(v js.Value) bool {
	return v.Type() == js.TypeFunction
}
