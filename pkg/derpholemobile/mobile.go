// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpholemobile

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

var errAmbiguousReceiveOutput = errors.New("received output directory contains more than one file")

var derpholeReceive = derphole.Receive
var derptunOpen = session.DerptunOpen

type Callbacks interface {
	Status(status string)
	Trace(trace string)
	Progress(current int64, total int64)
}

type Receiver struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	generation uint64
}

type TunnelCallbacks interface {
	Status(status string)
	Trace(trace string)
	BoundAddr(addr string)
}

type TunnelClient struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	generation uint64
}

func NewReceiver() *Receiver {
	return &Receiver{}
}

func NewTunnelClient() *TunnelClient {
	return &TunnelClient{}
}

type ParsedPayload struct {
	kind   string
	token  string
	scheme string
	path   string
}

func (p *ParsedPayload) Kind() string {
	if p == nil {
		return ""
	}
	return p.kind
}

func (p *ParsedPayload) Token() string {
	if p == nil {
		return ""
	}
	return p.token
}

func (p *ParsedPayload) Scheme() string {
	if p == nil {
		return ""
	}
	return p.scheme
}

func (p *ParsedPayload) Path() string {
	if p == nil {
		return ""
	}
	return p.path
}

func ParsePayload(payload string) (*ParsedPayload, error) {
	payload = strings.TrimSpace(payload)
	if strings.HasPrefix(payload, derptun.CompactInvitePrefix) {
		cred, err := derptun.DecodeClientInvite(payload, time.Now())
		if err != nil {
			return nil, err
		}
		clientToken, err := derptun.EncodeClientCredential(cred)
		if err != nil {
			return nil, err
		}
		return &ParsedPayload{kind: "tcp", token: clientToken}, nil
	}
	parsed, err := qrpayload.Parse(payload)
	if err != nil {
		return nil, err
	}
	return &ParsedPayload{
		kind:   string(parsed.Kind),
		token:  parsed.Token,
		scheme: parsed.Scheme,
		path:   parsed.Path,
	}, nil
}

func ParseFileToken(payload string) (string, error) {
	parsed, err := qrpayload.Parse(payload)
	if err != nil {
		return "", err
	}
	if parsed.Kind != qrpayload.KindFile {
		return "", qrpayload.ErrUnsupportedPayload
	}
	return parsed.Token, nil
}

func (c *TunnelClient) OpenInvite(invite, listenAddr string, callbacks TunnelCallbacks) error {
	parsed, err := ParsePayload(invite)
	if err != nil {
		return err
	}
	if parsed.Kind() != "tcp" {
		return qrpayload.ErrUnsupportedPayload
	}
	return c.Open(parsed.Token(), listenAddr, callbacks)
}

func (r *Receiver) Receive(payloadOrToken string, outputDir string, callbacks Callbacks) (string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return "", errors.New("output directory is required")
	}
	token, err := ParseFileToken(payloadOrToken)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	transferDir, err := os.MkdirTemp(outputDir, "derphole-receive-*")
	if err != nil {
		return "", err
	}

	ctx, cancel, generation := r.beginContext()
	defer cancel()
	defer r.clearCancel(generation)

	statusWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Status(line)
		}
	}}
	traceWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Trace(line)
		}
	}}

	err = derpholeReceive(ctx, derphole.ReceiveConfig{
		Token:          token,
		OutputPath:     transferDir,
		Stderr:         traceWriter,
		ProgressOutput: nil,
		Emitter:        telemetry.New(statusWriter, telemetry.LevelDefault),
		UsePublicDERP:  true,
		ForceRelay:     false,
		ParallelPolicy: session.DefaultParallelPolicy(),
		Progress: func(current, total int64) {
			if callbacks != nil {
				callbacks.Progress(current, total)
			}
		},
	})
	if err != nil {
		_ = os.RemoveAll(transferDir)
		return "", err
	}
	return singleReceivedFile(transferDir)
}

func (r *Receiver) Cancel() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *Receiver) context() (context.Context, context.CancelFunc) {
	ctx, cancel, _ := r.beginContext()
	return ctx, cancel
}

func (r *Receiver) beginContext() (context.Context, context.CancelFunc, uint64) {
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.generation++
	r.cancel = cancel
	generation := r.generation
	r.mu.Unlock()
	return ctx, cancel, generation
}

func (r *Receiver) clearCancel(generation uint64) {
	r.mu.Lock()
	if r.generation == generation {
		r.cancel = nil
	}
	r.mu.Unlock()
}

func (c *TunnelClient) Open(token, listenAddr string, callbacks TunnelCallbacks) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return qrpayload.ErrMissingToken
	}
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}

	ctx, cancel, generation := c.beginContext()
	bindSink := make(chan string, 1)
	done := make(chan error, 1)
	statusWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Status(line)
			callbacks.Trace(line)
		}
	}}

	go func() {
		err := derptunOpen(ctx, session.DerptunOpenConfig{
			ClientToken:   token,
			ListenAddr:    listenAddr,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(statusWriter, telemetry.LevelDefault),
			ForceRelay:    false,
			UsePublicDERP: true,
		})
		c.clearCancel(generation)
		done <- err
	}()

	select {
	case bindAddr := <-bindSink:
		if callbacks != nil {
			callbacks.BoundAddr(bindAddr)
		}
		return nil
	case err := <-done:
		cancel()
		if err != nil {
			return err
		}
		return nil
	}
}

func (c *TunnelClient) Cancel() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *TunnelClient) beginContext() (context.Context, context.CancelFunc, uint64) {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.generation++
	c.cancel = cancel
	generation := c.generation
	c.mu.Unlock()
	return ctx, cancel, generation
}

func (c *TunnelClient) clearCancel(generation uint64) {
	c.mu.Lock()
	if c.generation == generation {
		c.cancel = nil
	}
	c.mu.Unlock()
}

type callbackLineWriter struct {
	line func(string)
}

func (w callbackLineWriter) Write(p []byte) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(p)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && w.line != nil {
			w.line(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func singleReceivedFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	if len(files) != 1 {
		if len(files) == 0 {
			return "", io.ErrUnexpectedEOF
		}
		return "", errAmbiguousReceiveOutput
	}
	return files[0], nil
}
