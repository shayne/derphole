// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestParseSendArgs(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.addr != "127.0.0.1:1234" {
		t.Fatalf("addr = %q, want %q", got.addr, "127.0.0.1:1234")
	}
	if got.bytesToSend != 128<<20 {
		t.Fatalf("bytesToSend = %d, want %d", got.bytesToSend, int64(128<<20))
	}
	if got.reverse {
		t.Fatal("reverse = true, want false")
	}
}

func TestParseSendArgsReverse(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"--reverse", "127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.addr != "127.0.0.1:1234" {
		t.Fatalf("addr = %q, want %q", got.addr, "127.0.0.1:1234")
	}
	if got.bytesToSend != 128<<20 {
		t.Fatalf("bytesToSend = %d, want %d", got.bytesToSend, int64(128<<20))
	}
	if !got.reverse {
		t.Fatal("reverse = false, want true")
	}
}

func TestParseSendArgsStreams(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"--streams", "4", "127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.addr != "127.0.0.1:1234" {
		t.Fatalf("addr = %q, want %q", got.addr, "127.0.0.1:1234")
	}
	if got.bytesToSend != 128<<20 {
		t.Fatalf("bytesToSend = %d, want %d", got.bytesToSend, int64(128<<20))
	}
	if got.reverse {
		t.Fatal("reverse = true, want false")
	}
	if got.streams != 4 {
		t.Fatalf("streams = %d, want 4", got.streams)
	}
}

func TestParseSendArgsStreamsRejectsZero(t *testing.T) {
	t.Parallel()

	_, err := parseSendArgs([]string{"--streams", "0", "127.0.0.1:1234", "128MiB"})
	if err == nil {
		t.Fatal("parseSendArgs() error = nil, want usage error")
	}
}

func TestParseSendArgsConnections(t *testing.T) {
	t.Parallel()

	got, err := parseSendArgs([]string{"--connections", "4", "127.0.0.1:1234", "128MiB"})
	if err != nil {
		t.Fatalf("parseSendArgs() error = %v", err)
	}
	if got.connections != 4 {
		t.Fatalf("connections = %d, want 4", got.connections)
	}
	if got.streams != 1 {
		t.Fatalf("streams = %d, want 1", got.streams)
	}
}

func TestParseByteCount(t *testing.T) {
	t.Parallel()

	got, err := parseByteCount("128MiB")
	if err != nil {
		t.Fatalf("parseByteCount() error = %v", err)
	}
	if got != 128<<20 {
		t.Fatalf("parseByteCount() = %d, want %d", got, int64(128<<20))
	}
}

func TestThroughputMbps(t *testing.T) {
	t.Parallel()

	got := throughputMbps(64<<20, 4*time.Second)
	if got != 134.217728 {
		t.Fatalf("throughputMbps() = %f, want %f", got, 134.217728)
	}
}

func TestSendLocalBindAddrUsesPeerRouteIP(t *testing.T) {
	t.Parallel()

	addr := sendLocalBindAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("bind addr type = %T, want *net.UDPAddr", addr)
	}
	if got := udpAddr.IP.String(); got != "127.0.0.1" {
		t.Fatalf("bind addr IP = %q, want %q", got, "127.0.0.1")
	}
	if got := udpAddr.Port; got != 0 {
		t.Fatalf("bind addr port = %d, want 0", got)
	}
}

func TestQUICBenchForwardAndReverseTransfers(t *testing.T) {
	t.Parallel()

	cases := []sendArgs{{bytesToSend: 4097, streams: 2, connections: 2}}
	for _, tc := range cases {
		tc := tc
		name := "forward"
		if tc.reverse {
			name = "reverse"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runQUICBenchTransfer(t, tc)
		})
	}
}

func TestQUICBenchReverseTransfer(t *testing.T) {
	t.Parallel()

	udpConn, listener, err := listenQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenQUIC() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = udpConn.Close() }()

	cfg := sendArgs{
		addr:        udpConn.LocalAddr().String(),
		bytesToSend: 4097,
		reverse:     true,
		streams:     2,
		connections: 2,
	}
	transport, clientConns, err := dialInitialQUICConn(cfg.addr)
	if err != nil {
		t.Fatalf("dialInitialQUICConn() error = %v", err)
	}
	defer func() { _ = transport.Close() }()
	defer closeQUICConns(clientConns)
	if err := sendBenchRequest(clientConns[0], cfg); err != nil {
		t.Fatalf("sendBenchRequest() error = %v", err)
	}

	serverReady := make(chan struct {
		conns []*quic.Conn
		req   sendArgs
		err   error
	}, 1)
	go func() {
		conns, req, err := acceptBenchRequest(listener)
		serverReady <- struct {
			conns []*quic.Conn
			req   sendArgs
			err   error
		}{conns: conns, req: req, err: err}
	}()

	clientConns, err = dialExtraQUICConns(transport, clientConns[0].RemoteAddr(), clientConns, cfg.connections)
	if err != nil {
		t.Fatalf("dialExtraQUICConns() error = %v", err)
	}

	server := <-serverReady
	if server.err != nil {
		t.Fatalf("acceptBenchRequest() error = %v", server.err)
	}
	defer closeQUICConns(server.conns)

	serverDone := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		n, err := runListenReverseStreams(server.conns, server.req)
		serverDone <- struct {
			n   int64
			err error
		}{n: n, err: err}
	}()
	n, err := runSendReverseStreams(clientConns, cfg)
	if err != nil {
		t.Fatalf("runSendReverseStreams() error = %v", err)
	}
	got := <-serverDone
	if got.err != nil {
		t.Fatalf("runListenReverseStreams() error = %v", got.err)
	}
	if n != cfg.bytesToSend || got.n != cfg.bytesToSend {
		t.Fatalf("bytes client/server = %d/%d, want %d", n, got.n, cfg.bytesToSend)
	}
}

func TestRunListenAndRunSendExchange(t *testing.T) {
	t.Parallel()

	ready := &quicListenReadyWriter{ch: make(chan string, 1)}
	listenDone := make(chan struct {
		stdout string
		err    error
	}, 1)
	go func() {
		var stdout bytes.Buffer
		err := runListen("127.0.0.1:0", &stdout, ready)
		listenDone <- struct {
			stdout string
			err    error
		}{stdout: stdout.String(), err: err}
	}()

	var addr string
	select {
	case addr = <-ready.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for quicbench listener address")
	}

	var sendStdout bytes.Buffer
	if err := runSend(sendArgs{addr: addr, bytesToSend: 2049, streams: 1, connections: 1}, &sendStdout); err != nil {
		t.Fatalf("runSend() error = %v", err)
	}
	if !strings.Contains(sendStdout.String(), "bytes=2049 ") {
		t.Fatalf("runSend() stdout = %q, want bytes=2049", sendStdout.String())
	}
	select {
	case got := <-listenDone:
		if got.err != nil && !strings.Contains(got.err.Error(), "Application error 0x0") {
			t.Fatalf("runListen() error = %v", got.err)
		}
		if got.err == nil && !strings.Contains(got.stdout, "bytes=2049 ") {
			t.Fatalf("runListen() stdout = %q, want bytes=2049", got.stdout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for quicbench listener to finish")
	}
}

func runQUICBenchTransfer(t *testing.T, cfg sendArgs) {
	t.Helper()

	udpConn, listener, err := listenQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenQUIC() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = udpConn.Close() }()

	type result struct {
		n   int64
		err error
	}
	serverDone := make(chan result, 1)
	go func() {
		conns, req, err := acceptBenchRequest(listener)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		defer closeQUICConns(conns)
		n, err := runListenTransfer(conns, req)
		serverDone <- result{n: n, err: err}
	}()

	cfg.addr = udpConn.LocalAddr().String()
	var stdout bytes.Buffer
	if err := runSend(cfg, &stdout); err != nil {
		t.Fatalf("runSend() error = %v", err)
	}
	<-serverDone
	if !strings.Contains(stdout.String(), "bytes=4097 ") {
		t.Fatalf("runSend() output = %q, want bytes metric", stdout.String())
	}
}

func TestBenchRequestRoundTripAndValidation(t *testing.T) {
	t.Parallel()

	want := sendArgs{bytesToSend: 12345, reverse: true, streams: 3, connections: 2}
	var buf bytes.Buffer
	if err := writeBenchRequest(&buf, want); err != nil {
		t.Fatalf("writeBenchRequest() error = %v", err)
	}
	got, err := readBenchRequest(&buf)
	if err != nil {
		t.Fatalf("readBenchRequest() error = %v", err)
	}
	if got.bytesToSend != want.bytesToSend || got.reverse != want.reverse || got.streams != want.streams || got.connections != want.connections {
		t.Fatalf("readBenchRequest() = %#v, want %#v", got, want)
	}

	invalid := make([]byte, requestHeaderSize)
	if _, err := readBenchRequest(bytes.NewReader(invalid)); err == nil {
		t.Fatal("readBenchRequest() error = nil, want invalid stream count")
	}
	invalid[9] = 0
	invalid[10] = 1
	if _, err := readBenchRequest(bytes.NewReader(invalid)); err == nil {
		t.Fatal("readBenchRequest() error = nil, want invalid connection count")
	}
}

func TestRunCommandRejectsInvalidCommands(t *testing.T) {
	t.Parallel()

	if err := run(nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("run(nil) error = nil, want usage error")
	}
	if _, err := parseListenAddr([]string{"one", "two"}); err == nil {
		t.Fatal("parseListenAddr() error = nil, want usage error")
	}
	if err := runCommand("unknown", nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("runCommand() error = nil, want unknown command")
	}
}

func TestParsingAndMetricHelpers(t *testing.T) {
	t.Parallel()

	addr, err := parseListenAddr(nil)
	if err != nil {
		t.Fatalf("parseListenAddr(nil) error = %v", err)
	}
	if addr != "0.0.0.0:0" {
		t.Fatalf("parseListenAddr(nil) = %q, want default", addr)
	}
	addr, err = parseListenAddr([]string{"127.0.0.1:1234"})
	if err != nil {
		t.Fatalf("parseListenAddr(explicit) error = %v", err)
	}
	if addr != "127.0.0.1:1234" {
		t.Fatalf("parseListenAddr(explicit) = %q, want explicit addr", addr)
	}

	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{raw: "123", want: 123},
		{raw: "4B", want: 4},
		{raw: "5KiB", want: 5 << 10},
		{raw: "6GiB", want: 6 << 30},
	} {
		got, err := parseByteCount(tc.raw)
		if err != nil {
			t.Fatalf("parseByteCount(%q) error = %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("parseByteCount(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
	for _, raw := range []string{"bad", "-1"} {
		if _, err := parseByteCount(raw); err == nil {
			t.Fatalf("parseByteCount(%q) error = nil, want error", raw)
		}
	}

	if got := throughputMbps(100, 0); got != 0 {
		t.Fatalf("throughputMbps(zero elapsed) = %f, want 0", got)
	}
	addrValue := sendLocalBindAddr(nil)
	if udpAddr, ok := addrValue.(*net.UDPAddr); !ok || udpAddr.Port != 0 || len(udpAddr.IP) != 0 {
		t.Fatalf("sendLocalBindAddr(nil) = %#v, want wildcard UDP addr", addrValue)
	}
}

func TestBytesForStreamDistributesRemainder(t *testing.T) {
	t.Parallel()

	got := []int64{
		bytesForStream(10, 3, 0),
		bytesForStream(10, 3, 1),
		bytesForStream(10, 3, 2),
	}
	want := []int64{4, 3, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bytesForStream[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

type quicListenReadyWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ch  chan string
}

func (w *quicListenReadyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, _ := w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			if line != "" {
				_, _ = w.buf.WriteString(line)
			}
			return n, nil
		}
		if addr, ok := strings.CutPrefix(strings.TrimSpace(line), "listening on "); ok {
			select {
			case w.ch <- addr:
			default:
			}
		}
	}
}
