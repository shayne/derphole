// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/quicpath"
)

const listenUsage = "usage: quicbench listen [addr]"
const sendUsage = "usage: quicbench send [--reverse] [--streams N] [--connections N] <addr> <bytes>"
const copyBufferSize = 256 << 10
const requestHeaderSize = 13

type sendArgs struct {
	addr        string
	bytesToSend int64
	reverse     bool
	streams     int
	connections int
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: quicbench listen [addr] | quicbench send <addr> <bytes>")
	}
	switch args[0] {
	case "listen":
		addr := "0.0.0.0:0"
		if len(args) > 2 {
			return errors.New(listenUsage)
		}
		if len(args) == 2 {
			addr = args[1]
		}
		return runListen(addr, stdout, stderr)
	case "send":
		parsed, err := parseSendArgs(args[1:])
		if err != nil {
			return err
		}
		return runSend(parsed, stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runListen(addr string, stdout, stderr io.Writer) error {
	udpConn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	cert, err := quicpath.GenerateSelfSignedCertificate()
	if err != nil {
		return err
	}
	listener, err := quic.Listen(udpConn, quicpath.DefaultTLSConfig(cert, quicpath.ServerName), quicpath.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Fprintf(stderr, "listening on %s\n", udpConn.LocalAddr())

	conn, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}
	conns := []*quic.Conn{conn}
	defer closeQUICConns(conns)

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	req, err := readBenchRequest(stream)
	if err != nil {
		return err
	}
	for len(conns) < req.connections {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		conns = append(conns, conn)
	}

	started := time.Now()
	var n int64
	if req.reverse {
		n, err = runListenReverseStreams(conns, req)
		if err != nil {
			return err
		}
		if n != req.bytesToSend {
			return fmt.Errorf("sent %d bytes, want %d", n, req.bytesToSend)
		}
	} else {
		n, err = runListenForwardStreams(conns, req)
		if err != nil {
			return err
		}
	}
	elapsed := time.Since(started)
	fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, throughputMbps(n, elapsed))
	return nil
}

func runSend(cfg sendArgs, stdout io.Writer) error {
	serverAddr, err := net.ResolveUDPAddr("udp4", cfg.addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenPacket("udp4", sendLocalBindAddr(serverAddr).String())
	if err != nil {
		return err
	}
	defer udpConn.Close()

	transport := &quic.Transport{Conn: udpConn}
	defer transport.Close()

	conn, err := transport.Dial(context.Background(), serverAddr, quicpath.DefaultClientTLSConfig(), quicpath.DefaultQUICConfig())
	if err != nil {
		return err
	}
	conns := []*quic.Conn{conn}
	defer closeQUICConns(conns)

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	if err := writeBenchRequest(stream, cfg); err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	for len(conns) < cfg.connections {
		conn, err := transport.Dial(context.Background(), serverAddr, quicpath.DefaultClientTLSConfig(), quicpath.DefaultQUICConfig())
		if err != nil {
			return err
		}
		conns = append(conns, conn)
	}

	started := time.Now()
	var n int64
	if cfg.reverse {
		n, err = runSendReverseStreams(conns, cfg)
		if err != nil {
			return err
		}
	} else {
		n, err = runSendForwardStreams(conns, cfg)
		if err != nil {
			return err
		}
		if n != cfg.bytesToSend {
			return fmt.Errorf("sent %d bytes, want %d", n, cfg.bytesToSend)
		}
	}
	elapsed := time.Since(started)
	fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, throughputMbps(n, elapsed))
	return nil
}

func parseSendArgs(args []string) (sendArgs, error) {
	cfg := sendArgs{streams: 1, connections: 1}
	for len(args) > 0 {
		switch args[0] {
		case "--reverse":
			cfg.reverse = true
			args = args[1:]
		case "--streams":
			if len(args) < 2 {
				return sendArgs{}, errors.New(sendUsage)
			}
			streams, err := strconv.Atoi(args[1])
			if err != nil || streams < 1 {
				return sendArgs{}, errors.New(sendUsage)
			}
			cfg.streams = streams
			args = args[2:]
		case "--connections":
			if len(args) < 2 {
				return sendArgs{}, errors.New(sendUsage)
			}
			connections, err := strconv.Atoi(args[1])
			if err != nil || connections < 1 {
				return sendArgs{}, errors.New(sendUsage)
			}
			cfg.connections = connections
			args = args[2:]
		default:
			goto positional
		}
	}
positional:
	if len(args) != 2 {
		return sendArgs{}, errors.New(sendUsage)
	}
	cfg.addr = args[0]
	n, err := parseByteCount(args[1])
	if err != nil {
		return sendArgs{}, err
	}
	cfg.bytesToSend = n
	return cfg, nil
}

func writeBenchRequest(stream io.Writer, cfg sendArgs) error {
	var header [requestHeaderSize]byte
	if cfg.reverse {
		header[0] = 1
	}
	binary.BigEndian.PutUint64(header[1:], uint64(cfg.bytesToSend))
	binary.BigEndian.PutUint16(header[9:], uint16(cfg.streams))
	binary.BigEndian.PutUint16(header[11:], uint16(cfg.connections))
	_, err := stream.Write(header[:])
	return err
}

func readBenchRequest(stream io.Reader) (sendArgs, error) {
	var header [requestHeaderSize]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return sendArgs{}, err
	}
	streams := int(binary.BigEndian.Uint16(header[9:]))
	if streams < 1 {
		return sendArgs{}, errors.New("invalid stream count")
	}
	connections := int(binary.BigEndian.Uint16(header[11:]))
	if connections < 1 {
		return sendArgs{}, errors.New("invalid connection count")
	}
	return sendArgs{
		bytesToSend: int64(binary.BigEndian.Uint64(header[1:])),
		reverse:     header[0] == 1,
		streams:     streams,
		connections: connections,
	}, nil
}

func runListenForwardStreams(conns []*quic.Conn, cfg sendArgs) (int64, error) {
	return drainIncomingStreams(conns, cfg.streams)
}

func runListenReverseStreams(conns []*quic.Conn, cfg sendArgs) (int64, error) {
	streams := make([]*quic.Stream, 0, len(conns)*cfg.streams)
	for _, conn := range conns {
		for range cfg.streams {
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				return 0, err
			}
			streams = append(streams, stream)
		}
	}
	return transferFixedStreams(streams, cfg.bytesToSend)
}

func runSendForwardStreams(conns []*quic.Conn, cfg sendArgs) (int64, error) {
	streams := make([]*quic.Stream, 0, len(conns)*cfg.streams)
	for _, conn := range conns {
		for range cfg.streams {
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				return 0, err
			}
			streams = append(streams, stream)
		}
	}
	return transferFixedStreams(streams, cfg.bytesToSend)
}

func runSendReverseStreams(conns []*quic.Conn, cfg sendArgs) (int64, error) {
	return drainIncomingStreams(conns, cfg.streams)
}

func drainIncomingStreams(conns []*quic.Conn, streamCount int) (int64, error) {
	type streamResult struct {
		n   int64
		err error
	}
	streams := make([]*quic.Stream, 0, len(conns)*streamCount)
	for _, conn := range conns {
		for range streamCount {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return 0, err
			}
			streams = append(streams, stream)
		}
	}
	results := make(chan streamResult, len(streams))
	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(stream *quic.Stream) {
			defer wg.Done()
			n, err := io.CopyBuffer(io.Discard, stream, make([]byte, copyBufferSize))
			_ = stream.Close()
			results <- streamResult{n: n, err: err}
		}(stream)
	}
	wg.Wait()
	close(results)

	var total int64
	for result := range results {
		if result.err != nil {
			return 0, result.err
		}
		total += result.n
	}
	return total, nil
}

func transferFixedStreams(streams []*quic.Stream, bytesToSend int64) (int64, error) {
	type streamResult struct {
		n   int64
		err error
	}
	results := make(chan streamResult, len(streams))
	var wg sync.WaitGroup
	for i, stream := range streams {
		bytesToSend := bytesForStream(bytesToSend, len(streams), i)
		wg.Add(1)
		go func(stream *quic.Stream, bytesToSend int64) {
			defer wg.Done()
			n, err := io.CopyBuffer(stream, io.LimitReader(zeroReader{}, bytesToSend), make([]byte, copyBufferSize))
			if closeErr := stream.Close(); err == nil {
				err = closeErr
			} else {
				_ = stream.Close()
			}
			if err == nil && n != bytesToSend {
				err = fmt.Errorf("sent %d bytes, want %d", n, bytesToSend)
			}
			results <- streamResult{n: n, err: err}
		}(stream, bytesToSend)
	}
	wg.Wait()
	close(results)

	var total int64
	for result := range results {
		if result.err != nil {
			return 0, result.err
		}
		total += result.n
	}
	return total, nil
}

func closeQUICConns(conns []*quic.Conn) {
	for _, conn := range conns {
		_ = conn.CloseWithError(0, "")
	}
}

func bytesForStream(total int64, streamCount, index int) int64 {
	base := total / int64(streamCount)
	if int64(index) < total%int64(streamCount) {
		return base + 1
	}
	return base
}

func parseByteCount(value string) (int64, error) {
	switch {
	case strings.HasSuffix(value, "GiB"):
		return parseScaledByteCount(strings.TrimSuffix(value, "GiB"), 1<<30)
	case strings.HasSuffix(value, "MiB"):
		return parseScaledByteCount(strings.TrimSuffix(value, "MiB"), 1<<20)
	case strings.HasSuffix(value, "KiB"):
		return parseScaledByteCount(strings.TrimSuffix(value, "KiB"), 1<<10)
	case strings.HasSuffix(value, "B"):
		return parseScaledByteCount(strings.TrimSuffix(value, "B"), 1)
	default:
		return parseScaledByteCount(value, 1)
	}
}

func parseScaledByteCount(raw string, scale int64) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, errors.New("byte count must be non-negative")
	}
	return n * scale, nil
}

func throughputMbps(byteCount int64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(byteCount*8) / elapsed.Seconds() / 1e6
}

func sendLocalBindAddr(serverAddr *net.UDPAddr) net.Addr {
	fallbackAddr := &net.UDPAddr{Port: 0}
	if serverAddr == nil || len(serverAddr.IP) == 0 || serverAddr.IP.IsUnspecified() {
		return fallbackAddr
	}
	routeProbe, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		return fallbackAddr
	}
	defer routeProbe.Close()

	localAddr, ok := routeProbe.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil || len(localAddr.IP) == 0 || localAddr.IP.IsUnspecified() {
		return fallbackAddr
	}
	return &net.UDPAddr{IP: append(net.IP(nil), localAddr.IP...), Port: 0}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
