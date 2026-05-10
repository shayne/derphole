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
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: quicbench listen [addr] | quicbench send <addr> <bytes>")
	}
	return runCommand(args[0], args[1:], stdout, stderr)
}

func runCommand(command string, args []string, stdout, stderr io.Writer) error {
	switch command {
	case "listen":
		addr, err := parseListenAddr(args)
		if err != nil {
			return err
		}
		return runListen(addr, stdout, stderr)
	case "send":
		parsed, err := parseSendArgs(args)
		if err != nil {
			return err
		}
		return runSend(parsed, stdout)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func parseListenAddr(args []string) (string, error) {
	if len(args) > 1 {
		return "", errors.New(listenUsage)
	}
	if len(args) == 1 {
		return args[0], nil
	}
	return "0.0.0.0:0", nil
}

func runListen(addr string, stdout, stderr io.Writer) error {
	udpConn, listener, err := listenQUIC(addr)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = udpConn.Close() }()

	_, _ = fmt.Fprintf(stderr, "listening on %s\n", udpConn.LocalAddr())

	conns, req, err := acceptBenchRequest(listener)
	if err != nil {
		return err
	}
	defer closeQUICConns(conns)

	started := time.Now()
	n, err := runListenTransfer(conns, req)
	if err != nil {
		return err
	}
	elapsed := time.Since(started)
	_, _ = fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, throughputMbps(n, elapsed))
	return nil
}

func listenQUIC(addr string) (net.PacketConn, *quic.Listener, error) {
	udpConn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, nil, err
	}
	cert, err := quicpath.GenerateSelfSignedCertificate()
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	listener, err := quic.Listen(udpConn, quicpath.DefaultTLSConfig(cert, quicpath.ServerName), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	return udpConn, listener, nil
}

func acceptBenchRequest(listener *quic.Listener) ([]*quic.Conn, sendArgs, error) {
	conn, err := listener.Accept(context.Background())
	if err != nil {
		return nil, sendArgs{}, err
	}
	conns := []*quic.Conn{conn}
	req, err := readInitialBenchRequest(conn)
	if err != nil {
		closeQUICConns(conns)
		return nil, sendArgs{}, err
	}
	conns, err = acceptExtraQUICConns(listener, conns, req.connections)
	if err != nil {
		closeQUICConns(conns)
		return nil, sendArgs{}, err
	}
	return conns, req, nil
}

func readInitialBenchRequest(conn *quic.Conn) (sendArgs, error) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return sendArgs{}, err
	}
	defer func() { _ = stream.Close() }()
	return readBenchRequest(stream)
}

func acceptExtraQUICConns(listener *quic.Listener, conns []*quic.Conn, want int) ([]*quic.Conn, error) {
	for len(conns) < want {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return conns, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func runListenTransfer(conns []*quic.Conn, req sendArgs) (int64, error) {
	if !req.reverse {
		return runListenForwardStreams(conns, req)
	}
	n, err := runListenReverseStreams(conns, req)
	if err != nil {
		return 0, err
	}
	if n != req.bytesToSend {
		return 0, fmt.Errorf("sent %d bytes, want %d", n, req.bytesToSend)
	}
	return n, nil
}

func runSend(cfg sendArgs, stdout io.Writer) error {
	transport, conns, err := dialInitialQUICConn(cfg.addr)
	if err != nil {
		return err
	}
	defer func() { _ = transport.Close() }()
	defer func() { closeQUICConns(conns) }()

	serverAddr := conns[0].RemoteAddr()
	if err := sendBenchRequest(conns[0], cfg); err != nil {
		return err
	}
	conns, err = dialExtraQUICConns(transport, serverAddr, conns, cfg.connections)
	if err != nil {
		return err
	}

	started := time.Now()
	n, err := runSendTransfer(conns, cfg)
	if err != nil {
		return err
	}
	elapsed := time.Since(started)
	_, _ = fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, throughputMbps(n, elapsed))
	return nil
}

func dialInitialQUICConn(addr string) (*quic.Transport, []*quic.Conn, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenPacket("udp4", sendLocalBindAddr(serverAddr).String())
	if err != nil {
		return nil, nil, err
	}
	transport := &quic.Transport{Conn: udpConn}
	conn, err := transport.Dial(context.Background(), serverAddr, quicpath.DefaultClientTLSConfig(), quicpath.DefaultQUICConfig())
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	conns := []*quic.Conn{conn}
	return transport, conns, nil
}

func sendBenchRequest(conn *quic.Conn, cfg sendArgs) error {
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
	return nil
}

func dialExtraQUICConns(transport *quic.Transport, serverAddr net.Addr, conns []*quic.Conn, want int) ([]*quic.Conn, error) {
	udpAddr, ok := serverAddr.(*net.UDPAddr)
	if !ok {
		return conns, fmt.Errorf("unexpected QUIC remote address %T", serverAddr)
	}
	for len(conns) < want {
		conn, err := transport.Dial(context.Background(), udpAddr, quicpath.DefaultClientTLSConfig(), quicpath.DefaultQUICConfig())
		if err != nil {
			return conns, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func runSendTransfer(conns []*quic.Conn, cfg sendArgs) (int64, error) {
	if cfg.reverse {
		return runSendReverseStreams(conns, cfg)
	}
	n, err := runSendForwardStreams(conns, cfg)
	if err != nil {
		return 0, err
	}
	if n != cfg.bytesToSend {
		return 0, fmt.Errorf("sent %d bytes, want %d", n, cfg.bytesToSend)
	}
	return n, nil
}

func parseSendArgs(args []string) (sendArgs, error) {
	cfg := sendArgs{streams: 1, connections: 1}
	for len(args) > 0 {
		remaining, parsed, err := parseSendOption(&cfg, args)
		if err != nil {
			return sendArgs{}, err
		}
		if !parsed {
			break
		}
		args = remaining
	}
	return parseSendPositionals(cfg, args)
}

func parseSendOption(cfg *sendArgs, args []string) ([]string, bool, error) {
	switch args[0] {
	case "--reverse":
		cfg.reverse = true
		return args[1:], true, nil
	case "--streams":
		return parsePositiveIntOption(args, &cfg.streams)
	case "--connections":
		return parsePositiveIntOption(args, &cfg.connections)
	default:
		return args, false, nil
	}
}

func parsePositiveIntOption(args []string, target *int) ([]string, bool, error) {
	if len(args) < 2 {
		return nil, true, errors.New(sendUsage)
	}
	value, err := strconv.Atoi(args[1])
	if err != nil || value < 1 {
		return nil, true, errors.New(sendUsage)
	}
	*target = value
	return args[2:], true, nil
}

func parseSendPositionals(cfg sendArgs, args []string) (sendArgs, error) {
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

type streamResult struct {
	n   int64
	err error
}

func drainIncomingStreams(conns []*quic.Conn, streamCount int) (int64, error) {
	streams, err := acceptIncomingStreams(conns, streamCount)
	if err != nil {
		return 0, err
	}
	return drainStreams(streams)
}

func acceptIncomingStreams(conns []*quic.Conn, streamCount int) ([]*quic.Stream, error) {
	streams := make([]*quic.Stream, 0, len(conns)*streamCount)
	for _, conn := range conns {
		for range streamCount {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return nil, err
			}
			streams = append(streams, stream)
		}
	}
	return streams, nil
}

func drainStreams(streams []*quic.Stream) (int64, error) {
	results := make(chan streamResult, len(streams))
	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go drainStream(stream, results, &wg)
	}
	wg.Wait()
	close(results)
	return collectStreamResults(results)
}

func drainStream(stream *quic.Stream, results chan<- streamResult, wg *sync.WaitGroup) {
	defer wg.Done()
	n, err := io.CopyBuffer(io.Discard, stream, make([]byte, copyBufferSize))
	_ = stream.Close()
	results <- streamResult{n: n, err: err}
}

func collectStreamResults(results <-chan streamResult) (int64, error) {
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
	results := make(chan streamResult, len(streams))
	var wg sync.WaitGroup
	for i, stream := range streams {
		wg.Add(1)
		go transferFixedStream(stream, bytesForStream(bytesToSend, len(streams), i), results, &wg)
	}
	wg.Wait()
	close(results)
	return collectStreamResults(results)
}

func transferFixedStream(stream *quic.Stream, bytesToSend int64, results chan<- streamResult, wg *sync.WaitGroup) {
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
	if !usableUDPAddr(serverAddr) {
		return fallbackAddr
	}
	localAddr := probedLocalUDPAddr(serverAddr)
	if !usableUDPAddr(localAddr) {
		return fallbackAddr
	}
	return &net.UDPAddr{IP: append(net.IP(nil), localAddr.IP...), Port: 0}
}

func usableUDPAddr(addr *net.UDPAddr) bool {
	return addr != nil && len(addr.IP) > 0 && !addr.IP.IsUnspecified()
}

func probedLocalUDPAddr(serverAddr *net.UDPAddr) *net.UDPAddr {
	routeProbe, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		return nil
	}
	defer func() { _ = routeProbe.Close() }()
	localAddr, ok := routeProbe.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return localAddr
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
