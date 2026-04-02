package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derpcat/pkg/quicpath"
)

const listenUsage = "usage: quicbench listen [addr]"
const sendUsage = "usage: quicbench send <addr> <bytes>"
const copyBufferSize = 256 << 10

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
		if len(args) != 3 {
			return errors.New(sendUsage)
		}
		n, err := parseByteCount(args[2])
		if err != nil {
			return err
		}
		return runSend(args[1], n, stdout)
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
	defer conn.CloseWithError(0, "")

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	buf := make([]byte, copyBufferSize)
	started := time.Now()
	n, err := io.CopyBuffer(io.Discard, stream, buf)
	if err != nil {
		return err
	}
	elapsed := time.Since(started)
	fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, throughputMbps(n, elapsed))
	return nil
}

func runSend(addr string, bytesToSend int64, stdout io.Writer) error {
	udpConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return err
	}
	defer udpConn.Close()

	serverAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	conn, err := quic.Dial(context.Background(), udpConn, serverAddr, quicpath.DefaultClientTLSConfig(), quicpath.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	buf := make([]byte, copyBufferSize)
	src := io.LimitReader(zeroReader{}, bytesToSend)
	started := time.Now()
	n, err := io.CopyBuffer(stream, src, buf)
	if err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	if n != bytesToSend {
		return fmt.Errorf("sent %d bytes, want %d", n, bytesToSend)
	}
	elapsed := time.Since(started)
	fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, throughputMbps(n, elapsed))
	return nil
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

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
