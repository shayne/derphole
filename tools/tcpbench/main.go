// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

const usage = "usage: tcpbench send <addr> <bytes> | tcpbench send-stdin <addr> | tcpbench recv <addr> | tcpbench recv-discard <addr> | tcpbench listen-send <addr> <bytes> | tcpbench listen-send-stdin <addr> | tcpbench send-tls <addr> | tcpbench listen-tls <addr>"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) < 2 {
		return errors.New(usage)
	}
	started := time.Now()
	var (
		n   int64
		err error
	)
	switch args[0] {
	case "send":
		if len(args) != 3 {
			return errors.New(usage)
		}
		bytesToSend, parseErr := strconv.ParseInt(args[2], 10, 64)
		if parseErr != nil || bytesToSend < 0 {
			return errors.New(usage)
		}
		n, err = send(args[1], bytesToSend)
	case "send-stdin":
		if len(args) != 2 {
			return errors.New(usage)
		}
		n, err = sendFromReader(args[1], os.Stdin)
	case "recv":
		if len(args) != 2 {
			return errors.New(usage)
		}
		n, err = receiveToWriter(args[1], os.Stdout)
	case "recv-discard":
		if len(args) != 2 {
			return errors.New(usage)
		}
		n, err = receiveToWriter(args[1], io.Discard)
	case "listen-send":
		if len(args) != 3 {
			return errors.New(usage)
		}
		bytesToSend, parseErr := strconv.ParseInt(args[2], 10, 64)
		if parseErr != nil || bytesToSend < 0 {
			return errors.New(usage)
		}
		n, err = listenAndSend(args[1], bytesToSend)
	case "listen-send-stdin":
		if len(args) != 2 {
			return errors.New(usage)
		}
		n, err = listenAndSendFromReader(args[1], os.Stdin)
	case "send-tls":
		if len(args) != 2 {
			return errors.New(usage)
		}
		n, err = sendTLS(args[1], os.Stdin)
	case "listen-tls":
		if len(args) != 2 {
			return errors.New(usage)
		}
		n, err = listenTLS(args[1], os.Stdout)
	default:
		return errors.New(usage)
	}
	if err != nil {
		return err
	}
	elapsed := time.Since(started)
	fmt.Fprintf(stdout, "bytes=%d duration=%s mbps=%.2f\n", n, elapsed, float64(n*8)/elapsed.Seconds()/1e6)
	return nil
}

func send(addr string, bytesToSend int64) (int64, error) {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	buf := make([]byte, 1<<20)
	var sent int64
	for sent < bytesToSend {
		n := int64(len(buf))
		if remaining := bytesToSend - sent; remaining < n {
			n = remaining
		}
		wrote, err := conn.Write(buf[:n])
		sent += int64(wrote)
		if err != nil {
			return sent, err
		}
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	return sent, nil
}

func sendFromReader(addr string, src io.Reader) (int64, error) {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	buf := make([]byte, 1<<20)
	var total int64
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				return total, writeErr
			}
			total += int64(n)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		return total, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	return total, nil
}

func sendTLS(addr string, src io.Reader) (int64, error) {
	conn, err := tls.Dial("tcp4", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return writeFromReader(conn, src)
}

func writeFromReader(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 1<<20)
	var total int64
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return total, writeErr
			}
			total += int64(n)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		return total, err
	}
	return total, nil
}

func listenTLS(addr string, dst io.Writer) (int64, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return 0, err
	}
	ln, err := tls.Listen("tcp4", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	return receiveFromListener(ln, dst)
}

func receiveFromListener(ln net.Listener, dst io.Writer) (int64, error) {
	conn, err := ln.Accept()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return io.Copy(dst, conn)
}

func receiveToWriter(addr string, dst io.Writer) (int64, error) {
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return io.Copy(dst, conn)
}

func listenAndSend(addr string, bytesToSend int64) (int64, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	buf := make([]byte, 1<<20)
	var sent int64
	for sent < bytesToSend {
		n := int64(len(buf))
		if remaining := bytesToSend - sent; remaining < n {
			n = remaining
		}
		wrote, err := conn.Write(buf[:n])
		sent += int64(wrote)
		if err != nil {
			return sent, err
		}
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	return sent, nil
}

func listenAndSendFromReader(addr string, src io.Reader) (int64, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	n, err := writeFromReader(conn, src)
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	return n, err
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
