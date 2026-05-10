// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestRunRejectsInvalidArgs(t *testing.T) {
	t.Parallel()

	if err := run([]string{"send", "127.0.0.1:1"}, &bytes.Buffer{}); err == nil {
		t.Fatal("run() error = nil, want usage error")
	}
}

func TestSendFromReaderWritesAllBytes(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	gotCh := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		n, err := io.Copy(io.Discard, conn)
		gotCh <- int(n)
		errCh <- err
	}()

	n, err := sendFromReader(ln.Addr().String(), bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatalf("sendFromReader() error = %v", err)
	}
	if n != int64(len("hello world")) {
		t.Fatalf("sendFromReader() = %d, want %d", n, len("hello world"))
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server copy error = %v", err)
	}
	if got := <-gotCh; got != len("hello world") {
		t.Fatalf("server bytes = %d, want %d", got, len("hello world"))
	}
}

func TestSendTLSWritesAllBytes(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := mustTestCertificate(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	gotCh := make(chan int64, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		n, err := io.Copy(io.Discard, conn)
		gotCh <- n
		errCh <- err
	}()

	n, err := sendTLS(ln.Addr().String(), bytes.NewReader([]byte("hello tls")))
	if err != nil {
		t.Fatalf("sendTLS() error = %v", err)
	}
	if n != int64(len("hello tls")) {
		t.Fatalf("sendTLS() = %d, want %d", n, len("hello tls"))
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server copy error = %v", err)
	}
	if got := <-gotCh; got != int64(len("hello tls")) {
		t.Fatalf("server bytes = %d, want %d", got, len("hello tls"))
	}
}

func TestReceiveFromListenerWritesAllBytes(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	gotCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		var got bytes.Buffer
		n, err := receiveFromListener(ln, &got)
		if err == nil && n != int64(len("hello listener")) {
			err = io.ErrShortWrite
		}
		errCh <- err
		gotCh <- got.String()
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if _, err := conn.Write([]byte("hello listener")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("receiveFromListener() error = %v", err)
	}
	if got := <-gotCh; got != "hello listener" {
		t.Fatalf("receiveFromListener() = %q, want %q", got, "hello listener")
	}
}

func TestReceiveToWriterReadsAllBytes(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	sendDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			sendDone <- err
			return
		}
		defer conn.Close()

		_, err = conn.Write([]byte("hello recv"))
		sendDone <- err
	}()

	var got bytes.Buffer
	n, err := receiveToWriter(ln.Addr().String(), &got)
	if err != nil {
		t.Fatalf("receiveToWriter() error = %v", err)
	}
	if n != int64(len("hello recv")) {
		t.Fatalf("receiveToWriter() = %d, want %d", n, len("hello recv"))
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("server send error = %v", err)
	}
	if got.String() != "hello recv" {
		t.Fatalf("receiveToWriter() output = %q, want %q", got.String(), "hello recv")
	}
}

func TestRunRecvDiscardPrintsTransferMetrics(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	sendDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			sendDone <- err
			return
		}
		defer conn.Close()

		_, err = conn.Write([]byte("discard me"))
		sendDone <- err
	}()

	var got bytes.Buffer
	if err := run([]string{"recv-discard", ln.Addr().String()}, &got); err != nil {
		t.Fatalf("run(recv-discard) error = %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("server send error = %v", err)
	}
	if !bytes.Contains(got.Bytes(), []byte("bytes=10 ")) {
		t.Fatalf("run(recv-discard) output = %q, want bytes=10", got.String())
	}
}

func TestListenAndSendWritesAllBytes(t *testing.T) {
	t.Parallel()

	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	sendDone := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		n, err := listenAndSend(addr, int64(len("hello listen-send")))
		sendDone <- struct {
			n   int64
			err error
		}{n: n, err: err}
	}()

	var conn net.Conn
	deadline := time.Now().Add(time.Second)
	for {
		conn, err = net.Dial("tcp4", addr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Dial() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	result := <-sendDone
	if result.err != nil {
		t.Fatalf("listenAndSend() error = %v", result.err)
	}
	if result.n != int64(len("hello listen-send")) {
		t.Fatalf("listenAndSend() = %d, want %d", result.n, len("hello listen-send"))
	}
	if len(payload) != len("hello listen-send") {
		t.Fatalf("received bytes = %d, want %d", len(payload), len("hello listen-send"))
	}
}

func TestListenAndSendFromReaderWritesAllBytes(t *testing.T) {
	t.Parallel()

	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	sendDone := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		n, err := listenAndSendFromReader(addr, bytes.NewReader([]byte("hello listen-send-stdin")))
		sendDone <- struct {
			n   int64
			err error
		}{n: n, err: err}
	}()

	var conn net.Conn
	deadline := time.Now().Add(time.Second)
	for {
		conn, err = net.Dial("tcp4", addr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Dial() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	result := <-sendDone
	if result.err != nil {
		t.Fatalf("listenAndSendFromReader() error = %v", result.err)
	}
	if result.n != int64(len("hello listen-send-stdin")) {
		t.Fatalf("listenAndSendFromReader() = %d, want %d", result.n, len("hello listen-send-stdin"))
	}
	if string(payload) != "hello listen-send-stdin" {
		t.Fatalf("received payload = %q, want %q", string(payload), "hello listen-send-stdin")
	}
}

func mustTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
