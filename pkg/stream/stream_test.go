// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBridgeCopiesBothDirections(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	done := make(chan error, 1)
	go func() {
		done <- Bridge(context.Background(), left, right)
	}()

	if _, err := right.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	buf := make([]byte, 5)
	if _, err := left.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("buf = %q, want hello", buf)
	}

	if err := right.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Bridge() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Bridge() did not return")
	}
}

func TestBridgeReturnsOnContextCancel(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Bridge(ctx, left, right)
	}()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bridge() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Bridge() did not return after cancel")
	}
}

func TestStdioAttachmentWrapsReadersAndWriters(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer
	in.WriteString("payload")

	a := NewStdioAttachment(&in, &out)

	buf := make([]byte, 7)
	if _, err := a.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf) != "payload" {
		t.Fatalf("buf = %q, want payload", buf)
	}
	if _, err := a.Write([]byte("reply")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if out.String() != "reply" {
		t.Fatalf("out = %q, want reply", out.String())
	}
}

func TestStdioAttachmentPreservesWriterToFastPath(t *testing.T) {
	src := &writerToReader{payload: "writer-to"}
	a := NewStdioAttachment(src, io.Discard)

	var got bytes.Buffer
	n, err := io.Copy(&got, a)
	if err != nil {
		t.Fatalf("Copy() error = %v", err)
	}
	if n != int64(len("writer-to")) {
		t.Fatalf("Copy() = %d, want %d", n, len("writer-to"))
	}
	if got.String() != "writer-to" {
		t.Fatalf("Copy() output = %q, want writer-to", got.String())
	}
	if !src.writeToCalled {
		t.Fatal("Copy() did not use source WriteTo fast path")
	}
}

func TestStdioAttachmentPreservesReaderFromFastPath(t *testing.T) {
	dst := &readerFromWriter{}
	a := NewStdioAttachment(strings.NewReader("ignored"), dst)

	n, err := io.Copy(a, &readOnlyReader{Reader: strings.NewReader("reader-from")})
	if err != nil {
		t.Fatalf("Copy() error = %v", err)
	}
	if n != int64(len("reader-from")) {
		t.Fatalf("Copy() = %d, want %d", n, len("reader-from"))
	}
	if dst.String() != "reader-from" {
		t.Fatalf("Copy() output = %q, want reader-from", dst.String())
	}
	if !dst.readFromCalled {
		t.Fatal("Copy() did not use destination ReadFrom fast path")
	}
}

func TestListenOnceAndConnectRoundTrip(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	done := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := ListenOnce(context.Background(), addr)
		done <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()

	var client net.Conn
	deadline := time.Now().Add(time.Second)
	for {
		client, err = Connect(context.Background(), addr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Connect() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer client.Close()

	var res struct {
		conn net.Conn
		err  error
	}
	select {
	case res = <-done:
	case <-time.After(time.Second):
		t.Fatal("ListenOnce() did not return")
	}
	if res.err != nil {
		t.Fatalf("ListenOnce() error = %v", res.err)
	}
	defer res.conn.Close()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(res.conn, buf); err != nil {
		t.Fatalf("server Read() error = %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("buf = %q, want ping", buf)
	}
}

type writerToReader struct {
	payload       string
	writeToCalled bool
}

func (r *writerToReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (r *writerToReader) WriteTo(w io.Writer) (int64, error) {
	r.writeToCalled = true
	n, err := io.WriteString(w, r.payload)
	return int64(n), err
}

type readerFromWriter struct {
	bytes.Buffer
	readFromCalled bool
}

func (w *readerFromWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFromCalled = true
	return w.Buffer.ReadFrom(r)
}

type readOnlyReader struct {
	io.Reader
}
