// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type nativeTCPCopyFastPathSource struct {
	payload       []byte
	readOffset    int
	writeToCalled bool
}

func (s *nativeTCPCopyFastPathSource) Read(p []byte) (int, error) {
	if s.readOffset >= len(s.payload) {
		return 0, io.EOF
	}
	n := copy(p, s.payload[s.readOffset:])
	s.readOffset += n
	return n, nil
}

func (s *nativeTCPCopyFastPathSource) WriteTo(dst io.Writer) (int64, error) {
	s.writeToCalled = true
	n, err := dst.Write(s.payload)
	return int64(n), err
}

func TestExternalNativeTCPBearerAuthHandshakeAcceptsMatchingSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sessionID := [16]byte{1, 2, 3, 4}
	bearerSecret := [32]byte{5, 6, 7, 8}
	clientPublic := [32]byte{9, 10, 11, 12}
	serverPublic := [32]byte{13, 14, 15, 16}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- acceptExternalNativeTCPBearerAuth(ctx, serverConn, sessionID, bearerSecret, serverPublic, clientPublic)
	}()

	if err := dialExternalNativeTCPBearerAuth(ctx, clientConn, sessionID, bearerSecret, clientPublic, serverPublic); err != nil {
		t.Fatalf("dialExternalNativeTCPBearerAuth() error = %v", err)
	}
	if err := <-acceptErr; err != nil {
		t.Fatalf("acceptExternalNativeTCPBearerAuth() error = %v", err)
	}
}

func TestExternalNativeTCPBearerAuthHandshakeRejectsMismatchedSecret(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	sessionID := [16]byte{1, 2, 3, 4}
	dialSecret := [32]byte{5, 6, 7, 8}
	acceptSecret := [32]byte{8, 7, 6, 5}
	clientPublic := [32]byte{9, 10, 11, 12}
	serverPublic := [32]byte{13, 14, 15, 16}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- acceptExternalNativeTCPBearerAuth(ctx, serverConn, sessionID, acceptSecret, serverPublic, clientPublic)
	}()

	if err := dialExternalNativeTCPBearerAuth(ctx, clientConn, sessionID, dialSecret, clientPublic, serverPublic); err != nil {
		t.Fatalf("dialExternalNativeTCPBearerAuth() error = %v", err)
	}
	if err := <-acceptErr; err == nil {
		t.Fatal("acceptExternalNativeTCPBearerAuth() error = nil, want mismatch")
	}
}

func TestCopyExternalNativeTCPUsesSourceWriterToFastPath(t *testing.T) {
	src := &nativeTCPCopyFastPathSource{payload: []byte("native-tcp-fast-path")}
	var dst bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := copyExternalNativeTCP(ctx, &dst, src); err != nil {
		t.Fatalf("copyExternalNativeTCP() error = %v", err)
	}
	if got := dst.String(); got != "native-tcp-fast-path" {
		t.Fatalf("copyExternalNativeTCP() dst = %q, want %q", got, "native-tcp-fast-path")
	}
	if !src.writeToCalled {
		t.Fatal("copyExternalNativeTCP() did not use source WriteTo fast path")
	}
}

func TestExternalNativeTCPRouteCanUseLocalAddrCandidateUsesRouteSourceForPrivatePeer(t *testing.T) {
	prevRouteLocalIP := externalNativeTCPRouteLocalIP
	externalNativeTCPRouteLocalIP = func(net.Addr) (netip.Addr, bool) {
		return netip.MustParseAddr("192.168.100.229"), true
	}
	t.Cleanup(func() { externalNativeTCPRouteLocalIP = prevRouteLocalIP })

	if !externalNativeTCPRouteCanUseLocalAddrCandidate(
		&net.UDPAddr{IP: net.IPv4(192, 168, 100, 229), Port: 53246},
		&net.TCPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 45321},
	) {
		t.Fatal("externalNativeTCPRouteCanUseLocalAddrCandidate() = false, want route-source private address accepted")
	}
}

func TestExternalNativeTCPRouteCanUseLocalAddrCandidateRejectsPrivateRouteSourceForPublicPeer(t *testing.T) {
	prevRouteLocalIP := externalNativeTCPRouteLocalIP
	externalNativeTCPRouteLocalIP = func(net.Addr) (netip.Addr, bool) {
		return netip.MustParseAddr("10.0.4.2"), true
	}
	t.Cleanup(func() { externalNativeTCPRouteLocalIP = prevRouteLocalIP })

	if externalNativeTCPRouteCanUseLocalAddrCandidate(
		&net.UDPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 53246},
		&net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 45321},
	) {
		t.Fatal("externalNativeTCPRouteCanUseLocalAddrCandidate() = true, want private address rejected for public peer")
	}
}

func TestSelectExternalNativeTCPResponseAddrUsesRouteSourceOverBridgeAddress(t *testing.T) {
	prevRouteLocalIP := externalNativeTCPRouteLocalIP
	externalNativeTCPRouteLocalIP = func(net.Addr) (netip.Addr, bool) {
		return netip.MustParseAddr("192.168.100.229"), true
	}
	t.Cleanup(func() { externalNativeTCPRouteLocalIP = prevRouteLocalIP })

	got := selectExternalNativeTCPResponseAddr(
		&net.TCPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 45321},
		nil,
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(172, 17, 0, 1), Port: 56354},
			&net.UDPAddr{IP: net.IPv4(192, 168, 100, 229), Port: 56354},
		},
	)
	if got == nil {
		t.Fatal("selectExternalNativeTCPResponseAddr() = nil, want route-source candidate")
	}
	if got.String() != "192.168.100.229:56354" {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want 192.168.100.229:56354", got)
	}
}

func TestSelectExternalNativeTCPResponseAddrRejectsUnrelatedBridgeAddress(t *testing.T) {
	prevRouteLocalIP := externalNativeTCPRouteLocalIP
	externalNativeTCPRouteLocalIP = func(net.Addr) (netip.Addr, bool) {
		return netip.Addr{}, false
	}
	t.Cleanup(func() { externalNativeTCPRouteLocalIP = prevRouteLocalIP })

	got := selectExternalNativeTCPResponseAddr(
		&net.TCPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 45321},
		nil,
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(172, 17, 0, 1), Port: 56354},
		},
	)
	if got != nil {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want nil", got)
	}
}
