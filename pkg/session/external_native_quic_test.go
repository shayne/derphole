// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"tailscale.com/tailcfg"
)

func TestExternalNativeQUICTransfersWhenOnlyListenerDialPathWorks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	senderReady := make(chan struct{})
	streamReadDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		close(senderReady)
		quicTransport, quicConn, err := dialOrAcceptExternalNativeQUICConn(
			ctx,
			senderPacketConn,
			nil,
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer quicTransport.Close()
		defer quicConn.CloseWithError(0, "")

		streamConn, err := quicConn.OpenStreamSync(ctx)
		if err != nil {
			senderErr <- err
			return
		}
		if _, err := streamConn.Write([]byte("listener-dial-native-quic")); err != nil {
			senderErr <- err
			return
		}
		if err := streamConn.Close(); err != nil {
			senderErr <- err
			return
		}
		<-streamReadDone
		senderErr <- nil
	}()
	<-senderReady
	select {
	case err := <-senderErr:
		t.Fatalf("sender helper exited before listener dial: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	quicTransport, quicConn, streamConn, err := acceptExternalNativeQUICStream(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(senderPacketConn.LocalAddr()),
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStream() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer quicTransport.Close()
	defer quicConn.CloseWithError(0, "")
	defer streamConn.Close()

	got, err := io.ReadAll(streamConn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "listener-dial-native-quic" {
		t.Fatalf("stream payload = %q, want %q", got, "listener-dial-native-quic")
	}
	close(streamReadDone)

	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
}

func TestDialOrAcceptExternalNativeQUICConnOnTransportReturnsAfterFirstDialSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	senderTransport, senderListener, err := startExternalNativeQUICTransport(
		senderPacketConn,
		quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer senderTransport.Close()
	defer senderListener.Close()

	peerTransport, peerListener, err := startExternalNativeQUICTransport(
		listenerPacketConn,
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer peerTransport.Close()
	defer peerListener.Close()

	peerErr := make(chan error, 1)
	go func() {
		peerConn, err := peerListener.Accept(ctx)
		if err != nil {
			peerErr <- err
			return
		}
		_ = peerConn.CloseWithError(0, "")
		peerErr <- nil
	}()

	connectCtx, connectCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer connectCancel()

	start := time.Now()
	conn, _, err := dialOrAcceptExternalNativeQUICConnOnTransport(
		connectCtx,
		senderTransport,
		senderListener,
		cloneSessionAddr(listenerPacketConn.LocalAddr()),
		quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
		true,
	)
	if err != nil {
		t.Fatalf("dialOrAcceptExternalNativeQUICConnOnTransport() error = %v", err)
	}
	defer conn.CloseWithError(0, "")

	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("dialOrAcceptExternalNativeQUICConnOnTransport() elapsed = %v, want first dial success without waiting for connect timeout", elapsed)
	}

	if err := <-peerErr; err != nil {
		t.Fatalf("peer Accept() error = %v", err)
	}
}

func TestDialOrAcceptExternalNativeQUICConnWithRoleUsesPreferredStreamRoleWhenAcceptedConnWins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	type nativeQUICConnResult struct {
		transport *quic.Transport
		conn      *quic.Conn
		err       error
	}
	listenerResultCh := make(chan nativeQUICConnResult, 1)
	go func() {
		transport, conn, err := dialOrAcceptExternalNativeQUICConn(
			ctx,
			listenerPacketConn,
			cloneSessionAddr(senderPacketConn.LocalAddr()),
			quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
			quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		)
		listenerResultCh <- nativeQUICConnResult{transport: transport, conn: conn, err: err}
	}()

	senderTransport, senderConn, openStream, err := dialOrAcceptExternalNativeQUICConnWithRole(
		ctx,
		senderPacketConn,
		nil,
		quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
		quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer senderTransport.Close()
	defer senderConn.CloseWithError(0, "")

	listenerResult := <-listenerResultCh
	if listenerResult.err != nil {
		t.Fatal(listenerResult.err)
	}
	defer listenerResult.transport.Close()
	defer listenerResult.conn.CloseWithError(0, "")

	if !openStream {
		t.Fatal("dialOrAcceptExternalNativeQUICConnWithRole() openStream = false, want true for preferDial sender role even when Accept wins")
	}

	senderStream, err := openExternalNativeQUICStreamForConn(ctx, senderConn, openStream)
	if err != nil {
		t.Fatalf("sender openExternalNativeQUICStreamForConn() error = %v", err)
	}
	defer senderStream.Close()

	listenerStream, err := openExternalNativeQUICStreamForConn(ctx, listenerResult.conn, false)
	if err != nil {
		t.Fatalf("listener openExternalNativeQUICStreamForConn() error = %v", err)
	}
	defer listenerStream.Close()

	if _, err := senderStream.Write([]byte("preferred-stream-role")); err != nil {
		t.Fatal(err)
	}
	if err := senderStream.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(listenerStream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preferred-stream-role" {
		t.Fatalf("listener stream payload = %q, want %q", got, "preferred-stream-role")
	}
}

func TestExternalNativeQUICTransfersAllowSlowPrimaryHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rawSenderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawSenderPacketConn.Close()
	senderPacketConn := &slowWriteOncePacketConn{
		PacketConn: rawSenderPacketConn,
		delay:      1500 * time.Millisecond,
	}

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("slow-primary-native-quic")
	listenerDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		quicTransport, quicConn, err := dialOrAcceptExternalNativeQUICConn(
			ctx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer quicTransport.Close()
		defer quicConn.CloseWithError(0, "")

		streamConn, err := quicConn.OpenStreamSync(ctx)
		if err != nil {
			senderErr <- err
			return
		}
		if _, err := streamConn.Write(payload); err != nil {
			senderErr <- err
			return
		}
		if err := streamConn.Close(); err != nil {
			senderErr <- err
			return
		}
		<-listenerDone
		senderErr <- nil
	}()

	quicTransport, quicConn, streamConn, err := acceptExternalNativeQUICStream(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(rawSenderPacketConn.LocalAddr()),
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStream() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer quicTransport.Close()
	defer quicConn.CloseWithError(0, "")
	defer streamConn.Close()

	got, err := io.ReadAll(streamConn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		close(listenerDone)
		t.Fatalf("stream payload = %q, want %q", got, payload)
	}
	close(listenerDone)

	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
}

func TestExternalNativeQUICStripedTransferUsesMultipleConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("striped-native-quic"), 4096)
	listenerDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		quicTransport, quicConns, err := dialOrAcceptExternalNativeQUICConns(
			ctx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
			4,
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer quicTransport.Close()
		defer closeExternalNativeQUICConns(quicConns)

		writers := make([]io.WriteCloser, 0, len(quicConns))
		for _, quicConn := range quicConns {
			streamConn, err := quicConn.OpenStreamSync(ctx)
			if err != nil {
				senderErr <- err
				return
			}
			writers = append(writers, streamConn)
		}
		if err := sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 32<<10); err != nil {
			senderErr <- err
			return
		}
		<-listenerDone
		senderErr <- nil
	}()

	quicTransport, quicConns, streamConns, err := acceptExternalNativeQUICStreams(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(senderPacketConn.LocalAddr()),
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		4,
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStreams() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer quicTransport.Close()
	defer closeExternalNativeQUICConns(quicConns)
	defer closeExternalNativeQUICStreams(streamConns)

	readers := make([]io.ReadCloser, 0, len(streamConns))
	for _, streamConn := range streamConns {
		readers = append(readers, streamConn)
	}

	var got bytes.Buffer
	if err := receiveExternalStripedCopy(ctx, &got, readers, 32<<10); err != nil {
		t.Fatal(err)
	}
	close(listenerDone)
	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("striped payload mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
}

func TestExternalNativeQUICStripedTransferReusesPrimaryPacketConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("multi-socket-native-quic"), 4096)
	listenerDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		session, err := dialExternalNativeQUICStripedConns(
			ctx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			nil,
			nil,
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
			4,
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer session.Close()

		writers, err := session.OpenStreams(ctx)
		if err != nil {
			senderErr <- err
			return
		}
		if err := sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 32<<10); err != nil {
			senderErr <- err
			return
		}
		<-listenerDone
		senderErr <- nil
	}()

	session, streams, err := acceptExternalNativeQUICStripedConns(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(senderPacketConn.LocalAddr()),
		nil,
		nil,
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		4,
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStripedConns() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer session.Close()
	defer closeExternalNativeQUICStreams(streams)

	readers := make([]io.ReadCloser, 0, len(streams))
	for _, stream := range streams {
		readers = append(readers, stream)
	}

	var got bytes.Buffer
	if err := receiveExternalStripedCopy(ctx, &got, readers, 32<<10); err != nil {
		t.Fatal(err)
	}
	close(listenerDone)
	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("striped payload mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}

	if len(session.packetConns) != 1 {
		t.Fatalf("striped session packet conns = %d, want 1", len(session.packetConns))
	}
	if len(session.conns) != 4 {
		t.Fatalf("striped session QUIC conns = %d, want 4", len(session.conns))
	}
}

func TestExternalNativeQUICStripedTransferFallsBackToPrimaryWhenExtraStripeCandidatesAreUnusable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	defer func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	}()
	externalNativeQUICStripeProbeCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, publicPortmap) []string {
		return []string{"203.0.113.1:54321"}
	}
	prevLocalAddrCandidate := externalNativeQUICStripeCanUseLocalAddrCandidate
	defer func() {
		externalNativeQUICStripeCanUseLocalAddrCandidate = prevLocalAddrCandidate
	}()
	externalNativeQUICStripeCanUseLocalAddrCandidate = func(net.Addr, net.Addr) bool {
		return false
	}

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("fallback-native-quic"), 4096)
	listenerDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		session, err := dialExternalNativeQUICStripedConns(
			ctx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			nil,
			nil,
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
			4,
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer session.Close()
		if len(session.conns) != 1 {
			senderErr <- io.ErrUnexpectedEOF
			return
		}

		writers, err := session.OpenStreams(ctx)
		if err != nil {
			senderErr <- err
			return
		}
		if len(writers) != 1 {
			closeExternalStripedWriters(writers)
			senderErr <- io.ErrUnexpectedEOF
			return
		}
		if err := sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 32<<10); err != nil {
			senderErr <- err
			return
		}
		<-listenerDone
		senderErr <- nil
	}()

	session, streams, err := acceptExternalNativeQUICStripedConns(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(senderPacketConn.LocalAddr()),
		nil,
		nil,
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		4,
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStripedConns() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer session.Close()
	defer closeExternalNativeQUICStreams(streams)
	if len(session.conns) != 1 {
		t.Fatalf("fallback striped session conns = %d, want 1", len(session.conns))
	}
	if len(streams) != 1 {
		t.Fatalf("fallback striped session streams = %d, want 1", len(streams))
	}

	var got bytes.Buffer
	if err := receiveExternalStripedCopy(ctx, &got, []io.ReadCloser{streams[0]}, 32<<10); err != nil {
		t.Fatal(err)
	}
	close(listenerDone)
	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("fallback payload mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
}

func TestExternalNativeQUICStripedSessionOpenQUICStreamsSupportsMixedStreamRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	senderPacketConn0, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerPacketConn0, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	senderPacketConn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerPacketConn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	senderClientTLS := quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public)
	senderServerTLS := quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public)
	listenerClientTLS := quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public)
	listenerServerTLS := quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public)

	senderTransport0, senderConn0, listenerTransport0, listenerConn0 := connectExternalNativeQUICConnPairForTest(
		t,
		ctx,
		senderPacketConn0,
		listenerPacketConn0,
		senderClientTLS,
		senderServerTLS,
		listenerClientTLS,
		listenerServerTLS,
		true,
	)
	senderTransport1, senderConn1, listenerTransport1, listenerConn1 := connectExternalNativeQUICConnPairForTest(
		t,
		ctx,
		senderPacketConn1,
		listenerPacketConn1,
		senderClientTLS,
		senderServerTLS,
		listenerClientTLS,
		listenerServerTLS,
		false,
	)

	senderSession := &externalNativeQUICStripedSession{
		packetConns: []net.PacketConn{senderPacketConn0, senderPacketConn1},
		transports:  []*quic.Transport{senderTransport0, senderTransport1},
		conns:       []*quic.Conn{senderConn0, senderConn1},
		openStreams: []bool{true, false},
	}
	defer senderSession.Close()

	listenerSession := &externalNativeQUICStripedSession{
		packetConns: []net.PacketConn{listenerPacketConn0, listenerPacketConn1},
		transports:  []*quic.Transport{listenerTransport0, listenerTransport1},
		conns:       []*quic.Conn{listenerConn0, listenerConn1},
		openStreams: []bool{false, true},
	}
	defer listenerSession.Close()

	senderStreamsCh := make(chan []*quic.Stream, 1)
	senderErrCh := make(chan error, 1)
	go func() {
		streams, err := senderSession.OpenQUICStreams(ctx)
		if err == nil {
			senderStreamsCh <- streams
		}
		senderErrCh <- err
	}()

	listenerStreams, err := listenerSession.OpenQUICStreams(ctx)
	if err != nil {
		t.Fatalf("listener OpenQUICStreams() error = %v", err)
	}
	defer closeExternalNativeQUICStreams(listenerStreams)

	if len(listenerStreams) != 2 {
		t.Fatalf("listener OpenQUICStreams() len = %d, want 2", len(listenerStreams))
	}

	if err := <-senderErrCh; err != nil {
		t.Fatalf("sender OpenQUICStreams() error = %v", err)
	}
	senderStreams := <-senderStreamsCh
	defer closeExternalNativeQUICStreams(senderStreams)

	if len(senderStreams) != 2 {
		t.Fatalf("sender OpenQUICStreams() len = %d, want 2", len(senderStreams))
	}
}

func TestCloseExternalNativeQUICSendSetupResultAsyncReturnsBeforeSetupResultArrives(t *testing.T) {
	resultCh := make(chan externalNativeQUICSendSetupResult, 1)
	start := time.Now()

	closeExternalNativeQUICSendSetupResultAsync(resultCh)

	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("closeExternalNativeQUICSendSetupResultAsync() blocked for %v waiting for setup result", elapsed)
	}
	resultCh <- externalNativeQUICSendSetupResult{}
}

func TestCloseExternalNativeQUICListenSetupResultAsyncReturnsBeforeSetupResultArrives(t *testing.T) {
	resultCh := make(chan externalNativeQUICListenSetupResult, 1)
	start := time.Now()

	closeExternalNativeQUICListenSetupResultAsync(resultCh)

	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("closeExternalNativeQUICListenSetupResultAsync() blocked for %v waiting for setup result", elapsed)
	}
	resultCh <- externalNativeQUICListenSetupResult{}
}

func TestWaitExternalNativeQUICSetupGraceReturnsRelayResultWhenRelayFinishesWithinGrace(t *testing.T) {
	relayErrCh := make(chan error, 1)
	relayErrCh <- io.EOF

	relayErr, ok := waitExternalNativeQUICSetupGrace(relayErrCh, time.Second)
	if !ok {
		t.Fatal("waitExternalNativeQUICSetupGrace() ok = false, want true")
	}
	if !errors.Is(relayErr, io.EOF) {
		t.Fatalf("waitExternalNativeQUICSetupGrace() error = %v, want %v", relayErr, io.EOF)
	}
}

func TestWaitExternalNativeQUICSetupGraceReturnsFalseAfterGraceTimeout(t *testing.T) {
	relayErrCh := make(chan error, 1)
	start := time.Now()

	relayErr, ok := waitExternalNativeQUICSetupGrace(relayErrCh, 25*time.Millisecond)
	if ok {
		t.Fatalf("waitExternalNativeQUICSetupGrace() = (%v, true), want (_, false)", relayErr)
	}
	if relayErr != nil {
		t.Fatalf("waitExternalNativeQUICSetupGrace() error = %v, want nil", relayErr)
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("waitExternalNativeQUICSetupGrace() returned after %v, want to wait for grace timeout", elapsed)
	}
}

func TestExternalNativeQUICSetupGraceWaitForSpoolReturnsZeroForDrainedShortRelayTail(t *testing.T) {
	spool := &externalHandoffSpool{
		sourceOffset:   4 << 20,
		ackedWatermark: 4 << 20,
		eof:            true,
	}

	if got := externalNativeQUICSetupGraceWaitForSpool(spool); got != 0 {
		t.Fatalf("externalNativeQUICSetupGraceWaitForSpool() = %v, want 0 for short drained relay tail", got)
	}
}

func TestExternalNativeQUICSetupGraceWaitForSpoolKeepsGraceForShortUnackedRelayTail(t *testing.T) {
	spool := &externalHandoffSpool{
		sourceOffset:   5 << 20,
		ackedWatermark: 4 << 20,
		eof:            true,
	}

	if got := externalNativeQUICSetupGraceWaitForSpool(spool); got != 0 {
		t.Fatalf("externalNativeQUICSetupGraceWaitForSpool() = %v, want 0", got)
	}
}

func TestExternalNativeQUICSetupGraceWaitForSpoolKeepsGraceForUndrainedOrLargeRelayTail(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spool *externalHandoffSpool
	}{
		{
			name: "undrained-short-tail",
			spool: &externalHandoffSpool{
				sourceOffset:   5 << 20,
				ackedWatermark: 4 << 20,
			},
		},
		{
			name: "drained-large-tail",
			spool: &externalHandoffSpool{
				sourceOffset:   32 << 20,
				ackedWatermark: 4 << 20,
				eof:            true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := externalNativeQUICSetupGraceWaitForSpool(tc.spool); got != 0 {
				t.Fatalf("externalNativeQUICSetupGraceWaitForSpool() = %v, want 0", got)
			}
		})
	}
}

func TestExternalNativeQUICSetupShouldSkipForSpoolSkipsShortEOFRelayTail(t *testing.T) {
	spool := &externalHandoffSpool{
		sourceOffset:   (4 << 20) + (256 << 10),
		ackedWatermark: 4 << 20,
		eof:            true,
	}

	if !externalNativeQUICSetupShouldSkipForSpool(spool) {
		t.Fatal("externalNativeQUICSetupShouldSkipForSpool() = false, want true for short EOF relay tail")
	}
}

func TestExternalNativeQUICSetupShouldSkipForSpoolKeepsSetupForUndrainedOrLargeRelayTail(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spool *externalHandoffSpool
	}{
		{
			name: "undrained-short-tail",
			spool: &externalHandoffSpool{
				sourceOffset:   8 << 20,
				ackedWatermark: 4 << 20,
			},
		},
		{
			name: "drained-large-tail",
			spool: &externalHandoffSpool{
				sourceOffset:   6 << 20,
				ackedWatermark: 4 << 20,
				eof:            true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if externalNativeQUICSetupShouldSkipForSpool(tc.spool) {
				t.Fatal("externalNativeQUICSetupShouldSkipForSpool() = true, want false")
			}
		})
	}
}

func TestWaitExternalNativeQUICRelayTailPeerAckReturnsReadyAckForShortEOFRelayTail(t *testing.T) {
	spool := &externalHandoffSpool{
		sourceOffset:   (4 << 20) + (256 << 10),
		ackedWatermark: 4 << 20,
		eof:            true,
	}
	ackCh := make(chan derpbind.Packet, 1)
	ackCh <- derpbind.Packet{Payload: testPeerAckPayload(t, spool.sourceOffset)}

	done, err := waitExternalNativeQUICRelayTailPeerAck(context.Background(), spool, ackCh)
	if err != nil {
		t.Fatalf("waitExternalNativeQUICRelayTailPeerAck() error = %v", err)
	}
	if !done {
		t.Fatal("waitExternalNativeQUICRelayTailPeerAck() done = false, want true")
	}
}

func TestWaitExternalNativeQUICRelayTailPeerAckReturnsFalseForLargeEOFRelayTailWithoutConsumingAck(t *testing.T) {
	spool := &externalHandoffSpool{
		sourceOffset:   6 << 20,
		ackedWatermark: 4 << 20,
		eof:            true,
	}
	ackCh := make(chan derpbind.Packet, 1)
	ackCh <- derpbind.Packet{Payload: testPeerAckPayload(t, spool.sourceOffset)}

	done, err := waitExternalNativeQUICRelayTailPeerAck(context.Background(), spool, ackCh)
	if err != nil {
		t.Fatalf("waitExternalNativeQUICRelayTailPeerAck() error = %v", err)
	}
	if done {
		t.Fatal("waitExternalNativeQUICRelayTailPeerAck() done = true, want false")
	}
	if got := len(ackCh); got != 1 {
		t.Fatalf("ack channel len = %d, want 1", got)
	}
}

func connectExternalNativeQUICConnPairForTest(
	t *testing.T,
	ctx context.Context,
	senderPacketConn net.PacketConn,
	listenerPacketConn net.PacketConn,
	senderClientTLS *tls.Config,
	senderServerTLS *tls.Config,
	listenerClientTLS *tls.Config,
	listenerServerTLS *tls.Config,
	senderDials bool,
) (*quic.Transport, *quic.Conn, *quic.Transport, *quic.Conn) {
	t.Helper()

	senderTransport, senderListener, err := startExternalNativeQUICTransport(senderPacketConn, senderServerTLS)
	if err != nil {
		t.Fatal(err)
	}
	listenerTransport, listenerListener, err := startExternalNativeQUICTransport(listenerPacketConn, listenerServerTLS)
	if err != nil {
		_ = senderListener.Close()
		_ = senderTransport.Close()
		t.Fatal(err)
	}

	var senderConn *quic.Conn
	var listenerConn *quic.Conn
	errCh := make(chan error, 2)
	if senderDials {
		go func() {
			conn, err := senderTransport.Dial(
				ctx,
				cloneSessionAddr(listenerPacketConn.LocalAddr()),
				senderClientTLS,
				quicpath.DefaultQUICConfig(),
			)
			senderConn = conn
			errCh <- err
		}()
		go func() {
			conn, err := listenerListener.Accept(ctx)
			listenerConn = conn
			errCh <- err
		}()
	} else {
		go func() {
			conn, err := senderListener.Accept(ctx)
			senderConn = conn
			errCh <- err
		}()
		go func() {
			conn, err := listenerTransport.Dial(
				ctx,
				cloneSessionAddr(senderPacketConn.LocalAddr()),
				listenerClientTLS,
				quicpath.DefaultQUICConfig(),
			)
			listenerConn = conn
			errCh <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			_ = senderListener.Close()
			_ = listenerListener.Close()
			if senderConn != nil {
				_ = senderConn.CloseWithError(0, "")
			}
			if listenerConn != nil {
				_ = listenerConn.CloseWithError(0, "")
			}
			_ = senderTransport.Close()
			_ = listenerTransport.Close()
			t.Fatal(err)
		}
	}
	if err := senderListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listenerListener.Close(); err != nil {
		t.Fatal(err)
	}

	return senderTransport, senderConn, listenerTransport, listenerConn
}

func TestExternalNativeQUICStripedTransferNegotiatesAsymmetricStripeCounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	defer func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	}()
	externalNativeQUICStripeProbeCandidates = func(_ context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		udpAddr := packetConn.LocalAddr().(*net.UDPAddr)
		return []string{net.JoinHostPort("127.0.0.1", fmt.Sprint(udpAddr.Port))}
	}
	prevLocalAddrCandidate := externalNativeQUICStripeCanUseLocalAddrCandidate
	defer func() {
		externalNativeQUICStripeCanUseLocalAddrCandidate = prevLocalAddrCandidate
	}()
	externalNativeQUICStripeCanUseLocalAddrCandidate = func(net.Addr, net.Addr) bool {
		return false
	}

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("asymmetric-native-quic-stripes"), 4096)
	listenerDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		session, err := dialExternalNativeQUICStripedConns(
			ctx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			nil,
			nil,
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
			8,
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer session.Close()
		if len(session.conns) != 4 {
			senderErr <- fmt.Errorf("sender conn count = %d, want 4", len(session.conns))
			return
		}

		writers, err := session.OpenStreams(ctx)
		if err != nil {
			senderErr <- err
			return
		}
		if err := sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 32<<10); err != nil {
			senderErr <- err
			return
		}
		<-listenerDone
		senderErr <- nil
	}()

	session, streams, err := acceptExternalNativeQUICStripedConns(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(senderPacketConn.LocalAddr()),
		nil,
		nil,
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		4,
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStripedConns() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer session.Close()
	defer closeExternalNativeQUICStreams(streams)
	if len(session.conns) != 4 {
		t.Fatalf("listener conn count = %d, want 4", len(session.conns))
	}

	readers := make([]io.ReadCloser, 0, len(streams))
	for _, stream := range streams {
		readers = append(readers, stream)
	}

	var got bytes.Buffer
	if err := receiveExternalStripedCopy(ctx, &got, readers, 32<<10); err != nil {
		t.Fatal(err)
	}
	close(listenerDone)
	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
}

func TestDialExternalNativeQUICStripedConnsFallsBackToControlStreamWhenPeerSetupDecodeFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prevLocalAddrCandidate := externalNativeQUICStripeCanUseLocalAddrCandidate
	defer func() {
		externalNativeQUICStripeCanUseLocalAddrCandidate = prevLocalAddrCandidate
	}()
	externalNativeQUICStripeCanUseLocalAddrCandidate = func(net.Addr, net.Addr) bool {
		return false
	}

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	listenerControlClosed := make(chan error, 1)
	releaseListenerConn := make(chan struct{})
	listenerDone := make(chan error, 1)
	go func() {
		transport, conns, err := dialOrAcceptExternalNativeQUICConnsWithRole(
			ctx,
			listenerPacketConn,
			cloneSessionAddr(senderPacketConn.LocalAddr()),
			quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
			quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
			1,
			false,
		)
		if err != nil {
			listenerDone <- fmt.Errorf("listener dial-or-accept conn: %w", err)
			return
		}
		defer transport.Close()
		conn := conns[0]
		defer conn.CloseWithError(0, "")

		controlStream, err := openExternalNativeQUICStreamForConn(ctx, conn, false)
		if err != nil {
			listenerDone <- fmt.Errorf("listener accept control stream: %w", err)
			return
		}
		if err := controlStream.Close(); err != nil {
			listenerControlClosed <- fmt.Errorf("listener close control stream: %w", err)
			return
		}
		listenerControlClosed <- nil
		<-releaseListenerConn
		listenerDone <- nil
	}()

	session, err := dialExternalNativeQUICStripedConns(
		ctx,
		senderPacketConn,
		cloneSessionAddr(listenerPacketConn.LocalAddr()),
		nil,
		nil,
		quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
		quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if err := <-listenerControlClosed; err != nil {
		t.Fatal(err)
	}
	if session.primaryStream == nil {
		t.Fatal("fallback primaryStream is unset after peer setup decode failure")
	}
	if !session.setupFallback {
		t.Fatal("fallback setupFallback is false after peer setup decode failure")
	}

	writers, err := session.OpenStreams(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(writers) != 1 {
		closeExternalStripedWriters(writers)
		close(releaseListenerConn)
		<-listenerDone
		t.Fatalf("fallback writers = %d, want 1", len(writers))
	}
	closeExternalStripedWriters(writers)
	close(releaseListenerConn)
	if err := <-listenerDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialExternalNativeQUICStripedConnsReturnsPromptlyWhenSetupContextIsCanceledWhileReadingPeerSetup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prevLocalAddrCandidate := externalNativeQUICStripeCanUseLocalAddrCandidate
	t.Cleanup(func() {
		externalNativeQUICStripeCanUseLocalAddrCandidate = prevLocalAddrCandidate
	})
	externalNativeQUICStripeCanUseLocalAddrCandidate = func(net.Addr, net.Addr) bool {
		return false
	}

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	t.Cleanup(func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	})
	externalNativeQUICStripeProbeCandidates = func(_ context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		return []string{packetConn.LocalAddr().String()}
	}

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	controlStreamAccepted := make(chan struct{})
	releaseListener := make(chan struct{})
	listenerErr := make(chan error, 1)
	go func() {
		transport, conn, err := acceptExternalNativeQUICConnStrict(
			ctx,
			listenerPacketConn,
			quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		)
		if err != nil {
			listenerErr <- err
			return
		}
		defer transport.Close()
		defer conn.CloseWithError(0, "")

		controlStream, err := conn.AcceptStream(ctx)
		if err != nil {
			listenerErr <- err
			return
		}
		close(controlStreamAccepted)
		<-releaseListener
		_ = controlStream.Close()
		listenerErr <- nil
	}()

	setupCtx, setupCancel := context.WithCancel(ctx)
	setupErr := make(chan error, 1)
	go func() {
		session, err := dialExternalNativeQUICStripedConns(
			setupCtx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			nil,
			nil,
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
			4,
		)
		if session != nil {
			session.Close()
		}
		setupErr <- err
	}()

	select {
	case <-controlStreamAccepted:
	case err := <-listenerErr:
		t.Fatalf("listener setup failed before control stream accept: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	start := time.Now()
	setupCancel()
	select {
	case <-setupErr:
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			close(releaseListener)
			<-listenerErr
			t.Fatalf("dialExternalNativeQUICStripedConns() took %v after setup cancellation, want < 500ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		close(releaseListener)
		<-listenerErr
		t.Fatal("dialExternalNativeQUICStripedConns() did not return promptly after setup cancellation")
	}

	close(releaseListener)
	if err := <-listenerErr; err != nil {
		t.Fatal(err)
	}
}

func TestOpenExternalNativeQUICStripePacketConnsGathersCandidatesConcurrently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	defer func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	}()
	externalNativeQUICStripeProbeCandidates = func(_ context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		time.Sleep(200 * time.Millisecond)
		return []string{packetConn.LocalAddr().String()}
	}

	start := time.Now()
	packetConns, portmaps, candidateSets, err := openExternalNativeQUICStripePacketConns(
		ctx,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		nil,
		nil,
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExternalNativeQUICStripePacketConns(packetConns, portmaps)

	if elapsed := time.Since(start); elapsed > 350*time.Millisecond {
		t.Fatalf("openExternalNativeQUICStripePacketConns() took %v, want concurrent candidate gathering", elapsed)
	}
	if len(candidateSets) != 3 {
		t.Fatalf("candidate set count = %d, want 3", len(candidateSets))
	}
	for i, candidateSet := range candidateSets {
		if len(candidateSet) != 1 || candidateSet[0] != packetConns[i].LocalAddr().String() {
			t.Fatalf("candidateSet[%d] = %v, want [%q]", i, candidateSet, packetConns[i].LocalAddr().String())
		}
	}
}

func TestExternalNativeQUICStripedTransferAllowsSlowCandidateGatheringOnBothSides(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	defer func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	}()
	externalNativeQUICStripeProbeCandidates = func(_ context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		time.Sleep(1200 * time.Millisecond)
		udpAddr := packetConn.LocalAddr().(*net.UDPAddr)
		return []string{net.JoinHostPort("127.0.0.1", fmt.Sprint(udpAddr.Port))}
	}

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("slow-stripe-setup"), 4096)
	listenerDone := make(chan struct{})
	senderErr := make(chan error, 1)
	go func() {
		session, err := dialExternalNativeQUICStripedConns(
			ctx,
			senderPacketConn,
			cloneSessionAddr(listenerPacketConn.LocalAddr()),
			nil,
			nil,
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public),
			2,
		)
		if err != nil {
			senderErr <- err
			return
		}
		defer session.Close()
		if len(session.conns) != 2 {
			senderErr <- fmt.Errorf("sender conn count = %d, want 2", len(session.conns))
			return
		}

		writers, err := session.OpenStreams(ctx)
		if err != nil {
			senderErr <- err
			return
		}
		if err := sendExternalStripedCopy(ctx, bytes.NewReader(payload), writers, 32<<10); err != nil {
			senderErr <- err
			return
		}
		<-listenerDone
		senderErr <- nil
	}()

	session, streams, err := acceptExternalNativeQUICStripedConns(
		ctx,
		listenerPacketConn,
		cloneSessionAddr(senderPacketConn.LocalAddr()),
		nil,
		nil,
		quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
		quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public),
		2,
	)
	if err != nil {
		select {
		case senderSideErr := <-senderErr:
			t.Fatalf("acceptExternalNativeQUICStripedConns() error = %v; sender error = %v", err, senderSideErr)
		default:
		}
		t.Fatal(err)
	}
	defer session.Close()
	defer closeExternalNativeQUICStreams(streams)
	if len(session.conns) != 2 {
		t.Fatalf("listener conn count = %d, want 2", len(session.conns))
	}
	if len(streams) != 2 {
		t.Fatalf("listener stream count = %d, want 2", len(streams))
	}

	readers := make([]io.ReadCloser, 0, len(streams))
	for _, stream := range streams {
		readers = append(readers, stream)
	}

	var got bytes.Buffer
	if err := receiveExternalStripedCopy(ctx, &got, readers, 32<<10); err != nil {
		t.Fatal(err)
	}
	close(listenerDone)
	if err := <-senderErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
}

func TestOpenExternalNativeQUICStripePacketConnsClearsProbeReadDeadlines(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	defer func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	}()
	externalNativeQUICStripeProbeCandidates = func(_ context.Context, packetConn net.PacketConn, _ *tailcfg.DERPMap, _ publicPortmap) []string {
		_ = packetConn.SetReadDeadline(time.Now().Add(time.Millisecond))
		return []string{packetConn.LocalAddr().String()}
	}

	packetConns, portmaps, _, err := openExternalNativeQUICStripePacketConns(
		ctx,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		nil,
		nil,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExternalNativeQUICStripePacketConns(packetConns, portmaps)

	readErr := make(chan error, 1)
	go func() {
		_, _, err := packetConns[0].ReadFrom(make([]byte, 1))
		readErr <- err
	}()

	select {
	case err := <-readErr:
		t.Fatalf("stripe packet conn deadline was not cleared: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	_ = packetConns[0].Close()
	<-readErr
}

func TestOpenExternalNativeQUICStripePacketConnsSkipsProbeForRouteLocalPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	prevStripeCandidates := externalNativeQUICStripeProbeCandidates
	defer func() {
		externalNativeQUICStripeProbeCandidates = prevStripeCandidates
	}()
	externalNativeQUICStripeProbeCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, publicPortmap) []string {
		t.Fatal("externalNativeQUICStripeProbeCandidates called for route-local peer")
		return nil
	}

	packetConns, portmaps, candidateSets, err := openExternalNativeQUICStripePacketConns(
		ctx,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		nil,
		nil,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExternalNativeQUICStripePacketConns(packetConns, portmaps)

	for i, packetConn := range packetConns {
		want := packetConn.LocalAddr().String()
		if len(candidateSets[i]) != 1 || candidateSets[i][0] != want {
			t.Fatalf("candidateSets[%d] = %v, want [%q]", i, candidateSets[i], want)
		}
	}
}

func TestExternalNativeQUICStripeLocalBindAddrUsesPeerRouteIP(t *testing.T) {
	addr := externalNativeQUICStripeLocalBindAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
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

type slowWriteOncePacketConn struct {
	net.PacketConn
	delay     time.Duration
	delayOnce sync.Once
}

func (c *slowWriteOncePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.delayOnce.Do(func() {
		time.Sleep(c.delay)
	})
	return c.PacketConn.WriteTo(p, addr)
}
