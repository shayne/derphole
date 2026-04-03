package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/quicpath"
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

		controlStream, err := conn.AcceptStream(ctx)
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
	if session.primaryStream != nil {
		t.Fatal("fallback primaryStream is set after peer setup decode failure")
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
