package session

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/shayne/derpcat/pkg/transport"
)

func TestRequestExternalQUICModeSendsRequestBeforeLocalDirectIsReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer senderDERP.Close()

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerDERP.Close()
	warmExternalQUICModeTestDERPRoute(t, ctx, senderDERP, listenerDERP)

	senderPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderPacketConn.Close()

	peerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peerPacketConn.Close()

	manager := transport.NewManager(transport.ManagerConfig{
		RelayAddr:          relayTransportAddr(),
		DirectConn:         senderPacketConn,
		DiscoveryInterval:  50 * time.Millisecond,
		DirectStaleTimeout: 1 * time.Second,
	})
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		manager.Wait()
	}()

	go func() {
		buf := make([]byte, 64)
		for {
			_ = peerPacketConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, addr, err := peerPacketConn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			_, _ = peerPacketConn.WriteTo([]byte("derpcat-ack"), addr)
		}
	}()

	modeCh, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeRequestPayload(pkt.Payload)
	})
	defer unsubscribe()
	modeAckCh, unsubscribeAck := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()

	listenerDone := make(chan error, 1)
	go func() {
		req, err := receiveQUICModeRequest(ctx, modeCh)
		if err != nil {
			listenerDone <- err
			return
		}
		if !req.NativeDirect {
			listenerDone <- context.Canceled
			return
		}
		manager.SeedRemoteCandidates(ctx, []net.Addr{cloneSessionAddr(peerPacketConn.LocalAddr())})
		if err := sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type:         envelopeQUICModeResp,
			QUICModeResp: &quicModeResponse{NativeDirect: true},
		}); err != nil {
			listenerDone <- err
			return
		}
		if _, err := receiveQUICModeAck(ctx, modeAckCh); err != nil {
			listenerDone <- err
			return
		}
		listenerDone <- sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type:          envelopeQUICModeReady,
			QUICModeReady: &quicModeReady{NativeDirect: true},
		})
	}()

	nativeQUIC, nativeTCPConns, addr, err := requestExternalQUICMode(ctx, senderDERP, listenerDERP.PublicKey(), manager, nil, nil, nil, nil, externalNativeTCPAuth{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeQUIC {
		select {
		case listenerErr := <-listenerDone:
			t.Fatalf("requestExternalQUICMode() nativeQUIC = false, want true; listenerDone=%v", listenerErr)
		default:
			t.Fatal("requestExternalQUICMode() nativeQUIC = false, want true; listenerDone pending")
		}
	}
	if addr == nil || addr.String() != peerPacketConn.LocalAddr().String() {
		t.Fatalf("requestExternalQUICMode() addr = %v, want %v", addr, peerPacketConn.LocalAddr())
	}
	if len(nativeTCPConns) > 0 {
		closeExternalNativeTCPConns(nativeTCPConns)
		t.Fatal("requestExternalQUICMode() nativeTCPConns != nil, want nil")
	}
	if err := <-listenerDone; err != nil {
		t.Fatal(err)
	}
}

func TestRequestExternalQUICModeUsesPeerResponseAddrWhenLocalDirectIsNotReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer senderDERP.Close()

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerDERP.Close()
	warmExternalQUICModeTestDERPRoute(t, ctx, senderDERP, listenerDERP)

	manager := transport.NewManager(transport.ManagerConfig{
		RelayAddr: relayTransportAddr(),
	})
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		manager.Wait()
	}()

	modeCh, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeRequestPayload(pkt.Payload)
	})
	defer unsubscribe()
	modeAckCh, unsubscribeAck := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()

	wantAddr := "127.0.0.1:54321"
	listenerDone := make(chan error, 1)
	go func() {
		if _, err := receiveQUICModeRequest(ctx, modeCh); err != nil {
			listenerDone <- err
			return
		}
		if err := sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type: envelopeQUICModeResp,
			QUICModeResp: &quicModeResponse{
				NativeDirect: true,
				DirectAddr:   wantAddr,
			},
		}); err != nil {
			listenerDone <- err
			return
		}
		if _, err := receiveQUICModeAck(ctx, modeAckCh); err != nil {
			listenerDone <- err
			return
		}
		listenerDone <- sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type:          envelopeQUICModeReady,
			QUICModeReady: &quicModeReady{NativeDirect: true},
		})
	}()

	nativeQUIC, nativeTCPConns, addr, err := requestExternalQUICMode(ctx, senderDERP, listenerDERP.PublicKey(), manager, nil, nil, nil, nil, externalNativeTCPAuth{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeQUIC {
		select {
		case listenerErr := <-listenerDone:
			t.Fatalf("requestExternalQUICMode() nativeQUIC = false, want true; listenerDone=%v", listenerErr)
		default:
			t.Fatal("requestExternalQUICMode() nativeQUIC = false, want true; listenerDone pending")
		}
	}
	if addr == nil || addr.String() != wantAddr {
		t.Fatalf("requestExternalQUICMode() addr = %v, want %s", addr, wantAddr)
	}
	if len(nativeTCPConns) > 0 {
		closeExternalNativeTCPConns(nativeTCPConns)
		t.Fatal("requestExternalQUICMode() nativeTCPConns != nil, want nil")
	}
	if err := <-listenerDone; err != nil {
		t.Fatal(err)
	}
}

func TestRequestExternalQUICModeWaitsForListenerReadyBeforeReturningNativeQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer senderDERP.Close()

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerDERP.Close()
	warmExternalQUICModeTestDERPRoute(t, ctx, senderDERP, listenerDERP)

	manager := transport.NewManager(transport.ManagerConfig{RelayAddr: relayTransportAddr()})
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		manager.Wait()
	}()

	modeCh, unsubscribeMode := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeRequestPayload(pkt.Payload)
	})
	defer unsubscribeMode()
	modeAckCh, unsubscribeAck := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeAckPayload(pkt.Payload)
	})
	defer unsubscribeAck()

	listenerDone := make(chan error, 1)
	go func() {
		if _, err := receiveQUICModeRequest(ctx, modeCh); err != nil {
			listenerDone <- err
			return
		}
		if err := sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type: envelopeQUICModeResp,
			QUICModeResp: &quicModeResponse{
				NativeDirect: true,
				DirectAddr:   "127.0.0.1:54321",
			},
		}); err != nil {
			listenerDone <- err
			return
		}
		if _, err := receiveQUICModeAck(ctx, modeAckCh); err != nil {
			listenerDone <- err
			return
		}
		time.Sleep(200 * time.Millisecond)
		listenerDone <- sendEnvelope(ctx, listenerDERP, senderDERP.PublicKey(), envelope{
			Type:          envelopeQUICModeReady,
			QUICModeReady: &quicModeReady{NativeDirect: true},
		})
	}()

	start := time.Now()
	nativeQUIC, nativeTCPConns, addr, err := requestExternalQUICMode(
		ctx,
		senderDERP,
		listenerDERP.PublicKey(),
		manager,
		nil,
		nil,
		nil,
		nil,
		externalNativeTCPAuth{},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("requestExternalQUICMode() returned after %v, want it to wait for listener native-QUIC ready", elapsed)
	}
	if !nativeQUIC {
		t.Fatal("requestExternalQUICMode() nativeQUIC = false, want true")
	}
	if len(nativeTCPConns) > 0 {
		closeExternalNativeTCPConns(nativeTCPConns)
		t.Fatal("requestExternalQUICMode() nativeTCPConns != nil, want nil")
	}
	if addr == nil || addr.String() != "127.0.0.1:54321" {
		t.Fatalf("requestExternalQUICMode() addr = %v, want 127.0.0.1:54321", addr)
	}
	if err := <-listenerDone; err != nil {
		t.Fatal(err)
	}
}

func TestExternalQUICModeNegotiationUsesListenerResponseAddrWithoutSplitBrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer senderDERP.Close()

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerDERP.Close()
	warmExternalQUICModeTestDERPRoute(t, ctx, senderDERP, listenerDERP)

	listenerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerPacketConn.Close()

	peerPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peerPacketConn.Close()

	senderManager := transport.NewManager(transport.ManagerConfig{
		RelayAddr: relayTransportAddr(),
	})
	if err := senderManager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		senderManager.Wait()
	}()

	listenerManager := transport.NewManager(transport.ManagerConfig{
		RelayAddr:          relayTransportAddr(),
		DirectConn:         listenerPacketConn,
		DiscoveryInterval:  50 * time.Millisecond,
		DirectStaleTimeout: time.Second,
	})
	if err := listenerManager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer listenerManager.Wait()

	go func() {
		buf := make([]byte, 64)
		for {
			_ = peerPacketConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, addr, err := peerPacketConn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			_, _ = peerPacketConn.WriteTo([]byte("derpcat-ack"), addr)
		}
	}()

	listenerManager.SeedRemoteCandidates(ctx, []net.Addr{cloneSessionAddr(peerPacketConn.LocalAddr())})

	modeCh, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeRequestPayload(pkt.Payload)
	})
	defer unsubscribe()

	listenerDone := make(chan struct {
		nativeQUIC bool
		addr       net.Addr
		err        error
	}, 1)
	go func() {
		nativeQUIC, nativeTCPConns, addr, err := acceptExternalQUICMode(
			ctx,
			listenerDERP,
			modeCh,
			senderDERP.PublicKey(),
			listenerManager,
			[]net.Addr{cloneSessionAddr(listenerPacketConn.LocalAddr())},
			false,
			nil,
			nil,
			nil,
			externalNativeTCPAuth{},
		)
		closeExternalNativeTCPConns(nativeTCPConns)
		listenerDone <- struct {
			nativeQUIC bool
			addr       net.Addr
			err        error
		}{nativeQUIC: nativeQUIC, addr: addr, err: err}
	}()

	nativeQUIC, nativeTCPConns, addr, err := requestExternalQUICMode(ctx, senderDERP, listenerDERP.PublicKey(), senderManager, nil, nil, nil, nil, externalNativeTCPAuth{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !nativeQUIC {
		t.Fatal("requestExternalQUICMode() nativeQUIC = false, want true")
	}
	if len(nativeTCPConns) > 0 {
		closeExternalNativeTCPConns(nativeTCPConns)
		t.Fatal("requestExternalQUICMode() nativeTCPConns != nil, want nil")
	}
	if addr == nil || addr.String() != listenerPacketConn.LocalAddr().String() {
		t.Fatalf("requestExternalQUICMode() addr = %v, want %v", addr, listenerPacketConn.LocalAddr())
	}

	select {
	case got := <-listenerDone:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.nativeQUIC {
			t.Fatalf("acceptExternalQUICMode() nativeQUIC = false, want true; senderNative=%v senderAddr=%v", nativeQUIC, addr)
		}
		if got.addr == nil || got.addr.String() != peerPacketConn.LocalAddr().String() {
			t.Fatalf("acceptExternalQUICMode() addr = %v, want peer addr %v", got.addr, peerPacketConn.LocalAddr())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestExternalQUICModeNegotiationUsesRouteLocalNativeTCPBeforeUDPDirectPromotion(t *testing.T) {
	t.Setenv("DERPCAT_NATIVE_TCP_CONNS", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	srv := newSessionTestDERPServer(t)
	node := firstDERPNode(srv.Map, 1)

	senderDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer senderDERP.Close()

	listenerDERP, err := derpbind.NewClient(ctx, node, srv.DERPURL)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerDERP.Close()
	warmExternalQUICModeTestDERPRoute(t, ctx, senderDERP, listenerDERP)

	senderCandidateConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer senderCandidateConn.Close()

	listenerCandidateConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listenerCandidateConn.Close()

	senderManager := transport.NewManager(transport.ManagerConfig{
		RelayAddr: relayTransportAddr(),
	})
	if err := senderManager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		senderManager.Wait()
	}()

	listenerManager := transport.NewManager(transport.ManagerConfig{
		RelayAddr: relayTransportAddr(),
	})
	if err := listenerManager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer listenerManager.Wait()

	modeCh, unsubscribe := listenerDERP.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == senderDERP.PublicKey() && isQUICModeRequestPayload(pkt.Payload)
	})
	defer unsubscribe()

	listenerDone := make(chan struct {
		nativeQUIC bool
		conns      []net.Conn
		err        error
	}, 1)
	go func() {
		nativeQUIC, nativeTCPConns, _, err := acceptExternalQUICMode(
			ctx,
			listenerDERP,
			modeCh,
			senderDERP.PublicKey(),
			listenerManager,
			[]net.Addr{cloneSessionAddr(listenerCandidateConn.LocalAddr())},
			false,
			nil,
			nil,
			nil,
			externalNativeTCPAuth{},
		)
		listenerDone <- struct {
			nativeQUIC bool
			conns      []net.Conn
			err        error
		}{nativeQUIC: nativeQUIC, conns: nativeTCPConns, err: err}
	}()

	nativeQUIC, nativeTCPConns, addr, err := requestExternalQUICMode(
		ctx,
		senderDERP,
		listenerDERP.PublicKey(),
		senderManager,
		[]net.Addr{cloneSessionAddr(senderCandidateConn.LocalAddr())},
		nil,
		nil,
		nil,
		externalNativeTCPAuth{},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExternalNativeTCPConns(nativeTCPConns)

	if nativeQUIC {
		t.Fatal("requestExternalQUICMode() nativeQUIC = true, want false before UDP direct promotion")
	}
	if addr != nil {
		t.Fatalf("requestExternalQUICMode() addr = %v, want nil before UDP direct promotion", addr)
	}
	if len(nativeTCPConns) != 1 {
		t.Fatalf("requestExternalQUICMode() nativeTCPConns len = %d, want 1", len(nativeTCPConns))
	}

	var listenerResult struct {
		nativeQUIC bool
		conns      []net.Conn
		err        error
	}
	select {
	case listenerResult = <-listenerDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if listenerResult.err != nil {
		t.Fatal(listenerResult.err)
	}
	defer closeExternalNativeTCPConns(listenerResult.conns)

	if listenerResult.nativeQUIC {
		t.Fatal("acceptExternalQUICMode() nativeQUIC = true, want false before UDP direct promotion")
	}
	if len(listenerResult.conns) != 1 {
		t.Fatalf("acceptExternalQUICMode() nativeTCPConns len = %d, want 1", len(listenerResult.conns))
	}

	if _, err := nativeTCPConns[0].Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := io.ReadFull(listenerResult.conns[0], got[:]); err != nil {
		t.Fatal(err)
	}
	if got[0] != 'x' {
		t.Fatalf("listener received %q, want %q", got[0], 'x')
	}
}

func warmExternalQUICModeTestDERPRoute(t *testing.T, ctx context.Context, senderDERP, listenerDERP *derpbind.Client) {
	t.Helper()

	warmCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()

		for {
			_ = sendEnvelope(warmCtx, senderDERP, listenerDERP.PublicKey(), envelope{Type: envelopeAck})
			select {
			case <-ticker.C:
			case <-warmCtx.Done():
				return
			}
		}
	}()
	pkt, err := listenerDERP.Receive(warmCtx)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if pkt.From != senderDERP.PublicKey() {
		t.Fatalf("warmup DERP packet source = %v, want %v", pkt.From, senderDERP.PublicKey())
	}
	if !isAckPayload(pkt.Payload) {
		t.Fatalf("warmup DERP packet payload = %q, want ack envelope", pkt.Payload)
	}
}
