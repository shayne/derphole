// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type testDERPServer struct {
	MapURL  string
	DERPURL string
	Map     *tailcfg.DERPMap
	http    *httptest.Server
	server  *derpserver.Server
}

type fakeDERPClientConn struct {
	messages chan derp.ReceivedMessage
	pongs    chan [8]byte
	closed   chan struct{}
	once     sync.Once
}

func newFakeDERPClientConn() *fakeDERPClientConn {
	return &fakeDERPClientConn{
		messages: make(chan derp.ReceivedMessage, 4),
		pongs:    make(chan [8]byte, 4),
		closed:   make(chan struct{}),
	}
}

func (f *fakeDERPClientConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeDERPClientConn) Send(key.NodePublic, []byte) error { return nil }

func (f *fakeDERPClientConn) Recv() (derp.ReceivedMessage, error) {
	select {
	case msg := <-f.messages:
		return msg, nil
	case <-f.closed:
		return nil, errors.New("closed")
	}
}

func (f *fakeDERPClientConn) SendPong(data [8]byte) error {
	select {
	case f.pongs <- data:
	case <-f.closed:
	}
	return nil
}

func newTestDERPServer(t *testing.T) *testDERPServer {
	t.Helper()

	server := derpserver.New(key.NewNode(), t.Logf)
	t.Cleanup(func() {
		_ = server.Close()
	})

	derpHTTP := httptest.NewServer(derpserver.Handler(server))
	t.Cleanup(derpHTTP.Close)

	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "test-1",
						RegionID: 1,
						HostName: "127.0.0.1",
						IPv4:     "127.0.0.1",
						STUNPort: -1,
						DERPPort: 0,
					},
				},
			},
		},
	}

	mapHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(dm)
	}))
	t.Cleanup(mapHTTP.Close)

	return &testDERPServer{
		MapURL:  mapHTTP.URL,
		DERPURL: derpHTTP.URL + "/derp",
		Map:     dm,
		http:    derpHTTP,
		server:  server,
	}
}

func TestFetchMapParsesDERPMapJSON(t *testing.T) {
	srv := newTestDERPServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dm, err := FetchMap(ctx, srv.MapURL)
	if err != nil {
		t.Fatalf("FetchMap() error = %v", err)
	}
	if got := len(dm.Regions); got != 1 {
		t.Fatalf("len(Regions) = %d, want 1", got)
	}
	region := dm.Regions[1]
	if region == nil {
		t.Fatal("Regions[1] is nil, want region")
	}
	if region.RegionCode != "test" {
		t.Fatalf("RegionCode = %q, want %q", region.RegionCode, "test")
	}
	if got := region.Nodes[0].HostName; got != "127.0.0.1" {
		t.Fatalf("HostName = %q, want 127.0.0.1", got)
	}
}

func TestFetchMapUsesStaticFallbackForPublicDERPMap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dm, err := FetchMap(ctx, PublicDERPMapURL)
	if err != nil {
		t.Fatalf("FetchMap() error = %v", err)
	}
	if dm == nil {
		t.Fatal("FetchMap() = nil, want static DERP map")
	}
	if len(dm.Regions) == 0 {
		t.Fatal("len(Regions) = 0, want static DERP regions")
	}
}

func TestClientReceiveTimeoutDoesNotKillSession(t *testing.T) {
	srv := newTestDERPServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a, err := NewClient(ctx, srv.Map.Regions[1].Nodes[0], srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(a) error = %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	b, err := NewClient(ctx, srv.Map.Regions[1].Nodes[0], srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(b) error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer timeoutCancel()
	if _, err := b.Receive(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive(timeout) error = %v, want deadline exceeded", err)
	}

	payload := []byte("still alive")
	if err := a.Send(ctx, b.PublicKey(), payload); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	got, err := b.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() after timeout error = %v", err)
	}
	if got.From != a.PublicKey() {
		t.Fatalf("Receive().From = %v, want %v", got.From, a.PublicKey())
	}
	if string(got.Payload) != string(payload) {
		t.Fatalf("Receive().Payload = %q, want %q", got.Payload, payload)
	}
}

func TestClientRecoversAfterTransientTransportDisconnect(t *testing.T) {
	srv := newTestDERPServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a, err := NewClient(ctx, srv.Map.Regions[1].Nodes[0], srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(a) error = %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	b, err := NewClient(ctx, srv.Map.Regions[1].Nodes[0], srv.DERPURL)
	if err != nil {
		t.Fatalf("NewClient(b) error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	srv.http.CloseClientConnections()
	time.Sleep(50 * time.Millisecond)

	payload := []byte("reconnected packet")
	if err := a.Send(ctx, b.PublicKey(), payload); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	got, err := b.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() after reconnect error = %v", err)
	}
	if got.From != a.PublicKey() {
		t.Fatalf("Receive().From = %v, want %v", got.From, a.PublicKey())
	}
	if string(got.Payload) != string(payload) {
		t.Fatalf("Receive().Payload = %q, want %q", got.Payload, payload)
	}
}

func TestClientsExchangePacketAndReconnectThroughHTTPProxy(t *testing.T) {
	srv := newTestDERPServer(t)
	derpTarget := strings.TrimPrefix(srv.DERPURL, "http://")
	derpTarget = strings.TrimSuffix(derpTarget, "/derp")
	proxy := newForwardingConnectProxy(t, derpTarget)
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	oldProxyFromEnvironment := derpProxyFromEnvironment
	derpProxyFromEnvironment = func(*url.URL) (*url.URL, error) {
		return proxyURL, nil
	}
	t.Cleanup(func() { derpProxyFromEnvironment = oldProxyFromEnvironment })

	node := *srv.Map.Regions[1].Nodes[0]
	node.HostName = "derp.proxy-test.invalid"
	node.IPv4 = "192.0.2.1"
	serverURL := "http://derp.proxy-test.invalid/derp"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	a, err := NewClient(ctx, &node, serverURL)
	if err != nil {
		t.Fatalf("NewClient(a) error = %v", err)
	}
	defer a.Close()
	b, err := NewClient(ctx, &node, serverURL)
	if err != nil {
		t.Fatalf("NewClient(b) error = %v", err)
	}
	defer b.Close()
	waitForTestDERPClient(t, ctx, srv.server, a.PublicKey())
	waitForTestDERPClient(t, ctx, srv.server, b.PublicKey())

	payload := []byte("proxied DERP packet")
	if err := a.Send(ctx, b.PublicKey(), payload); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	got, err := b.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, payload)
	}
	if proxy.ConnectCount() != 2 {
		t.Fatalf("CONNECT count = %d, want 2", proxy.ConnectCount())
	}
	if info, ok := a.ProxyInfo(); !ok || info.TargetAddr != "derp.proxy-test.invalid:80" {
		t.Fatalf("ProxyInfo = %#v, %v", info, ok)
	}

	connectsBeforeReconnect := proxy.ConnectCount()
	srv.http.CloseClientConnections()
	proxy.CloseConnections()
	time.Sleep(50 * time.Millisecond)
	second := []byte("proxied after reconnect")
	if err := a.Send(ctx, b.PublicKey(), second); err != nil {
		t.Fatalf("Send() after disconnect error = %v", err)
	}
	got, err = b.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() after disconnect error = %v", err)
	}
	if !bytes.Equal(got.Payload, second) {
		t.Fatalf("reconnected payload = %q, want %q", got.Payload, second)
	}
	if proxy.ConnectCount() <= connectsBeforeReconnect {
		t.Fatalf("CONNECT count did not increase across reconnect: before=%d after=%d", connectsBeforeReconnect, proxy.ConnectCount())
	}
}

func waitForTestDERPClient(t *testing.T, ctx context.Context, server *derpserver.Server, clientKey key.NodePublic) {
	t.Helper()
	for !server.IsClientConnectedForTest(clientKey) {
		select {
		case <-ctx.Done():
			t.Fatalf("DERP client %v was not registered: %v", clientKey, ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestCanonicalDERPTarget(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "https default port", rawURL: "https://derp.example/derp", want: "derp.example:443"},
		{name: "http default port", rawURL: "http://derp.example/derp", want: "derp.example:80"},
		{name: "explicit port", rawURL: "https://derp.example:8443/derp", want: "derp.example:8443"},
		{name: "unsupported scheme", rawURL: "ftp://derp.example:21/derp", wantErr: true},
		{name: "missing hostname", rawURL: "https:///derp", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derpURL, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalDERPTarget(derpURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("canonicalDERPTarget() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("canonicalDERPTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientRecvLoopRepliesToDERPPing(t *testing.T) {
	fake := newFakeDERPClientConn()
	c := &Client{
		dc:          fake,
		packetCh:    make(chan Packet, 16),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}
	go c.recvLoop()
	t.Cleanup(func() { _ = c.Close() })

	ping := derp.PingMessage{1, 2, 3, 4, 5, 6, 7, 8}
	fake.messages <- ping

	select {
	case got := <-fake.pongs:
		if got != [8]byte(ping) {
			t.Fatalf("SendPong payload = %v, want %v", got, [8]byte(ping))
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("recvLoop did not reply to DERP ping")
	}

	src := key.NewNode().Public()
	payload := []byte("after-ping")
	fake.messages <- derp.ReceivedPacket{Source: src, Data: payload}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := c.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive() after ping error = %v", err)
	}
	if got.From != src {
		t.Fatalf("Receive().From = %v, want %v", got.From, src)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("Receive().Payload = %q, want %q", got.Payload, payload)
	}
}

func TestClientRecvLoopFullFallbackQueueDoesNotBlockSubscribers(t *testing.T) {
	fake := newFakeDERPClientConn()
	c := &Client{
		dc:          fake,
		packetCh:    make(chan Packet, 1),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}
	go c.recvLoop()
	t.Cleanup(func() { _ = c.Close() })

	unmatchedSrc := key.NewNode().Public()
	fake.messages <- derp.ReceivedPacket{Source: unmatchedSrc, Data: []byte("stale-1")}
	deadline := time.Now().Add(time.Second)
	for len(c.packetCh) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(c.packetCh) == 0 {
		t.Fatal("fallback packet queue did not fill")
	}

	fake.messages <- derp.ReceivedPacket{Source: unmatchedSrc, Data: []byte("stale-2")}

	wantPayload := []byte("claim-after-stale")
	subCh, unsubscribe := c.SubscribeLossless(func(pkt Packet) bool {
		return bytes.Equal(pkt.Payload, wantPayload)
	})
	defer unsubscribe()

	matchSrc := key.NewNode().Public()
	fake.messages <- derp.ReceivedPacket{Source: matchSrc, Data: wantPayload}

	select {
	case pkt := <-subCh:
		if pkt.From != matchSrc {
			t.Fatalf("subscriber From = %v, want %v", pkt.From, matchSrc)
		}
		if !bytes.Equal(pkt.Payload, wantPayload) {
			t.Fatalf("subscriber payload = %q, want %q", pkt.Payload, wantPayload)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("subscriber did not receive matching packet after fallback queue filled")
	}
}

func TestClientSubscribeInterceptsMatchingPackets(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}
	controlPayload := []byte(`{"type":"control"}`)
	controlCh, unsubscribe := c.Subscribe(func(pkt Packet) bool {
		return bytes.Equal(pkt.Payload, controlPayload)
	})
	defer unsubscribe()

	controlPacket := Packet{
		From:    key.NewNode().Public(),
		Payload: controlPayload,
	}
	if !c.dispatchSubscriber(controlPacket) {
		t.Fatal("dispatchSubscriber(control) = false, want true")
	}

	select {
	case pkt := <-controlCh:
		if pkt.From != controlPacket.From {
			t.Fatalf("control packet From = %v, want %v", pkt.From, controlPacket.From)
		}
		if !bytes.Equal(pkt.Payload, controlPayload) {
			t.Fatalf("control packet payload = %q, want %q", pkt.Payload, controlPayload)
		}
	default:
		t.Fatal("subscribed control packet was not delivered")
	}

	if c.dispatchSubscriber(Packet{Payload: []byte("wireguard-bytes")}) {
		t.Fatal("dispatchSubscriber(data) = true, want false")
	}
}

func TestClientDispatchSubscriberDeliversToAllMatchingSubscribers(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	firstCh, unsubscribeFirst := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribeFirst()
	secondCh, unsubscribeSecond := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribeSecond()

	payload := []byte("fanout")
	if !c.dispatchSubscriber(Packet{From: key.NewNode().Public(), Payload: payload}) {
		t.Fatal("dispatchSubscriber() = false, want true")
	}

	for name, ch := range map[string]<-chan Packet{
		"first":  firstCh,
		"second": secondCh,
	} {
		select {
		case pkt := <-ch:
			if !bytes.Equal(pkt.Payload, payload) {
				t.Fatalf("%s subscriber payload = %q, want %q", name, pkt.Payload, payload)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("%s subscriber did not receive matching packet", name)
		}
	}
}

func TestNewDERPNodeDialerFallsBackToIPv4WhenIPv6TargetFails(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp4) error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	node := &tailcfg.DERPNode{
		HostName: "derp.example.test",
		IPv4:     "127.0.0.1",
		IPv6:     "2001:db8::1",
	}
	oldProxyFromEnvironment := derpProxyFromEnvironment
	derpProxyFromEnvironment = func(*url.URL) (*url.URL, error) { return nil, nil }
	t.Cleanup(func() { derpProxyFromEnvironment = oldProxyFromEnvironment })
	dialer := newDERPNodeDialer(node, &url.URL{Scheme: "https", Host: node.HostName}, &proxyInfoRecorder{}, t.Logf, netmon.NewStatic())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialer(ctx, "tcp", net.JoinHostPort(node.HostName, portString(t, ln.Addr())))
	if err != nil {
		t.Fatalf("dialer() error = %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("dialer() did not reach IPv4 listener")
	}
}

func TestNewDERPNodeDialerUsesOverrideHostInsteadOfNodeIPs(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp4) error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	node := &tailcfg.DERPNode{
		HostName: "derp.example.test",
		IPv4:     "203.0.113.10",
		IPv6:     "2001:db8::1",
	}
	oldProxyFromEnvironment := derpProxyFromEnvironment
	derpProxyFromEnvironment = func(*url.URL) (*url.URL, error) { return nil, nil }
	t.Cleanup(func() { derpProxyFromEnvironment = oldProxyFromEnvironment })
	dialer := newDERPNodeDialer(node, &url.URL{Scheme: "https", Host: node.HostName}, &proxyInfoRecorder{}, t.Logf, netmon.NewStatic())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialer(ctx, "tcp", net.JoinHostPort("127.0.0.1", portString(t, ln.Addr())))
	if err != nil {
		t.Fatalf("dialer() with override host error = %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("dialer() did not reach override host listener")
	}
}

func TestRaceDERPDialDoesNotReturnFirstFailedTarget(t *testing.T) {
	restore := stubDERPDial(t, func(ctx context.Context, _ logger.Logf, _ *netmon.Monitor, network, _ string) (net.Conn, error) {
		if network == "tcp6" {
			return nil, errors.New("network unreachable")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		local, remote := net.Pipe()
		go remote.Close()
		return local, nil
	})
	defer restore()

	conn, err := raceDERPDial(context.Background(), t.Logf, netmon.NewStatic(), []derpDialTarget{
		derpDialTargetFor("tcp6", "2001:db8::1", "443"),
		derpDialTargetFor("tcp4", "127.0.0.1", "443"),
	})
	if err != nil {
		t.Fatalf("raceDERPDial() error = %v", err)
	}
	_ = conn.Close()
}

func TestRaceDERPDialReportsPendingTargetsOnTimeout(t *testing.T) {
	dialExited := make(chan struct{})
	restore := stubDERPDial(t, func(ctx context.Context, _ logger.Logf, _ *netmon.Monitor, network, _ string) (net.Conn, error) {
		if network == "tcp6" {
			return nil, errors.New("network unreachable")
		}
		defer close(dialExited)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	defer restore()

	prevTimeout := derpDialTimeout
	derpDialTimeout = 10 * time.Millisecond
	defer func() { derpDialTimeout = prevTimeout }()

	_, err := raceDERPDial(context.Background(), t.Logf, netmon.NewStatic(), []derpDialTarget{
		derpDialTargetFor("tcp6", "2001:db8::1", "443"),
		derpDialTargetFor("tcp4", "203.0.113.10", "443"),
	})
	if err == nil {
		t.Fatal("raceDERPDial() error = nil, want joined target errors")
	}
	msg := err.Error()
	for _, want := range []string{
		"dial tcp6 [2001:db8::1]:443: network unreachable",
		"dial tcp4 203.0.113.10:443: context deadline exceeded",
	} {
		if !bytes.Contains([]byte(msg), []byte(want)) {
			t.Fatalf("raceDERPDial() error = %q, want substring %q", msg, want)
		}
	}
	select {
	case <-dialExited:
	case <-time.After(time.Second):
		t.Fatal("pending DERP dial did not exit after timeout")
	}
}

func stubDERPDial(t *testing.T, fn func(context.Context, logger.Logf, *netmon.Monitor, string, string) (net.Conn, error)) func() {
	t.Helper()
	prev := derpDialContext
	derpDialContext = fn
	return func() {
		derpDialContext = prev
	}
}

func portString(t *testing.T, addr net.Addr) string {
	t.Helper()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr = %T, want *net.TCPAddr", addr)
	}
	return strconv.Itoa(tcpAddr.Port)
}

func TestClientSubscribeDropsOldestWhenSubscriberBackedUp(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.Subscribe(func(Packet) bool { return true })
	defer unsubscribe()

	for i := 0; i < cap(controlCh); i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
			t.Fatalf("dispatchSubscriber(prefill %d) = false, want true", i)
		}
	}

	done := make(chan bool, 1)
	latest := Packet{Payload: []byte("latest")}
	go func() {
		done <- c.dispatchSubscriber(latest)
	}()

	select {
	case handled := <-done:
		if !handled {
			t.Fatal("dispatchSubscriber(latest) = false, want true")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("dispatchSubscriber(latest) blocked on full subscriber")
	}

	var gotLatest bool
	for i := 0; i < cap(controlCh); i++ {
		pkt := <-controlCh
		if bytes.Equal(pkt.Payload, latest.Payload) {
			gotLatest = true
		}
	}
	if !gotLatest {
		t.Fatalf("subscriber queue did not retain latest packet %q", latest.Payload)
	}
}

func TestClientSubscribeLosslessRetainsAllBackedUpPackets(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribe()

	const total = 64
	for i := 0; i < total; i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
			t.Fatalf("dispatchSubscriber(%d) = false, want true", i)
		}
	}

	got := make([]byte, 0, total)
	for i := 0; i < total; i++ {
		select {
		case pkt := <-controlCh:
			got = append(got, pkt.Payload...)
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}

	for i := 0; i < total; i++ {
		if got[i] != byte(i) {
			t.Fatalf("got packet sequence %v, want ordered 0..%d", got, total-1)
		}
	}
}

func TestClientSubscribeLosslessBlocksWhenQueueFull(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribe()

	for i := 0; i < cap(controlCh); i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
			t.Fatalf("dispatchSubscriber(channel-fill %d) = false, want true", i)
		}
	}
	for i := 0; i < losslessSubscriberQueueSize; i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i + cap(controlCh))}}) {
			t.Fatalf("dispatchSubscriber(queue-fill %d) = false, want true", i)
		}
	}

	done := make(chan bool, 1)
	go func() {
		done <- c.dispatchSubscriber(Packet{Payload: []byte("blocked")})
	}()

	select {
	case handled := <-done:
		t.Fatalf("dispatchSubscriber past hard limit returned %v, want blocked", handled)
	case <-time.After(50 * time.Millisecond):
	}

	<-controlCh

	select {
	case handled := <-done:
		if !handled {
			t.Fatal("dispatchSubscriber after drain = false, want true")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dispatchSubscriber did not unblock after drain")
	}
}

func TestClientSubscribeLosslessUnsubscribeReleasesBlockedDispatch(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	for i := 0; i < cap(controlCh); i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
			t.Fatalf("dispatchSubscriber(channel-fill %d) = false, want true", i)
		}
	}
	for i := 0; i < losslessSubscriberQueueSize; i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i + cap(controlCh))}}) {
			t.Fatalf("dispatchSubscriber(queue-fill %d) = false, want true", i)
		}
	}

	done := make(chan bool, 1)
	go func() {
		done <- c.dispatchSubscriber(Packet{Payload: []byte("blocked")})
	}()

	select {
	case handled := <-done:
		t.Fatalf("dispatchSubscriber past hard limit returned %v, want blocked", handled)
	case <-time.After(50 * time.Millisecond):
	}

	unsubscribe()

	select {
	case handled := <-done:
		if handled {
			t.Fatal("dispatchSubscriber after unsubscribe = true, want false")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dispatchSubscriber did not unblock after unsubscribe")
	}
}

func TestClientSubscribeLosslessDoesNotBlockBeforeHardLimit(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribe()

	const total = losslessSubscriberQueueSize
	done := make(chan bool, 1)
	go func() {
		handled := true
		for i := 0; i < total; i++ {
			if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
				handled = false
				break
			}
		}
		done <- handled
	}()

	select {
	case handled := <-done:
		if !handled {
			t.Fatal("dispatchSubscriber() = false, want true for all queued packets")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("dispatchSubscriber() blocked behind backed-up lossless subscriber")
	}

	got := make([]byte, 0, total)
	for i := 0; i < total; i++ {
		select {
		case pkt := <-controlCh:
			got = append(got, pkt.Payload...)
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}

	for i := 0; i < total; i++ {
		if got[i] != byte(i) {
			t.Fatalf("got packet sequence %v, want ordered 0..%d", got, total-1)
		}
	}
}

func TestClientSubscribeUnsubscribeWhileDispatchingDoesNotPanic(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	for i := 0; i < 200; i++ {
		controlCh, unsubscribe := c.Subscribe(func(Packet) bool { return true })

		var wg sync.WaitGroup
		wg.Add(2)
		go func(iteration int) {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				c.dispatchSubscriber(Packet{Payload: []byte{byte(iteration), byte(j)}})
			}
		}(i)
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			unsubscribe()
		}()
		wg.Wait()

		select {
		case _, ok := <-controlCh:
			if ok {
				for {
					select {
					case _, ok := <-controlCh:
						if !ok {
							goto closed
						}
					case <-time.After(100 * time.Millisecond):
						t.Fatal("subscriber channel remained open after unsubscribe")
					}
				}
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timed out waiting for unsubscribe to close subscriber channel")
		}
	closed:
	}
}
