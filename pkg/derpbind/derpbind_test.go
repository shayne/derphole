package derpbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type testDERPServer struct {
	MapURL  string
	DERPURL string
	Map     *tailcfg.DERPMap
	http    *httptest.Server
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

func TestClientSubscribeLosslessDoesNotBlockDispatchWhenConsumerBacksUp(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribe()

	const total = losslessSubscriberQueueSize + 32
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
