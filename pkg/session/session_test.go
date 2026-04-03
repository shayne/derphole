package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/portmap"
	"github.com/shayne/derpcat/pkg/quicpath"
	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/transport"
	"go4.org/mem"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDERPPublicKeyRaw32RoundTrip(t *testing.T) {
	want := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	pub := key.NodePublicFromRaw32(mem.B(want[:]))
	if got := derpPublicKeyRaw32(pub); got != want {
		t.Fatalf("derpPublicKeyRaw32() = %x, want %x", got, want)
	}
}

func TestRelayOnlyStdioRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var senderIn bytes.Buffer
	senderIn.WriteString("hello over derp")

	listenerReady := make(chan string, 1)
	go func() {
		token, err := Listen(ctx, ListenConfig{
			Emitter:   telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink: listenerReady,
			StdioOut:  &listenerOut,
		})
		if err != nil || token == "" {
			t.Errorf("Listen() err=%v token=%q", err, token)
		}
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:      token,
		StdioIn:    &senderIn,
		Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		ForceRelay: true,
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := listenerOut.String(); got != "hello over derp" {
		t.Fatalf("listener output = %q, want %q", got, "hello over derp")
	}
}

func TestSessionPromotesDirectStateWhenProbeSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var listenerOut syncBuffer
	var senderIn bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer
	senderIn.WriteString("hello direct")

	listenerReady := make(chan string, 1)
	go func() {
		token, err := Listen(ctx, ListenConfig{
			Emitter:   telemetry.New(&listenerStatus, telemetry.LevelDefault),
			TokenSink: listenerReady,
			StdioOut:  &listenerOut,
		})
		if err != nil || token == "" {
			t.Errorf("Listen() err=%v token=%q", err, token)
		}
	}()

	token := <-listenerReady
	if err := Send(ctx, SendConfig{
		Token:   token,
		StdioIn: &senderIn,
		Emitter: telemetry.New(&senderStatus, telemetry.LevelDefault),
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if !strings.Contains(listenerStatus.String(), string(StateDirect)) {
		t.Fatalf("listener statuses = %q, want %q", listenerStatus.String(), StateDirect)
	}
	if !strings.Contains(senderStatus.String(), string(StateDirect)) {
		t.Fatalf("sender statuses = %q, want %q", senderStatus.String(), StateDirect)
	}
	if got := listenerOut.String(); got != "hello direct" {
		t.Fatalf("listener output = %q, want %q", got, "hello direct")
	}
}

func TestShareOpenUsesEphemeralLocalBind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  tokenSink,
			TargetAddr: backendAddr,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(ctx, OpenConfig{
			Token:        tok,
			BindAddrSink: bindSink,
			Emitter:      telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		})
	}()

	bindAddr := <-bindSink
	if !strings.HasPrefix(bindAddr, "127.0.0.1:") {
		t.Fatalf("bindAddr = %q, want ephemeral localhost listener", bindAddr)
	}
	if strings.HasSuffix(bindAddr, ":0") {
		t.Fatalf("bindAddr = %q, want assigned port", bindAddr)
	}

	cancel()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestDecodeEnvelopeRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, maxEnvelopeBytes+1)
	if _, err := decodeEnvelope(payload); err == nil {
		t.Fatal("decodeEnvelope() error = nil, want invalid envelope size")
	}
}

func TestShareOpenForwardsSequentialConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	openAddr, stop, shareErr, openErr := startSharedSession(t, ctx, backendAddr, "")

	for _, payload := range []string{"alpha", "beta", "gamma"} {
		reply, err := roundTripTCP(ctx, openAddr, payload)
		if err != nil {
			t.Fatalf("roundTripTCP() error = %v", err)
		}
		if reply != payload {
			t.Fatalf("reply = %q, want %q", reply, payload)
		}
	}

	stop()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestShareOpenForwardsConcurrentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	openAddr, stop, shareErr, openErr := startSharedSession(t, ctx, backendAddr, "")

	payloads := []string{"one", "two", "three", "four", "five"}
	var wg sync.WaitGroup
	errCh := make(chan error, len(payloads))
	for _, payload := range payloads {
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			reply, err := roundTripTCP(ctx, openAddr, payload)
			if err != nil {
				errCh <- err
				return
			}
			if reply != payload {
				errCh <- errors.New("reply mismatch: payload=" + payload + " reply=" + reply)
			}
		}(payload)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	stop()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestShareTokenAllowsOneClaimer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  tokenSink,
			TargetAddr: backendAddr,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(ctx, OpenConfig{
			Token:        tok,
			BindAddrSink: bindSink,
			Emitter:      telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		})
	}()
	<-bindSink

	err := Open(ctx, OpenConfig{
		Token:   tok,
		Emitter: telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
	})
	if !errors.Is(err, ErrSessionClaimed) {
		t.Fatalf("Open() error = %v, want %v", err, ErrSessionClaimed)
	}

	cancel()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)
	backendDone()
}

func TestShareOpenExternalAllowsOneClaimerUnderContention(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	defer backendDone()

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			TargetAddr:    backendAddr,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	firstOpenErr := make(chan error, 1)
	go func() {
		firstOpenErr <- Open(ctx, OpenConfig{
			Token:         tok,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	openAddr := <-bindSink
	reply, err := roundTripTCP(ctx, openAddr, "claimed")
	if err != nil {
		t.Fatalf("roundTripTCP() error = %v", err)
	}
	if reply != "claimed" {
		t.Fatalf("reply = %q, want %q", reply, "claimed")
	}

	const contenders = 18
	errCh := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			secondCtx, secondCancel := context.WithTimeout(ctx, 15*time.Second)
			defer secondCancel()
			errCh <- Open(secondCtx, OpenConfig{
				Token:         tok,
				Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
				ForceRelay:    true,
				UsePublicDERP: true,
			})
		}()
	}

	for i := 0; i < contenders; i++ {
		err := <-errCh
		if err == nil {
			t.Fatal("contending Open() error = nil, want rejection")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contending Open() error = %v, want deterministic rejection", err)
		}
		if !strings.Contains(err.Error(), "session already claimed") {
			t.Fatalf("contending Open() error = %v, want session already claimed", err)
		}
	}

	cancel()
	waitNoErr(t, <-firstOpenErr)
	waitNoErr(t, <-shareErr)
}

func TestShareOpenExternalClaimPressureDoesNotStallAcceptedRelaySession(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	defer backendDone()

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     tokenSink,
			TargetAddr:    backendAddr,
			ForceRelay:    true,
			UsePublicDERP: true,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	firstOpenErr := make(chan error, 1)
	go func() {
		firstOpenErr <- Open(ctx, OpenConfig{
			Token:         tok,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			ForceRelay:    true,
			UsePublicDERP: true,
		})
	}()

	openAddr := <-bindSink
	if reply, err := roundTripTCP(ctx, openAddr, "accepted-before-pressure"); err != nil {
		t.Fatalf("initial roundTripTCP() error = %v", err)
	} else if reply != "accepted-before-pressure" {
		t.Fatalf("initial reply = %q, want %q", reply, "accepted-before-pressure")
	}

	const contenders = 96
	start := make(chan struct{})
	errCh := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			<-start
			secondCtx, secondCancel := context.WithTimeout(ctx, 15*time.Second)
			defer secondCancel()
			errCh <- Open(secondCtx, OpenConfig{
				Token:         tok,
				Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
				ForceRelay:    true,
				UsePublicDERP: true,
			})
		}()
	}
	close(start)

	responsiveCtx, responsiveCancel := context.WithTimeout(ctx, 5*time.Second)
	reply, err := roundTripTCP(responsiveCtx, openAddr, "accepted-under-pressure")
	responsiveCancel()
	if err != nil {
		t.Fatalf("roundTripTCP() under claim pressure error = %v", err)
	}
	if reply != "accepted-under-pressure" {
		t.Fatalf("reply under claim pressure = %q, want %q", reply, "accepted-under-pressure")
	}

	for i := 0; i < contenders; i++ {
		err := <-errCh
		if err == nil {
			t.Fatal("contending Open() error = nil, want rejection")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("contending Open() error = %v, want deterministic rejection", err)
		}
		if !strings.Contains(err.Error(), "session already claimed") {
			t.Fatalf("contending Open() error = %v, want session already claimed", err)
		}
	}

	cancel()
	waitNoErr(t, <-firstOpenErr)
	waitNoErr(t, <-shareErr)
}

func TestShareOpenExternalCanUpgradeAfterRelayStartAndServeConnections(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")

	result := runExternalShareOpenSession(t, shareOpenRoundTripConfig{
		relayPayload:    "relay-first",
		upgradePayloads: []string{"direct-one", "direct-two", "direct-three"},
	})

	if !result.SeenRelay || !result.SeenDirect {
		t.Fatalf("SeenRelay=%v SeenDirect=%v share=%q open=%q", result.SeenRelay, result.SeenDirect, result.ShareStatus, result.OpenStatus)
	}
	if got := result.RelayReply; got != "relay-first" {
		t.Fatalf("relay reply = %q, want %q", got, "relay-first")
	}
	if !strings.Contains(result.ShareStatus, string(StateClaimed)) {
		t.Fatalf("ShareStatus = %q, want %q", result.ShareStatus, StateClaimed)
	}
	for _, payload := range []string{"direct-one", "direct-two", "direct-three"} {
		if got := result.UpgradeReplies[payload]; got != payload {
			t.Fatalf("upgrade reply for %q = %q, want %q", payload, got, payload)
		}
	}
}

func TestExternalListenSendCanUpgradeAfterRelayStart(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	result := runExternalRoundTrip(t, roundTripConfig{
		payload: []byte("upgrade-me"),
	})

	if !result.SeenRelay || !result.SeenDirect {
		t.Fatalf("SeenRelay=%v SeenDirect=%v listener=%q sender=%q", result.SeenRelay, result.SeenDirect, result.ListenerStatus, result.SenderStatus)
	}
	if got := result.Output; got != "upgrade-me" {
		t.Fatalf("output = %q, want %q", got, "upgrade-me")
	}
}

func TestExternalListenSendUsesNativeDirectQUICWhenBothSidesAreDirectReady(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader([]byte("native-direct")),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if got := listenerOut.String(); got != "native-direct" {
		t.Fatalf("listener output = %q, want %q", got, "native-direct")
	}
	if got := senderStatus.String(); !strings.Contains(got, "sender-quic-direct") {
		t.Fatalf("sender status = %q, want sender-quic-direct", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "listener-quic-direct") {
		t.Fatalf("listener status = %q, want listener-quic-direct", got)
	}
}

func TestExternalListenSendUsesNativeDirectTCPWhenAllowed(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return true }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader([]byte("native-tcp-direct")),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if got := listenerOut.String(); got != "native-tcp-direct" {
		t.Fatalf("listener output = %q, want %q", got, "native-tcp-direct")
	}
	if got := senderStatus.String(); !strings.Contains(got, "sender-tcp-direct") {
		t.Fatalf("sender status = %q, want sender-tcp-direct", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "listener-tcp-direct") {
		t.Fatalf("listener status = %q, want listener-tcp-direct", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "connected-direct") {
		t.Fatalf("listener status = %q, want connected-direct", got)
	}
}

func TestExternalListenSendUsesStripedNativeDirectTCPWhenRequested(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0")
	t.Setenv("DERPCAT_NATIVE_TCP_CONNS", "4")

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return true }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("striped-native-tcp:"), 1<<15)
	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader(payload),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if !bytes.Equal(listenerOut.Bytes(), payload) {
		t.Fatalf("listener output length = %d, want %d", listenerOut.Len(), len(payload))
	}
	if got := senderStatus.String(); !strings.Contains(got, "native-tcp-stripes=4") {
		t.Fatalf("sender status = %q, want native-tcp-stripes=4", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "native-tcp-stripes=4") {
		t.Fatalf("listener status = %q, want native-tcp-stripes=4", got)
	}
}

func TestExternalListenSendUsesNativeDirectQUICWhenDirectPromotionIsSlightlyDelayed(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(3*time.Second).UnixNano(), 10))

	prevTCPAddrAllowed := externalNativeTCPAddrAllowed
	externalNativeTCPAddrAllowed = func(net.Addr) bool { return false }
	t.Cleanup(func() { externalNativeTCPAddrAllowed = prevTCPAddrAllowed })

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelVerbose),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelVerbose),
			StdioIn:       bytes.NewReader([]byte("delayed-native-direct")),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v listener=%q sender=%q", err, listenerStatus.String(), senderStatus.String())
	}

	if got := listenerOut.String(); got != "delayed-native-direct" {
		t.Fatalf("listener output = %q, want %q", got, "delayed-native-direct")
	}
	if got := senderStatus.String(); !strings.Contains(got, "sender-quic-direct") {
		t.Fatalf("sender status = %q, want sender-quic-direct", got)
	}
	if got := listenerStatus.String(); !strings.Contains(got, "listener-quic-direct") {
		t.Fatalf("listener status = %q, want listener-quic-direct", got)
	}
}

func TestTransportPathEmitterCompletionIsTerminal(t *testing.T) {
	var status bytes.Buffer
	emitter := newTransportPathEmitter(telemetry.New(&status, telemetry.LevelDefault))

	emitter.Handle(transport.PathRelay)
	emitter.Complete(nil)
	emitter.Handle(transport.PathDirect)
	emitter.Emit(StateDirect)

	if got := sessionStatusLines(status.String()); len(got) != 2 || got[0] != string(StateRelay) || got[1] != string(StateComplete) {
		t.Fatalf("status lines = %q, want [%q %q]", got, StateRelay, StateComplete)
	}
}

func TestPublicProbeCandidatesIncludesMappedCandidate(t *testing.T) {
	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	mapped := netip.MustParseAddrPort("198.51.100.10:54321")
	pm := portmap.NewForTest(&sessionFakePortmapMapper{have: true, external: mapped}, telemetry.New(io.Discard, telemetry.LevelVerbose))
	pm.SetLocalPort(4242)
	if changed := pm.Refresh(time.Now()); !changed {
		t.Fatal("initial portmap Refresh() changed = false, want true")
	}

	prev := gatherTraversalCandidates
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})
	gatherTraversalCandidates = func(_ context.Context, gotConn net.PacketConn, _ *tailcfg.DERPMap, mappedFn func() (netip.AddrPort, bool)) ([]string, error) {
		if gotConn != conn {
			t.Fatalf("gatherTraversalCandidates() conn = %v, want live probe conn %v", gotConn, conn)
		}
		gotMapped, ok := mappedFn()
		if !ok {
			t.Fatal("gatherTraversalCandidates() mapped callback = false, want true")
		}
		if gotMapped != mapped {
			t.Fatalf("gatherTraversalCandidates() mapped callback = %v, want %v", gotMapped, mapped)
		}
		return []string{"100.64.0.11:5555", gotMapped.String(), "not-an-endpoint"}, nil
	}

	got := publicProbeCandidates(ctx, conn, &tailcfg.DERPMap{}, pm)
	if !containsString(got, "100.64.0.11:5555") {
		t.Fatalf("publicProbeCandidates() = %v, want gathered host:port candidate", got)
	}
	if !containsString(got, mapped.String()) {
		t.Fatalf("publicProbeCandidates() = %v, want mapped candidate %q", got, mapped)
	}
}

func TestPublicInitialProbeCandidatesDoesNotSynchronouslyGatherTraversalCandidates(t *testing.T) {
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	mapped := netip.MustParseAddrPort("198.51.100.10:54321")
	pm := &sessionLifecyclePortmap{have: true, snapshot: mapped}

	called := false
	prev := gatherTraversalCandidates
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		called = true
		return []string{"203.0.113.10:4242"}, nil
	}
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})

	got := publicInitialProbeCandidates(conn, pm)
	if called {
		t.Fatal("publicInitialProbeCandidates() synchronously called gatherTraversalCandidates")
	}
	if !containsString(got, "127.0.0.1:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want local socket candidate", got)
	}
	if !containsString(got, mapped.String()) {
		t.Fatalf("publicInitialProbeCandidates() = %v, want mapped candidate %q", got, mapped)
	}
	if containsString(got, "203.0.113.10:4242") {
		t.Fatalf("publicInitialProbeCandidates() = %v, want no gathered traversal candidate", got)
	}
}

func TestPublicCandidateSourceRefreshesDynamicProbeCandidatesForRealSessions(t *testing.T) {
	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	localCandidates := []net.Addr{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}

	call := 0
	prev := gatherTraversalCandidates
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		call++
		if call == 1 {
			return []string{"203.0.113.10:4242"}, nil
		}
		return []string{"203.0.113.11:4242"}, nil
	}
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})

	source := publicCandidateSource(conn, &tailcfg.DERPMap{}, nil, localCandidates)
	first := source(ctx)
	second := source(ctx)

	if !containsAddrString(first, "203.0.113.10:4242") {
		t.Fatalf("first publicCandidateSource() = %v, want refreshed candidate 203.0.113.10:4242", first)
	}
	if containsAddrString(first, "203.0.113.11:4242") {
		t.Fatalf("first publicCandidateSource() = %v, want no second refresh candidate", first)
	}
	if !containsAddrString(second, "203.0.113.11:4242") {
		t.Fatalf("second publicCandidateSource() = %v, want refreshed candidate 203.0.113.11:4242", second)
	}
}

func TestPublicProbeCandidatesSkipsTailscaleCGNATInInternetOnlyTestMode(t *testing.T) {
	t.Setenv("DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES", "1")

	ctx := context.Background()
	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}

	prev := gatherTraversalCandidates
	t.Cleanup(func() {
		gatherTraversalCandidates = prev
	})
	gatherTraversalCandidates = func(context.Context, net.PacketConn, *tailcfg.DERPMap, func() (netip.AddrPort, bool)) ([]string, error) {
		return []string{
			"100.64.0.11:5555",
			"100.125.235.82:4242",
			"192.0.2.10:5555",
		}, nil
	}

	got := publicProbeCandidates(ctx, conn, &tailcfg.DERPMap{}, nil)
	if containsCGNATCandidate(got) {
		t.Fatalf("publicProbeCandidates() = %v, want no 100.64.0.0/10 candidates", got)
	}
	if !containsString(got, "192.0.2.10:5555") {
		t.Fatalf("publicProbeCandidates() = %v, want non-CGNAT gathered candidate", got)
	}
}

func TestIssuePublicSessionAttachesAndClosesPortmap(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	prevCtor := newPublicPortmap
	fake := &sessionLifecyclePortmap{
		have:     true,
		snapshot: netip.MustParseAddrPort("198.51.100.10:54321"),
	}
	newPublicPortmap = func(*telemetry.Emitter) publicPortmap { return fake }
	t.Cleanup(func() { newPublicPortmap = prevCtor })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, session, err := issuePublicSession(ctx)
	if err != nil {
		t.Fatalf("issuePublicSession() error = %v", err)
	}
	defer session.derp.Close()

	pm := publicSessionPortmap(session)
	if pm == nil {
		t.Fatal("publicSessionPortmap() = nil, want attached portmap")
	}
	if pm != fake {
		t.Fatalf("publicSessionPortmap() = %T, want fake portmap", pm)
	}

	wantPort := uint16(session.probeConn.LocalAddr().(*net.UDPAddr).Port)
	if got := fake.localPort; got != wantPort {
		t.Fatalf("SetLocalPort() = %d, want %d", got, wantPort)
	}

	closePublicSessionTransport(session)
	closePublicSessionTransport(session)

	if got, want := fake.closeCalls, 1; got != want {
		t.Fatalf("Close() calls = %d, want %d", got, want)
	}
	if publicSessionPortmap(session) != nil {
		t.Fatal("publicSessionPortmap() after close = non-nil, want nil")
	}
}

func TestNewBoundPublicPortmapDoesNotSynchronouslyRefresh(t *testing.T) {
	prevCtor := newPublicPortmap
	fake := &sessionLifecyclePortmap{refreshDelay: 250 * time.Millisecond}
	newPublicPortmap = func(*telemetry.Emitter) publicPortmap { return fake }
	t.Cleanup(func() { newPublicPortmap = prevCtor })

	conn := &stubPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}}
	started := time.Now()
	pm := newBoundPublicPortmap(conn, telemetry.New(io.Discard, telemetry.LevelVerbose))
	if pm == nil {
		t.Fatal("newBoundPublicPortmap() = nil, want portmap")
	}

	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("newBoundPublicPortmap() took %s, want non-blocking startup", elapsed)
	}
	if got := fake.localPort; got != 4242 {
		t.Fatalf("SetLocalPort() = %d, want 4242", got)
	}
}

func TestExternalNativeQUICConnCountUsesEnvOverride(t *testing.T) {
	t.Setenv("DERPCAT_NATIVE_QUIC_CONNS", "8")

	if got := externalNativeQUICConnCount(); got != 8 {
		t.Fatalf("externalNativeQUICConnCount() = %d, want 8", got)
	}
}

func TestExternalNativeQUICConnCountIgnoresInvalidEnvOverride(t *testing.T) {
	t.Setenv("DERPCAT_NATIVE_QUIC_CONNS", "0")

	if got := externalNativeQUICConnCount(); got != defaultExternalNativeQUICConns {
		t.Fatalf("externalNativeQUICConnCount() = %d, want %d", got, defaultExternalNativeQUICConns)
	}
}

func TestExternalNativeQUICConnCountKeepsFakeTransportSingleConn(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")
	t.Setenv("DERPCAT_NATIVE_QUIC_CONNS", "8")

	if got := externalNativeQUICConnCount(); got != 1 {
		t.Fatalf("externalNativeQUICConnCount() = %d, want 1", got)
	}
}

func TestExternalNativeTCPConnCountUsesEnvOverride(t *testing.T) {
	t.Setenv("DERPCAT_NATIVE_TCP_CONNS", "4")

	if got := externalNativeTCPConnCount(); got != 4 {
		t.Fatalf("externalNativeTCPConnCount() = %d, want 4", got)
	}
}

func TestExternalNativeTCPConnCountDefaultsToTwo(t *testing.T) {
	t.Setenv("DERPCAT_NATIVE_TCP_CONNS", "")

	if got := externalNativeTCPConnCount(); got != 2 {
		t.Fatalf("externalNativeTCPConnCount() = %d, want 2", got)
	}
}

func TestExternalNativeTCPConnCountIgnoresInvalidEnvOverride(t *testing.T) {
	t.Setenv("DERPCAT_NATIVE_TCP_CONNS", "0")

	if got := externalNativeTCPConnCount(); got != defaultExternalNativeTCPConns {
		t.Fatalf("externalNativeTCPConnCount() = %d, want %d", got, defaultExternalNativeTCPConns)
	}
}

func TestExternalNativeTCPHandshakeConnCountNegotiatesMinimumPositive(t *testing.T) {
	t.Parallel()

	if got := externalNativeTCPHandshakeConnCount(1, 2); got != 1 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(1, 2) = %d, want 1", got)
	}
	if got := externalNativeTCPHandshakeConnCount(4, 2); got != 2 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(4, 2) = %d, want 2", got)
	}
	if got := externalNativeTCPHandshakeConnCount(0, 2); got != 2 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(0, 2) = %d, want 2", got)
	}
	if got := externalNativeTCPHandshakeConnCount(-1, 2); got != 2 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(-1, 2) = %d, want 2", got)
	}
	if got := externalNativeTCPHandshakeConnCount(2, 0); got != 1 {
		t.Fatalf("externalNativeTCPHandshakeConnCount(2, 0) = %d, want 1", got)
	}
}

func TestExternalNativeTCPAddrAllowedDefaultAcceptsRouteLocalAddressesOnly(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{name: "loopback", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, want: true},
		{name: "private", addr: &net.UDPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 12345}, want: true},
		{name: "tailscale-cgnat", addr: &net.UDPAddr{IP: net.IPv4(100, 88, 145, 8), Port: 12345}, want: true},
		{name: "public-internet", addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 12345}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalNativeTCPAddrAllowedDefault(tt.addr); got != tt.want {
				t.Fatalf("externalNativeTCPAddrAllowedDefault(%v) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestListenExternalNativeTCPOnCandidatesPrefersTailscaleCandidate(t *testing.T) {
	prevListen := externalNativeTCPListen
	externalNativeTCPListen = func(addr net.Addr, _ *tls.Config) (net.Listener, error) {
		tcpAddr, _, ok := externalNativeTCPAddr(addr)
		if !ok {
			return nil, errors.New("native tcp direct address unavailable")
		}
		return &testAddrListener{addr: tcpAddr}, nil
	}
	t.Cleanup(func() {
		externalNativeTCPListen = prevListen
	})

	ln, ok := listenExternalNativeTCPOnCandidates([]net.Addr{
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 12345},
		&net.UDPAddr{IP: net.IPv4(100, 125, 235, 82), Port: 12345},
	}, nil)
	if !ok {
		t.Fatal("listenExternalNativeTCPOnCandidates() ok = false, want true")
	}
	defer ln.Close()

	got := ln.Addr().(*net.TCPAddr)
	if got.IP.String() != "100.125.235.82" {
		t.Fatalf("listenExternalNativeTCPOnCandidates() addr = %v, want 100.125.235.82", got)
	}
}

type testAddrListener struct {
	net.Listener
	addr net.Addr
}

func (l *testAddrListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (l *testAddrListener) Close() error {
	return nil
}

func (l *testAddrListener) Addr() net.Addr {
	return l.addr
}

func TestSelectExternalNativeTCPResponseAddrPrefersRequestRoute(t *testing.T) {
	got := selectExternalNativeTCPResponseAddr(
		&net.UDPAddr{IP: net.IPv4(100, 125, 235, 82), Port: 53600},
		&net.UDPAddr{IP: net.IPv4(10, 0, 1, 254), Port: 61216},
		[]net.Addr{
			&net.UDPAddr{IP: net.IPv4(10, 0, 4, 2), Port: 41678},
			&net.UDPAddr{IP: net.IPv4(100, 88, 145, 8), Port: 41678},
		},
	)
	if got == nil {
		t.Fatal("selectExternalNativeTCPResponseAddr() = nil, want 100.88.145.8:41678")
	}
	if got.String() != "100.88.145.8:41678" {
		t.Fatalf("selectExternalNativeTCPResponseAddr() = %v, want 100.88.145.8:41678", got)
	}
}

func TestConnectExternalNativeTCPConnsEstablishesStripedConnectionsWithBidirectionalFallback(t *testing.T) {
	senderIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(sender) error = %v", err)
	}
	listenerIdentity, err := quicpath.GenerateSessionIdentity()
	if err != nil {
		t.Fatalf("GenerateSessionIdentity(listener) error = %v", err)
	}

	senderListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(sender) error = %v", err)
	}
	defer senderListener.Close()
	senderListener = tls.NewListener(senderListener, quicpath.ServerTLSConfig(senderIdentity, listenerIdentity.Public))

	listenerListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(listener) error = %v", err)
	}
	defer listenerListener.Close()
	listenerListener = tls.NewListener(listenerListener, quicpath.ServerTLSConfig(listenerIdentity, senderIdentity.Public))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senderResult := make(chan []net.Conn, 1)
	senderErr := make(chan error, 1)
	go func() {
		conns, err := connectExternalNativeTCPConns(
			ctx,
			senderListener,
			listenerListener.Addr(),
			quicpath.ClientTLSConfig(senderIdentity, listenerIdentity.Public),
			externalNativeTCPAuth{},
			0,
			4,
		)
		senderResult <- conns
		senderErr <- err
	}()

	listenerResult := make(chan []net.Conn, 1)
	listenerErr := make(chan error, 1)
	go func() {
		conns, err := connectExternalNativeTCPConns(
			ctx,
			listenerListener,
			senderListener.Addr(),
			quicpath.ClientTLSConfig(listenerIdentity, senderIdentity.Public),
			externalNativeTCPAuth{},
			25*time.Millisecond,
			4,
		)
		listenerResult <- conns
		listenerErr <- err
	}()

	senderConns := <-senderResult
	defer closeExternalNativeTCPConns(senderConns)
	if err := <-senderErr; err != nil {
		t.Fatalf("connectExternalNativeTCPConns(sender) error = %v", err)
	}
	if got := len(senderConns); got != 4 {
		t.Fatalf("connectExternalNativeTCPConns(sender) len = %d, want 4", got)
	}

	listenerConns := <-listenerResult
	defer closeExternalNativeTCPConns(listenerConns)
	if err := <-listenerErr; err != nil {
		t.Fatalf("connectExternalNativeTCPConns(listener) error = %v", err)
	}
	if got := len(listenerConns); got != 4 {
		t.Fatalf("connectExternalNativeTCPConns(listener) len = %d, want 4", got)
	}

	payload := []byte("x")
	for i := range senderConns {
		if _, err := senderConns[i].Write(payload); err != nil {
			t.Fatalf("senderConns[%d].Write() error = %v", i, err)
		}
	}
	for i := range listenerConns {
		var got [1]byte
		if _, err := io.ReadFull(listenerConns[i], got[:]); err != nil {
			t.Fatalf("listenerConns[%d] ReadFull() error = %v", i, err)
		}
		if got[0] != payload[0] {
			t.Fatalf("listenerConns[%d] payload = %q, want %q", i, got[:], payload)
		}
	}
}

func TestExternalRoundTripUsesSessionPortmapLifecycle(t *testing.T) {
	t.Setenv("DERPCAT_FAKE_TRANSPORT", "1")

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	fakes := []*sessionLifecyclePortmap{
		{have: true, snapshot: netip.MustParseAddrPort("198.51.100.10:54321")},
		{have: true, snapshot: netip.MustParseAddrPort("198.51.100.11:54322")},
	}
	var ctorMu sync.Mutex
	var ctorCalls int
	prevCtor := newPublicPortmap
	newPublicPortmap = func(*telemetry.Emitter) publicPortmap {
		ctorMu.Lock()
		defer ctorMu.Unlock()
		if ctorCalls >= len(fakes) {
			return &sessionLifecyclePortmap{}
		}
		pm := fakes[ctorCalls]
		ctorCalls++
		return pm
	}
	t.Cleanup(func() { newPublicPortmap = prevCtor })

	seenPortmaps := make(chan publicPortmap, len(fakes))
	prevTransportCtor := newTransportManager
	newTransportManager = func(cfg transport.ManagerConfig) *transport.Manager {
		if cfg.Portmap != nil {
			if pm, ok := cfg.Portmap.(publicPortmap); ok {
				select {
				case seenPortmaps <- pm:
				default:
				}
			}
		}
		return prevTransportCtor(cfg)
	}
	t.Cleanup(func() { newTransportManager = prevTransportCtor })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var listenerOut bytes.Buffer
	var senderIn bytes.Buffer
	senderIn.WriteString("hello over public session")
	listenerReady := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:     listenerReady,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-listenerReady
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			StdioIn:       &senderIn,
			Emitter:       telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			UsePublicDERP: true,
		})
	}()

	if err := <-listenErr; err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got := listenerOut.String(); got != "hello over public session" {
		t.Fatalf("listener output = %q, want %q", got, "hello over public session")
	}

	gotPortmaps := make(map[publicPortmap]int)
	for i := 0; i < len(fakes); i++ {
		pm := <-seenPortmaps
		gotPortmaps[pm]++
	}
	close(seenPortmaps)

	if got, want := ctorCalls, len(fakes); got != want {
		t.Fatalf("portmap ctor calls = %d, want %d", got, want)
	}
	for i, pm := range fakes {
		pm.mu.Lock()
		localPort := pm.localPort
		closeCalls := pm.closeCalls
		pm.mu.Unlock()

		if localPort == 0 {
			t.Fatalf("fake portmap %d localPort = 0, want bound port", i)
		}
		if gotPortmaps[pm] == 0 {
			t.Fatalf("fake portmap %d was not threaded into transport manager", i)
		}
		if closeCalls != 1 {
			t.Fatalf("fake portmap %d Close() calls = %d, want 1", i, closeCalls)
		}
	}
}

type sessionFakePortmapMapper struct {
	localPort uint16
	external  netip.AddrPort
	have      bool
	closed    int
}

func (m *sessionFakePortmapMapper) SetLocalPort(p uint16) { m.localPort = p }

func (m *sessionFakePortmapMapper) SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool)) {}

func (m *sessionFakePortmapMapper) Probe(context.Context) (portmappertype.ProbeResult, error) {
	return portmappertype.ProbeResult{}, nil
}

func (m *sessionFakePortmapMapper) HaveMapping() bool { return m.have }

func (m *sessionFakePortmapMapper) GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool) {
	if !m.have {
		return netip.AddrPort{}, false
	}
	return m.external, true
}

func (m *sessionFakePortmapMapper) Close() error {
	m.closed++
	return nil
}

type sessionLifecyclePortmap struct {
	mu                 sync.Mutex
	localPort          uint16
	snapshot           netip.AddrPort
	have               bool
	refreshDelay       time.Duration
	refreshCalls       int
	snapshotAddrsCalls int
	closeCalls         int
}

func (m *sessionLifecyclePortmap) SetLocalPort(p uint16) {
	m.mu.Lock()
	m.localPort = p
	m.mu.Unlock()
}

func (m *sessionLifecyclePortmap) SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool)) {}

func (m *sessionLifecyclePortmap) Probe(context.Context) (portmappertype.ProbeResult, error) {
	return portmappertype.ProbeResult{}, nil
}

func (m *sessionLifecyclePortmap) HaveMapping() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.have
}

func (m *sessionLifecyclePortmap) GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.have {
		return netip.AddrPort{}, false
	}
	return m.snapshot, true
}

func (m *sessionLifecyclePortmap) Snapshot() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.have {
		return netip.AddrPort{}, false
	}
	return m.snapshot, true
}

func (m *sessionLifecyclePortmap) SnapshotAddrs() []net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotAddrsCalls++
	if !m.have || !m.snapshot.Addr().IsValid() || m.snapshot.Port() == 0 {
		return nil
	}
	return []net.Addr{&net.UDPAddr{
		IP:   append(net.IP(nil), m.snapshot.Addr().AsSlice()...),
		Port: int(m.snapshot.Port()),
		Zone: m.snapshot.Addr().Zone(),
	}}
}

func (m *sessionLifecyclePortmap) Refresh(time.Time) bool {
	if m.refreshDelay > 0 {
		time.Sleep(m.refreshDelay)
	}
	m.mu.Lock()
	m.refreshCalls++
	m.mu.Unlock()
	return true
}

func (m *sessionLifecyclePortmap) Close() error {
	m.mu.Lock()
	m.closeCalls++
	m.mu.Unlock()
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAddrString(values []net.Addr, target string) bool {
	for _, value := range values {
		if value != nil && value.String() == target {
			return true
		}
	}
	return false
}

func containsCGNATCandidate(values []string) bool {
	tailscaleCGNAT := netip.MustParsePrefix("100.64.0.0/10")
	for _, value := range values {
		addrPort, err := netip.ParseAddrPort(value)
		if err != nil {
			continue
		}
		if tailscaleCGNAT.Contains(addrPort.Addr()) {
			return true
		}
	}
	return false
}

func TestSeedAcceptedDecisionCandidatesUsesAcceptCandidates(t *testing.T) {
	ctx := context.Background()
	decision := rendezvous.Decision{
		Accepted: true,
		Accept: &rendezvous.AcceptInfo{
			Candidates: []string{
				"100.64.0.10:12345",
				"[2001:db8::10]:23456",
				"not-an-addr",
			},
		},
	}
	seeder := &captureCandidateSeeder{}

	seedAcceptedDecisionCandidates(ctx, seeder, decision)

	if seeder.calls != 1 {
		t.Fatalf("SeedRemoteCandidates() calls = %d, want 1", seeder.calls)
	}
	if got := len(seeder.candidates); got != 2 {
		t.Fatalf("seeded candidates = %#v, want 2 parsed candidates", seeder.candidates)
	}
	if got := seeder.candidates[0].String(); got != "100.64.0.10:12345" {
		t.Fatalf("first seeded candidate = %q, want %q", got, "100.64.0.10:12345")
	}
	if got := seeder.candidates[1].String(); got != "[2001:db8::10]:23456" {
		t.Fatalf("second seeded candidate = %q, want %q", got, "[2001:db8::10]:23456")
	}
}

func TestSeedAcceptedClaimCandidatesUsesClaimCandidates(t *testing.T) {
	ctx := context.Background()
	claim := rendezvous.Claim{
		Candidates: []string{
			"192.0.2.20:2345",
			"not-an-addr",
		},
	}
	seeder := &captureCandidateSeeder{}

	seedAcceptedClaimCandidates(ctx, seeder, claim)

	if seeder.calls != 1 {
		t.Fatalf("SeedRemoteCandidates() calls = %d, want 1", seeder.calls)
	}
	if got := len(seeder.candidates); got != 1 {
		t.Fatalf("seeded candidates = %#v, want 1 parsed candidate", seeder.candidates)
	}
	if got := seeder.candidates[0].String(); got != "192.0.2.20:2345" {
		t.Fatalf("first seeded candidate = %q, want %q", got, "192.0.2.20:2345")
	}
}

type roundTripConfig struct {
	payload []byte
}

type shareOpenRoundTripConfig struct {
	relayPayload    string
	upgradePayloads []string
}

type roundTripResult struct {
	Output         string
	ListenerStatus string
	SenderStatus   string
	SeenRelay      bool
	SeenDirect     bool
}

type shareOpenRoundTripResult struct {
	RelayReply     string
	UpgradeReplies map[string]string
	ShareStatus    string
	OpenStatus     string
	SeenRelay      bool
	SeenDirect     bool
}

type captureCandidateSeeder struct {
	calls      int
	candidates []net.Addr
}

type stubPacketConn struct {
	localAddr net.Addr
}

func (c *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (c *stubPacketConn) Close() error                           { return nil }
func (c *stubPacketConn) LocalAddr() net.Addr                    { return c.localAddr }
func (c *stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (c *stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }

func (c *captureCandidateSeeder) SeedRemoteCandidates(_ context.Context, candidates []net.Addr) {
	c.calls++
	c.candidates = append([]net.Addr(nil), candidates...)
}

func runExternalRoundTrip(t *testing.T, cfg roundTripConfig) roundTripResult {
	t.Helper()

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timeout := time.After(40 * time.Second)

	var listenerOut bytes.Buffer
	var listenerStatus syncBuffer
	var senderStatus syncBuffer

	tokenSink := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		_, err := Listen(ctx, ListenConfig{
			Emitter:       telemetry.New(&listenerStatus, telemetry.LevelDefault),
			TokenSink:     tokenSink,
			StdioOut:      &listenerOut,
			UsePublicDERP: true,
		})
		listenErr <- err
	}()

	token := <-tokenSink
	releaseEOF := make(chan struct{})
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- Send(ctx, SendConfig{
			Token:         token,
			Emitter:       telemetry.New(&senderStatus, telemetry.LevelDefault),
			StdioIn:       &sessionDirectGateReader{ctx: ctx, payload: cfg.payload, releaseEOF: releaseEOF},
			UsePublicDERP: true,
		})
	}()

	waitForStatusPrefixBuffer(t, &listenerStatus, 20*time.Second, "waiting-for-claim", "connected-relay")
	waitForStatusPrefixBuffer(t, &senderStatus, 20*time.Second, "probing-direct", "connected-relay")
	if err := os.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0"); err != nil {
		t.Fatalf("Setenv(enable direct) error = %v", err)
	}
	waitForStatusPrefixBuffer(t, &listenerStatus, 20*time.Second, "waiting-for-claim", "connected-relay", "connected-direct")
	waitForStatusPrefixBuffer(t, &senderStatus, 20*time.Second, "probing-direct", "connected-relay", "connected-direct")
	close(releaseEOF)

	select {
	case err := <-listenErr:
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}
	case <-timeout:
		cancel()
		t.Fatalf("timed out waiting for Listen(); listener=%q sender=%q", listenerStatus.String(), senderStatus.String())
	}

	sendGrace := time.NewTimer(3 * time.Second)
	defer sendGrace.Stop()
	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("Send() error = %v", err)
		}
	case <-sendGrace.C:
		cancel()
		err := <-sendErr
		t.Fatalf("Send() did not exit after listener completion; error after forced cleanup = %v", err)
	}

	listenerStatuses := listenerStatus.String()
	senderStatuses := senderStatus.String()
	return roundTripResult{
		Output:         listenerOut.String(),
		ListenerStatus: listenerStatuses,
		SenderStatus:   senderStatuses,
		SeenRelay:      strings.Contains(listenerStatuses, string(StateRelay)) && strings.Contains(senderStatuses, string(StateRelay)),
		SeenDirect:     strings.Contains(listenerStatuses, string(StateDirect)) && strings.Contains(senderStatuses, string(StateDirect)),
	}
}

func runExternalShareOpenSession(t *testing.T, cfg shareOpenRoundTripConfig) shareOpenRoundTripResult {
	t.Helper()

	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)
	t.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backendAddr, backendDone := startEchoServer(t, ctx)
	defer backendDone()

	var shareStatus syncBuffer
	var openStatus syncBuffer

	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(ctx, ShareConfig{
			Emitter:       telemetry.New(&shareStatus, telemetry.LevelDefault),
			TokenSink:     tokenSink,
			TargetAddr:    backendAddr,
			UsePublicDERP: true,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(ctx, OpenConfig{
			Token:         tok,
			BindAddrSink:  bindSink,
			Emitter:       telemetry.New(&openStatus, telemetry.LevelDefault),
			UsePublicDERP: true,
		})
	}()

	openAddr := <-bindSink
	relayReply, err := roundTripTCP(ctx, openAddr, cfg.relayPayload)
	if err != nil {
		t.Fatalf("relay roundTripTCP() error = %v", err)
	}

	waitForStatusPrefixBuffer(t, &shareStatus, 20*time.Second, string(StateWaiting), string(StateClaimed), string(StateRelay))
	waitForStatusPrefixBuffer(t, &openStatus, 20*time.Second, string(StateProbing), string(StateRelay))
	if err := os.Setenv("DERPCAT_FAKE_TRANSPORT_ENABLE_DIRECT_AT", "0"); err != nil {
		t.Fatalf("Setenv(enable direct) error = %v", err)
	}
	waitForStatusPrefixBuffer(t, &shareStatus, 20*time.Second, string(StateWaiting), string(StateClaimed), string(StateRelay), string(StateDirect))
	waitForStatusPrefixBuffer(t, &openStatus, 20*time.Second, string(StateProbing), string(StateRelay), string(StateDirect))

	replies := make(map[string]string, len(cfg.upgradePayloads))
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(cfg.upgradePayloads))
	for _, payload := range cfg.upgradePayloads {
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			reply, err := roundTripTCP(ctx, openAddr, payload)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			replies[payload] = reply
			mu.Unlock()
		}(payload)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("post-upgrade roundTripTCP() error = %v", err)
		}
	}

	cancel()
	waitNoErr(t, <-openErr)
	waitNoErr(t, <-shareErr)

	shareStatuses := shareStatus.String()
	openStatuses := openStatus.String()
	return shareOpenRoundTripResult{
		RelayReply:     relayReply,
		UpgradeReplies: replies,
		ShareStatus:    shareStatuses,
		OpenStatus:     openStatuses,
		SeenRelay:      strings.Contains(shareStatuses, string(StateRelay)) && strings.Contains(openStatuses, string(StateRelay)),
		SeenDirect:     strings.Contains(shareStatuses, string(StateDirect)) && strings.Contains(openStatuses, string(StateDirect)),
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type sessionDirectGateReader struct {
	ctx        context.Context
	payload    []byte
	releaseEOF <-chan struct{}
	sent       bool
}

func (r *sessionDirectGateReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.payload), nil
	}
	select {
	case <-r.releaseEOF:
		return 0, io.EOF
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
}

func waitForStatusPrefixBuffer(t *testing.T, buf interface{ String() string }, timeout time.Duration, want ...string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hasSessionStatusPrefix(sessionStatusLines(buf.String()), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("statuses = %q, want prefix %v", buf.String(), want)
}

func hasSessionStatusPrefix(got, want []string) bool {
	if len(got) < len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func sessionStatusLines(got string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case string(StateWaiting), string(StateClaimed), string(StateProbing), string(StateRelay), string(StateDirect), string(StateComplete):
			lines = append(lines, line)
		}
	}
	return lines
}

type sessionTestDERPServer struct {
	MapURL  string
	DERPURL string
	Map     *tailcfg.DERPMap
}

func newSessionTestDERPServer(t *testing.T) *sessionTestDERPServer {
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
				RegionName: "Session Test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "session-test-1",
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

	return &sessionTestDERPServer{
		MapURL:  mapHTTP.URL,
		DERPURL: derpHTTP.URL + "/derp",
		Map:     dm,
	}
}

func connectWithRetry(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func startEchoServer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := acceptNetListener(ctx, listener)
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func startSharedSession(t *testing.T, ctx context.Context, backendAddr, bindAddr string) (string, func(), <-chan error, <-chan error) {
	t.Helper()

	sessionCtx, cancel := context.WithCancel(ctx)
	tokenSink := make(chan string, 1)
	shareErr := make(chan error, 1)
	go func() {
		_, err := Share(sessionCtx, ShareConfig{
			Emitter:    telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
			TokenSink:  tokenSink,
			TargetAddr: backendAddr,
		})
		shareErr <- err
	}()

	tok := <-tokenSink
	bindSink := make(chan string, 1)
	openErr := make(chan error, 1)
	go func() {
		openErr <- Open(sessionCtx, OpenConfig{
			Token:        tok,
			BindAddr:     bindAddr,
			BindAddrSink: bindSink,
			Emitter:      telemetry.New(&bytes.Buffer{}, telemetry.LevelSilent),
		})
	}()

	return <-bindSink, cancel, shareErr, openErr
}

func roundTripTCP(ctx context.Context, addr, payload string) (string, error) {
	conn, err := connectWithRetry(ctx, addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, payload); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func waitNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
}
