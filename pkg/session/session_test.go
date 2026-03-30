package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/rendezvous"
	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/transport"
	"go4.org/mem"
	"tailscale.com/derp/derpserver"
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
