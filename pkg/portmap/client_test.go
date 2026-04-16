package portmap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

type fakeMapper struct {
	localPort          uint16
	external           netip.AddrPort
	have               bool
	probe              portmappertype.ProbeResult
	closed             int
	gatewayLookupCalls int
}

func (f *fakeMapper) SetLocalPort(p uint16) { f.localPort = p }

func (f *fakeMapper) SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool)) {
	f.gatewayLookupCalls++
}

func (f *fakeMapper) Probe(context.Context) (portmappertype.ProbeResult, error) {
	return f.probe, nil
}

func (f *fakeMapper) HaveMapping() bool { return f.have }

func (f *fakeMapper) GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool) {
	return f.external, f.have
}

func (f *fakeMapper) Close() error {
	f.closed++
	return nil
}

func newMappedClient(t *testing.T) (*Client, *fakeMapper, *bytes.Buffer) {
	t.Helper()

	mapper := &fakeMapper{
		have:     true,
		external: netip.MustParseAddrPort("198.51.100.10:54321"),
	}
	var buf bytes.Buffer
	c := NewForTest(mapper, telemetry.New(&buf, telemetry.LevelVerbose))

	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("initial Refresh() changed = false, want true")
	}

	if got, ok := c.Snapshot(); !ok || got != mapper.external {
		t.Fatalf("Snapshot() = %v, %v, want %v, true", got, ok, mapper.external)
	}

	return c, mapper, &buf
}

func TestClientSetLocalPortAndSnapshot(t *testing.T) {
	c, mapper, _ := newMappedClient(t)

	c.SetLocalPort(45678)
	if got, want := mapper.localPort, uint16(45678); got != want {
		t.Fatalf("local port = %d, want %d", got, want)
	}

	if got, ok := c.Snapshot(); ok {
		t.Fatalf("Snapshot() = %v, %v, want zero, false", got, ok)
	}

	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("Refresh() after rebinding changed = false, want true")
	}

	c.SetLocalPort(45678)
	if got, want := mapper.localPort, uint16(45678); got != want {
		t.Fatalf("local port = %d, want %d", got, want)
	}

	if got, ok := c.Snapshot(); !ok || got != mapper.external {
		t.Fatalf("Snapshot() = %v, %v, want %v, true", got, ok, mapper.external)
	}
}

func TestClientSetLocalPortChangedPortClearsSnapshot(t *testing.T) {
	c, mapper, _ := newMappedClient(t)

	c.SetLocalPort(45678)
	if got, want := mapper.localPort, uint16(45678); got != want {
		t.Fatalf("local port = %d, want %d", got, want)
	}

	if got, ok := c.Snapshot(); ok {
		t.Fatalf("Snapshot() = %v, %v, want zero, false", got, ok)
	}

	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("Refresh() after rebinding changed = false, want true")
	}

	c.SetLocalPort(45679)
	if got, want := mapper.localPort, uint16(45679); got != want {
		t.Fatalf("local port = %d, want %d", got, want)
	}

	if got, ok := c.Snapshot(); ok {
		t.Fatalf("Snapshot() = %v, %v, want zero, false", got, ok)
	}
}

type blockingMapper struct {
	mu             sync.Mutex
	localPort      uint16
	externalByPort map[uint16]netip.AddrPort
	have           bool
	setStarted     chan uint16
	allowSet       chan struct{}
}

func (m *blockingMapper) SetLocalPort(p uint16) {
	m.setStarted <- p
	<-m.allowSet
	m.mu.Lock()
	m.localPort = p
	m.mu.Unlock()
}

func (m *blockingMapper) HaveMapping() bool { return m.have }

func (m *blockingMapper) Probe(context.Context) (portmappertype.ProbeResult, error) {
	return portmappertype.ProbeResult{}, nil
}

func (m *blockingMapper) GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	external, ok := m.externalByPort[m.localPort]
	if !ok {
		return netip.AddrPort{}, false
	}
	return external, true
}

func (m *blockingMapper) Close() error { return nil }

func (m *blockingMapper) SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool)) {}

func TestClientSetLocalPortBlocksRefreshUntilComplete(t *testing.T) {
	mapper := &blockingMapper{
		localPort: 45678,
		externalByPort: map[uint16]netip.AddrPort{
			45678: netip.MustParseAddrPort("198.51.100.10:54321"),
			45679: netip.MustParseAddrPort("198.51.100.10:54322"),
		},
		have:       true,
		setStarted: make(chan uint16, 1),
		allowSet:   make(chan struct{}),
	}
	var buf bytes.Buffer
	c := NewForTest(mapper, telemetry.New(&buf, telemetry.LevelVerbose))

	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("initial Refresh() changed = false, want true")
	}

	setDone := make(chan struct{})
	go func() {
		c.SetLocalPort(45679)
		close(setDone)
	}()

	select {
	case got := <-mapper.setStarted:
		if got != 45679 {
			t.Fatalf("SetLocalPort arg = %d, want 45679", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for SetLocalPort to enter mapper")
	}

	refreshDone := make(chan struct {
		changed bool
		snap    netip.AddrPort
		ok      bool
	})
	go func() {
		changed := c.Refresh(time.Now())
		snap, ok := c.Snapshot()
		refreshDone <- struct {
			changed bool
			snap    netip.AddrPort
			ok      bool
		}{changed: changed, snap: snap, ok: ok}
	}()

	select {
	case <-refreshDone:
		t.Fatal("Refresh completed before SetLocalPort finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(mapper.allowSet)

	select {
	case <-setDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for SetLocalPort to finish")
	}

	select {
	case got := <-refreshDone:
		if !got.changed {
			t.Fatal("Refresh() changed = false, want true")
		}
		if !got.ok || got.snap != mapper.externalByPort[45679] {
			t.Fatalf("Snapshot() = %v, %v, want %v, true", got.snap, got.ok, mapper.externalByPort[45679])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for Refresh to finish")
	}
}

func TestClientRefreshPublishesExternalMapping(t *testing.T) {
	mapper := &fakeMapper{
		have:     true,
		external: netip.MustParseAddrPort("198.51.100.10:54321"),
	}
	var buf bytes.Buffer
	c := NewForTest(mapper, telemetry.New(&buf, telemetry.LevelVerbose))

	changed := c.Refresh(time.Now())
	if !changed {
		t.Fatal("Refresh() changed = false, want true")
	}

	got, ok := c.Snapshot()
	if !ok || got != mapper.external {
		t.Fatalf("Snapshot() = %v, %v, want %v, true", got, ok, mapper.external)
	}

	if got := buf.String(); !strings.Contains(got, "portmap=external external=198.51.100.10:54321") {
		t.Fatalf("debug output = %q, want external mapping line", got)
	}
}

func TestClientRefreshLogsVerbosePortmapStates(t *testing.T) {
	mapper := &fakeMapper{
		probe: portmappertype.ProbeResult{UPnP: true, PMP: true},
	}
	var buf bytes.Buffer
	c := NewForTest(mapper, telemetry.New(&buf, telemetry.LevelVerbose))

	if changed := c.Refresh(time.Now()); changed {
		t.Fatal("initial Refresh() changed = true, want false without mapping")
	}
	if got := buf.String(); !strings.Contains(got, "portmap=probing services=upnp,pmp") {
		t.Fatalf("debug output = %q, want probing services line", got)
	}

	buf.Reset()
	mapper.probe = portmappertype.ProbeResult{}
	if changed := c.Refresh(time.Now()); changed {
		t.Fatal("Refresh() changed = true, want false without mapping")
	}
	if got := buf.String(); !strings.Contains(got, "portmap=none") {
		t.Fatalf("debug output = %q, want none line", got)
	}

	buf.Reset()
	mapper.have = true
	mapper.external = netip.MustParseAddrPort("198.51.100.10:54321")
	c.mu.Lock()
	c.mapType = "pcp"
	c.mu.Unlock()
	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("Refresh() changed = false, want true when mapping appears")
	}
	if got := buf.String(); !strings.Contains(got, "portmap=pcp external=198.51.100.10:54321") {
		t.Fatalf("debug output = %q, want concrete mapping type line", got)
	}
}

func TestClientRefreshSuppressesPortmapLogsWithoutVerbose(t *testing.T) {
	mapper := &fakeMapper{
		probe: portmappertype.ProbeResult{UPnP: true, PMP: true},
	}
	var buf bytes.Buffer
	c := NewForTest(mapper, telemetry.New(&buf, telemetry.LevelDefault))

	c.Refresh(time.Now())
	if got := buf.String(); got != "" {
		t.Fatalf("debug output = %q, want empty outside verbose mode", got)
	}
}

func TestClientCloseClosesUnderlyingMapper(t *testing.T) {
	mapper := &fakeMapper{
		have:     true,
		external: netip.MustParseAddrPort("198.51.100.10:54321"),
	}
	c := NewForTest(mapper, telemetry.New(io.Discard, telemetry.LevelVerbose))

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if got, want := mapper.closed, 1; got != want {
		t.Fatalf("mapper closed count = %d, want %d", got, want)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
	if got, want := mapper.closed, 1; got != want {
		t.Fatalf("mapper closed count after second Close = %d, want %d", got, want)
	}
}

func TestNewFallsBackWhenMonitorConstructionFails(t *testing.T) {
	old := newNetMon
	newNetMon = func(*eventbus.Bus, logger.Logf) (*netmon.Monitor, error) {
		return nil, errors.New("monitor unavailable")
	}
	oldCtor := newPortmapperClient
	fake := &fakeMapper{}
	newPortmapperClient = func(portmapper.Config) mapper { return fake }
	t.Cleanup(func() { newPortmapperClient = oldCtor })
	t.Cleanup(func() { newNetMon = old })

	c := New(telemetry.New(io.Discard, telemetry.LevelVerbose))
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if got, want := fake.gatewayLookupCalls, 0; got != want {
		t.Fatalf("SetGatewayLookupFunc called %d times, want %d", got, want)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
}

func TestSnapshotAddrsReturnsUDPAddr(t *testing.T) {
	c, _, _ := newMappedClient(t)

	addrs := c.SnapshotAddrs()
	if got, want := len(addrs), 1; got != want {
		t.Fatalf("len(addrs) = %d, want %d", got, want)
	}

	udp, ok := addrs[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("addrs[0] type = %T, want *net.UDPAddr", addrs[0])
	}
	if got, want := udp.String(), "198.51.100.10:54321"; got != want {
		t.Fatalf("udp.String() = %q, want %q", got, want)
	}
}

func TestClientRefreshTransitionsAndStability(t *testing.T) {
	mapper := &fakeMapper{
		have:     true,
		external: netip.MustParseAddrPort("198.51.100.10:54321"),
	}
	var buf bytes.Buffer
	c := NewForTest(mapper, telemetry.New(&buf, telemetry.LevelVerbose))

	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("initial Refresh() changed = false, want true")
	}

	mapper.have = false
	mapper.external = netip.AddrPort{}

	if changed := c.Refresh(time.Now()); !changed {
		t.Fatal("Refresh() mapped->unmapped changed = false, want true")
	}

	if got, ok := c.Snapshot(); ok {
		t.Fatalf("Snapshot() = %v, %v, want zero, false", got, ok)
	}

	if changed := c.Refresh(time.Now()); changed {
		t.Fatal("second identical Refresh() changed = true, want false")
	}
}
