// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

type mapper interface {
	SetLocalPort(uint16)
	SetGatewayLookupFunc(func() (gw, myIP netip.Addr, ok bool))
	Probe(context.Context) (portmappertype.ProbeResult, error)
	HaveMapping() bool
	GetCachedMappingOrStartCreatingOne() (netip.AddrPort, bool)
	Close() error
}

var newNetMon = netmon.New
var newPortmapperClient = func(c portmapper.Config) mapper {
	return portmapper.NewClient(c)
}

type Client struct {
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
	mapper    mapper
	monitor   *netmon.Monitor
	bus       *eventbus.Bus
	subClient *eventbus.Client
	emitter   *telemetry.Emitter
	localPort uint16
	mapped    netip.AddrPort
	have      bool
	initial   bool
	probe     portmappertype.ProbeResult
	hasProbe  bool
	mapType   string
	lastLog   string
}

func NewForTest(m mapper, emitter *telemetry.Emitter) *Client {
	return &Client{mapper: m, emitter: emitter}
}

func New(emitter *telemetry.Emitter) *Client {
	bus := eventbus.New()
	nm, err := newNetMon(bus, logger.Discard)
	useGatewayLookup := err == nil
	if err != nil {
		nm = netmon.NewStatic()
	} else {
		nm.Start()
	}
	c := &Client{
		mapper: newPortmapperClient(portmapper.Config{
			EventBus: bus,
			NetMon:   nm,
			Logf:     logger.Discard,
		}),
		monitor: nm,
		bus:     bus,
		emitter: emitter,
	}
	if useGatewayLookup {
		c.mapper.SetGatewayLookupFunc(nm.GatewayAndSelfIP)
	}

	if c.emitter != nil && c.emitter.DebugEnabled() {
		c.subClient = bus.Client("derphole-portmap")
		sub := eventbus.Subscribe[portmappertype.Mapping](c.subClient)
		go c.consumeMappings(sub)
	}

	return c
}

func (c *Client) consumeMappings(sub *eventbus.Subscriber[portmappertype.Mapping]) {
	for {
		select {
		case mapping, ok := <-sub.Events():
			if !ok {
				return
			}
			c.applyMapping(mapping)
		case <-sub.Done():
			return
		}
	}
}

func (c *Client) applyMapping(mapping portmappertype.Mapping) {
	if c == nil {
		return
	}

	c.mu.Lock()
	c.have = true
	c.mapped = mapping.External
	c.mapType = mapping.Type
	c.mu.Unlock()
}

func (c *Client) SetLocalPort(port uint16) {
	if c == nil || c.mapper == nil {
		return
	}

	c.mu.Lock()
	if c.localPort == port {
		c.mapper.SetLocalPort(port)
		c.mu.Unlock()
		return
	}

	c.localPort = port
	c.mapped = netip.AddrPort{}
	c.have = false
	c.initial = false
	c.hasProbe = false
	c.mapType = ""
	c.lastLog = ""
	c.mapper.SetLocalPort(port)
	c.mu.Unlock()
}

func (c *Client) Refresh(now time.Time) bool {
	_ = now
	if c == nil || c.mapper == nil {
		return false
	}

	var (
		probe portmappertype.ProbeResult
		err   error
	)
	if c.emitter != nil && c.emitter.DebugEnabled() {
		probe, err = c.mapper.Probe(context.Background())
	}

	c.mu.Lock()
	next, ok := c.mapper.GetCachedMappingOrStartCreatingOne()

	changed := c.have != ok || c.mapped != next
	if ok {
		c.have = true
		c.mapped = next
		if c.mapType == "" {
			c.mapType = "external"
		}
	} else {
		c.have = false
		c.mapped = netip.AddrPort{}
	}
	c.probe = probe
	c.hasProbe = err == nil
	status := c.statusLocked()
	shouldLog := status != "" && (!c.initial || status != c.lastLog)
	c.initial = true
	if shouldLog {
		c.lastLog = status
	}
	c.mu.Unlock()

	if shouldLog && c.emitter != nil {
		c.emitter.Debug(status)
	}

	return changed
}

func (c *Client) statusLocked() string {
	if c.have && c.mapped.Addr().IsValid() && c.mapped.Port() != 0 {
		kind := c.mapType
		if kind == "" {
			kind = "external"
		}
		return fmt.Sprintf("portmap=%s external=%s", kind, c.mapped)
	}
	if !c.hasProbe {
		return "portmap=probing"
	}
	services := portmapServices(c.probe)
	if services == "" {
		return "portmap=none"
	}
	return "portmap=probing services=" + services
}

func portmapServices(res portmappertype.ProbeResult) string {
	parts := make([]string, 0, 3)
	if res.UPnP {
		parts = append(parts, "upnp")
	}
	if res.PMP {
		parts = append(parts, "pmp")
	}
	if res.PCP {
		parts = append(parts, "pcp")
	}
	return strings.Join(parts, ",")
}

func (c *Client) Snapshot() (netip.AddrPort, bool) {
	if c == nil {
		return netip.AddrPort{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mapped, c.have
}

func (c *Client) SnapshotAddrs() []net.Addr {
	mapped, ok := c.Snapshot()
	if !ok || !mapped.Addr().IsValid() || mapped.Port() == 0 {
		return nil
	}

	return []net.Addr{
		&net.UDPAddr{
			IP:   append(net.IP(nil), mapped.Addr().AsSlice()...),
			Port: int(mapped.Port()),
			Zone: mapped.Addr().Zone(),
		},
	}
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	c.closeOnce.Do(func() {
		var errs []error
		if c.subClient != nil {
			c.subClient.Close()
		}
		if c.mapper != nil {
			if err := c.mapper.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if c.monitor != nil {
			if err := c.monitor.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if c.bus != nil {
			c.bus.Close()
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

var _ mapper = (portmappertype.Client)(nil)
