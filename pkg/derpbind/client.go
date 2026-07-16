// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type Packet struct {
	From    key.NodePublic
	Payload []byte
}

type Client struct {
	pub       key.NodePublic
	dc        derpClientConn
	packetCh  chan Packet
	stopCh    chan struct{}
	doneCh    chan struct{}
	proxyInfo *proxyInfoRecorder

	subMu       sync.RWMutex
	subscribers map[uint64]*packetSubscriber
	nextSubID   uint64
	stopOnce    sync.Once
}

type derpClientConn interface {
	Close() error
	Send(key.NodePublic, []byte) error
	Recv() (derp.ReceivedMessage, error)
	SendPong([8]byte) error
}

type packetSubscriber struct {
	filter func(Packet) bool
	ch     chan Packet
	mode   subscriberMode
	done   chan struct{}
	once   sync.Once

	queueMu    sync.Mutex
	queue      []Packet
	queueReady chan struct{}
	queueSlots chan struct{}

	deliverMu sync.Mutex
	closed    bool
}

type subscriberMode uint8

const (
	subscriberLossy subscriberMode = iota
	subscriberLossless
)

const losslessSubscriberQueueSize = 64

var derpDialTimeout = 5 * time.Second

const maxProxyIPFallbackTargets = 2

var derpLookupNetIP = net.DefaultResolver.LookupNetIP

var derpDialContext = func(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor, network, addr string) (net.Conn, error) {
	return netns.NewDialer(logf, netMon).DialContext(ctx, network, addr)
}

func NewClient(ctx context.Context, node *tailcfg.DERPNode, serverURL string) (*Client, error) {
	priv := key.NewNode()
	return newClientWithPrivateKey(ctx, node, serverURL, priv)
}

func NewClientWithPrivateKey(ctx context.Context, node *tailcfg.DERPNode, serverURL string, priv key.NodePrivate) (*Client, error) {
	if priv.IsZero() {
		return nil, errors.New("zero DERP private key")
	}
	return newClientWithPrivateKey(ctx, node, serverURL, priv)
}

func newClientWithPrivateKey(ctx context.Context, node *tailcfg.DERPNode, serverURL string, priv key.NodePrivate) (*Client, error) {
	if node == nil {
		return nil, errors.New("nil DERP node")
	}
	derpURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse DERP URL: %w", err)
	}

	logf := logger.Logf(func(string, ...any) {})
	netMon := netmon.NewStatic()
	dc, err := derphttp.NewClient(priv, serverURL, logf, netMon)
	if err != nil {
		return nil, err
	}
	proxyInfo := &proxyInfoRecorder{}
	dc.SetURLDialer(newDERPNodeDialer(node, derpURL, proxyInfo, logf, netMon))
	dc.SetCanAckPings(true)
	if err := dc.Connect(ctx); err != nil {
		_ = dc.Close()
		return nil, fmt.Errorf("connect derp client: %w", err)
	}

	c := &Client{
		pub:         priv.Public(),
		dc:          dc,
		packetCh:    make(chan Packet, 16),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		proxyInfo:   proxyInfo,
		subscribers: make(map[uint64]*packetSubscriber),
	}
	go c.recvLoop()
	return c, nil
}

type derpDialTarget struct {
	network string
	addr    string
}

type derpDialResult struct {
	target derpDialTarget
	conn   net.Conn
	err    error
}

type proxyInfoRecorder struct {
	mu   sync.RWMutex
	info ProxyInfo
}

func (r *proxyInfoRecorder) Store(info ProxyInfo) {
	r.mu.Lock()
	r.info = info
	r.mu.Unlock()
}

func (r *proxyInfoRecorder) Load() (ProxyInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.info, r.info.Scheme != ""
}

func newDERPNodeDialer(node *tailcfg.DERPNode, derpURL *url.URL, proxyInfo *proxyInfoRecorder, logf logger.Logf, netMon *netmon.Monitor) func(context.Context, string, string) (net.Conn, error) {
	if node == nil {
		return nil
	}
	if netMon == nil {
		panic("nil netMon")
	}
	return func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		selectedProxy, err := derpProxyForURL(derpURL)
		if err != nil {
			return nil, err
		}
		if selectedProxy != nil {
			conn, info, err := dialDERPNodeThroughProxy(ctx, selectedProxy, node, derpURL, logf, netMon)
			if err != nil {
				return nil, err
			}
			proxyInfo.Store(info)
			return conn, nil
		}
		return dialDERPDirect(ctx, node, logf, netMon, addr)
	}
}

func dialDERPNodeThroughProxy(ctx context.Context, proxyURL *url.URL, node *tailcfg.DERPNode, derpURL *url.URL, logf logger.Logf, netMon *netmon.Monitor) (net.Conn, ProxyInfo, error) {
	target, err := canonicalDERPTarget(derpURL)
	if err != nil {
		return nil, ProxyInfo{}, err
	}
	conn, info, err := dialDERPThroughProxy(ctx, proxyURL, target, logf, netMon)
	if err == nil {
		return conn, info, nil
	}
	attemptErrors := []error{fmt.Errorf("CONNECT %s through DERP proxy: %w", target, err)}
	if !retryableProxyConnectResponseError(ctx, err) {
		return nil, ProxyInfo{}, attemptErrors[0]
	}

	ipTargets, resolveErr := proxyDERPIPTargets(ctx, node, derpURL)
	if resolveErr != nil {
		attemptErrors = append(attemptErrors, resolveErr)
		return nil, ProxyInfo{}, errors.Join(attemptErrors...)
	}
	for _, ipTarget := range ipTargets {
		if ctxErr := ctx.Err(); ctxErr != nil {
			attemptErrors = append(attemptErrors, ctxErr)
			return nil, ProxyInfo{}, errors.Join(attemptErrors...)
		}
		conn, info, err = dialDERPThroughProxy(ctx, proxyURL, ipTarget, logf, netMon)
		if err == nil {
			return conn, info, nil
		}
		attemptErrors = append(attemptErrors, fmt.Errorf("CONNECT %s through DERP proxy: %w", ipTarget, err))
		if !retryableProxyConnectResponseError(ctx, err) {
			return nil, ProxyInfo{}, errors.Join(attemptErrors...)
		}
	}
	return nil, ProxyInfo{}, errors.Join(attemptErrors...)
}

func canonicalDERPTarget(derpURL *url.URL) (string, error) {
	if derpURL == nil {
		return "", errors.New("nil DERP URL")
	}
	host := derpURL.Hostname()
	if host == "" {
		return "", errors.New("DERP URL has no hostname")
	}
	defaultPort := ""
	switch derpURL.Scheme {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	default:
		return "", fmt.Errorf("unsupported DERP URL scheme %q", derpURL.Scheme)
	}
	port := derpURL.Port()
	if port == "" {
		port = defaultPort
	}
	return net.JoinHostPort(host, port), nil
}

func proxyDERPIPTargets(ctx context.Context, node *tailcfg.DERPNode, derpURL *url.URL) ([]string, error) {
	canonicalTarget, err := canonicalDERPTarget(derpURL)
	if err != nil {
		return nil, err
	}
	host := derpURL.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, nil
	}
	_, port, err := net.SplitHostPort(canonicalTarget)
	if err != nil {
		return nil, err
	}

	addresses, allowResolvedV4, allowResolvedV6 := proxyDERPNodeAddresses(node)
	if len(addresses) == 0 && (allowResolvedV4 || allowResolvedV6) {
		addresses, err = resolveProxyDERPAddresses(ctx, host, allowResolvedV4, allowResolvedV6)
		if err != nil {
			return nil, err
		}
	}
	return proxyDERPTargetsForAddresses(addresses, port), nil
}

func proxyDERPNodeAddresses(node *tailcfg.DERPNode) ([]netip.Addr, bool, bool) {
	allowResolvedV4 := node == nil || node.IPv4 == ""
	allowResolvedV6 := node == nil || node.IPv6 == ""
	if node == nil {
		return nil, allowResolvedV4, allowResolvedV6
	}

	addresses := make([]netip.Addr, 0, 2)
	if addr, err := netip.ParseAddr(node.IPv4); err == nil && addr.Is4() {
		addresses = append(addresses, addr)
	}
	if addr, err := netip.ParseAddr(node.IPv6); err == nil && addr.Is6() && !addr.Is4() {
		addresses = append(addresses, addr)
	}
	return addresses, allowResolvedV4, allowResolvedV6
}

func resolveProxyDERPAddresses(ctx context.Context, host string, allowV4, allowV6 bool) ([]netip.Addr, error) {
	resolved, err := derpLookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve DERP hostname for proxy IP fallback %s: %w", host, err)
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, addr := range resolved {
		addr = addr.Unmap()
		if addr.Is4() && !allowV4 || addr.Is6() && !addr.Is4() && !allowV6 {
			continue
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}

func proxyDERPTargetsForAddresses(addresses []netip.Addr, port string) []string {
	targets := make([]string, 0, maxProxyIPFallbackTargets)
	seen := make(map[netip.Addr]struct{}, maxProxyIPFallbackTargets)
	for _, addr := range addresses {
		if addr.Zone() != "" {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsValid() || !addr.IsGlobalUnicast() && !addr.IsLoopback() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		targets = append(targets, net.JoinHostPort(addr.String(), port))
		if len(targets) == maxProxyIPFallbackTargets {
			break
		}
	}
	return targets
}

func dialDERPDirect(ctx context.Context, node *tailcfg.DERPNode, logf logger.Logf, netMon *netmon.Monitor, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	targets, explicitDisable := derpDialTargets(node, host, port)
	if explicitDisable && len(targets) == 0 {
		return nil, errors.New("both IPv4 and IPv6 are explicitly disabled for node")
	}
	if len(targets) == 0 {
		targets = append(targets, derpDialTarget{
			network: "tcp",
			addr:    net.JoinHostPort(host, port),
		})
	}
	return raceDERPDial(ctx, logf, netMon, targets)
}

func derpDialTargets(node *tailcfg.DERPNode, host, port string) ([]derpDialTarget, bool) {
	if node == nil {
		return nil, false
	}
	if host == node.HostName {
		return derpDialTargetsForNodeHost(node, host, port)
	}

	if ip := net.ParseIP(host); ip != nil {
		return derpDialTargetsForIP(ip, port), false
	}

	return []derpDialTarget{
		derpDialTargetFor("tcp4", host, port),
		derpDialTargetFor("tcp6", host, port),
	}, false
}

func derpDialTargetsForNodeHost(node *tailcfg.DERPNode, host, port string) ([]derpDialTarget, bool) {
	var targets []derpDialTarget
	explicitDisable := false
	if target, ok, disabled := derpDialTargetForNodeIP("tcp4", node.IPv4, host, port, true); ok {
		targets = append(targets, target)
	} else if disabled {
		explicitDisable = true
	}
	if target, ok, disabled := derpDialTargetForNodeIP("tcp6", node.IPv6, host, port, false); ok {
		targets = append(targets, target)
	} else if disabled {
		explicitDisable = true
	}
	return targets, explicitDisable
}

func derpDialTargetForNodeIP(network string, configuredHost string, fallbackHost string, port string, wantV4 bool) (derpDialTarget, bool, bool) {
	ip := net.ParseIP(configuredHost)
	if ipMatchesFamily(ip, wantV4) {
		return derpDialTargetFor(network, ip.String(), port), true, false
	}
	if configuredHost == "" {
		return derpDialTargetFor(network, fallbackHost, port), true, false
	}
	return derpDialTarget{}, false, true
}

func ipMatchesFamily(ip net.IP, wantV4 bool) bool {
	if ip == nil {
		return false
	}
	return (ip.To4() != nil) == wantV4
}

func derpDialTargetsForIP(ip net.IP, port string) []derpDialTarget {
	if ip.To4() != nil {
		return []derpDialTarget{derpDialTargetFor("tcp4", ip.String(), port)}
	}
	return []derpDialTarget{derpDialTargetFor("tcp6", ip.String(), port)}
}

func derpDialTargetFor(network, host, port string) derpDialTarget {
	return derpDialTarget{
		network: network,
		addr:    net.JoinHostPort(host, port),
	}
}

func raceDERPDial(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor, targets []derpDialTarget) (net.Conn, error) {
	if len(targets) == 0 {
		return nil, errors.New("no DERP dial targets")
	}
	ctx, cancel := derpDialContextWithTimeout(ctx)
	defer cancel()

	results, pending := startDERPDials(ctx, logf, netMon, targets)
	errs := make([]error, 0, len(targets))
	for range targets {
		conn, done, err := receiveDERPDialResult(ctx, results, pending, &errs)
		if done {
			return conn, err
		}
	}
	return nil, errors.Join(errs...)
}

func startDERPDials(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor, targets []derpDialTarget) (<-chan derpDialResult, map[derpDialTarget]struct{}) {
	results := make(chan derpDialResult, len(targets))
	pending := make(map[derpDialTarget]struct{}, len(targets))
	for _, target := range targets {
		target := target
		pending[target] = struct{}{}
		go func() {
			conn, err := derpDialContext(ctx, logf, netMon, target.network, target.addr)
			select {
			case results <- derpDialResult{target: target, conn: conn, err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	return results, pending
}

func receiveDERPDialResult(ctx context.Context, results <-chan derpDialResult, pending map[derpDialTarget]struct{}, errs *[]error) (net.Conn, bool, error) {
	select {
	case res := <-results:
		return handleDERPDialResult(res, pending, errs)
	case <-ctx.Done():
		return nil, true, finishDERPDialErrors(pending, *errs, ctx.Err())
	}
}

func handleDERPDialResult(res derpDialResult, pending map[derpDialTarget]struct{}, errs *[]error) (net.Conn, bool, error) {
	delete(pending, res.target)
	if res.err == nil {
		return res.conn, true, nil
	}
	*errs = append(*errs, derpDialTargetError(res.target, res.err))
	return nil, false, nil
}

func finishDERPDialErrors(pending map[derpDialTarget]struct{}, errs []error, err error) error {
	for target := range pending {
		errs = append(errs, derpDialTargetError(target, err))
	}
	return errors.Join(errs...)
}

func derpDialTargetError(target derpDialTarget, err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Net == target.network && opErr.Addr != nil && opErr.Addr.String() == target.addr {
		return err
	}
	return fmt.Errorf("dial %s %s: %w", target.network, target.addr, err)
}

func derpDialContextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= derpDialTimeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, derpDialTimeout)
}

func (c *Client) PublicKey() key.NodePublic { return c.pub }

func (c *Client) ProxyInfo() (ProxyInfo, bool) {
	if c == nil || c.proxyInfo == nil {
		return ProxyInfo{}, false
	}
	return c.proxyInfo.Load()
}

func (c *Client) Close() error {
	if c == nil || c.dc == nil {
		return nil
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	err := c.dc.Close()
	<-c.doneCh
	return err
}

func (c *Client) Send(ctx context.Context, dst key.NodePublic, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.dc.Send(dst, payload)
}

func (c *Client) Subscribe(filter func(Packet) bool) (<-chan Packet, func()) {
	return c.subscribe(filter, subscriberLossy)
}

func (c *Client) SubscribeLossless(filter func(Packet) bool) (<-chan Packet, func()) {
	return c.subscribe(filter, subscriberLossless)
}

func (c *Client) subscribe(filter func(Packet) bool, mode subscriberMode) (<-chan Packet, func()) {
	ch := make(chan Packet, 16)
	if filter == nil {
		close(ch)
		return ch, func() {}
	}

	sub := &packetSubscriber{
		filter: filter,
		ch:     ch,
		mode:   mode,
	}
	if mode == subscriberLossless {
		sub.done = make(chan struct{})
		sub.queueReady = make(chan struct{}, 1)
		sub.queueSlots = make(chan struct{}, losslessSubscriberQueueSize)
		go sub.run(c.stopCh)
	}

	c.subMu.Lock()
	id := c.nextSubID
	c.nextSubID++
	c.subscribers[id] = sub
	c.subMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			c.subMu.Lock()
			sub, ok := c.subscribers[id]
			if ok {
				delete(c.subscribers, id)
			}
			c.subMu.Unlock()
			if ok {
				sub.close()
			}
		})
	}
}

func (c *Client) Receive(ctx context.Context) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}

	select {
	case pkt := <-c.packetCh:
		return pkt, nil
	default:
	}

	select {
	case pkt := <-c.packetCh:
		return pkt, nil
	case <-c.doneCh:
		select {
		case pkt := <-c.packetCh:
			return pkt, nil
		default:
		}
		return Packet{}, errors.New("derpbind client closed")
	case <-ctx.Done():
		return Packet{}, ctx.Err()
	}
}

func (c *Client) recvLoop() {
	defer close(c.doneCh)
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		msg, err := c.dc.Recv()
		if err != nil {
			if !c.waitAfterRecvError() {
				return
			}
			continue
		}
		c.handleDERPMessage(msg)
	}
}

func (c *Client) waitAfterRecvError() bool {
	select {
	case <-c.stopCh:
		return false
	default:
	}
	select {
	case <-time.After(10 * time.Millisecond):
		return true
	case <-c.stopCh:
		return false
	}
}

func (c *Client) handleDERPMessage(msg derp.ReceivedMessage) {
	pkt, ok := msg.(derp.ReceivedPacket)
	if !ok {
		c.handleDERPControlMessage(msg)
		return
	}
	out := Packet{
		From:    pkt.Source,
		Payload: append([]byte(nil), pkt.Data...),
	}
	if c.dispatchSubscriber(out) {
		return
	}
	c.enqueueFallback(out)
}

func (c *Client) handleDERPControlMessage(msg derp.ReceivedMessage) {
	ping, ok := msg.(derp.PingMessage)
	if !ok {
		return
	}
	pingData := [8]byte(ping)
	go func() {
		_ = c.dc.SendPong(pingData)
	}()
}

func (c *Client) enqueueFallback(pkt Packet) {
	select {
	case c.packetCh <- pkt:
		return
	case <-c.stopCh:
		return
	default:
	}

	select {
	case <-c.packetCh:
	default:
	}

	select {
	case c.packetCh <- pkt:
	case <-c.stopCh:
	default:
	}
}

func (c *Client) dispatchSubscriber(pkt Packet) bool {
	c.subMu.RLock()
	matches := make([]*packetSubscriber, 0, len(c.subscribers))
	for _, sub := range c.subscribers {
		if !sub.filter(pkt) {
			continue
		}
		matches = append(matches, sub)
	}
	c.subMu.RUnlock()

	delivered := false
	for _, sub := range matches {
		if c.tryDeliverSubscriber(sub, pkt) {
			delivered = true
		}
	}
	return delivered
}

func (c *Client) tryDeliverSubscriber(sub *packetSubscriber, pkt Packet) bool {
	if sub.mode == subscriberLossless {
		return sub.enqueue(c.stopCh, pkt)
	}
	return sub.tryDeliverLossy(c.stopCh, pkt)
}

func (s *packetSubscriber) enqueue(stopCh <-chan struct{}, pkt Packet) bool {
	select {
	case <-s.done:
		return false
	case <-stopCh:
		return false
	default:
	}

	select {
	case s.queueSlots <- struct{}{}:
	case <-s.done:
		return false
	case <-stopCh:
		return false
	}

	s.queueMu.Lock()
	if s.closed {
		s.queueMu.Unlock()
		<-s.queueSlots
		return false
	}
	s.queue = append(s.queue, pkt)
	s.queueMu.Unlock()

	select {
	case s.queueReady <- struct{}{}:
	default:
	}
	return true
}

func (s *packetSubscriber) close() {
	if s.mode == subscriberLossless {
		s.once.Do(func() {
			s.queueMu.Lock()
			s.closed = true
			s.queueMu.Unlock()
			close(s.done)
		})
		return
	}
	s.deliverMu.Lock()
	defer s.deliverMu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.ch)
}

func (s *packetSubscriber) run(stopCh <-chan struct{}) {
	defer s.once.Do(func() {
		close(s.ch)
	})
	for {
		pkt, ok := s.nextQueuedPacket(stopCh)
		if !ok {
			return
		}
		delivered := false
		select {
		case s.ch <- pkt:
			delivered = true
		case <-s.done:
		case <-stopCh:
		}
		if s.queueSlots != nil {
			<-s.queueSlots
		}
		if !delivered {
			return
		}
	}
}

func (s *packetSubscriber) nextQueuedPacket(stopCh <-chan struct{}) (Packet, bool) {
	for {
		s.queueMu.Lock()
		if len(s.queue) > 0 {
			pkt := s.queue[0]
			var zero Packet
			s.queue[0] = zero
			s.queue = s.queue[1:]
			s.queueMu.Unlock()
			return pkt, true
		}
		s.queueMu.Unlock()

		select {
		case <-s.queueReady:
		case <-s.done:
			return Packet{}, false
		case <-stopCh:
			return Packet{}, false
		}
	}
}

func (s *packetSubscriber) tryDeliverLossy(stopCh <-chan struct{}, pkt Packet) bool {
	s.deliverMu.Lock()
	defer s.deliverMu.Unlock()

	if s.closed {
		return false
	}

	select {
	case s.ch <- pkt:
		return true
	case <-stopCh:
		return true
	default:
	}

	if !s.dropLossyPacket(stopCh) {
		return true
	}

	if s.closed {
		return false
	}

	select {
	case s.ch <- pkt:
	case <-stopCh:
	}
	return true
}

func (s *packetSubscriber) dropLossyPacket(stopCh <-chan struct{}) bool {
	select {
	case <-s.ch:
		return true
	case <-stopCh:
		return false
	default:
		return true
	}
}
