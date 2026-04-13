package derpbind

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	pub      key.NodePublic
	dc       derpClientConn
	packetCh chan Packet
	stopCh   chan struct{}
	doneCh   chan struct{}

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

	deliverMu sync.Mutex
	closed    bool
}

type subscriberMode uint8

const (
	subscriberLossy subscriberMode = iota
	subscriberLossless
)

const losslessSubscriberQueueSize = 64

func NewClient(ctx context.Context, node *tailcfg.DERPNode, serverURL string) (*Client, error) {
	if node == nil {
		return nil, errors.New("nil DERP node")
	}

	priv := key.NewNode()
	logf := logger.Logf(func(string, ...any) {})
	netMon := netmon.NewStatic()
	dc, err := derphttp.NewClient(priv, serverURL, logf, netMon)
	if err != nil {
		return nil, err
	}
	dc.SetURLDialer(newDERPNodeDialer(node, logf, netMon))
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
		subscribers: make(map[uint64]*packetSubscriber),
	}
	go c.recvLoop()
	return c, nil
}

type derpDialTarget struct {
	network string
	addr    string
}

func newDERPNodeDialer(node *tailcfg.DERPNode, logf logger.Logf, netMon *netmon.Monitor) func(context.Context, string, string) (net.Conn, error) {
	if node == nil {
		return nil
	}
	if netMon == nil {
		panic("nil netMon")
	}
	return func(ctx context.Context, _ string, addr string) (net.Conn, error) {
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
}

func derpDialTargets(node *tailcfg.DERPNode, host, port string) ([]derpDialTarget, bool) {
	if node == nil {
		return nil, false
	}
	add := func(targets []derpDialTarget, network, host, port string) []derpDialTarget {
		return append(targets, derpDialTarget{
			network: network,
			addr:    net.JoinHostPort(host, port),
		})
	}
	var targets []derpDialTarget
	explicitDisable := false

	if host == node.HostName {
		switch ip := net.ParseIP(node.IPv4); {
		case ip != nil && ip.To4() != nil:
			targets = add(targets, "tcp4", ip.String(), port)
		case node.IPv4 == "":
			targets = add(targets, "tcp4", host, port)
		default:
			explicitDisable = true
		}
		switch ip := net.ParseIP(node.IPv6); {
		case ip != nil && ip.To4() == nil:
			targets = add(targets, "tcp6", ip.String(), port)
		case node.IPv6 == "":
			targets = add(targets, "tcp6", host, port)
		default:
			explicitDisable = true
		}
		return targets, explicitDisable
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			targets = add(targets, "tcp4", ip.String(), port)
			return targets, false
		}
		targets = add(targets, "tcp6", ip.String(), port)
		return targets, false
	}

	targets = add(targets, "tcp4", host, port)
	targets = add(targets, "tcp6", host, port)
	return targets, false
}

func raceDERPDial(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor, targets []derpDialTarget) (net.Conn, error) {
	if len(targets) == 0 {
		return nil, errors.New("no DERP dial targets")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dialer := netns.NewDialer(logf, netMon)
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(targets))
	for _, target := range targets {
		target := target
		go func() {
			conn, err := dialer.DialContext(ctx, target.network, target.addr)
			select {
			case results <- result{conn: conn, err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}

	var firstErr error
	for range targets {
		res := <-results
		if res.err == nil {
			return res.conn, nil
		}
		if firstErr == nil {
			firstErr = res.err
		}
	}
	if firstErr == nil {
		firstErr = context.Canceled
	}
	return nil, firstErr
}

func (c *Client) PublicKey() key.NodePublic { return c.pub }

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
			select {
			case <-c.stopCh:
				return
			default:
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-c.stopCh:
				return
			}
			continue
		}
		pkt, ok := msg.(derp.ReceivedPacket)
		if !ok {
			if ping, ok := msg.(derp.PingMessage); ok {
				pingData := [8]byte(ping)
				go func() {
					_ = c.dc.SendPong(pingData)
				}()
			}
			continue
		}
		out := Packet{
			From:    pkt.Source,
			Payload: append([]byte(nil), pkt.Data...),
		}
		if c.dispatchSubscriber(out) {
			continue
		}
		select {
		case c.packetCh <- out:
		case <-c.stopCh:
			return
		}
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

	s.queueMu.Lock()
	if s.closed {
		s.queueMu.Unlock()
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
		select {
		case s.ch <- pkt:
		case <-s.done:
			return
		case <-stopCh:
			return
		}
	}
}

func (s *packetSubscriber) nextQueuedPacket(stopCh <-chan struct{}) (Packet, bool) {
	for {
		s.queueMu.Lock()
		if len(s.queue) > 0 {
			pkt := s.queue[0]
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

	select {
	case <-s.ch:
	case <-stopCh:
		return true
	default:
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
