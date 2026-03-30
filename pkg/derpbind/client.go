package derpbind

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type Packet struct {
	From    key.NodePublic
	Payload []byte
}

type Client struct {
	pub      key.NodePublic
	dc       *derphttp.Client
	packetCh chan Packet
	stopCh   chan struct{}
	doneCh   chan struct{}

	subMu       sync.RWMutex
	subscribers map[uint64]packetSubscriber
	nextSubID   uint64
	stopOnce    sync.Once
}

type packetSubscriber struct {
	filter func(Packet) bool
	ch     chan Packet
}

func NewClient(ctx context.Context, node *tailcfg.DERPNode, serverURL string) (*Client, error) {
	if node == nil {
		return nil, errors.New("nil DERP node")
	}

	priv := key.NewNode()
	dc, err := derphttp.NewClient(priv, serverURL, func(string, ...any) {}, netmon.NewStatic())
	if err != nil {
		return nil, err
	}
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
		subscribers: make(map[uint64]packetSubscriber),
	}
	go c.recvLoop()
	return c, nil
}

func (c *Client) PublicKey() key.NodePublic { return c.pub }

func (c *Client) Close() error {
	if c == nil || c.dc == nil {
		return nil
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	return c.dc.Close()
}

func (c *Client) Send(ctx context.Context, dst key.NodePublic, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.dc.Send(dst, payload)
}

func (c *Client) Subscribe(filter func(Packet) bool) (<-chan Packet, func()) {
	ch := make(chan Packet, 16)
	if filter == nil {
		close(ch)
		return ch, func() {}
	}

	c.subMu.Lock()
	id := c.nextSubID
	c.nextSubID++
	c.subscribers[id] = packetSubscriber{
		filter: filter,
		ch:     ch,
	}
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
				close(sub.ch)
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
	defer c.subMu.RUnlock()
	for _, sub := range c.subscribers {
		if !sub.filter(pkt) {
			continue
		}
		select {
		case sub.ch <- pkt:
			return true
		case <-c.stopCh:
			return true
		}
	}
	return false
}
