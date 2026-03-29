package derpbind

import (
	"context"
	"errors"
	"fmt"
	"sync"

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

	mu          sync.Mutex
	terminalErr error
	stopOnce    sync.Once
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
		pub:      priv.Public(),
		dc:       dc,
		packetCh: make(chan Packet, 16),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
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
		if err := c.recvErr(); err != nil {
			return Packet{}, err
		}
		return Packet{}, errors.New("derpbind client closed")
	case <-ctx.Done():
		return Packet{}, ctx.Err()
	}
}

func (c *Client) recvLoop() {
	defer close(c.doneCh)
	for {
		msg, err := c.dc.Recv()
		if err != nil {
			c.setRecvErr(err)
			return
		}
		pkt, ok := msg.(derp.ReceivedPacket)
		if !ok {
			continue
		}
		out := Packet{
			From:    pkt.Source,
			Payload: append([]byte(nil), pkt.Data...),
		}
		select {
		case c.packetCh <- out:
		case <-c.stopCh:
			return
		}
	}
}

func (c *Client) setRecvErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.terminalErr = err
}

func (c *Client) recvErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminalErr
}
