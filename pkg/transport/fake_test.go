package transport

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"
)

type packet struct {
	payload []byte
	addr    net.Addr
}

type fakePacketConn struct {
	mu                 sync.Mutex
	local              net.Addr
	reads              []packet
	writes             []packet
	responderEndpoints map[string]net.Addr
	notify             chan struct{}
	closed             bool
	deadline           time.Time
}

func newFakePacketConn(local net.Addr) *fakePacketConn {
	return &fakePacketConn{
		local:              local,
		responderEndpoints: make(map[string]net.Addr),
		notify:             make(chan struct{}),
	}
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if len(c.reads) > 0 {
			pkt := c.reads[0]
			c.reads = c.reads[1:]
			c.mu.Unlock()
			n := copy(b, pkt.payload)
			return n, pkt.addr, nil
		}
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := c.deadline
		waitCh := c.notify
		c.mu.Unlock()

		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, timeoutErr{}
		}
		if deadline.IsZero() {
			<-waitCh
			continue
		}

		delay := time.Until(deadline)
		if delay <= 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-waitCh:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (c *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}

	payload := append([]byte(nil), b...)
	c.writes = append(c.writes, packet{
		payload: payload,
		addr:    addr,
	})
	if string(payload) == string(discoProbePayload) {
		if responder, ok := c.responderEndpoints[addr.String()]; ok {
			c.reads = append(c.reads, packet{
				payload: append([]byte(nil), discoAckPayload...),
				addr:    cloneAddr(responder),
			})
		}
	}
	c.signalLocked()
	return len(b), nil
}

func (c *fakePacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.signalLocked()
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return c.local }

func (c *fakePacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	c.signalLocked()
	return nil
}

func (c *fakePacketConn) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error  { return nil }

func (c *fakePacketConn) enableResponder(addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responderEndpoints[addr.String()] = cloneAddr(addr)
}

func (c *fakePacketConn) enqueueRead(payload []byte, addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads = append(c.reads, packet{
		payload: append([]byte(nil), payload...),
		addr:    cloneAddr(addr),
	})
	c.signalLocked()
}

func (c *fakePacketConn) signalLocked() {
	next := make(chan struct{})
	close(c.notify)
	c.notify = next
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.PacketConn = (*fakePacketConn)(nil)
var _ error = timeoutErr{}

func (c *fakePacketConn) writeCountTo(addr net.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for _, pkt := range c.writes {
		if pkt.addr.String() == addr.String() {
			count++
		}
	}
	return count
}

func (c *fakePacketConn) waitForWriteCountTo(addr net.Addr, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		count := 0
		for _, pkt := range c.writes {
			if pkt.addr.String() == addr.String() {
				count++
			}
		}
		if count >= n {
			c.mu.Unlock()
			return true
		}
		if c.closed {
			c.mu.Unlock()
			return false
		}
		waitCh := c.notify
		c.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}

		timer := time.NewTimer(remaining)
		select {
		case <-waitCh:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (c *fakePacketConn) waitForWritePayloadTo(addr net.Addr, payload []byte, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		for _, pkt := range c.writes {
			if pkt.addr.String() == addr.String() && string(pkt.payload) == string(payload) {
				c.mu.Unlock()
				return true
			}
		}
		if c.closed {
			c.mu.Unlock()
			return false
		}
		waitCh := c.notify
		c.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-waitCh:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

type fakeControlPipe struct {
	mu             sync.Mutex
	inbound        chan []byte
	sent           []ControlMessage
	peerCandidates []string
	notify         chan struct{}
}

func newFakeControlPipe() *fakeControlPipe {
	return &fakeControlPipe{
		inbound: make(chan []byte, 16),
		notify:  make(chan struct{}),
	}
}

func (p *fakeControlPipe) send(ctx context.Context, msg ControlMessage) error {
	wire, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	var decoded ControlMessage
	if err := json.Unmarshal(wire, &decoded); err != nil {
		return err
	}

	p.mu.Lock()
	p.sent = append(p.sent, decoded)
	peerCandidates := append([]string(nil), p.peerCandidates...)
	p.signalLocked()
	p.mu.Unlock()

	if decoded.Type == ControlCallMeMaybe && len(peerCandidates) > 0 {
		if p.deliver(ControlMessage{
			Type:       ControlCandidates,
			Candidates: peerCandidates,
		}, 50*time.Millisecond) {
			return nil
		}
		return context.DeadlineExceeded
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (p *fakeControlPipe) receive(ctx context.Context) (ControlMessage, error) {
	select {
	case <-ctx.Done():
		return ControlMessage{}, ctx.Err()
	case wire := <-p.inbound:
		var msg ControlMessage
		if err := json.Unmarshal(wire, &msg); err != nil {
			return ControlMessage{}, err
		}
		return msg, nil
	}
}

func (p *fakeControlPipe) deliver(msg ControlMessage, timeout time.Duration) bool {
	wire, err := json.Marshal(msg)
	if err != nil {
		return false
	}

	timer := time.NewTimer(timeout)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	select {
	case p.inbound <- wire:
		return true
	case <-timer.C:
		return false
	}
}

func (p *fakeControlPipe) enablePeerCandidate(addr net.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peerCandidates = []string{addr.String()}
}

func (p *fakeControlPipe) sentCount(typ ControlType) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	count := 0
	for _, msg := range p.sent {
		if msg.Type == typ {
			count++
		}
	}
	return count
}

func (p *fakeControlPipe) waitForSentCount(typ ControlType, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		count := 0
		for _, msg := range p.sent {
			if msg.Type == typ {
				count++
			}
		}
		if count >= n {
			p.mu.Unlock()
			return true
		}
		waitCh := p.notify
		p.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-waitCh:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (p *fakeControlPipe) waitForSentType(typ ControlType, timeout time.Duration) *ControlMessage {
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		for _, msg := range p.sent {
			if msg.Type == typ {
				copyMsg := msg
				p.mu.Unlock()
				return &copyMsg
			}
		}
		waitCh := p.notify
		p.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		timer := time.NewTimer(remaining)
		select {
		case <-waitCh:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (p *fakeControlPipe) signalLocked() {
	next := make(chan struct{})
	close(p.notify)
	p.notify = next
}
