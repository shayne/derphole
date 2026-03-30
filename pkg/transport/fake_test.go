package transport

import (
	"context"
	"encoding/json"
	"net"
	"slices"
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
	readAttempts       int
	readErrors         []error
	responderEndpoints map[string]net.Addr
	failWritesTo       map[string]int
	notify             chan struct{}
	closed             bool
	deadline           time.Time
	deadlineTimer      Timer
	clock              Clock
}

func newFakePacketConn(local net.Addr) *fakePacketConn {
	return &fakePacketConn{
		local:              local,
		responderEndpoints: make(map[string]net.Addr),
		failWritesTo:       make(map[string]int),
		notify:             make(chan struct{}),
		clock:              realClock{},
	}
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		c.readAttempts++
		if len(c.readErrors) > 0 {
			err := c.readErrors[0]
			c.readErrors = c.readErrors[1:]
			c.signalLocked()
			c.mu.Unlock()
			return 0, nil, err
		}
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

		if !deadline.IsZero() && !c.clock.Now().Before(deadline) {
			return 0, nil, timeoutErr{}
		}
		if deadline.IsZero() {
			<-waitCh
			continue
		}
		<-waitCh
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
	if c.failWritesTo[addr.String()] > 0 {
		c.failWritesTo[addr.String()]--
		c.signalLocked()
		return 0, net.ErrClosed
	}
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
	if c.deadlineTimer != nil {
		c.deadlineTimer.Stop()
		c.deadlineTimer = nil
	}
	c.deadline = t
	if !t.IsZero() {
		wait := t.Sub(c.clock.Now())
		if wait < 0 {
			wait = 0
		}
		c.deadlineTimer = c.clock.AfterFunc(wait, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.signalLocked()
		})
	}
	c.signalLocked()
	return nil
}

func (c *fakePacketConn) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error  { return nil }

func (c *fakePacketConn) useClock(clock Clock) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clock = clock
}

func (c *fakePacketConn) enableResponder(addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responderEndpoints[addr.String()] = cloneAddr(addr)
}

func (c *fakePacketConn) enableResponderAfter(clock *fakeClock, d time.Duration, addr net.Addr) {
	clock.AfterFunc(d, func() {
		c.enableResponder(addr)
	})
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

func waitForNotify(timeout time.Duration, snapshot func() (bool, <-chan struct{})) bool {
	if timeout <= 0 {
		ok, _ := snapshot()
		return ok
	}

	deadline := time.After(timeout)
	for {
		ok, waitCh := snapshot()
		if ok {
			return true
		}
		select {
		case <-waitCh:
		case <-deadline:
			ok, _ = snapshot()
			return ok
		}
	}
}

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
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		c.mu.Lock()
		count := 0
		for _, pkt := range c.writes {
			if pkt.addr.String() == addr.String() {
				count++
			}
		}
		if count >= n {
			c.mu.Unlock()
			return true, nil
		}
		if c.closed {
			c.mu.Unlock()
			return false, nil
		}
		waitCh := c.notify
		c.mu.Unlock()
		return false, waitCh
	})
}

func (c *fakePacketConn) waitForWritePayloadTo(addr net.Addr, payload []byte, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		c.mu.Lock()
		for _, pkt := range c.writes {
			if pkt.addr.String() == addr.String() && string(pkt.payload) == string(payload) {
				c.mu.Unlock()
				return true, nil
			}
		}
		if c.closed {
			c.mu.Unlock()
			return false, nil
		}
		waitCh := c.notify
		c.mu.Unlock()
		return false, waitCh
	})
}

func (c *fakePacketConn) clearWrites() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = nil
}

func (c *fakePacketConn) failNextWriteTo(addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failWritesTo[addr.String()]++
}

func (c *fakePacketConn) failNextRead(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readErrors = append(c.readErrors, err)
	c.signalLocked()
}

func (c *fakePacketConn) waitForReadAttempts(n int, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		c.mu.Lock()
		count := c.readAttempts
		if count >= n {
			c.mu.Unlock()
			return true, nil
		}
		waitCh := c.notify
		c.mu.Unlock()
		return false, waitCh
	})
}

func (c *fakePacketConn) readAttemptsCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readAttempts
}

type fakeControlPipe struct {
	mu              sync.Mutex
	inbound         chan []byte
	sent            []ControlMessage
	sendAttempts    map[ControlType]int
	receiveAttempts int
	receiveCount    int
	failNextByType  map[ControlType]int
	receiveErrors   int
	terminalErr     error
	blockByType     map[ControlType]chan struct{}
	peerCandidates  []string
	notify          chan struct{}
}

func newFakeControlPipe() *fakeControlPipe {
	return &fakeControlPipe{
		inbound:        make(chan []byte, 16),
		sendAttempts:   make(map[ControlType]int),
		failNextByType: make(map[ControlType]int),
		blockByType:    make(map[ControlType]chan struct{}),
		notify:         make(chan struct{}),
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
	p.sendAttempts[decoded.Type]++
	blockCh := p.blockByType[decoded.Type]
	if p.failNextByType[decoded.Type] > 0 {
		p.failNextByType[decoded.Type]--
		p.signalLocked()
		p.mu.Unlock()
		return context.DeadlineExceeded
	}
	p.sent = append(p.sent, decoded)
	peerCandidates := append([]string(nil), p.peerCandidates...)
	p.signalLocked()
	p.mu.Unlock()

	if blockCh != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-blockCh:
		}
	}

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
	p.mu.Lock()
	p.receiveAttempts++
	if p.terminalErr != nil {
		err := p.terminalErr
		p.signalLocked()
		p.mu.Unlock()
		return ControlMessage{}, err
	}
	if p.receiveErrors > 0 {
		p.receiveErrors--
		p.signalLocked()
		p.mu.Unlock()
		return ControlMessage{}, timeoutErr{}
	}
	p.mu.Unlock()

	select {
	case <-ctx.Done():
		return ControlMessage{}, ctx.Err()
	case wire := <-p.inbound:
		var msg ControlMessage
		if err := json.Unmarshal(wire, &msg); err != nil {
			return ControlMessage{}, err
		}
		p.mu.Lock()
		p.receiveCount++
		p.signalLocked()
		p.mu.Unlock()
		return msg, nil
	}
}

func (p *fakeControlPipe) deliver(msg ControlMessage, timeout time.Duration) bool {
	wire, err := json.Marshal(msg)
	if err != nil {
		return false
	}

	select {
	case p.inbound <- wire:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *fakeControlPipe) enablePeerCandidate(addr net.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peerCandidates = []string{addr.String()}
}

func (p *fakeControlPipe) enablePeerCandidateAfter(clock *fakeClock, d time.Duration, addr net.Addr) {
	clock.AfterFunc(d, func() {
		p.enablePeerCandidate(addr)
	})
}

func (p *fakeControlPipe) deliverAfter(clock *fakeClock, d time.Duration, msg ControlMessage) {
	clock.AfterFunc(d, func() {
		_ = p.deliver(msg, 50*time.Millisecond)
	})
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

func (p *fakeControlPipe) failNextSend(typ ControlType) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failNextByType[typ]++
}

func (p *fakeControlPipe) failNextReceive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.receiveErrors++
}

func (p *fakeControlPipe) closeReceive(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.terminalErr = err
	p.signalLocked()
}

func (p *fakeControlPipe) blockSend(typ ControlType) chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch := make(chan struct{})
	p.blockByType[typ] = ch
	return ch
}

func (p *fakeControlPipe) unblockSend(typ ControlType) {
	p.mu.Lock()
	ch := p.blockByType[typ]
	delete(p.blockByType, typ)
	p.signalLocked()
	p.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (p *fakeControlPipe) waitForSendAttempts(typ ControlType, n int, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		p.mu.Lock()
		count := p.sendAttempts[typ]
		if count >= n {
			p.mu.Unlock()
			return true, nil
		}
		waitCh := p.notify
		p.mu.Unlock()
		return false, waitCh
	})
}

func (p *fakeControlPipe) waitForReceiveCount(n int, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		p.mu.Lock()
		count := p.receiveCount
		if count >= n {
			p.mu.Unlock()
			return true, nil
		}
		waitCh := p.notify
		p.mu.Unlock()
		return false, waitCh
	})
}

func (p *fakeControlPipe) waitForReceiveAttempts(n int, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		p.mu.Lock()
		count := p.receiveAttempts
		if count >= n {
			p.mu.Unlock()
			return true, nil
		}
		waitCh := p.notify
		p.mu.Unlock()
		return false, waitCh
	})
}

func (p *fakeControlPipe) receiveAttemptsCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.receiveAttempts
}

func (p *fakeControlPipe) waitForReceiveErrorsDrained(timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		p.mu.Lock()
		remainingErrors := p.receiveErrors
		if remainingErrors == 0 {
			p.mu.Unlock()
			return true, nil
		}
		waitCh := p.notify
		p.mu.Unlock()
		return false, waitCh
	})
}

func (p *fakeControlPipe) waitForSentCount(typ ControlType, n int, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		p.mu.Lock()
		count := 0
		for _, msg := range p.sent {
			if msg.Type == typ {
				count++
			}
		}
		if count >= n {
			p.mu.Unlock()
			return true, nil
		}
		waitCh := p.notify
		p.mu.Unlock()
		return false, waitCh
	})
}

func (p *fakeControlPipe) waitForSentType(typ ControlType, timeout time.Duration) *ControlMessage {
	var found *ControlMessage
	if !waitForNotify(timeout, func() (bool, <-chan struct{}) {
		p.mu.Lock()
		for _, msg := range p.sent {
			if msg.Type == typ {
				copyMsg := msg
				p.mu.Unlock()
				found = &copyMsg
				return true, nil
			}
		}
		waitCh := p.notify
		p.mu.Unlock()
		return false, waitCh
	}) {
		return nil
	}
	return found
}

func (p *fakeControlPipe) lastSentType(typ ControlType) *ControlMessage {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := len(p.sent) - 1; i >= 0; i-- {
		if p.sent[i].Type == typ {
			copyMsg := p.sent[i]
			return &copyMsg
		}
	}
	return nil
}

func (p *fakeControlPipe) signalLocked() {
	next := make(chan struct{})
	close(p.notify)
	p.notify = next
}

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	notify  chan struct{}
	nextSeq int
}

type fakeTimer struct {
	clock   *fakeClock
	at      time.Time
	seq     int
	ch      chan time.Time
	fn      func()
	stopped bool
	fired   bool
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start, notify: make(chan struct{})}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) timerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	timer := &fakeTimer{
		clock: c,
		at:    c.now.Add(d),
		seq:   c.nextSeq,
		ch:    make(chan time.Time, 1),
	}
	c.nextSeq++
	c.timers = append(c.timers, timer)
	c.signalLocked()
	return timer.ch
}

func (c *fakeClock) AfterFunc(d time.Duration, fn func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()

	timer := &fakeTimer{
		clock: c,
		at:    c.now.Add(d),
		seq:   c.nextSeq,
		fn:    fn,
	}
	c.nextSeq++
	c.timers = append(c.timers, timer)
	c.signalLocked()
	return timer
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	due := make([]*fakeTimer, 0, len(c.timers))
	remaining := make([]*fakeTimer, 0, len(c.timers))
	for _, timer := range c.timers {
		if timer.stopped || timer.fired {
			continue
		}
		if !timer.at.After(now) {
			timer.fired = true
			due = append(due, timer)
			continue
		}
		remaining = append(remaining, timer)
	}
	slices.SortFunc(due, func(a, b *fakeTimer) int {
		switch {
		case a.at.Before(b.at):
			return -1
		case a.at.After(b.at):
			return 1
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		default:
			return 0
		}
	})
	c.timers = remaining
	c.signalLocked()
	c.mu.Unlock()

	for _, timer := range due {
		if timer.fn != nil {
			timer.fn()
			continue
		}
		timer.ch <- timer.at
	}
}

func (c *fakeClock) waitForTimerCountAtLeast(n int, timeout time.Duration) bool {
	return waitForNotify(timeout, func() (bool, <-chan struct{}) {
		c.mu.Lock()
		count := len(c.timers)
		if count >= n {
			c.mu.Unlock()
			return true, nil
		}
		waitCh := c.notify
		c.mu.Unlock()
		return false, waitCh
	})
}

func (c *fakeClock) signalLocked() {
	next := make(chan struct{})
	close(c.notify)
	c.notify = next
}

func (t *fakeTimer) Stop() bool {
	if t.clock != nil {
		t.clock.mu.Lock()
		defer t.clock.mu.Unlock()
	}
	if t.fired || t.stopped {
		return false
	}
	t.stopped = true
	return true
}
