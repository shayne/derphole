package wg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv6"
	"tailscale.com/net/batching"
	"tailscale.com/net/packet"
	"tailscale.com/net/sockopts"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
)

const wireGuardSocketBufferSize = 7 << 20
const derpDirectReceivePoll = 2 * time.Millisecond

type BindConfig struct {
	PacketConn     net.PacketConn
	Transport      string
	DERPClient     *derpbind.Client
	PeerDERP       key.NodePublic
	PathSelector   PathSelector
	DirectEndpoint string
}

type PathSelector interface {
	DirectPath() (endpoint string, active bool)
}

type directBreakReporter interface {
	MarkDirectBroken() error
}

type directActivityReporter interface {
	NoteDirectActivity(addr net.Addr)
}

type DirectPacketHandler interface {
	HandleDirectPacket(conn net.PacketConn, addr net.Addr, payload []byte) bool
}

type Bind struct {
	mu        sync.Mutex
	conn      net.PacketConn
	ownsConn  bool
	transport string
	derp      *derpbind.Client
	peerDERP  key.NodePublic
	selector  PathSelector
	state     *bindState
	opened    bool
	direct    directState
	sent      atomic.Int64
	received  atomic.Int64
}

type directState struct {
	addr *net.UDPAddr
	seen bool
}

type bindState struct {
	parent   *Bind
	conn     net.PacketConn
	pconn    nettype.PacketConn
	batched  batching.Conn
	derp     *derpbind.Client
	peerDERP key.NodePublic
	recvCh   chan inboundPacket
	errCh    chan error
	closeCtx context.Context
	closeFn  context.CancelFunc
	msgs     []ipv6.Message
}

type inboundPacket struct {
	payload []byte
	ep      *Endpoint
}

type Endpoint struct {
	dst      string
	addrPort netip.AddrPort
	ip       netip.Addr
}

func NewBind(cfg BindConfig) *Bind {
	b := &Bind{
		conn:      cfg.PacketConn,
		ownsConn:  cfg.PacketConn == nil,
		transport: cfg.Transport,
		derp:      cfg.DERPClient,
		peerDERP:  cfg.PeerDERP,
		selector:  cfg.PathSelector,
	}
	if cfg.DirectEndpoint != "" {
		_ = b.SetDirectEndpoint(cfg.DirectEndpoint)
	}
	return b
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opened {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.conn == nil {
		pc, err := net.ListenPacket("udp4", net.JoinHostPort("0.0.0.0", "0"))
		if err != nil {
			return nil, 0, err
		}
		b.conn = pc
		b.ownsConn = true
	} else {
		_ = b.conn.SetReadDeadline(time.Time{})
	}
	upgraded := upgradePacketConn(b.conn, b.transport, b.BatchSize())
	ctx, cancel := context.WithCancel(context.Background())
	state := &bindState{
		parent:   b,
		conn:     b.conn,
		pconn:    upgraded,
		derp:     b.derp,
		peerDERP: b.peerDERP,
		recvCh:   make(chan inboundPacket, 128),
		errCh:    make(chan error, 1),
		closeCtx: ctx,
		closeFn:  cancel,
	}
	if batched, ok := upgraded.(batching.Conn); ok {
		state.batched = batched
		state.msgs = makeReadBatch(b.BatchSize())
	}
	b.state = state
	b.opened = true

	if state.derp != nil && !state.peerDERP.IsZero() {
		go state.readDERP()
	}

	actualPort := uint16(0)
	if udpAddr, ok := b.conn.LocalAddr().(*net.UDPAddr); ok {
		actualPort = uint16(udpAddr.Port)
	}
	return []conn.ReceiveFunc{state.receive}, actualPort, nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	if !b.opened || b.state == nil {
		b.mu.Unlock()
		return nil
	}
	state := b.state
	pc := state.conn
	ownsConn := b.ownsConn
	b.state = nil
	if ownsConn {
		b.conn = nil
	}
	b.opened = false
	b.mu.Unlock()

	state.closeFn()
	if pc != nil && ownsConn {
		_ = pc.Close()
	} else if pc != nil {
		_ = pc.SetReadDeadline(time.Now())
	}
	return nil
}

func (b *Bind) SetMark(uint32) error { return nil }

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	pc := b.conn
	state := b.state
	b.mu.Unlock()

	directEndpoint, directConfirmed := b.directPath()
	directAddr := resolveUDPAddr(directEndpoint)
	sentCount := countNonEmptyPayloads(bufs, offset)
	if sentCount == 0 {
		return nil
	}

	if directAddr != nil {
		if pc == nil {
			return net.ErrClosed
		}
		if err := writePackets(state, pc, bufs, directAddr, offset); err != nil {
			if reporter, ok := b.selector.(directBreakReporter); ok {
				_ = reporter.MarkDirectBroken()
			}
			directConfirmed = false
			if state == nil || state.derp == nil || state.peerDERP.IsZero() {
				return err
			}
		} else {
			b.sent.Add(int64(sentCount))
			b.noteDirectActivity(directAddr)
		}
		if directConfirmed || state == nil || state.derp == nil || state.peerDERP.IsZero() {
			return nil
		}
	}

	if state != nil && state.derp != nil && !state.peerDERP.IsZero() {
		for _, buf := range bufs {
			payload := buf[offset:]
			if len(payload) == 0 {
				continue
			}
			if err := state.derp.Send(state.closeCtx, state.peerDERP, payload); err != nil {
				return err
			}
			b.sent.Add(1)
		}
		return nil
	}

	if endpoint, ok := ep.(*Endpoint); ok {
		addr, err := endpoint.udpAddr()
		if err != nil {
			return err
		}
		if addr == nil {
			return errors.New("wireguard bind has no active transport")
		}
		if pc == nil {
			return net.ErrClosed
		}
		if err := writePackets(state, pc, bufs, addr, offset); err != nil {
			return err
		}
		b.sent.Add(int64(sentCount))
		return nil
	}

	return errors.New("wireguard bind has no active transport")
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == "" || s == "derp" {
		return &Endpoint{dst: "derp"}, nil
	}
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	addrPort, ok := udpAddrPort(addr)
	if !ok {
		return nil, errors.New("invalid udp endpoint")
	}
	return &Endpoint{addrPort: addrPort, ip: addrPort.Addr()}, nil
}

func (b *Bind) BatchSize() int {
	if b.transport != "batched" {
		return 1
	}
	if runtime.GOOS == "linux" {
		return conn.IdealBatchSize
	}
	return 1
}

func (b *Bind) SetDirectEndpoint(s string) error {
	if s == "" {
		b.mu.Lock()
		b.direct = directState{}
		b.mu.Unlock()
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.direct = directState{addr: cloneUDPAddr(addr)}
	b.mu.Unlock()
	return nil
}

func (b *Bind) DirectEndpoint() string {
	endpoint, _ := b.directPath()
	return endpoint
}

func (s *bindState) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if s.derp == nil || s.peerDERP.IsZero() {
		if s.batched != nil {
			return s.receiveDirectBatch(packets, sizes, eps)
		}
		return s.receiveDirectUDP(packets, sizes, eps)
	}
	return s.receiveDERPMultiplexed(packets, sizes, eps)
}

func (s *bindState) receiveDERPMultiplexed(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for {
		if s.parent != nil && s.parent.directConfirmed() {
			n, err := s.receiveDirectWithTimeout(packets, sizes, eps, 0)
			if n > 0 || nonTimeoutErr(err) {
				return n, err
			}
		}

		select {
		case pkt := <-s.recvCh:
			return s.fillRelayReceiveBatch(packets, sizes, eps, pkt), nil
		case err := <-s.errCh:
			return 0, err
		case <-s.closeCtx.Done():
			return 0, net.ErrClosed
		default:
		}

		n, err := s.receiveDirectWithTimeout(packets, sizes, eps, derpDirectReceivePoll)
		if n > 0 || nonTimeoutErr(err) {
			return n, err
		}

		select {
		case pkt := <-s.recvCh:
			return s.fillRelayReceiveBatch(packets, sizes, eps, pkt), nil
		case err := <-s.errCh:
			return 0, err
		case <-s.closeCtx.Done():
			return 0, net.ErrClosed
		default:
		}
	}
}

func (s *bindState) receiveDirectWithTimeout(packets [][]byte, sizes []int, eps []conn.Endpoint, timeout time.Duration) (int, error) {
	if s.conn != nil && timeout > 0 {
		if err := s.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return 0, err
		}
		defer s.conn.SetReadDeadline(time.Time{})
	}
	if s.batched != nil {
		return s.receiveDirectBatch(packets, sizes, eps)
	}
	return s.receiveDirectUDP(packets, sizes, eps)
}

func (s *bindState) fillRelayReceiveBatch(packets [][]byte, sizes []int, eps []conn.Endpoint, pkt inboundPacket) int {
	n := fillReceivePacket(packets[0], sizes, eps, 0, pkt)
	for n < len(packets) {
		select {
		case pkt := <-s.recvCh:
			n = fillReceivePacket(packets[n], sizes, eps, n, pkt)
		default:
			return n
		}
	}
	return n
}

func nonTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return !errors.As(err, &netErr) || !netErr.Timeout()
}

func (s *bindState) receiveDirectBatch(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(s.msgs) < len(packets) {
		s.msgs = makeReadBatch(len(packets))
	}
	msgs := s.msgs[:len(packets)]
	for i := range msgs {
		msgs[i].Buffers[0] = packets[i]
		msgs[i].OOB = msgs[i].OOB[:cap(msgs[i].OOB)]
		msgs[i].N = 0
		msgs[i].NN = 0
		msgs[i].Flags = 0
		msgs[i].Addr = nil
		sizes[i] = 0
		eps[i] = nil
	}

	for {
		n, err := s.batched.ReadBatch(msgs, 0)
		if err != nil {
			if s.closeCtx.Err() != nil {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		reportToCaller := false
		for i := 0; i < n; i++ {
			msg := &msgs[i]
			if msg.N == 0 {
				continue
			}
			udpAddr, ok := msg.Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			payload := msg.Buffers[0][:msg.N]
			if handler, ok := s.parent.selector.(DirectPacketHandler); ok && handler.HandleDirectPacket(s.conn, udpAddr, payload) {
				continue
			}
			ip, ok := netip.AddrFromSlice(udpAddr.IP)
			if !ok {
				continue
			}
			s.parent.noteDirectValidation(udpAddr)
			s.parent.noteDirectActivity(udpAddr)
			s.parent.received.Add(1)
			sizes[i] = msg.N
			eps[i] = &Endpoint{addrPort: netip.AddrPortFrom(ip, uint16(udpAddr.Port)), ip: ip}
			reportToCaller = true
		}
		if reportToCaller {
			return n, nil
		}
	}
}

func (s *bindState) receiveDirectUDP(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	for {
		n, addr, err := s.conn.ReadFrom(packets[0])
		if err != nil {
			if s.closeCtx.Err() != nil {
				return 0, net.ErrClosed
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() && s.closeCtx.Err() != nil {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		if handler, ok := s.parent.selector.(DirectPacketHandler); ok && handler.HandleDirectPacket(s.conn, udpAddr, packets[0][:n]) {
			continue
		}
		ip, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			continue
		}
		s.parent.noteDirectValidation(udpAddr)
		s.parent.noteDirectActivity(udpAddr)
		s.parent.received.Add(1)
		sizes[0] = n
		eps[0] = &Endpoint{addrPort: netip.AddrPortFrom(ip, uint16(udpAddr.Port)), ip: ip}
		return 1, nil
	}
}

func (s *bindState) readDERP() {
	for {
		pkt, err := s.derp.Receive(s.closeCtx)
		if err != nil {
			if s.closeCtx.Err() != nil {
				return
			}
			s.reportErr(err)
			return
		}
		if pkt.From != s.peerDERP {
			continue
		}
		s.parent.received.Add(1)
		s.deliver(inboundPacket{
			payload: append([]byte(nil), pkt.Payload...),
			ep:      &Endpoint{dst: "derp"},
		})
	}
}

func (s *bindState) deliver(pkt inboundPacket) {
	select {
	case s.recvCh <- pkt:
	case <-s.closeCtx.Done():
	}
}

func (s *bindState) reportErr(err error) {
	select {
	case s.errCh <- err:
	default:
	}
}

func (b *Bind) activeDirectAddr() *net.UDPAddr {
	endpoint, _ := b.directPath()
	return resolveUDPAddr(endpoint)
}

func (b *Bind) directUDPAddr() *net.UDPAddr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return cloneUDPAddr(b.direct.addr)
}

func (b *Bind) directPath() (endpoint string, active bool) {
	if b.selector != nil {
		return b.selector.DirectPath()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.direct.addr == nil {
		return "", false
	}
	return b.direct.addr.String(), b.direct.seen
}

func (b *Bind) noteDirectValidation(addr *net.UDPAddr) {
	if b.selector != nil || addr == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if udpAddrsEqual(b.direct.addr, addr) {
		b.direct.seen = true
	}
}

func (b *Bind) noteDirectActivity(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	if reporter, ok := b.selector.(directActivityReporter); ok {
		reporter.NoteDirectActivity(addr)
	}
}

func (b *Bind) directConfirmed() bool {
	_, active := b.directPath()
	return active
}

func udpAddrsEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func resolveUDPAddr(endpoint string) *net.UDPAddr {
	if endpoint == "" {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil
	}
	return addr
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	if addr.IP != nil {
		clone.IP = append(net.IP(nil), addr.IP...)
	}
	return &clone
}

func (e *Endpoint) ClearSrc() {}

func (e *Endpoint) SrcToString() string { return "" }

func (e *Endpoint) DstToString() string {
	if e.dst != "" {
		return e.dst
	}
	if e.addrPort.IsValid() {
		return e.addrPort.String()
	}
	return ""
}

func (e *Endpoint) DstToBytes() []byte { return []byte(e.DstToString()) }

func (e *Endpoint) DstIP() netip.Addr { return e.ip }

func (e *Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (b *Bind) Stats() (sent, received int64) {
	return b.sent.Load(), b.received.Load()
}

func (b *Bind) DirectConfirmed() bool {
	return b.directConfirmed()
}

func (e *Endpoint) udpAddr() (*net.UDPAddr, error) {
	if e == nil {
		return nil, nil
	}
	if e.dst != "" {
		if e.dst == "derp" {
			return nil, nil
		}
		return net.ResolveUDPAddr("udp", e.dst)
	}
	if !e.addrPort.IsValid() {
		return nil, nil
	}
	return &net.UDPAddr{
		IP:   e.addrPort.Addr().AsSlice(),
		Port: int(e.addrPort.Port()),
		Zone: e.addrPort.Addr().Zone(),
	}, nil
}

func writePackets(state *bindState, pc net.PacketConn, bufs [][]byte, addr *net.UDPAddr, offset int) error {
	if len(bufs) == 0 || addr == nil {
		return nil
	}
	if state != nil && state.batched != nil {
		ap, ok := udpAddrPort(addr)
		if ok {
			return state.batched.WriteBatchTo(bufs, ap, packet.GeneveHeader{}, offset)
		}
	}
	for _, buf := range bufs {
		payload := buf[offset:]
		if len(payload) == 0 {
			continue
		}
		if _, err := pc.WriteTo(payload, addr); err != nil {
			return err
		}
	}
	return nil
}

func countNonEmptyPayloads(bufs [][]byte, offset int) int {
	count := 0
	for _, buf := range bufs {
		if len(buf[offset:]) > 0 {
			count++
		}
	}
	return count
}

func upgradePacketConn(pc net.PacketConn, transport string, batchSize int) nettype.PacketConn {
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return nil
	}
	if transport == "" {
		transport = "legacy"
	}
	_, _ = sockopts.SetBufferSize(udpConn, sockopts.ReadDirection, wireGuardSocketBufferSize)
	_, _ = sockopts.SetBufferSize(udpConn, sockopts.WriteDirection, wireGuardSocketBufferSize)
	if transport != "batched" {
		return udpConn
	}
	network := udpNetwork(udpConn.LocalAddr())
	if network == "" {
		return udpConn
	}
	return batching.TryUpgradeToConn(udpConn, network, batchSize)
}

func udpNetwork(addr net.Addr) string {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return ""
	}
	if udpAddr.IP == nil || udpAddr.IP.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

func makeReadBatch(batchSize int) []ipv6.Message {
	if batchSize < 1 {
		batchSize = 1
	}
	msgs := make([]ipv6.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, 64<<10)
		msgs[i].OOB = make([]byte, batching.MinControlMessageSize())
	}
	return msgs
}

func fillReceivePacket(dst []byte, sizes []int, eps []conn.Endpoint, idx int, pkt inboundPacket) int {
	n := copy(dst, pkt.payload)
	sizes[idx] = n
	eps[idx] = pkt.ep
	return idx + 1
}

func udpAddrPort(addr *net.UDPAddr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	ip = ip.Unmap()
	if addr.Zone != "" {
		ip = ip.WithZone(addr.Zone)
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port)), true
}
