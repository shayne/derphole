package wg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shayne/derpcat/pkg/derpbind"
	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/key"
)

type BindConfig struct {
	PacketConn     net.PacketConn
	DERPClient     *derpbind.Client
	PeerDERP       key.NodePublic
	PathSelector   PathSelector
	DirectEndpoint string
}

type PathSelector interface {
	DirectPath() (endpoint string, active bool)
}

type Bind struct {
	mu       sync.Mutex
	conn     net.PacketConn
	ownsConn bool
	derp     *derpbind.Client
	peerDERP key.NodePublic
	selector PathSelector
	state    *bindState
	opened   bool
	direct   directState
	sent     atomic.Int64
	received atomic.Int64
}

type directState struct {
	addr *net.UDPAddr
	seen bool
}

type bindState struct {
	parent   *Bind
	conn     net.PacketConn
	derp     *derpbind.Client
	peerDERP key.NodePublic
	recvCh   chan inboundPacket
	errCh    chan error
	closeCtx context.Context
	closeFn  context.CancelFunc
}

type inboundPacket struct {
	payload []byte
	ep      *Endpoint
}

type Endpoint struct {
	dst string
	ip  netip.Addr
}

func NewBind(cfg BindConfig) *Bind {
	b := &Bind{
		conn:     cfg.PacketConn,
		ownsConn: cfg.PacketConn == nil,
		derp:     cfg.DERPClient,
		peerDERP: cfg.PeerDERP,
		selector: cfg.PathSelector,
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
	ctx, cancel := context.WithCancel(context.Background())
	state := &bindState{
		parent:   b,
		conn:     b.conn,
		derp:     b.derp,
		peerDERP: b.peerDERP,
		recvCh:   make(chan inboundPacket, 128),
		errCh:    make(chan error, 1),
		closeCtx: ctx,
		closeFn:  cancel,
	}
	b.state = state
	b.opened = true

	go state.readUDP()
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

	for _, buf := range bufs {
		payload := buf[offset:]
		if len(payload) == 0 {
			continue
		}

		if directAddr != nil {
			if pc == nil {
				return net.ErrClosed
			}
			if _, err := pc.WriteTo(payload, directAddr); err != nil {
				if state == nil || state.derp == nil || state.peerDERP.IsZero() {
					return err
				}
			}
			b.sent.Add(1)
			if directConfirmed || state == nil || state.derp == nil || state.peerDERP.IsZero() {
				continue
			}
		}

		if state != nil && state.derp != nil && !state.peerDERP.IsZero() {
			if err := state.derp.Send(state.closeCtx, state.peerDERP, payload); err != nil {
				return err
			}
			b.sent.Add(1)
			continue
		}

		if endpoint, ok := ep.(*Endpoint); ok && endpoint.dst != "" {
			addr, err := net.ResolveUDPAddr("udp", endpoint.dst)
			if err != nil {
				return err
			}
			if pc == nil {
				return net.ErrClosed
			}
			if _, err := pc.WriteTo(payload, addr); err != nil {
				return err
			}
			b.sent.Add(1)
			continue
		}

		return errors.New("wireguard bind has no active transport")
	}
	return nil
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == "" || s == "derp" {
		return &Endpoint{dst: "derp"}, nil
	}
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{dst: addr.String(), ip: netip.MustParseAddr(addr.IP.String())}, nil
}

func (b *Bind) BatchSize() int { return 1 }

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
	select {
	case pkt := <-s.recvCh:
		n := copy(packets[0], pkt.payload)
		sizes[0] = n
		eps[0] = pkt.ep
		return 1, nil
	case err := <-s.errCh:
		return 0, err
	case <-s.closeCtx.Done():
		return 0, net.ErrClosed
	}
}

func (s *bindState) readUDP() {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if s.closeCtx.Err() != nil {
				return
			}
			s.reportErr(err)
			return
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(udpAddr.IP); ok {
			s.parent.noteDirectValidation(udpAddr)
			s.parent.received.Add(1)
			s.deliver(inboundPacket{
				payload: append([]byte(nil), buf[:n]...),
				ep:      &Endpoint{dst: udpAddr.String(), ip: ip},
			})
		}
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

func (e *Endpoint) DstToString() string { return e.dst }

func (e *Endpoint) DstToBytes() []byte { return []byte(e.dst) }

func (e *Endpoint) DstIP() netip.Addr { return e.ip }

func (e *Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (b *Bind) Stats() (sent, received int64) {
	return b.sent.Load(), b.received.Load()
}

func (b *Bind) DirectConfirmed() bool {
	return b.directConfirmed()
}
