package session

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/stream"
	"github.com/shayne/derphole/pkg/token"
)

var ErrSessionClaimed = errors.New("session already claimed")

type shareClaim struct {
	path   State
	tunnel *localTunnel
}

type localTunnel struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newLocalTunnel() *localTunnel {
	return &localTunnel{
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (t *localTunnel) Dial(ctx context.Context) (net.Conn, error) {
	left, right := net.Pipe()
	select {
	case t.conns <- right:
		return left, nil
	case <-t.closed:
		_ = left.Close()
		_ = right.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		return nil, ctx.Err()
	}
}

func (t *localTunnel) Accept(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-t.conns:
		return conn, nil
	case <-t.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *localTunnel) Close() {
	t.once.Do(func() {
		close(t.closed)
	})
}

func issueLocalShareToken(cfg ShareConfig) (string, *relaySession, error) {
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return "", nil, err
	}

	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		return "", nil, err
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		SessionID:    sessionID,
		ExpiresUnix:  time.Now().Add(time.Hour).Unix(),
		BearerSecret: bearerSecret,
		Capabilities: token.CapabilityShare,
	})
	if err != nil {
		return "", nil, err
	}

	var probeConn net.PacketConn
	probeConn, _ = net.ListenPacket("udp", "127.0.0.1:0")

	session := &relaySession{
		mailbox:      make(chan relayMessage),
		probeConn:    probeConn,
		shareClaimCh: make(chan shareClaim, 1),
	}
	relayMu.Lock()
	relayMailboxes[tok] = session
	relayMu.Unlock()
	return tok, session, nil
}

func Share(ctx context.Context, cfg ShareConfig) (string, error) {
	if cfg.UsePublicDERP {
		return shareExternal(ctx, cfg)
	}

	tok, session, err := issueLocalShareToken(cfg)
	if err != nil {
		return "", err
	}
	defer deleteRelayMailbox(tok, session)

	emitStatus(cfg.Emitter, StateWaiting)
	if cfg.TokenSink != nil {
		select {
		case cfg.TokenSink <- tok:
		case <-ctx.Done():
			return tok, ctx.Err()
		}
	}

	var claim shareClaim
	select {
	case claim = <-session.shareClaimCh:
	case <-ctx.Done():
		return tok, ctx.Err()
	}

	emitStatus(cfg.Emitter, StateClaimed)
	emitStatus(cfg.Emitter, claim.path)
	return tok, serveSharedTarget(ctx, cfg, claim.tunnel)
}

func serveSharedTarget(ctx context.Context, cfg ShareConfig, tunnel *localTunnel) error {
	for {
		overlayConn, err := tunnel.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		backendConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.TargetAddr)
		if err != nil {
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("backend-dial-failed")
			}
			_ = overlayConn.Close()
			continue
		}

		go func() {
			defer overlayConn.Close()
			defer backendConn.Close()
			_ = stream.Bridge(ctx, overlayConn, backendConn)
		}()
	}
}
