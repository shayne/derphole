package session

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/shayne/derpcat/pkg/stream"
	"github.com/shayne/derpcat/pkg/token"
)

func Open(ctx context.Context, cfg OpenConfig) error {
	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	if tok.Capabilities&token.CapabilityShare == 0 {
		return ErrUnknownSession
	}
	if cfg.UsePublicDERP {
		return openExternal(ctx, cfg, tok)
	}

	session, ok := relayMailbox(cfg.Token)
	if !ok {
		return ErrUnknownSession
	}

	claim := shareClaim{
		path:   detectPath(ctx, cfg.ForceRelay, session.probeConn),
		tunnel: newLocalTunnel(),
	}
	if err := claimRelayShare(session, claim); err != nil {
		return err
	}
	defer claim.tunnel.Close()

	listener, err := openLocalListener(cfg, tok)
	if err != nil {
		return err
	}
	defer listener.Close()
	notifyBindAddr(cfg.BindAddrSink, listener.Addr().String(), ctx)

	emitStatus(cfg.Emitter, claim.path)
	return serveOpenListener(ctx, listener, func(ctx context.Context) (net.Conn, error) {
		return claim.tunnel.Dial(ctx)
	}, cfg.Emitter)
}

func claimRelayShare(session *relaySession, claim shareClaim) error {
	session.claimMu.Lock()
	defer session.claimMu.Unlock()
	if session.claimed {
		return ErrSessionClaimed
	}
	session.claimed = true
	session.shareClaimCh <- claim
	return nil
}

func openLocalListener(cfg OpenConfig, tok token.Token) (net.Listener, error) {
	addr := cfg.BindAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return net.Listen("tcp", addr)
}

func notifyBindAddr(sink chan<- string, addr string, ctx context.Context) {
	if sink == nil {
		return
	}
	select {
	case sink <- addr:
	case <-ctx.Done():
	}
}

func serveOpenListener(ctx context.Context, listener net.Listener, dial func(context.Context) (net.Conn, error), emitter interface{ Debug(string) }) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		clientConn, err := acceptNetListener(ctx, listener)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		overlayConn, err := dial(ctx)
		if err != nil {
			if emitter != nil {
				emitter.Debug("overlay-dial-failed")
			}
			_ = clientConn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer clientConn.Close()
			defer overlayConn.Close()
			_ = stream.Bridge(ctx, clientConn, overlayConn)
		}()
	}
}

func acceptNetListener(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		done <- result{conn: conn, err: err}
	}()
	select {
	case res := <-done:
		return res.conn, res.err
	case <-ctx.Done():
		_ = listener.Close()
		return nil, ctx.Err()
	}
}
