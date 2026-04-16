package session

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/token"
)

var (
	attachMu       sync.Mutex
	attachSessions = map[string]*attachSession{}
)

var attachDialHook func()

type attachSession struct {
	mu     sync.Mutex
	closed bool
	conn   net.Conn
	wake   chan struct{}
	once   sync.Once
}

func newAttachSession() *attachSession {
	return &attachSession{
		wake: make(chan struct{}),
	}
}

func (s *attachSession) signal() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.wake)
	})
}

func issueLocalAttachToken() (string, *attachSession, error) {
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
		Capabilities: token.CapabilityAttach,
	})
	if err != nil {
		return "", nil, err
	}

	session := newAttachSession()
	attachMu.Lock()
	attachSessions[tok] = session
	attachMu.Unlock()
	return tok, session, nil
}

func removeAttachSession(tok string, session *attachSession) {
	attachMu.Lock()
	if attachSessions[tok] == session {
		delete(attachSessions, tok)
	}
	attachMu.Unlock()
}

func closeAttachSession(tok string, session *attachSession) {
	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return
	}
	session.closed = true
	session.mu.Unlock()

	removeAttachSession(tok, session)
	session.signal()
}

func ListenAttach(ctx context.Context, cfg AttachListenConfig) (*AttachListener, error) {
	if cfg.UsePublicDERP {
		return listenAttachExternal(ctx, cfg)
	}
	tok, session, err := issueLocalAttachToken()
	if err != nil {
		return nil, err
	}

	listener := &AttachListener{Token: tok}
	listener.accept = func(ctx context.Context) (net.Conn, error) {
		for {
			session.mu.Lock()
			if session.conn != nil {
				conn := session.conn
				session.conn = nil
				session.mu.Unlock()
				return conn, nil
			}
			if session.closed {
				session.mu.Unlock()
				return nil, net.ErrClosed
			}
			wake := session.wake
			session.mu.Unlock()

			select {
			case <-wake:
				continue
			case <-ctx.Done():
				session.mu.Lock()
				if session.conn != nil {
					conn := session.conn
					session.conn = nil
					session.mu.Unlock()
					return conn, nil
				}
				if session.closed {
					session.mu.Unlock()
					return nil, net.ErrClosed
				}
				session.mu.Unlock()
				return nil, ctx.Err()
			}
		}
	}
	listener.close = func() error {
		closeAttachSession(tok, session)
		return nil
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-session.wake:
		}
	}()

	return listener, nil
}

func DialAttach(ctx context.Context, cfg AttachDialConfig) (net.Conn, error) {
	if cfg.UsePublicDERP {
		tok, err := token.Decode(cfg.Token, time.Now())
		if err != nil {
			return nil, err
		}
		if tok.Capabilities&token.CapabilityAttach == 0 {
			return nil, ErrUnknownSession
		}
		return dialAttachExternal(ctx, cfg, tok)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	attachMu.Lock()
	session, ok := attachSessions[cfg.Token]
	attachMu.Unlock()
	if !ok {
		return nil, ErrUnknownSession
	}

	left, right := net.Pipe()
	if hook := attachDialHook; hook != nil {
		hook()
	}
	select {
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		return nil, ctx.Err()
	default:
	}

	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		_ = left.Close()
		_ = right.Close()
		return nil, net.ErrClosed
	}
	if session.conn != nil {
		session.mu.Unlock()
		_ = left.Close()
		_ = right.Close()
		return nil, ErrUnknownSession
	}

	removeAttachSession(cfg.Token, session)
	session.conn = right
	session.mu.Unlock()
	session.signal()

	return left, nil
}
