package session

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/shayne/derpcat/pkg/token"
)

var (
	attachMu       sync.Mutex
	attachSessions = map[string]*attachSession{}
)

type attachSession struct {
	mailbox chan net.Conn
	closed  chan struct{}
	once    sync.Once
}

func newAttachSession() *attachSession {
	return &attachSession{
		mailbox: make(chan net.Conn),
		closed:  make(chan struct{}),
	}
}

func (s *attachSession) close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.closed)
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

func finishAttachSession(tok string, session *attachSession) {
	if session == nil {
		return
	}
	attachMu.Lock()
	if attachSessions[tok] == session {
		delete(attachSessions, tok)
	}
	attachMu.Unlock()
	session.close()
}

func ListenAttach(ctx context.Context, cfg AttachListenConfig) (*AttachListener, error) {
	tok, session, err := issueLocalAttachToken()
	if err != nil {
		return nil, err
	}

	listener := &AttachListener{Token: tok}
	listener.accept = func(ctx context.Context) (net.Conn, error) {
		select {
		case conn := <-session.mailbox:
			finishAttachSession(tok, session)
			return conn, nil
		case <-session.closed:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	listener.close = func() error {
		finishAttachSession(tok, session)
		return nil
	}
	return listener, nil
}

func DialAttach(ctx context.Context, cfg AttachDialConfig) (net.Conn, error) {
	attachMu.Lock()
	session, ok := attachSessions[cfg.Token]
	attachMu.Unlock()
	if !ok {
		return nil, ErrUnknownSession
	}

	left, right := net.Pipe()
	select {
	case session.mailbox <- right:
		finishAttachSession(cfg.Token, session)
		return left, nil
	case <-session.closed:
		_ = left.Close()
		_ = right.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = left.Close()
		_ = right.Close()
		return nil, ctx.Err()
	}
}
