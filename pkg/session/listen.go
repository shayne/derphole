package session

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/quicpath"
	"github.com/shayne/derphole/pkg/rendezvous"
	"github.com/shayne/derphole/pkg/token"
	"tailscale.com/tailcfg"
)

var (
	relayMu        sync.Mutex
	relayMailboxes = map[string]*relaySession{}
	offerMu        sync.Mutex
	offerMailboxes = map[string]*offerSession{}
)

type relayMessage struct {
	payload []byte
	ack     chan error
	path    State
}

type offerSession struct {
	probeConn net.PacketConn
	accepted  chan struct{}
	reader    *io.PipeReader
	writer    *io.PipeWriter
	closeOnce sync.Once
	claimed   bool
}

type relaySession struct {
	mailbox      chan relayMessage
	probeConn    net.PacketConn
	derp         *derpbind.Client
	token        token.Token
	gate         *rendezvous.Gate
	derpMap      *tailcfg.DERPMap
	quicIdentity quicpath.SessionIdentity
	wgPrivate    [32]byte
	wgPublic     [32]byte
	claimMu      sync.Mutex
	claimed      bool
	shareClaimCh chan shareClaim
}

func issueLocalSessionToken(capabilities uint32) (string, net.PacketConn, error) {
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
		Capabilities: capabilities,
	})
	if err != nil {
		return "", nil, err
	}

	var probeConn net.PacketConn
	probeConn, _ = net.ListenPacket("udp", "127.0.0.1:0")
	return tok, probeConn, nil
}

func issueLocalToken() (string, *relaySession, error) {
	tok, probeConn, err := issueLocalSessionToken(token.CapabilityStdio)
	if err != nil {
		return "", nil, err
	}
	session := &relaySession{
		mailbox:   make(chan relayMessage),
		probeConn: probeConn,
	}
	relayMu.Lock()
	relayMailboxes[tok] = session
	relayMu.Unlock()
	return tok, session, nil
}

func issueLocalOfferToken() (string, *offerSession, error) {
	tok, probeConn, err := issueLocalSessionToken(token.CapabilityStdioOffer)
	if err != nil {
		return "", nil, err
	}
	reader, writer := io.Pipe()
	session := &offerSession{
		probeConn: probeConn,
		accepted:  make(chan struct{}),
		reader:    reader,
		writer:    writer,
	}
	offerMu.Lock()
	offerMailboxes[tok] = session
	offerMu.Unlock()
	return tok, session, nil
}

func deleteRelayMailbox(tok string, session *relaySession) {
	var probeConn net.PacketConn

	relayMu.Lock()
	if relayMailboxes[tok] == session {
		delete(relayMailboxes, tok)
		probeConn = session.probeConn
	}
	relayMu.Unlock()

	if probeConn != nil {
		_ = probeConn.Close()
	}
}

func claimOfferMailbox(tok string) (*offerSession, bool) {
	offerMu.Lock()
	defer offerMu.Unlock()
	session, ok := offerMailboxes[tok]
	if ok {
		session.claimed = true
		delete(offerMailboxes, tok)
	}
	return session, ok
}

func closeOfferSession(session *offerSession) {
	if session == nil {
		return
	}
	session.closeOnce.Do(func() {
		if session.reader != nil && !session.claimed {
			_ = session.reader.Close()
		}
		if session.writer != nil {
			_ = session.writer.Close()
		}
		if session.probeConn != nil {
			_ = session.probeConn.Close()
		}
	})
}

func deleteOfferMailbox(tok string, session *offerSession) {
	offerMu.Lock()
	if offerMailboxes[tok] == session {
		delete(offerMailboxes, tok)
	}
	offerMu.Unlock()

	closeOfferSession(session)
}

func Listen(ctx context.Context, cfg ListenConfig) (string, error) {
	if cfg.UsePublicDERP {
		return listenExternal(ctx, cfg)
	}

	tok, session, err := issueLocalToken()
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

	select {
	case msg := <-session.mailbox:
		path := msg.path
		if path == "" {
			path = StateRelay
		}
		emitStatus(cfg.Emitter, path)
		dst, err := openListenSink(ctx, cfg)
		if err == nil {
			_, err = dst.Write(msg.payload)
			closeErr := dst.Close()
			if err == nil {
				err = closeErr
			}
		}
		msg.ack <- err
		if err != nil {
			return tok, err
		}
		emitStatus(cfg.Emitter, StateComplete)
		return tok, nil
	case <-ctx.Done():
		return tok, ctx.Err()
	}
}
