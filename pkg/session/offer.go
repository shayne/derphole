// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"io"
)

func Offer(ctx context.Context, cfg OfferConfig) (string, error) {
	if cfg.UsePublicDERP {
		return offerExternal(ctx, cfg)
	}
	return offerLocal(ctx, cfg)
}

func offerLocal(ctx context.Context, cfg OfferConfig) (string, error) {
	tok, session, err := issueLocalOfferToken()
	if err != nil {
		return "", err
	}
	defer deleteOfferMailbox(tok, session)

	emitStatus(cfg.Emitter, StateWaiting)
	if err := emitListenToken(ctx, cfg.TokenSink, tok); err != nil {
		return tok, err
	}

	src, err := openSendSource(ctx, SendConfig{StdioIn: cfg.StdioIn})
	if err != nil {
		return tok, err
	}
	defer func() { _ = src.Close() }()

	if err := streamLocalOffer(ctx, cfg, session, src); err != nil {
		return tok, err
	}
	emitStatus(cfg.Emitter, StateComplete)
	return tok, nil
}

func streamLocalOffer(ctx context.Context, cfg OfferConfig, session *offerSession, src io.Reader) error {
	if err := waitLocalOfferAccepted(ctx, session); err != nil {
		return err
	}
	emitStatus(cfg.Emitter, StateDirect)
	if _, err := io.Copy(session.writer, src); err != nil {
		_ = session.writer.CloseWithError(err)
		return err
	}
	return session.writer.Close()
}

func waitLocalOfferAccepted(ctx context.Context, session *offerSession) error {
	select {
	case <-session.accepted:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func Receive(ctx context.Context, cfg ReceiveConfig) error {
	if session, ok := claimOfferMailbox(cfg.Token); ok {
		dst, err := openListenSink(ctx, ListenConfig{StdioOut: cfg.StdioOut})
		if err != nil {
			return err
		}
		defer func() { _ = dst.Close() }()

		emitStatus(cfg.Emitter, StateDirect)
		select {
		case <-session.accepted:
		default:
			close(session.accepted)
		}
		if _, err := io.Copy(dst, session.reader); err != nil {
			_ = session.reader.CloseWithError(err)
			return err
		}
		emitStatus(cfg.Emitter, StateComplete)
		return nil
	}

	if !cfg.UsePublicDERP {
		return ErrUnknownSession
	}
	return receiveExternal(ctx, cfg)
}

func openOfferSource(ctx context.Context, cfg OfferConfig) (io.ReadCloser, error) {
	return openSendSource(ctx, SendConfig{StdioIn: cfg.StdioIn})
}

func openReceiveSink(ctx context.Context, cfg ReceiveConfig) (io.WriteCloser, error) {
	return openListenSink(ctx, ListenConfig{StdioOut: cfg.StdioOut})
}
