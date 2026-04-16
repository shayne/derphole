package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/shayne/derphole/pkg/derphole/protocol"
	"github.com/shayne/derphole/pkg/session"
)

type InviteConfig struct {
	Listener       *session.AttachListener
	AuthorizedKeys string
}

type AcceptConfig struct {
	Token         string
	PublicKey     string
	UsePublicDERP bool
	ForceRelay    bool
}

func Invite(ctx context.Context, cfg InviteConfig) error {
	if cfg.Listener == nil {
		return fmt.Errorf("ssh invite listener is required")
	}

	conn, err := cfg.Listener.Accept(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := protocol.WriteHeader(conn, protocol.Header{
		Version: 1,
		Kind:    protocol.KindSSHInvite,
	}); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	hdr, err := protocol.ReadHeader(reader)
	if err != nil {
		return err
	}
	if hdr.Kind != protocol.KindSSHAccept {
		return fmt.Errorf("unexpected ssh response %q", hdr.Kind)
	}

	payload, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	return AppendAuthorizedKey(cfg.AuthorizedKeys, string(payload))
}

func Accept(ctx context.Context, cfg AcceptConfig) error {
	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         cfg.Token,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	hdr, err := protocol.ReadHeader(reader)
	if err != nil {
		return err
	}
	if hdr.Kind != protocol.KindSSHInvite {
		return fmt.Errorf("unexpected ssh request %q", hdr.Kind)
	}

	if err := protocol.WriteHeader(conn, protocol.Header{
		Version: 1,
		Kind:    protocol.KindSSHAccept,
	}); err != nil {
		return err
	}

	_, err = io.WriteString(conn, cfg.PublicKey)
	return err
}
