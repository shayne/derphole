package derphole

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/shayne/derpcat/pkg/derphole/protocol"
	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
)

type SendConfig struct {
	Token         string
	Text          string
	What          string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Emitter       *telemetry.Emitter
	UsePublicDERP bool
	ForceRelay    bool
}

type ReceiveConfig struct {
	Token         string
	Allocate      bool
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	PromptFor     func(io.Reader, io.Writer) (string, error)
	Emitter       *telemetry.Emitter
	UsePublicDERP bool
	ForceRelay    bool
}

func Send(ctx context.Context, cfg SendConfig) error {
	header, body, err := prepareSendTransfer(cfg)
	if err != nil {
		return err
	}

	if cfg.Token == "" {
		listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
			Emitter:       cfg.Emitter,
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
		})
		if err != nil {
			return err
		}
		defer listener.Close()

		header.Verify = VerificationString(listener.Token)
		WriteSendInstruction(cfg.Stderr, listener.Token)

		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()

		return writeTransfer(conn, header, body)
	}

	header.Verify = VerificationString(cfg.Token)
	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         cfg.Token,
		Emitter:       cfg.Emitter,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	return writeTransfer(conn, header, body)
}

func Receive(ctx context.Context, cfg ReceiveConfig) error {
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	if cfg.Allocate {
		listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
			Emitter:       cfg.Emitter,
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
		})
		if err != nil {
			return err
		}
		defer listener.Close()

		WriteReceiveToken(cfg.Stderr, listener.Token)

		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()

		return readTransfer(conn, listener.Token, cfg.Stdout)
	}

	token := cfg.Token
	if token == "" && cfg.PromptFor != nil {
		var err error
		token, err = cfg.PromptFor(stdin, cfg.Stderr)
		if err != nil {
			return err
		}
	}
	if token == "" {
		return errors.New("receive code is required")
	}

	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         token,
		Emitter:       cfg.Emitter,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	return readTransfer(conn, token, cfg.Stdout)
}

func prepareSendTransfer(cfg SendConfig) (protocol.Header, io.Reader, error) {
	if cfg.Text != "" {
		return protocol.Header{Version: 1, Kind: protocol.KindText}, strings.NewReader(cfg.Text), nil
	}
	if cfg.What != "" {
		if info, err := os.Stat(cfg.What); err == nil {
			if info.IsDir() {
				return protocol.Header{}, nil, errors.New("directory transfer is not implemented yet")
			}
			return protocol.Header{}, nil, errors.New("file transfer is not implemented yet")
		} else if !errors.Is(err, os.ErrNotExist) {
			return protocol.Header{}, nil, err
		}
		return protocol.Header{Version: 1, Kind: protocol.KindText}, strings.NewReader(cfg.What), nil
	}
	if cfg.Stdin != nil {
		return protocol.Header{Version: 1, Kind: protocol.KindText}, cfg.Stdin, nil
	}
	return protocol.Header{Version: 1, Kind: protocol.KindText}, strings.NewReader(""), nil
}

func writeTransfer(w io.Writer, header protocol.Header, body io.Reader) error {
	if err := protocol.WriteHeader(w, header); err != nil {
		return err
	}
	_, err := io.Copy(w, body)
	return err
}

func readTransfer(conn net.Conn, token string, stdout io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}

	reader := bufio.NewReader(conn)
	header, err := protocol.ReadHeader(reader)
	if err != nil {
		return err
	}
	if want := VerificationString(token); header.Verify != "" && header.Verify != want {
		return fmt.Errorf("verification mismatch: got %q, want %q", header.Verify, want)
	}

	switch header.Kind {
	case protocol.KindText:
		_, err = io.Copy(stdout, reader)
		return err
	case protocol.KindFile:
		return errors.New("file transfer is not implemented yet")
	case protocol.KindDirectoryTar:
		return errors.New("directory transfer is not implemented yet")
	default:
		return fmt.Errorf("unsupported derphole transfer kind %q", header.Kind)
	}
}
