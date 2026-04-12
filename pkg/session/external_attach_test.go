package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/token"
)

func TestListenAttachAndDialAttachExternalRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	tok, err := token.Decode(listener.Token, time.Now())
	if err != nil {
		t.Fatalf("token.Decode() error = %v", err)
	}
	if tok.Capabilities&token.CapabilityAttach == 0 {
		t.Fatalf("token capabilities = %v, want CapabilityAttach", tok.Capabilities)
	}
	if tok.Capabilities&token.CapabilityShare != 0 {
		t.Fatalf("token capabilities = %v, want CapabilityShare cleared", tok.Capabilities)
	}
	if tok.BootstrapRegion == 0 {
		t.Fatalf("token bootstrap region = %d, want public DERP bootstrap region", tok.BootstrapRegion)
	}
	if tok.DERPPublic == ([32]byte{}) {
		t.Fatal("token DERP public key = zero, want public DERP token")
	}
	if tok.QUICPublic == ([32]byte{}) {
		t.Fatal("token QUIC public key = zero, want public attach token")
	}

	errCh := make(chan error, 1)
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		payload, err := io.ReadAll(conn)
		if err != nil {
			errCh <- err
			return
		}
		received <- payload
	}()

	conn, err := DialAttach(ctx, AttachDialConfig{
		Token:         listener.Token,
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("DialAttach() error = %v", err)
	}
	if _, err := conn.Write([]byte("hello external attach")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Accept/read error = %v", err)
	case payload := <-received:
		if !bytes.Equal(payload, []byte("hello external attach")) {
			t.Fatalf("payload = %q, want %q", payload, "hello external attach")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for payload")
	}
}

func TestListenAttachAndDialAttachExternalReverseRoundTrip(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("hello external attach back"))
		errCh <- err
	}()

	conn, err := DialAttach(ctx, AttachDialConfig{
		Token:         listener.Token,
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("DialAttach() error = %v", err)
	}
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(payload, []byte("hello external attach back")) {
		t.Fatalf("payload = %q, want %q", payload, "hello external attach back")
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Accept/write error = %v", err)
	}
}

func TestListenAttachAndDialAttachExternalIsOneShot(t *testing.T) {
	srv := newSessionTestDERPServer(t)
	t.Setenv("DERPCAT_TEST_DERP_MAP_URL", srv.MapURL)
	t.Setenv("DERPCAT_TEST_DERP_SERVER_URL", srv.DERPURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	release := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		close(accepted)
		<-release
		errCh <- nil
	}()

	firstConn, err := DialAttach(ctx, AttachDialConfig{
		Token:         listener.Token,
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err != nil {
		t.Fatalf("first DialAttach() error = %v", err)
	}
	defer firstConn.Close()

	select {
	case <-accepted:
	case err := <-errCh:
		t.Fatalf("Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for first attach accept")
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	_, err = DialAttach(secondCtx, AttachDialConfig{
		Token:         listener.Token,
		ForceRelay:    true,
		UsePublicDERP: true,
	})
	if err == nil {
		t.Fatal("second DialAttach() error = nil, want rejection")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("second DialAttach() error = %v, want immediate rejection", err)
	}
	if !strings.Contains(err.Error(), "claimed") {
		t.Fatalf("second DialAttach() error = %v, want claimed rejection", err)
	}

	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("accept goroutine error = %v", err)
	}
}
