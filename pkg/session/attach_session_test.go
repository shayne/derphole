// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestListenAttachAndDialAttachLocalRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	received := make(chan []byte, 1)
	errCh := make(chan error, 1)
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

	conn, err := DialAttach(ctx, AttachDialConfig{Token: listener.Token})
	if err != nil {
		t.Fatalf("DialAttach() error = %v", err)
	}
	if _, err := conn.Write([]byte("hello attach")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Accept/read error = %v", err)
	case got := <-received:
		if !bytes.Equal(got, []byte("hello attach")) {
			t.Fatalf("payload = %q, want %q", got, "hello attach")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for payload")
	}
}

func TestListenAttachIsOneShot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := ListenAttach(ctx, AttachListenConfig{})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	received := make(chan []byte, 1)
	errCh := make(chan error, 1)
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

	conn, err := DialAttach(ctx, AttachDialConfig{Token: listener.Token})
	if err != nil {
		t.Fatalf("first DialAttach() error = %v", err)
	}
	if _, err := conn.Write([]byte("hello attach")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Accept/read error = %v", err)
	case got := <-received:
		if !bytes.Equal(got, []byte("hello attach")) {
			t.Fatalf("payload = %q, want %q", got, "hello attach")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for payload")
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	if _, err := DialAttach(secondCtx, AttachDialConfig{Token: listener.Token}); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("second DialAttach() error = %v, want ErrUnknownSession", err)
	}
}

func TestListenAttachCloseStopsBlockedAcceptAndDial(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		listener, err := ListenAttach(ctx, AttachListenConfig{})
		if err != nil {
			t.Fatalf("ListenAttach() error = %v", err)
		}

		errCh := make(chan error, 1)
		go func() {
			_, err := listener.Accept(ctx)
			errCh <- err
		}()

		if err := listener.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		select {
		case err := <-errCh:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept() error = %v, want net.ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Accept() did not return promptly")
		}
	})

	t.Run("dial", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		listener, err := ListenAttach(ctx, AttachListenConfig{})
		if err != nil {
			t.Fatalf("ListenAttach() error = %v", err)
		}

		started := make(chan struct{}, 1)
		resume := make(chan struct{})
		previousHook := attachDialHook
		attachDialHook = func() {
			select {
			case started <- struct{}{}:
			default:
			}
			<-resume
		}
		defer func() {
			attachDialHook = previousHook
		}()

		errCh := make(chan error, 1)
		go func() {
			_, err := DialAttach(ctx, AttachDialConfig{Token: listener.Token})
			errCh <- err
		}()

		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("DialAttach() did not reach the blocked handoff point")
		}

		if err := listener.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		close(resume)

		select {
		case err := <-errCh:
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, ErrUnknownSession) {
				t.Fatalf("DialAttach() error = %v, want net.ErrClosed or ErrUnknownSession", err)
			}
		case <-time.After(time.Second):
			t.Fatal("DialAttach() did not return promptly")
		}
	})
}

func TestListenAttachContextCancelCleansUpSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	listener, err := ListenAttach(ctx, AttachListenConfig{})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}

	cancel()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := DialAttach(context.Background(), AttachDialConfig{Token: listener.Token}); errors.Is(err, ErrUnknownSession) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("DialAttach() still found session after context cancellation")
}
