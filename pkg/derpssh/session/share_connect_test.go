// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/shayne/derphole/pkg/derptun"
	appsession "github.com/shayne/derphole/pkg/session"
)

func TestInviteRoundTrip(t *testing.T) {
	encoded, err := EncodeInvite(Invite{ClientToken: "dtc1_test"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	if !strings.HasPrefix(encoded, InvitePrefix) {
		t.Fatalf("invite = %q, want %s prefix", encoded, InvitePrefix)
	}
	decoded, err := DecodeInvite(encoded)
	if err != nil {
		t.Fatalf("DecodeInvite() error = %v", err)
	}
	if decoded.ClientToken != "dtc1_test" {
		t.Fatalf("ClientToken = %q, want dtc1_test", decoded.ClientToken)
	}
}

func TestDecodeInviteRejectsWrongPrefix(t *testing.T) {
	if _, err := DecodeInvite("DT1test"); err == nil {
		t.Fatal("DecodeInvite(wrong prefix) error = nil, want error")
	}
}

func TestDecodeInviteRejectsEmptyClientToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_token":""}`))
	if _, err := DecodeInvite(InvitePrefix + payload); err == nil {
		t.Fatal("DecodeInvite(empty client token) error = nil, want error")
	}
}

func TestSharePrintsConnectCommandBeforeServing(t *testing.T) {
	oldGenerateServerToken := generateServerToken
	oldGenerateClientToken := generateClientToken
	oldServe := serveAppMux
	defer func() {
		generateServerToken = oldGenerateServerToken
		generateClientToken = oldGenerateClientToken
		serveAppMux = oldServe
	}()
	generateServerToken = func(derptun.ServerTokenOptions) (string, error) {
		return "server-token", nil
	}
	generateClientToken = func(opts derptun.ClientTokenOptions) (string, error) {
		if opts.ServerToken != "server-token" {
			t.Fatalf("ServerToken = %q, want server-token", opts.ServerToken)
		}
		return "client-token", nil
	}
	serveErr := errors.New("stop")
	serveAppMux = func(ctx context.Context, cfg appsession.DerptunAppServeConfig) error {
		_, _ = ctx, cfg
		return serveErr
	}

	var stderr strings.Builder
	err := Share(context.Background(), ShareConfig{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: &stderr})
	if !errors.Is(err, serveErr) {
		t.Fatalf("Share() error = %v, want %v", err, serveErr)
	}
	if !strings.Contains(stderr.String(), "npx -y derpssh@latest connect DSH1") {
		t.Fatalf("stderr missing connect command:\n%s", stderr.String())
	}
}

func TestConnectDecodesInviteAndDials(t *testing.T) {
	oldDial := dialAppMux
	defer func() { dialAppMux = oldDial }()

	invite, err := EncodeInvite(Invite{ClientToken: "client-token"})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	dialAppMux = func(ctx context.Context, cfg appsession.DerptunAppDialConfig) (*derptun.Mux, func(), error) {
		_, _ = ctx, cfg.Emitter
		if cfg.ClientToken != "client-token" {
			t.Fatalf("ClientToken = %q, want client-token", cfg.ClientToken)
		}
		return nil, func() {}, errors.New("stop")
	}

	err = Connect(context.Background(), ConnectConfig{
		Invite:      invite,
		DisplayName: "Alex",
		Stdin:       strings.NewReader(""),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if err == nil || err.Error() != "stop" {
		t.Fatalf("Connect() error = %v, want stop", err)
	}
}
