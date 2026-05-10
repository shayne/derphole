// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/session"
)

func TestInviteAcceptAppendsAuthorizedKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	listener, err := session.ListenAttach(ctx, session.AttachListenConfig{})
	if err != nil {
		t.Fatalf("ListenAttach() error = %v", err)
	}
	defer listener.Close()

	inviteDone := make(chan error, 1)
	go func() {
		inviteDone <- Invite(ctx, InviteConfig{
			Listener:       listener,
			AuthorizedKeys: filepath.Join(sshDir, "authorized_keys"),
		})
	}()

	err = Accept(ctx, AcceptConfig{
		Token:     listener.Token,
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test",
	})
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := <-inviteDone; err != nil {
		t.Fatalf("Invite() error = %v", err)
	}

	got, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(got), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test") {
		t.Fatalf("authorized_keys = %q, want appended key", got)
	}
}

func TestFindPublicKeyUsesExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519.pub")
	want := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test"
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	typ, keyID, pubkey, err := FindPublicKey(path)
	if err != nil {
		t.Fatalf("FindPublicKey() error = %v", err)
	}
	if typ != "ssh-ed25519" || keyID != "user@test" || pubkey != want {
		t.Fatalf("FindPublicKey() = (%q, %q, %q), want parsed explicit key", typ, keyID, pubkey)
	}
}

func TestAuthorizedKeysPathDefaultsToCurrentHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := AuthorizedKeysPath("")
	if err != nil {
		t.Fatalf("AuthorizedKeysPath(empty user) error = %v", err)
	}
	want := filepath.Join(home, ".ssh", "authorized_keys")
	if got != want {
		t.Fatalf("AuthorizedKeysPath(empty user) = %q, want %q", got, want)
	}
}

func TestFindPublicKeyDiscoversSingleKeyInDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519.pub")
	want := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, keyID, pubkey, err := FindPublicKey(dir)
	if err != nil {
		t.Fatalf("FindPublicKey() error = %v", err)
	}
	if keyID != "user@test" || pubkey != want {
		t.Fatalf("FindPublicKey() = keyID %q pubkey %q, want discovered key", keyID, pubkey)
	}
}

func TestFindPublicKeyRejectsAmbiguousDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"id_ed25519.pub", "id_rsa.pub"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("ssh-ed25519 AAAA user@test"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}

	_, _, _, err := FindPublicKey(dir)
	if err == nil || !strings.Contains(err.Error(), "multiple public keys") {
		t.Fatalf("FindPublicKey() error = %v, want multiple public keys", err)
	}
}

func TestFindPublicKeyRejectsInvalidPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(path, []byte("not-a-public-key"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, _, _, err := FindPublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "invalid public key") {
		t.Fatalf("FindPublicKey() error = %v, want invalid public key", err)
	}
}

func TestFindPublicKeyDefaultsToHomeSSHDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	want := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@test"
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519.pub"), []byte(want), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, _, pubkey, err := FindPublicKey("")
	if err != nil {
		t.Fatalf("FindPublicKey() error = %v", err)
	}
	if pubkey != want {
		t.Fatalf("FindPublicKey() pubkey = %q, want %q", pubkey, want)
	}
}

func TestFindPublicKeyReportsMissingHint(t *testing.T) {
	_, _, _, err := FindPublicKey(filepath.Join(t.TempDir(), "missing.pub"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FindPublicKey() error = %v, want not exist", err)
	}
}
