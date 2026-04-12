package ssh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derpcat/pkg/session"
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
