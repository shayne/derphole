package derpbind

import (
	"context"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNewClientWithPrivateKeyRejectsZeroKey(t *testing.T) {
	_, err := NewClientWithPrivateKey(context.Background(), &tailcfg.DERPNode{}, "https://127.0.0.1", key.NodePrivate{})
	if err == nil {
		t.Fatal("NewClientWithPrivateKey() error = nil, want error")
	}
}
