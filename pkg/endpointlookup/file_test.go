// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package endpointlookup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateName(t *testing.T) {
	for _, name := range []string{"web", "alpha-ssh", "prod.api", "home_lab_1"} {
		t.Run("valid_"+name, func(t *testing.T) {
			if err := ValidateName(name); err != nil {
				t.Fatalf("ValidateName(%q) error = %v, want nil", name, err)
			}
		})
	}

	longName := strings.Repeat("a", 129)
	for _, name := range []string{"", ".", "..", "../web", "web/api", ".hidden", "-bad", "has space", longName} {
		t.Run("invalid_"+name, func(t *testing.T) {
			if err := ValidateName(name); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("ValidateName(%q) error = %v, want ErrInvalidName", name, err)
			}
		})
	}
}

func TestFileRegistryRoundTripDerptunToken(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	registry := FileRegistry{
		Path: filepath.Join(t.TempDir(), "services", "registry.json"),
		Now:  func() time.Time { return now },
	}
	record, err := NewRecord("web", KindDerptunClientToken, "DT1secret", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	if err := registry.Publish(ctx, record); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	got, err := registry.Resolve(ctx, "web", KindDerptunClientToken)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got != record {
		t.Fatalf("Resolve() = %#v, want %#v", got, record)
	}
}

func TestFileRegistryRejectsExpiredRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	registry := FileRegistry{
		Path: filepath.Join(t.TempDir(), "registry.json"),
		Now:  func() time.Time { return now },
	}
	record, err := NewRecord("web", KindDerptunClientToken, "DT1expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	if err := registry.Publish(ctx, record); !errors.Is(err, ErrExpired) {
		t.Fatalf("Publish(expired) error = %v, want ErrExpired", err)
	}
}

func TestFileRegistryListRedactsValues(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	registry := FileRegistry{
		Path: filepath.Join(t.TempDir(), "registry.json"),
		Now:  func() time.Time { return now },
	}
	record, err := NewRecord("shell", KindDerpsshInvite, "DSH1secret-invite", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if err := registry.Publish(ctx, record); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	summaries, err := registry.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("List() len = %d, want 1", len(summaries))
	}
	if summaries[0].Name != "shell" || summaries[0].Kind != KindDerpsshInvite {
		t.Fatalf("summary = %#v, want shell derpssh invite", summaries[0])
	}
	if strings.Contains(summaries[0].Display, record.Value) || strings.Contains(summaries[0].Display, "DSH1secret") {
		t.Fatalf("summary display leaks bearer value: %#v", summaries[0])
	}
}

func TestFileRegistryRemove(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	registry := FileRegistry{
		Path: filepath.Join(t.TempDir(), "registry.json"),
		Now:  func() time.Time { return now },
	}
	record, err := NewRecord("web", KindDerptunClientToken, "DT1secret", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if err := registry.Publish(ctx, record); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	if err := registry.Remove(ctx, "web"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := registry.Resolve(ctx, "web", KindDerptunClientToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve(removed) error = %v, want ErrNotFound", err)
	}
}

func TestFileRegistryWritesPrivateMode(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	dir := filepath.Join(t.TempDir(), "services")
	registryPath := filepath.Join(dir, "registry.json")
	registry := FileRegistry{
		Path: registryPath,
		Now:  func() time.Time { return now },
	}
	record, err := NewRecord("web", KindDerptunClientToken, "DT1secret", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	if err := registry.Publish(ctx, record); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(dir) error = %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("dir mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(registryPath)
	if err != nil {
		t.Fatalf("Stat(file) error = %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
}
