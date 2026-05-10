// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"path/filepath"
	"testing"
)

func TestResolveOutputPathUsesSuggestedFilenameInsideDirectory(t *testing.T) {
	dir := t.TempDir()

	got, err := ResolveOutputPath(dir, "photo.jpg")
	if err != nil {
		t.Fatalf("ResolveOutputPath() error = %v", err)
	}

	want := filepath.Join(dir, "photo.jpg")
	if got != want {
		t.Fatalf("ResolveOutputPath() = %q, want %q", got, want)
	}
}
