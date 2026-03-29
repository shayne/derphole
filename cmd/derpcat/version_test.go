package main

import "testing"

func TestVersionStringDefaults(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = origVersion, origCommit, origBuildDate
	})

	version = "dev"
	commit = "unknown"
	buildDate = "unknown"

	if got := versionString(); got != "dev" {
		t.Fatalf("versionString() = %q, want %q", got, "dev")
	}
}

func TestVersionStringUsesInjectedValue(t *testing.T) {
	origVersion, origCommit, origBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = origVersion, origCommit, origBuildDate
	})

	version = "v0.0.1"
	commit = "abc1234"
	buildDate = "2026-03-29T12:00:00Z"

	if got := versionString(); got != "v0.0.1" {
		t.Fatalf("versionString() = %q, want %q", got, "v0.0.1")
	}
}
