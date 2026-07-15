// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestWriteImmutableJSONCannotOverwrite(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.json")
	first := map[string]int{"value": 1}
	if _, err := WriteImmutableJSON(path, first); err != nil {
		t.Fatalf("first write: %v", err)
	}

	for name, value := range map[string]any{
		"different bytes": map[string]int{"value": 2},
		"same bytes":      first,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := WriteImmutableJSON(path, value); err == nil {
				t.Fatal("overwrite unexpectedly succeeded")
			}
		})
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"value\":1}\n"; string(got) != want {
		t.Fatalf("artifact changed: got %q want %q", got, want)
	}
	assertNoArtifactTemps(t, path)
}

func TestWriteImmutableJSONDigestMatchesExactBytes(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.json")
	digest, err := WriteImmutableJSON(path, map[string]int{"z": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":1,\"z\":2}\n"; string(got) != want {
		t.Fatalf("bytes = %q, want %q", got, want)
	}
	if digest != DigestBytes(got) {
		t.Fatalf("digest = %q, exact bytes digest = %q", digest, DigestBytes(got))
	}
	fileDigest, err := FileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if fileDigest != digest {
		t.Fatalf("file digest = %q, write digest = %q", fileDigest, digest)
	}
}

func TestWriteImmutableJSONDeterministicAcrossRoots(t *testing.T) {
	t.Parallel()

	values := []map[string]any{
		{"z": 3, "nested": map[string]int{"b": 2, "a": 1}},
		{"nested": map[string]int{"a": 1, "b": 2}, "z": 3},
	}
	var bytesByRoot [][]byte
	var digests []SHA256Digest
	for i, value := range values {
		path := filepath.Join(t.TempDir(), "root", "manifest.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		digest, err := WriteImmutableJSON(path, value)
		if err != nil {
			t.Fatalf("root %d: %v", i, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bytesByRoot = append(bytesByRoot, data)
		digests = append(digests, digest)
	}
	if string(bytesByRoot[0]) != string(bytesByRoot[1]) || digests[0] != digests[1] {
		t.Fatalf("nondeterministic output: bytes %q / %q, digests %q / %q", bytesByRoot[0], bytesByRoot[1], digests[0], digests[1])
	}
}

func TestVerifyArtifactRejectsMutation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact")
	digest, err := WriteImmutableBytes(path, []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(path, digest); err != nil {
		t.Fatalf("verify original: %v", err)
	}
	if err := os.WriteFile(path, []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(path, digest); err == nil {
		t.Fatal("mutated artifact accepted")
	}
}

func TestVerifyArtifactRejectsMalformedDigest(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []SHA256Digest{"", "abc", SHA256Digest(strings.Repeat("A", 64)), SHA256Digest(strings.Repeat("g", 64))} {
		if err := VerifyArtifact(path, digest); err == nil {
			t.Fatalf("malformed digest %q accepted", digest)
		}
	}
}

func TestWriteImmutableBytesRefusesExistingSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteImmutableBytes(target, []byte("replacement")); err == nil {
		t.Fatal("existing symlink was replaced")
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "outside" {
		t.Fatalf("symlink target changed: %q", got)
	}
	assertNoArtifactTemps(t, target)
}

func TestWriteImmutableBytesCleansTemporaryAfterPublicationFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteImmutableBytes(path, []byte("new")); err == nil {
		t.Fatal("expected existing-target failure")
	}
	assertNoArtifactTemps(t, path)
}

func TestWriteImmutableBytesConcurrentWritersHaveExactlyOneWinner(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact")
	const writers = 24
	start := make(chan struct{})
	results := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := WriteImmutableBytes(path, []byte{byte(i)})
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want 1", winners)
	}
	assertNoArtifactTemps(t, path)
}

func TestWriteImmutableBytesPrepublicationFailureLeavesNoFinal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "missing", "artifact")
	if _, err := WriteImmutableBytes(path, []byte("data")); err == nil {
		t.Fatal("write into missing directory unexpectedly succeeded")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final artifact exists or wrong error: %v", err)
	}
}

func TestWriteImmutableBytesPrepublicationFaultsReturnNoIdentity(t *testing.T) {
	t.Parallel()

	for _, fault := range []string{"write", "file sync", "close", "link"} {
		t.Run(fault, func(t *testing.T) {
			injected := fmt.Errorf("injected %s failure", fault)
			operations := prepublicationFaultOperations(fault, injected)
			path := filepath.Join(t.TempDir(), "artifact")
			digest, err := writeImmutableBytesWithOperations(path, []byte("data"), operations)
			if !errors.Is(err, injected) {
				t.Fatalf("error = %v, want injected fault", err)
			}
			if digest != "" {
				t.Fatalf("digest = %q before publication, want empty", digest)
			}
			var published *PublishedArtifactError
			if errors.As(err, &published) {
				t.Fatalf("prepublication failure classified as published: %v", err)
			}
			if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("prepublication failure left final artifact: %v", statErr)
			}
			assertNoArtifactTemps(t, path)
		})
	}
}

func TestWriteImmutableBytesPostlinkFaultsRetainPublishedIdentity(t *testing.T) {
	t.Parallel()

	for _, fault := range []string{"temporary unlink", "directory sync"} {
		t.Run(fault, func(t *testing.T) {
			injected := fmt.Errorf("injected %s failure", fault)
			operations, calls := postlinkFaultOperations(fault, injected)
			path := filepath.Join(t.TempDir(), "artifact")
			data := []byte("published data")
			digest, err := writeImmutableBytesWithOperations(path, data, operations)
			if digest != DigestBytes(data) {
				t.Fatalf("digest = %q, want published digest %q", digest, DigestBytes(data))
			}
			var published *PublishedArtifactError
			if !errors.As(err, &published) || !errors.Is(err, injected) {
				t.Fatalf("error = %v, want typed published fault wrapping injected error", err)
			}
			if published.Digest != digest || !strings.Contains(err.Error(), string(digest)) {
				t.Fatalf("published error recovery digest = %q in %q, want %q", published.Digest, err, digest)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != string(data) {
				t.Fatalf("published artifact = %q, %v", got, readErr)
			}
			if calls.directorySync == 0 {
				t.Fatal("post-link fault skipped directory sync")
			}
			if fault == "temporary unlink" && calls.remove < 2 {
				t.Fatalf("temporary cleanup attempts = %d, want at least 2", calls.remove)
			}
			assertNoArtifactTemps(t, path)

			retryDigest, retryErr := WriteImmutableBytes(path, []byte("replacement"))
			if retryErr == nil || retryDigest != "" {
				t.Fatalf("retry = digest %q, error %v; want nonpublished refusal", retryDigest, retryErr)
			}
			var retryPublished *PublishedArtifactError
			if errors.As(retryErr, &retryPublished) {
				t.Fatalf("refused retry classified as published: %v", retryErr)
			}
		})
	}
}

func TestWriteImmutableBytesJoinsPostlinkCleanupAndDurabilityFaults(t *testing.T) {
	t.Parallel()

	unlinkErr := errors.New("injected persistent unlink failure")
	directoryErr := errors.New("injected directory sync failure")
	operations := defaultImmutableOperations()
	removeCalls := 0
	directoryCalls := 0
	operations.remove = func(string) error {
		removeCalls++
		return unlinkErr
	}
	operations.syncDirectory = func(string) error {
		directoryCalls++
		return directoryErr
	}
	path := filepath.Join(t.TempDir(), "artifact")
	data := []byte("published despite cleanup faults")
	digest, err := writeImmutableBytesWithOperations(path, data, operations)
	var published *PublishedArtifactError
	if digest != DigestBytes(data) || !errors.As(err, &published) || !errors.Is(err, unlinkErr) || !errors.Is(err, directoryErr) {
		t.Fatalf("digest/error = %q, %v; want exact digest and joined published faults", digest, err)
	}
	if published.Digest != digest || !strings.Contains(err.Error(), string(digest)) {
		t.Fatalf("published error recovery digest = %q in %q, want %q", published.Digest, err, digest)
	}
	if removeCalls < 2 || directoryCalls != 1 {
		t.Fatalf("remove/sync calls = %d/%d, want best-effort retry and one sync", removeCalls, directoryCalls)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(data) {
		t.Fatalf("published artifact = %q, %v", got, readErr)
	}
}

type immutableFaultCalls struct {
	remove        int
	directorySync int
}

func prepublicationFaultOperations(fault string, injected error) immutableOperations {
	operations := defaultImmutableOperations()
	switch fault {
	case "write":
		operations.writeFile = func(*os.File, []byte) error { return injected }
	case "file sync":
		operations.syncFile = func(*os.File) error { return injected }
	case "close":
		operations.closeFile = func(file *os.File) error {
			return errors.Join(file.Close(), injected)
		}
	case "link":
		operations.link = func(string, string) error { return injected }
	}
	return operations
}

func postlinkFaultOperations(fault string, injected error) (immutableOperations, *immutableFaultCalls) {
	operations := defaultImmutableOperations()
	calls := &immutableFaultCalls{}
	defaultRemove := operations.remove
	defaultDirectorySync := operations.syncDirectory
	operations.remove = func(path string) error {
		calls.remove++
		if fault == "temporary unlink" && calls.remove == 1 {
			return injected
		}
		return defaultRemove(path)
	}
	operations.syncDirectory = func(path string) error {
		calls.directorySync++
		if fault == "directory sync" {
			return injected
		}
		return defaultDirectorySync(path)
	}
	return operations, calls
}

func TestCanonicalJSONRejectsUnsupportedValue(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact")
	if _, err := WriteImmutableJSON(path, map[string]any{"channel": make(chan int)}); err == nil {
		t.Fatal("unsupported JSON value accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final artifact exists or wrong error: %v", err)
	}
}

func assertNoArtifactTemps(t *testing.T, finalPath string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(finalPath))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "." + filepath.Base(finalPath) + ".tmp-"
	var leftovers []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			leftovers = append(leftovers, entry.Name())
		}
	}
	sort.Strings(leftovers)
	if len(leftovers) != 0 {
		data, _ := json.Marshal(leftovers)
		t.Fatalf("temporary artifacts remain: %s", data)
	}
}
