// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SHA256Digest is a lowercase hexadecimal SHA-256 digest.
type SHA256Digest string

// PublishedArtifactError reports a post-link cleanup or durability failure.
// The returned digest still identifies the immutable final artifact.
type PublishedArtifactError struct {
	Digest SHA256Digest
	err    error
}

func (err *PublishedArtifactError) Error() string {
	message := fmt.Sprintf("artifact was published with recoverable digest %s but cleanup or durability failed", err.Digest)
	if err.err == nil {
		return message
	}
	return message + ": " + err.err.Error()
}

func (err *PublishedArtifactError) Unwrap() error {
	return err.err
}

// DigestBytes returns the digest of the exact supplied bytes.
func DigestBytes(data []byte) SHA256Digest {
	sum := sha256.Sum256(data)
	return SHA256Digest(hex.EncodeToString(sum[:]))
}

// FileDigest returns the digest of the exact bytes stored at path.
func FileDigest(path string) (SHA256Digest, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open artifact: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", errors.Join(fmt.Errorf("hash artifact: %w", err), file.Close())
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close artifact: %w", err)
	}
	return digestHash(hasher), nil
}

// WriteImmutableBytes publishes data only when path does not already exist.
func WriteImmutableBytes(path string, data []byte) (SHA256Digest, error) {
	return writeImmutableBytesWithOperations(path, data, defaultImmutableOperations())
}

func writeImmutableBytesWithOperations(path string, data []byte, operations immutableOperations) (SHA256Digest, error) {
	dir := filepath.Dir(path)
	temporary, err := newImmutableTemporary(dir, filepath.Base(path), operations)
	if err != nil {
		return "", err
	}
	if err := temporary.seal(data); err != nil {
		return "", errors.Join(err, temporary.cleanup())
	}
	if err := temporary.link(path); err != nil {
		return "", errors.Join(err, temporary.cleanup())
	}
	digest := DigestBytes(data)
	if err := temporary.finishPublished(dir); err != nil {
		return digest, &PublishedArtifactError{Digest: digest, err: err}
	}
	return digest, nil
}

// WriteImmutableJSON writes deterministic compact JSON with one final newline.
func WriteImmutableJSON(path string, value any) (SHA256Digest, error) {
	data, err := canonicalJSONBytes(value)
	if err != nil {
		return "", err
	}
	return WriteImmutableBytes(path, data)
}

// VerifyArtifact verifies both digest syntax and exact file bytes.
func VerifyArtifact(path string, want SHA256Digest) error {
	if err := validateSHA256Digest(want); err != nil {
		return err
	}
	got, err := FileDigest(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("artifact digest mismatch: got %s, want %s", got, want)
	}
	return nil
}

func canonicalJSONBytes(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON: %w", err)
	}
	return append(data, '\n'), nil
}

func validateSHA256Digest(digest SHA256Digest) error {
	value := string(digest)
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return fmt.Errorf("invalid SHA-256 digest %q", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("invalid SHA-256 digest %q", value)
	}
	return nil
}

func digestHash(hasher hash.Hash) SHA256Digest {
	return SHA256Digest(hex.EncodeToString(hasher.Sum(nil)))
}

func writeEveryByte(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return fmt.Errorf("invalid write count %d for %d bytes", written, len(data))
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open artifact directory: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync artifact directory: %w", err), dir.Close())
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close artifact directory: %w", err)
	}
	return nil
}

type immutableTemporary struct {
	file       *os.File
	path       string
	operations immutableOperations
}

type immutableOperations struct {
	createTemp    func(string, string) (*os.File, error)
	writeFile     func(*os.File, []byte) error
	syncFile      func(*os.File) error
	closeFile     func(*os.File) error
	link          func(string, string) error
	remove        func(string) error
	syncDirectory func(string) error
}

func defaultImmutableOperations() immutableOperations {
	return immutableOperations{
		createTemp:    os.CreateTemp,
		writeFile:     func(file *os.File, data []byte) error { return writeEveryByte(file, data) },
		syncFile:      func(file *os.File) error { return file.Sync() },
		closeFile:     func(file *os.File) error { return file.Close() },
		link:          os.Link,
		remove:        os.Remove,
		syncDirectory: syncDirectory,
	}
}

func newImmutableTemporary(dir, base string, operations immutableOperations) (*immutableTemporary, error) {
	file, err := operations.createTemp(dir, "."+base+".tmp-")
	if err != nil {
		return nil, fmt.Errorf("create immutable artifact temporary: %w", err)
	}
	return &immutableTemporary{file: file, path: file.Name(), operations: operations}, nil
}

func (temporary *immutableTemporary) seal(data []byte) error {
	if err := temporary.operations.writeFile(temporary.file, data); err != nil {
		return fmt.Errorf("write immutable artifact temporary: %w", err)
	}
	if err := temporary.operations.syncFile(temporary.file); err != nil {
		return fmt.Errorf("sync immutable artifact temporary: %w", err)
	}
	if err := temporary.operations.closeFile(temporary.file); err != nil {
		return fmt.Errorf("close immutable artifact temporary: %w", err)
	}
	temporary.file = nil
	return nil
}

func (temporary *immutableTemporary) link(finalPath string) error {
	if err := temporary.operations.link(temporary.path, finalPath); err != nil {
		return fmt.Errorf("publish immutable artifact without replacement: %w", err)
	}
	return nil
}

func (temporary *immutableTemporary) finishPublished(dir string) error {
	removeErr := temporary.remove()
	cleanupErr := temporary.cleanup()
	directoryErr := temporary.operations.syncDirectory(dir)
	return errors.Join(removeErr, cleanupErr, directoryErr)
}

func (temporary *immutableTemporary) remove() error {
	if temporary.path == "" {
		return nil
	}
	if err := temporary.operations.remove(temporary.path); err != nil {
		return fmt.Errorf("remove published artifact temporary: %w", err)
	}
	temporary.path = ""
	return nil
}

func (temporary *immutableTemporary) cleanup() error {
	var cleanupErr error
	if temporary.file != nil {
		cleanupErr = temporary.operations.closeFile(temporary.file)
		temporary.file = nil
	}
	if temporary.path != "" {
		if err := temporary.operations.remove(temporary.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove immutable artifact temporary: %w", err))
		}
		temporary.path = ""
	}
	return cleanupErr
}
