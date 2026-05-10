// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

func AppendAuthorizedKey(path, publicKey string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return errors.New("public key is empty")
	}
	_, err = io.WriteString(f, publicKey+"\n")
	return err
}

func AuthorizedKeysPath(userName string) (string, error) {
	if userName == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".ssh", "authorized_keys"), nil
	}

	u, err := user.Lookup(userName)
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, ".ssh", "authorized_keys"), nil
}

func FindPublicKey(hint string) (string, string, string, error) {
	if hint == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", "", err
		}
		hint = filepath.Join(home, ".ssh")
	}

	info, err := os.Stat(hint)
	if err != nil {
		return "", "", "", err
	}

	path := hint
	if info.IsDir() {
		entries, err := os.ReadDir(hint)
		if err != nil {
			return "", "", "", err
		}

		var pubkeys []string
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
				continue
			}
			pubkeys = append(pubkeys, filepath.Join(hint, entry.Name()))
		}
		switch len(pubkeys) {
		case 0:
			return "", "", "", errors.New("no public keys found; pass --key-file")
		case 1:
			path = pubkeys[0]
		default:
			return "", "", "", errors.New("multiple public keys found; pass --key-file")
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
	}

	pubkey := strings.TrimSpace(string(raw))
	parts := strings.Fields(pubkey)
	if len(parts) < 2 {
		return "", "", "", errors.New("invalid public key")
	}
	keyID := "unknown"
	if len(parts) >= 3 {
		keyID = parts[2]
	}
	return parts[0], keyID, pubkey, nil
}
