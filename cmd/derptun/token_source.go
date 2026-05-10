// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type tokenSource struct {
	Token      string
	TokenFile  string
	TokenStdin bool
}

func resolveTokenSource(stdin io.Reader, source tokenSource) (string, io.Reader, error) {
	count := 0
	if source.Token != "" {
		count++
	}
	if source.TokenFile != "" {
		count++
	}
	if source.TokenStdin {
		count++
	}
	if count != 1 {
		return "", stdin, errors.New("exactly one of --token, --token-file, or --token-stdin is required")
	}
	if source.Token != "" {
		return strings.TrimSpace(source.Token), stdin, nil
	}
	if source.TokenFile != "" {
		raw, err := os.ReadFile(source.TokenFile)
		if err != nil {
			return "", stdin, fmt.Errorf("read --token-file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", stdin, errors.New("--token-file is empty")
		}
		return token, stdin, nil
	}
	reader, ok := stdin.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(stdin)
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", reader, fmt.Errorf("read --token-stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", reader, errors.New("--token-stdin is empty")
	}
	return token, reader, nil
}
