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
	if tokenSourceCount(source) != 1 {
		return "", stdin, errors.New("exactly one of --token, --token-file, or --token-stdin is required")
	}
	if source.Token != "" {
		return strings.TrimSpace(source.Token), stdin, nil
	}
	if source.TokenFile != "" {
		token, err := readTokenFile(source.TokenFile)
		return token, stdin, err
	}
	return readTokenStdin(stdin)
}

func tokenSourceCount(source tokenSource) int {
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
	return count
}

func readTokenFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read --token-file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("--token-file is empty")
	}
	return token, nil
}

func readTokenStdin(stdin io.Reader) (string, io.Reader, error) {
	reader := bufferedTokenReader(stdin)
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

func bufferedTokenReader(stdin io.Reader) *bufio.Reader {
	if reader, ok := stdin.(*bufio.Reader); ok {
		return reader
	}
	return bufio.NewReader(stdin)
}
