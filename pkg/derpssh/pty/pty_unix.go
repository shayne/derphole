// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package pty

import (
	"os"
	"os/exec"
	"strings"

	creackpty "github.com/creack/pty"
)

type Session struct {
	File *os.File
	Cmd  *exec.Cmd
}

type StartConfig struct {
	Shell string
	Term  string
	Size  Size
	Env   []string
}

func Start(cfg StartConfig) (*Session, error) {
	shell := strings.TrimSpace(cfg.Shell)
	if shell == "" {
		shell = DefaultShell()
	}

	cmd := exec.Command(shell)
	cmd.Env = startEnv(cfg)

	file, err := creackpty.StartWithSize(cmd, winSize(cfg.Size))
	if err != nil {
		return nil, err
	}
	return &Session{File: file, Cmd: cmd}, nil
}

func (s *Session) Resize(size Size) error {
	if s == nil || s.File == nil {
		return os.ErrClosed
	}
	ws := winSize(size)
	if ws == nil {
		return nil
	}
	return creackpty.Setsize(s.File, ws)
}

func (s *Session) Close() error {
	if s == nil || s.File == nil {
		return nil
	}
	err := s.File.Close()
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Kill()
	}
	return err
}

func (s *Session) Wait() error {
	if s == nil || s.Cmd == nil {
		return os.ErrInvalid
	}
	return s.Cmd.Wait()
}

func winSize(size Size) *creackpty.Winsize {
	if size.Cols <= 0 || size.Rows <= 0 {
		return nil
	}
	return &creackpty.Winsize{
		Cols: uint16(size.Cols),
		Rows: uint16(size.Rows),
	}
}

func startEnv(cfg StartConfig) []string {
	env := append([]string(nil), os.Environ()...)
	for _, kv := range cfg.Env {
		env = setEnv(env, kv)
	}
	if term := strings.TrimSpace(cfg.Term); term != "" {
		env = setEnv(env, "TERM="+term)
	}
	return env
}

func setEnv(env []string, kv string) []string {
	name, _, ok := strings.Cut(kv, "=")
	if !ok {
		return append(env, kv)
	}
	prefix := name + "="
	for i, existing := range env {
		if strings.HasPrefix(existing, prefix) {
			env[i] = kv
			return env
		}
	}
	return append(env, kv)
}
