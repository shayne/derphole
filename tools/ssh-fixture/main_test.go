// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHFixtureServesShellAndLogsInput(t *testing.T) {
	t.Parallel()

	config := sshFixtureServerConfig("alice", "secret")
	if err := addEphemeralHostKey(config); err != nil {
		t.Fatalf("addEphemeralHostKey() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	dir := t.TempDir()
	addrFile := filepath.Join(dir, "addr")
	shellOpenedFile := filepath.Join(dir, "opened")
	inputLogFile := filepath.Join(dir, "input")
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveSSHFixture(listener, config, addrFile, shellOpenedFile, inputLogFile, "fixture ready")
	}()

	client := dialSSHFixture(t, listener.Addr().String(), "alice", "secret")
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error = %v", err)
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error = %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell() error = %v", err)
	}

	reader := bufio.NewReader(stdout)
	prompt, err := reader.ReadString('$')
	if err != nil {
		t.Fatalf("ReadString(prompt) error = %v", err)
	}
	if !strings.Contains(prompt, "fixture ready") {
		t.Fatalf("prompt = %q, want marker", prompt)
	}
	if _, err := io.WriteString(stdin, "echo hello\n"); err != nil {
		t.Fatalf("stdin write error = %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("stdin close error = %v", err)
	}

	waitForFileContains(t, shellOpenedFile, "opened")
	waitForFileContains(t, inputLogFile, "echo hello")
	waitForFileContains(t, addrFile, listener.Addr().String())

	if err := listener.Close(); err != nil {
		t.Fatalf("listener Close() error = %v", err)
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("serveSSHFixture() error = nil after listener close, want closed listener error")
		}
	case <-time.After(time.Second):
		t.Fatal("serveSSHFixture() did not stop after listener close")
	}
}

func TestSSHFixtureRejectsWrongCredentials(t *testing.T) {
	t.Parallel()

	config := sshFixtureServerConfig("alice", "secret")
	if err := addEphemeralHostKey(config); err != nil {
		t.Fatalf("addEphemeralHostKey() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		handleConn(conn, config, "", "", "marker")
		accepted <- nil
	}()
	_, err = ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	})
	if err == nil {
		t.Fatal("ssh.Dial() error = nil, want authentication failure")
	}
	if err := <-accepted; err != nil {
		t.Fatalf("fixture accept error = %v", err)
	}
}

func TestShellInputWriterFallbacks(t *testing.T) {
	t.Parallel()

	writer, closeWriter := shellInputWriter("")
	if writer != io.Discard {
		t.Fatalf("empty shellInputWriter writer = %T, want io.Discard", writer)
	}
	closeWriter()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "input.log")
	writer, closeWriter = shellInputWriter(logPath)
	if _, err := io.WriteString(writer, "abc"); err != nil {
		t.Fatalf("write input log error = %v", err)
	}
	closeWriter()
	waitForFileContains(t, logPath, "abc")

	writer, closeWriter = shellInputWriter(filepath.Join(dir, "missing", "input.log"))
	if writer != io.Discard {
		t.Fatalf("bad path shellInputWriter writer = %T, want io.Discard", writer)
	}
	closeWriter()
}

func TestRunRejectsBadListenAddress(t *testing.T) {
	t.Parallel()

	err := run("not-a-valid-address", "", "", "", "alice", "secret", "marker")
	if err == nil {
		t.Fatal("run() error = nil, want listen address error")
	}
}

func TestWriteSSHFixtureAddrWritesOptionalFile(t *testing.T) {
	t.Parallel()

	addrPath := filepath.Join(t.TempDir(), "addr")
	if err := writeSSHFixtureAddr("127.0.0.1:1234", addrPath); err != nil {
		t.Fatalf("writeSSHFixtureAddr() error = %v", err)
	}
	waitForFileContains(t, addrPath, "127.0.0.1:1234")

	err := writeSSHFixtureAddr("127.0.0.1:1234", filepath.Join(t.TempDir(), "missing", "addr"))
	if err == nil {
		t.Fatal("writeSSHFixtureAddr(bad path) error = nil, want error")
	}
}

func dialSSHFixture(t *testing.T, addr, user, password string) *ssh.Client {
	t.Helper()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial() error = %v", err)
	}
	return client
}

func waitForFileContains(t *testing.T, path string, want string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(raw), want) {
			return
		}
		if time.Now().After(deadline) {
			if errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s was not created; want content %q", path, want)
			}
			t.Fatalf("%s = %q, err=%v; want content %q", path, string(raw), err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
