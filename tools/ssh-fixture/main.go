// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "TCP listen address")
	addrFile := flag.String("addr-file", "", "Path to write the bound address")
	shellOpenedFile := flag.String("shell-opened-file", "", "Path to touch when a shell opens")
	inputLogFile := flag.String("input-log-file", "", "Path to append bytes received from shell input")
	username := flag.String("username", "derphole", "Accepted SSH username")
	password := flag.String("password", "derphole", "Accepted SSH password")
	marker := flag.String("marker", "Derphole SSH fixture", "Text written to each shell")
	flag.Parse()

	if err := run(*addr, *addrFile, *shellOpenedFile, *inputLogFile, *username, *password, *marker); err != nil {
		log.Fatal(err)
	}
}

func run(addr, addrFile, shellOpenedFile, inputLogFile, username, password, marker string) error {
	config := sshFixtureServerConfig(username, password)
	if err := addEphemeralHostKey(config); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	return serveSSHFixture(listener, config, addrFile, shellOpenedFile, inputLogFile, marker)
}

func sshFixtureServerConfig(username, password string) *ssh.ServerConfig {
	return &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, supplied []byte) (*ssh.Permissions, error) {
			if conn.User() == username && string(supplied) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials for %s", conn.User())
		},
	}
}

func serveSSHFixture(listener net.Listener, config *ssh.ServerConfig, addrFile, shellOpenedFile, inputLogFile, marker string) error {
	if err := writeSSHFixtureAddr(listener.Addr().String(), addrFile); err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, config, shellOpenedFile, inputLogFile, marker)
	}
}

func writeSSHFixtureAddr(boundAddr, addrFile string) error {
	if addrFile != "" {
		if err := os.WriteFile(addrFile, []byte(boundAddr+"\n"), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("addr: %s\n", boundAddr)
	return nil
}

func addEphemeralHostKey(config *ssh.ServerConfig) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}
	config.AddHostKey(signer)
	return nil
}

func handleConn(conn net.Conn, config *ssh.ServerConfig, shellOpenedFile, inputLogFile, marker string) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = serverConn.Close() }()
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "session channels only")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go handleSessionChannel(channel, requests, shellOpenedFile, inputLogFile, marker)
	}
}

func handleSessionChannel(channel ssh.Channel, requests <-chan *ssh.Request, shellOpenedFile, inputLogFile, marker string) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		switch request.Type {
		case "pty-req":
			_ = request.Reply(true, nil)
		case "shell":
			_ = request.Reply(true, nil)
			if shellOpenedFile != "" {
				_ = os.WriteFile(shellOpenedFile, []byte("opened\n"), 0o600)
			}
			_, _ = fmt.Fprintf(channel, "\r\n%s\r\n$ ", marker)
			inputWriter, closeInputWriter := shellInputWriter(inputLogFile)
			defer closeInputWriter()
			_, _ = io.Copy(inputWriter, channel)
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
}

func shellInputWriter(inputLogFile string) (io.Writer, func()) {
	if inputLogFile == "" {
		return io.Discard, func() {}
	}
	file, err := os.OpenFile(inputLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return io.Discard, func() {}
	}
	return file, func() {
		_ = file.Close()
	}
}
