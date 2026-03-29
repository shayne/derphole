package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/shayne/derpcat/pkg/telemetry"
	"github.com/shayne/derpcat/pkg/token"
)

func runListen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	printTokenOnly := fs.Bool("print-token-only", false, "print only the session token")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: derpcat listen [--print-token-only]")
		return 2
	}

	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var bearerSecret [32]byte
	if _, err := rand.Read(bearerSecret[:]); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	tok, err := token.Encode(token.Token{
		Version:      token.SupportedVersion,
		SessionID:    sessionID,
		ExpiresUnix:  time.Now().Add(10 * time.Minute).Unix(),
		BearerSecret: bearerSecret,
		Capabilities: token.CapabilityStdio | token.CapabilityTCP,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if *printTokenOnly {
		fmt.Fprintln(stdout, tok)
		return 0
	}

	telemetry.New(stderr, telemetry.LevelDefault).Status("waiting-for-claim")
	fmt.Fprintln(stdout, tok)
	return 0
}
