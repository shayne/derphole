package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

func runClient(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[clientFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}

	mode := parsed.Flags.Mode
	if mode == "" {
		mode = "raw"
	}
	if mode == "aead" {
		fmt.Fprintln(stderr, "aead not implemented yet")
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	if mode != "raw" {
		fmt.Fprintln(stderr, "unsupported mode:", mode)
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}
	remoteAddr := parsed.Flags.Host
	if remoteAddr == "" {
		fmt.Fprint(stderr, subcommandUsageLine("client"))
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := listenPacket("udp", ":0")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer conn.Close()

	src := bytes.NewReader(bytes.Repeat([]byte("probe"), 256))
	if _, err := probe.Send(ctx, conn, remoteAddr, src, probe.SendConfig{Raw: mode == "raw"}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

type clientFlags struct {
	Host string `flag:"host" help:"Remote host to connect to"`
	Mode string `flag:"mode" help:"Probe mode"`
}
