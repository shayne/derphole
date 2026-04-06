package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/signal"
	"syscall"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

var listenPacket = net.ListenPacket

func runServer(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[serverFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}

	mode := parsed.Flags.Mode
	if mode == "" {
		mode = "raw"
	}
	if mode == "aead" {
		fmt.Fprintln(stderr, "aead not implemented yet")
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}
	if mode != "raw" {
		fmt.Fprintln(stderr, "unsupported mode:", mode)
		fmt.Fprint(stderr, subcommandUsageLine("server"))
		return 2
	}
	listenAddr := parsed.Flags.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := listenPacket("udp", listenAddr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer conn.Close()

	if _, err := probe.ReceiveToWriter(ctx, conn, "", io.Discard, probe.ReceiveConfig{Raw: mode == "raw"}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	_ = stdout
	return 0
}

type serverFlags struct {
	ListenAddr string `flag:"listen" help:"Listen address for the server"`
	Mode       string `flag:"mode" help:"Probe mode"`
}
