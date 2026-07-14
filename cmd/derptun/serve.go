// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mdp/qrterminal/v3"
	derptunpkg "github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type serveFlags struct {
	Token      string `flag:"token" help:"Server token for serving a local target"`
	TokenFile  string `flag:"token-file" help:"Read the server token from a file"`
	TokenStdin bool   `flag:"token-stdin" help:"Read the server token from the first stdin line"`
	TCP        string `flag:"tcp" help:"Local TCP target to expose, for example 127.0.0.1:22"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
	QR         bool   `flag:"qr" help:"Render a QR code for mobile tunnel clients"`
	Register   string `flag:"register" help:"Publish the derived client token under a local service name"`
	Registry   string `flag:"registry" help:"Path to the local service registry"`
}

var serveHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Serve a local TCP service and print the command for the connecting side.",
		Examples: []string{
			"derptun serve --tcp 127.0.0.1:8080",
			"derptun token server --days 365 > server.dts",
			"derptun serve --token-file server.dts --tcp 127.0.0.1:8080 --register web",
			"derptun serve --token-file server.dts --tcp 127.0.0.1:8080",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"serve": {
			Name:        "serve",
			Description: "Expose a local TCP target until Ctrl-C.",
			Usage:       "[--token TOKEN|--token-file PATH|--token-stdin] --tcp HOST:PORT [--force-relay] [--qr] [--register NAME] [--registry PATH]",
			Examples: []string{
				"derptun serve --tcp 127.0.0.1:8080",
				"derptun token server --days 365 > server.dts",
				"derptun serve --token-file server.dts --tcp 127.0.0.1:8080 --register web",
				"derptun serve --token-file server.dts --tcp 127.0.0.1:8080",
			},
		},
	},
}

var derptunServe = session.DerptunServe

func runServe(args []string, level telemetry.Level, stdin io.Reader, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, serveFlags, struct{}](append([]string{"serve"}, args...), serveHelpConfig)
	if code, handled := handleYargsError(parsed, err, stderr, serveHelpText); handled {
		return code
	}
	if !validServeParse(parsed) {
		_, _ = fmt.Fprint(stderr, serveHelpText())
		return 2
	}
	token, code, failed := resolveServeServerToken(parsed.SubCommandFlags, stdin, stderr)
	if failed {
		return code
	}
	clientToken, code, failed := prepareServeClientToken(token, stderr)
	if failed {
		return code
	}
	ctx, stop := commandContext()
	defer stop()
	if code, failed := publishServeRegistration(ctx, parsed.SubCommandFlags, clientToken, stderr); failed {
		return code
	}
	if code, failed := writeServeClientAccess(parsed.SubCommandFlags.QR, clientToken, stderr); failed {
		return code
	}
	return runServeSession(ctx, parsed.SubCommandFlags, token, level, stderr)
}

func validServeParse(parsed *yargs.TypedParseResult[struct{}, serveFlags, struct{}]) bool {
	return parsed.SubCommandFlags.TCP != "" && len(parsed.Parser.Args) == 0 && len(parsed.RemainingArgs) == 0
}

func prepareServeClientToken(token string, stderr io.Writer) (string, int, bool) {
	clientToken, err := deriveServeClientToken(token, time.Now())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return "", 1, true
	}
	return clientToken, 0, false
}

func publishServeRegistration(ctx context.Context, flags serveFlags, clientToken string, stderr io.Writer) (int, bool) {
	if flags.Register == "" {
		return 0, false
	}
	if err := publishDerptunClientToken(ctx, flags.Register, clientToken, flags.Registry); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return serviceErrorCode(err), true
	}
	return 0, false
}

func runServeSession(ctx context.Context, flags serveFlags, token string, level telemetry.Level, stderr io.Writer) int {
	if err := derptunServe(ctx, session.DerptunServeConfig{
		ServerToken: token,
		TargetAddr:  flags.TCP,
		Emitter:     telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		ForceRelay:  flags.ForceRelay,
	}); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func resolveServeServerToken(flags serveFlags, stdin io.Reader, stderr io.Writer) (string, int, bool) {
	token, _, hasToken, err := resolveOptionalTokenSource(stdin, tokenSource{
		Token:      flags.Token,
		TokenFile:  flags.TokenFile,
		TokenStdin: flags.TokenStdin,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, serveHelpText())
		return "", 2, true
	}
	if hasToken {
		return token, 0, false
	}
	if flags.Register != "" {
		_, _ = fmt.Fprintln(stderr, "--register requires --token, --token-file, or --token-stdin")
		_, _ = fmt.Fprint(stderr, serveHelpText())
		return "", 2, true
	}

	token, err = derptunpkg.GenerateServerTokenFromEnvironment(derptunpkg.ServerTokenOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return "", 1, true
	}
	return token, 0, false
}

func writeServeClientAccess(qr bool, clientToken string, stderr io.Writer) (int, bool) {
	writeServeOpenCommand(stderr, clientToken)
	if qr {
		writeServeQRInstruction(stderr, clientToken)
	}
	return 0, false
}

func serveHelpText() string {
	return yargs.GenerateSubCommandHelp(serveHelpConfig, "serve", struct{}{}, serveFlags{}, struct{}{})
}

func deriveServeClientToken(serverToken string, now time.Time) (string, error) {
	server, err := derptunpkg.DecodeServerToken(serverToken, now)
	if err != nil {
		return "", err
	}
	expires := now.Add(time.Duration(derptunpkg.DefaultClientDays) * 24 * time.Hour)
	serverExpires := time.Unix(server.ExpiresUnix, 0)
	if serverExpires.Before(expires) {
		expires = serverExpires
	}
	return derptunpkg.GenerateClientToken(derptunpkg.ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Expires:     expires,
	})
}

func writeServeOpenCommand(stderr io.Writer, clientToken string) {
	if stderr == nil {
		return
	}
	_, _ = fmt.Fprintln(stderr, "On the other machine, run:")
	_, _ = fmt.Fprintf(stderr, "  npx -y derptun@latest open --token %s\n", clientToken)
}

func writeServeQRInstruction(stderr io.Writer, clientToken string) {
	if stderr == nil {
		return
	}
	_, _ = fmt.Fprintln(stderr, "Scan this QR code with a derptun-compatible mobile app to open this TCP tunnel:")
	_, _ = fmt.Fprintf(stderr, "Token: %s\n", clientToken)
	qrterminal.GenerateHalfBlock(clientToken, qrterminal.M, stderr)
}
