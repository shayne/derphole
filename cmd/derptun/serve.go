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
}

var serveHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derptun",
		Description: "Serve a local TCP service through a derptun server token.",
		Examples: []string{
			"derptun token server --days 365 > server.dts",
			"derptun serve --token-file server.dts --tcp 127.0.0.1:22",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"serve": {
			Name:        "serve",
			Description: "Expose a local TCP target until Ctrl-C.",
			Usage:       "(--token TOKEN|--token-file PATH|--token-stdin) --tcp HOST:PORT [--force-relay] [--qr]",
			Examples: []string{
				"derptun serve --token-file server.dts --tcp 127.0.0.1:22",
				"derptun serve --token-file server.dts --tcp 127.0.0.1:4222 --qr",
				"printf '%s\\n' \"$DERPTUN_SERVER_TOKEN\" | derptun serve --token-stdin --tcp 127.0.0.1:22",
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
	if parsed.SubCommandFlags.TCP == "" || len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		_, _ = fmt.Fprint(stderr, serveHelpText())
		return 2
	}
	token, _, err := resolveTokenSource(stdin, tokenSource{
		Token:      parsed.SubCommandFlags.Token,
		TokenFile:  parsed.SubCommandFlags.TokenFile,
		TokenStdin: parsed.SubCommandFlags.TokenStdin,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, serveHelpText())
		return 2
	}
	if code, failed := maybeWriteServeQR(parsed.SubCommandFlags.QR, token, stderr); failed {
		return code
	}

	ctx, stop := commandContext()
	defer stop()
	if err := derptunServe(ctx, session.DerptunServeConfig{
		ServerToken:   token,
		TargetAddr:    parsed.SubCommandFlags.TCP,
		Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
		UsePublicDERP: usePublicDERPTransport(),
	}); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func maybeWriteServeQR(enabled bool, token string, stderr io.Writer) (int, bool) {
	if !enabled {
		return 0, false
	}
	invite, err := serveQRInvite(token)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1, true
	}
	writeServeQRInstruction(stderr, invite)
	return 0, false
}

func serveHelpText() string {
	return yargs.GenerateSubCommandHelp(serveHelpConfig, "serve", struct{}{}, serveFlags{}, struct{}{})
}

func serveQRInvite(serverToken string) (string, error) {
	clientToken, err := deriveServeQRClientToken(serverToken, time.Now())
	if err != nil {
		return "", err
	}
	return derptunpkg.EncodeClientInvite(clientToken)
}

func deriveServeQRClientToken(serverToken string, now time.Time) (string, error) {
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

func writeServeQRInstruction(stderr io.Writer, invite string) {
	if stderr == nil {
		return
	}
	_, _ = fmt.Fprintln(stderr, "Scan this QR code with a derptun-compatible mobile app to open this TCP tunnel:")
	_, _ = fmt.Fprintf(stderr, "Invite: %s\n", invite)
	qrterminal.GenerateHalfBlock(invite, qrterminal.M, stderr)
}
