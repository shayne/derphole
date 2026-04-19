package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
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
	Web        bool   `flag:"web" help:"Mark the QR payload as an HTTP web tunnel"`
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
			Usage:       "(--token TOKEN|--token-file PATH|--token-stdin) --tcp HOST:PORT [--force-relay] [--qr] [--web]",
			Examples: []string{
				"derptun serve --token-file server.dts --tcp 127.0.0.1:22",
				"derptun serve --token-file server.dts --tcp 127.0.0.1:8080 --qr --web",
				"printf '%s\\n' \"$DERPTUN_SERVER_TOKEN\" | derptun serve --token-stdin --tcp 127.0.0.1:22",
			},
		},
	},
}

var derptunServe = session.DerptunServe

func runServe(args []string, level telemetry.Level, stdin io.Reader, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, serveFlags, struct{}](append([]string{"serve"}, args...), serveHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, serveHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, serveHelpText())
			return 2
		}
	}
	if parsed.SubCommandFlags.TCP == "" || len(parsed.Parser.Args) != 0 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, serveHelpText())
		return 2
	}
	if parsed.SubCommandFlags.Web && !parsed.SubCommandFlags.QR {
		fmt.Fprintln(stderr, "--web requires --qr")
		fmt.Fprint(stderr, serveHelpText())
		return 2
	}
	token, _, err := resolveTokenSource(stdin, tokenSource{
		Token:      parsed.SubCommandFlags.Token,
		TokenFile:  parsed.SubCommandFlags.TokenFile,
		TokenStdin: parsed.SubCommandFlags.TokenStdin,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, serveHelpText())
		return 2
	}
	if parsed.SubCommandFlags.QR {
		payload, webHint, err := serveQRPayload(token, parsed.SubCommandFlags.TCP, parsed.SubCommandFlags.Web)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		writeServeQRInstruction(stderr, payload, webHint)
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
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func serveHelpText() string {
	return yargs.GenerateSubCommandHelp(serveHelpConfig, "serve", struct{}{}, serveFlags{}, struct{}{})
}

func serveQRPayload(serverToken, targetAddr string, web bool) (string, string, error) {
	clientToken, err := deriveServeQRClientToken(serverToken, time.Now())
	if err != nil {
		return "", "", err
	}
	if web {
		payload, err := qrpayload.EncodeWebToken(clientToken, "http", "/")
		if err != nil {
			return "", "", err
		}
		return payload, webURLHint(targetAddr), nil
	}
	payload, err := qrpayload.EncodeTCPToken(clientToken)
	if err != nil {
		return "", "", err
	}
	return payload, "", nil
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

func writeServeQRInstruction(stderr io.Writer, payload, webHint string) {
	if stderr == nil {
		return
	}
	if webHint != "" {
		fmt.Fprintf(stderr, "Scan this QR code with the Derphole iOS app to open %s:\n", webHint)
		fmt.Fprintf(stderr, "Web URL: %s\n", webHint)
	} else {
		fmt.Fprintln(stderr, "Scan this QR code with the Derphole iOS app to open this TCP tunnel:")
	}
	fmt.Fprintf(stderr, "Payload: %s\n", payload)
	qrterminal.GenerateHalfBlock(payload, qrterminal.M, stderr)
}

func webURLHint(targetAddr string) string {
	host, port, err := net.SplitHostPort(targetAddr)
	if err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/"}).String()
	}
	return (&url.URL{Scheme: "http", Host: targetAddr, Path: "/"}).String()
}
