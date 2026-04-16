package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	pkgssh "github.com/shayne/derphole/pkg/derphole/ssh"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/yargs"
)

type sshInviteFlags struct {
	User       string `flag:"user" short:"u" help:"Append to USER's ~/.ssh/authorized_keys"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
}
type sshInviteArgs struct{}

type sshAcceptFlags struct {
	KeyFile    string `flag:"key-file" short:"F" help:"SSH public key file to send"`
	Yes        bool   `flag:"yes" short:"y" help:"Skip confirmation prompt"`
	ForceRelay bool   `flag:"force-relay" help:"Disable direct probing"`
}
type sshAcceptArgs struct {
	Token string `pos:"0?" help:"Receive token from ssh invite"`
}

type sshInviteCommandConfig struct {
	User          string
	Stderr        io.Writer
	Emitter       *telemetry.Emitter
	UsePublicDERP bool
	ForceRelay    bool
}

type sshAcceptCommandConfig struct {
	Token         string
	KeyFile       string
	Yes           bool
	Stdin         io.Reader
	Stderr        io.Writer
	UsePublicDERP bool
	ForceRelay    bool
}

var sshHelpConfig = yargs.HelpConfig{
	Command: yargs.CommandInfo{
		Name:        "derphole",
		Description: "Exchange SSH access invites with derphole.",
		Examples: []string{
			"derphole ssh invite",
			"derphole ssh accept <token>",
		},
	},
	SubCommands: map[string]yargs.SubCommandInfo{
		"ssh": {
			Name:        "ssh",
			Description: "SSH invite and accept workflows.",
			Usage:       "<invite|accept>",
		},
		"invite": {
			Name:        "invite",
			Description: "Add a public key to authorized_keys on the receiving host.",
			Usage:       "[--user USER] [--force-relay]",
		},
		"accept": {
			Name:        "accept",
			Description: "Accept an SSH key invite and update authorized_keys.",
			Usage:       "[--key-file PATH] [--yes] [--force-relay] <token>",
		},
	},
}

var (
	runSSHInviteCommand = executeSSHInviteCommand
	runSSHAcceptCommand = executeSSHAcceptCommand
)

func runSSH(args []string, level telemetry.Level, stdin io.Reader, stdout, stderr io.Writer) int {
	_ = stdout

	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, sshHelpText())
		return 0
	}

	switch canonicalSSHCommand(args[0]) {
	case "invite":
		return runSSHInvite(args[1:], level, stdin, stderr)
	case "accept":
		return runSSHAccept(args[1:], level, stdin, stderr)
	default:
		fmt.Fprintf(stderr, "unknown ssh command: %s\n", args[0])
		fmt.Fprint(stderr, sshHelpText())
		return 2
	}
}

func runSSHInvite(args []string, level telemetry.Level, stdin io.Reader, stderr io.Writer) int {
	_ = stdin

	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, sshInviteFlags, sshInviteArgs](append([]string{"invite"}, args...), sshHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, sshInviteHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, sshInviteHelpText())
			return 2
		}
	}

	if len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, sshInviteHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := runSSHInviteCommand(ctx, sshInviteCommandConfig{
		User:          parsed.SubCommandFlags.User,
		Stderr:        stderr,
		Emitter:       telemetry.New(stderr, commandSessionTelemetryLevel(level)),
		UsePublicDERP: usePublicDERPTransport(),
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runSSHAccept(args []string, level telemetry.Level, stdin io.Reader, stderr io.Writer) int {
	parsed, err := yargs.ParseWithCommandAndHelp[struct{}, sshAcceptFlags, sshAcceptArgs](append([]string{"accept"}, args...), sshHelpConfig)
	if err != nil {
		switch {
		case errors.Is(err, yargs.ErrHelp), errors.Is(err, yargs.ErrSubCommandHelp), errors.Is(err, yargs.ErrHelpLLM):
			if parsed != nil && parsed.HelpText != "" {
				fmt.Fprint(stderr, parsed.HelpText)
			} else {
				fmt.Fprint(stderr, sshAcceptHelpText())
			}
			return 0
		default:
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, sshAcceptHelpText())
			return 2
		}
	}

	if len(parsed.Parser.Args) > 1 || len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, sshAcceptHelpText())
		return 2
	}
	if parsed.Args.Token == "" {
		fmt.Fprint(stderr, sshAcceptHelpText())
		return 2
	}

	ctx, stop := commandContext()
	defer stop()
	if err := runSSHAcceptCommand(ctx, sshAcceptCommandConfig{
		Token:         parsed.Args.Token,
		KeyFile:       parsed.SubCommandFlags.KeyFile,
		Yes:           parsed.SubCommandFlags.Yes,
		Stdin:         stdin,
		Stderr:        stderr,
		UsePublicDERP: usePublicDERPTransport(),
		ForceRelay:    parsed.SubCommandFlags.ForceRelay,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func canonicalSSHCommand(name string) string {
	return name
}

func sshHelpText() string {
	return yargs.GenerateSubCommandHelp(sshHelpConfig, "ssh", struct{}{}, struct{}{}, struct{}{})
}

func sshInviteHelpText() string {
	return yargs.GenerateSubCommandHelp(sshHelpConfig, "invite", struct{}{}, sshInviteFlags{}, sshInviteArgs{})
}

func sshAcceptHelpText() string {
	return yargs.GenerateSubCommandHelp(sshHelpConfig, "accept", struct{}{}, sshAcceptFlags{}, sshAcceptArgs{})
}

func executeSSHInviteCommand(ctx context.Context, cfg sshInviteCommandConfig) error {
	authPath, err := pkgssh.AuthorizedKeysPath(cfg.User)
	if err != nil {
		return err
	}

	listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
		Emitter:       cfg.Emitter,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Fprintln(cfg.Stderr, "On the other machine, run:")
	fmt.Fprintf(cfg.Stderr, "derphole ssh accept %s\n", listener.Token)

	if err := pkgssh.Invite(ctx, pkgssh.InviteConfig{
		Listener:       listener,
		AuthorizedKeys: authPath,
	}); err != nil {
		return err
	}

	fmt.Fprintf(cfg.Stderr, "Appended SSH public key to %s\n", authPath)
	return nil
}

func executeSSHAcceptCommand(ctx context.Context, cfg sshAcceptCommandConfig) error {
	kind, keyID, pubkey, err := pkgssh.FindPublicKey(cfg.KeyFile)
	if err != nil {
		return err
	}

	fmt.Fprintf(cfg.Stderr, "Sending public key type='%s' keyid='%s'\n", kind, keyID)
	if !cfg.Yes {
		ok, err := confirmSSHSend(cfg.Stdin, cfg.Stderr, keyID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}

	if err := pkgssh.Accept(ctx, pkgssh.AcceptConfig{
		Token:         cfg.Token,
		PublicKey:     pubkey,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	}); err != nil {
		return err
	}

	fmt.Fprintln(cfg.Stderr, "Public key sent.")
	return nil
}

func confirmSSHSend(stdin io.Reader, stderr io.Writer, keyID string) (bool, error) {
	if stdin == nil {
		return false, errors.New("confirmation required; rerun with --yes")
	}
	fmt.Fprintf(stderr, "Really send public key %q? [y/N] ", keyID)
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
