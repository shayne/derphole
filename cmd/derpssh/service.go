// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	derpsshsession "github.com/shayne/derphole/pkg/derpssh/session"
	"github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/endpointlookup"
)

type parsedServiceSetArgs struct {
	Name     string
	Invite   string
	Registry string
}

type parsedServiceNameArgs struct {
	Name     string
	Registry string
}

func runService(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "set":
		return runServiceSet(args[1:], stderr)
	case "list":
		return runServiceList(args[1:], stdout, stderr)
	case "rm":
		return runServiceRemove(args[1:], stderr)
	default:
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return 2
	}
}

func runServiceSet(args []string, stderr io.Writer) int {
	parsed, ok := parseServiceSetArgs(args, stderr)
	if !ok {
		return 2
	}
	if err := publishDerpsshInvite(context.Background(), parsed.Name, parsed.Invite, parsed.Registry); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return serviceErrorCode(err)
	}
	return 0
}

func runServiceList(args []string, stdout, stderr io.Writer) int {
	registryPath, ok := parseServiceListArgs(args, stderr)
	if !ok {
		return 2
	}
	registry, err := derpsshServiceRegistry(registryPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	summaries, err := registry.List(context.Background())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	for _, summary := range summaries {
		if summary.Kind != endpointlookup.KindDerpsshInvite {
			continue
		}
		_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", summary.Name, summary.Kind, formatServiceExpiry(summary.ExpiresUnix), summary.Display)
	}
	return 0
}

func runServiceRemove(args []string, stderr io.Writer) int {
	parsed, ok := parseServiceNameArgs(args, stderr, "rm")
	if !ok {
		return 2
	}
	registry, err := derpsshServiceRegistry(parsed.Registry)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	if err := registry.Remove(context.Background(), parsed.Name); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return serviceErrorCode(err)
	}
	return 0
}

func publishDerpsshInvite(ctx context.Context, name, invite, registryPath string) error {
	now := time.Now()
	decoded, err := derpsshsession.DecodeInvite(strings.TrimSpace(invite))
	if err != nil {
		return err
	}
	client, err := derptun.DecodeClientToken(decoded.ClientToken, now)
	if err != nil {
		return err
	}
	record, err := endpointlookup.NewRecord(name, endpointlookup.KindDerpsshInvite, invite, now, time.Unix(client.ExpiresUnix, 0))
	if err != nil {
		return err
	}
	registry, err := derpsshServiceRegistry(registryPath)
	if err != nil {
		return err
	}
	return registry.Publish(ctx, record)
}

func resolveDerpsshServiceInvite(ctx context.Context, service, registryPath string) (string, error) {
	registry, err := derpsshServiceRegistry(registryPath)
	if err != nil {
		return "", err
	}
	record, err := registry.Resolve(ctx, service, endpointlookup.KindDerpsshInvite)
	if err != nil {
		return "", err
	}
	return record.Value, nil
}

func derpsshServiceRegistry(path string) (endpointlookup.FileRegistry, error) {
	if strings.TrimSpace(path) != "" {
		return endpointlookup.FileRegistry{Path: path}, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return endpointlookup.FileRegistry{}, fmt.Errorf("resolve service registry path: %w", err)
	}
	return endpointlookup.FileRegistry{Path: filepath.Join(dir, "derphole", "services.json")}, nil
}

func parseServiceSetArgs(args []string, stderr io.Writer) (parsedServiceSetArgs, bool) {
	var parsed parsedServiceSetArgs
	for i := 0; i < len(args); i++ {
		if !parseServiceSetArg(args, &i, stderr, &parsed) {
			return parsedServiceSetArgs{}, false
		}
	}
	if parsed.Name == "" || parsed.Invite == "" {
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return parsedServiceSetArgs{}, false
	}
	return parsed, true
}

func parseServiceSetArg(args []string, index *int, stderr io.Writer, parsed *parsedServiceSetArgs) bool {
	arg := args[*index]
	if handled, ok := parseServiceSetRegistryArg(args, index, stderr, parsed); handled {
		return ok
	}
	if strings.HasPrefix(arg, "-") {
		_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return false
	}
	return parseServiceSetPositional(arg, stderr, parsed)
}

func parseServiceSetRegistryArg(args []string, index *int, stderr io.Writer, parsed *parsedServiceSetArgs) (bool, bool) {
	arg := args[*index]
	switch {
	case arg == "--registry":
		value, ok := serviceFlagValue(args, index, "--registry", stderr)
		parsed.Registry = value
		return true, ok
	case strings.HasPrefix(arg, "--registry="):
		parsed.Registry = strings.TrimPrefix(arg, "--registry=")
		return true, true
	default:
		return false, false
	}
}

func parseServiceSetPositional(arg string, stderr io.Writer, parsed *parsedServiceSetArgs) bool {
	if parsed.Name == "" {
		parsed.Name = arg
		return true
	}
	if parsed.Invite == "" {
		parsed.Invite = arg
		return true
	}
	_, _ = fmt.Fprint(stderr, serviceHelpText())
	return false
}

func parseServiceListArgs(args []string, stderr io.Writer) (string, bool) {
	var registry string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--registry":
			value, ok := serviceFlagValue(args, &i, "--registry", stderr)
			if !ok {
				return "", false
			}
			registry = value
		case strings.HasPrefix(arg, "--registry="):
			registry = strings.TrimPrefix(arg, "--registry=")
		default:
			if strings.HasPrefix(arg, "-") {
				_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
			}
			_, _ = fmt.Fprint(stderr, serviceHelpText())
			return "", false
		}
	}
	return registry, true
}

func parseServiceNameArgs(args []string, stderr io.Writer, command string) (parsedServiceNameArgs, bool) {
	var parsed parsedServiceNameArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--registry":
			value, ok := serviceFlagValue(args, &i, "--registry", stderr)
			if !ok {
				return parsedServiceNameArgs{}, false
			}
			parsed.Registry = value
		case strings.HasPrefix(arg, "--registry="):
			parsed.Registry = strings.TrimPrefix(arg, "--registry=")
		case strings.HasPrefix(arg, "-"):
			_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
			_, _ = fmt.Fprint(stderr, serviceHelpText())
			return parsedServiceNameArgs{}, false
		default:
			if parsed.Name != "" {
				_, _ = fmt.Fprint(stderr, serviceHelpText())
				return parsedServiceNameArgs{}, false
			}
			parsed.Name = arg
		}
	}
	if parsed.Name == "" {
		_, _ = fmt.Fprintf(stderr, "service %s requires NAME\n", command)
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return parsedServiceNameArgs{}, false
	}
	return parsed, true
}

func serviceFlagValue(args []string, index *int, flag string, stderr io.Writer) (string, bool) {
	if *index+1 >= len(args) {
		_, _ = fmt.Fprintf(stderr, "%s requires a value\n", flag)
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return "", false
	}
	*index = *index + 1
	return args[*index], true
}

func serviceErrorCode(err error) int {
	switch {
	case errors.Is(err, derpsshsession.ErrInvalidInvite), errors.Is(err, derptun.ErrInvalidToken), errors.Is(err, derptun.ErrExpired):
		return 2
	case errors.Is(err, endpointlookup.ErrInvalidName), errors.Is(err, endpointlookup.ErrInvalidKind), errors.Is(err, endpointlookup.ErrExpired), errors.Is(err, endpointlookup.ErrNotFound):
		return 2
	default:
		return 1
	}
}

func formatServiceExpiry(expiresUnix int64) string {
	if expiresUnix == 0 {
		return "no-expiry"
	}
	return time.Unix(expiresUnix, 0).UTC().Format(time.RFC3339)
}

func serviceHelpText() string {
	return `Manage local derpssh service-name registry entries.

USAGE:
    derpssh service set NAME INVITE [--registry PATH]
    derpssh service list [--registry PATH]
    derpssh service rm NAME [--registry PATH]

`
}
