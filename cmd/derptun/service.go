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

	derptunpkg "github.com/shayne/derphole/pkg/derptun"
	"github.com/shayne/derphole/pkg/endpointlookup"
)

type serviceSource struct {
	Service  string
	Registry string
}

type parsedServiceSetArgs struct {
	Name     string
	Source   tokenSource
	Registry string
}

type parsedServiceNameArgs struct {
	Name     string
	Registry string
}

func runService(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "set":
		return runServiceSet(args[1:], stdin, stderr)
	case "list":
		return runServiceList(args[1:], stdout, stderr)
	case "rm":
		return runServiceRemove(args[1:], stderr)
	default:
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return 2
	}
}

func runServiceSet(args []string, stdin io.Reader, stderr io.Writer) int {
	parsed, ok := parseServiceSetArgs(args, stderr)
	if !ok {
		return 2
	}
	token, _, err := resolveTokenSource(stdin, parsed.Source)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return 2
	}
	if err := publishDerptunClientToken(context.Background(), parsed.Name, token, parsed.Registry); err != nil {
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
	registry, err := derptunServiceRegistry(registryPath)
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
		if summary.Kind != endpointlookup.KindDerptunClientToken {
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
	registry, err := derptunServiceRegistry(parsed.Registry)
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

func publishDerptunClientToken(ctx context.Context, name, token, registryPath string) error {
	if err := validateClientTokenForCLI(token); err != nil {
		return err
	}
	now := time.Now()
	cred, err := derptunpkg.DecodeClientToken(token, now)
	if err != nil {
		return err
	}
	record, err := endpointlookup.NewRecord(name, endpointlookup.KindDerptunClientToken, token, now, time.Unix(cred.ExpiresUnix, 0))
	if err != nil {
		return err
	}
	registry, err := derptunServiceRegistry(registryPath)
	if err != nil {
		return err
	}
	return registry.Publish(ctx, record)
}

func resolveDerptunServiceToken(ctx context.Context, service, registryPath string) (string, error) {
	registry, err := derptunServiceRegistry(registryPath)
	if err != nil {
		return "", err
	}
	record, err := registry.Resolve(ctx, service, endpointlookup.KindDerptunClientToken)
	if err != nil {
		return "", err
	}
	return record.Value, nil
}

func derptunServiceRegistry(path string) (endpointlookup.FileRegistry, error) {
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
	if parsed.Name == "" || tokenSourceCount(parsed.Source) != 1 {
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return parsedServiceSetArgs{}, false
	}
	return parsed, true
}

func parseServiceSetArg(args []string, index *int, stderr io.Writer, parsed *parsedServiceSetArgs) bool {
	arg := args[*index]
	if handled, ok := parseServiceSetTokenArg(args, index, stderr, parsed); handled {
		return ok
	}
	if handled, ok := parseServiceSetRegistryArg(args, index, stderr, parsed); handled {
		return ok
	}
	if strings.HasPrefix(arg, "-") {
		_, _ = fmt.Fprintf(stderr, "unknown flag: %s\n", arg)
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return false
	}
	return parseServiceSetName(arg, stderr, parsed)
}

func parseServiceSetTokenArg(args []string, index *int, stderr io.Writer, parsed *parsedServiceSetArgs) (bool, bool) {
	arg := args[*index]
	switch {
	case arg == "--token":
		value, ok := serviceFlagValue(args, index, "--token", stderr)
		parsed.Source.Token = value
		return true, ok
	case strings.HasPrefix(arg, "--token="):
		parsed.Source.Token = strings.TrimPrefix(arg, "--token=")
		return true, true
	case arg == "--token-file":
		value, ok := serviceFlagValue(args, index, "--token-file", stderr)
		parsed.Source.TokenFile = value
		return true, ok
	case strings.HasPrefix(arg, "--token-file="):
		parsed.Source.TokenFile = strings.TrimPrefix(arg, "--token-file=")
		return true, true
	case arg == "--token-stdin":
		parsed.Source.TokenStdin = true
		return true, true
	default:
		return false, false
	}
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

func parseServiceSetName(arg string, stderr io.Writer, parsed *parsedServiceSetArgs) bool {
	if parsed.Name != "" {
		_, _ = fmt.Fprint(stderr, serviceHelpText())
		return false
	}
	parsed.Name = arg
	return true
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
	case errors.Is(err, errServerTokenForClient), errors.Is(err, derptunpkg.ErrInvalidToken), errors.Is(err, derptunpkg.ErrExpired):
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
	return `Manage local derptun service-name registry entries.

USAGE:
    derptun service set NAME (--token TOKEN|--token-file PATH|--token-stdin) [--registry PATH]
    derptun service list [--registry PATH]
    derptun service rm NAME [--registry PATH]

`
}
