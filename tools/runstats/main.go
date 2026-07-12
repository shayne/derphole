// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"time"
)

type result struct {
	UserCPUSeconds         float64 `json:"user_cpu_seconds"`
	SystemCPUSeconds       float64 `json:"system_cpu_seconds"`
	MaxRSSBytes            uint64  `json:"max_rss_bytes"`
	ResourceStatsAvailable bool    `json:"resource_stats_available"`
	ExitCode               int     `json:"exit_code"`
}

type rssReader func(*os.ProcessState) (uint64, bool)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, maxRSSBytes))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, readRSS rssReader) int {
	out, command, ok := parseArgs(args, stderr)
	if !ok {
		return 2
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := runChild(cmd)
	exitCode := childExitCode(err)

	measurement := result{ExitCode: exitCode}
	if cmd.ProcessState != nil {
		measurement.UserCPUSeconds = cmd.ProcessState.UserTime().Seconds()
		measurement.SystemCPUSeconds = cmd.ProcessState.SystemTime().Seconds()
		measurement.MaxRSSBytes, measurement.ResourceStatsAvailable = readRSS(cmd.ProcessState)
	}
	if writeErr := writeResultAtomic(out, measurement); writeErr != nil {
		_, _ = fmt.Fprintf(stderr, "runstats: write resource stats: %v\n", writeErr)
		if exitCode == 0 {
			return 1
		}
	}
	if err != nil && cmd.ProcessState == nil {
		_, _ = fmt.Fprintf(stderr, "runstats: start child: %v\n", err)
	}
	return exitCode
}

func parseArgs(args []string, stderr io.Writer) (string, []string, bool) {
	flags := flag.NewFlagSet("runstats", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("out", "", "resource JSON output path")
	delimiter := -1
	for index, arg := range args {
		if arg == "--" {
			delimiter = index
			break
		}
	}
	if delimiter < 0 {
		_, _ = fmt.Fprintln(stderr, "usage: runstats -out <path> -- <command> [args...]")
		return "", nil, false
	}
	if err := flags.Parse(args[:delimiter]); err != nil {
		return "", nil, false
	}
	command := args[delimiter+1:]
	if *out == "" || len(flags.Args()) != 0 || len(command) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: runstats -out <path> -- <command> [args...]")
		return "", nil, false
	}
	return *out, command, true
}

func runChild(cmd *exec.Cmd) error {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, forwardedSignals()...)
	err := cmd.Start()
	if err == nil {
		go forwardSignals(cmd, signals, done)
		err = cmd.Wait()
	}
	close(done)
	signal.Stop(signals)
	return err
}

func forwardSignals(cmd *exec.Cmd, signals <-chan os.Signal, done <-chan struct{}) {
	var escalate sync.Once
	for {
		select {
		case childSignal := <-signals:
			_ = cmd.Process.Signal(childSignal)
			escalate.Do(func() {
				go func() {
					select {
					case <-time.After(1500 * time.Millisecond):
						_ = cmd.Process.Kill()
					case <-done:
					}
				}()
			})
		case <-done:
			return
		}
	}
}

func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
		return 1
	}
	return 127
}

func writeResultAtomic(path string, measurement result) (returnErr error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			if closeErr := tmp.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
		if returnErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := json.NewEncoder(tmp).Encode(measurement); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}
