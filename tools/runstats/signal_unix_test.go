// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunForwardsTerminationToChild(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	terminated := filepath.Join(dir, "terminated")
	childPIDPath := filepath.Join(dir, "child.pid")
	resultPath := filepath.Join(dir, "resource.json")
	cmd := exec.Command(os.Args[0], "-test.run=TestRunstatsSignalHelper")
	cmd.Env = append(os.Environ(),
		"RUNSTATS_SIGNAL_HELPER=1",
		"RUNSTATS_SIGNAL_READY="+ready,
		"RUNSTATS_SIGNAL_TERMINATED="+terminated,
		"RUNSTATS_SIGNAL_CHILD_PID="+childPIDPath,
		"RUNSTATS_SIGNAL_RESULT="+resultPath,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start runstats helper: %v", err)
	}
	waitForPath(t, ready)
	childPIDData, err := os.ReadFile(childPIDPath)
	if err != nil {
		t.Fatalf("read child PID: %v", err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(childPIDData)))
	if err != nil {
		t.Fatalf("parse child PID: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	})

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal runstats helper: %v", err)
	}
	waited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waited)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, termErr := os.Stat(terminated)
		processErr := syscall.Kill(childPID, 0)
		if termErr == nil && processErr == syscall.ESRCH {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	<-waited
	termState := "missing"
	if _, err := os.Stat(terminated); err == nil {
		termState = "present"
	}
	processState, _ := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(childPID)).CombinedOutput()
	t.Fatalf("child did not terminate after forwarded SIGTERM: marker=%s process_state=%q", termState, strings.TrimSpace(string(processState)))
}

func TestRunstatsSignalHelper(t *testing.T) {
	if os.Getenv("RUNSTATS_SIGNAL_HELPER") != "1" {
		return
	}
	ready := os.Getenv("RUNSTATS_SIGNAL_READY")
	terminated := os.Getenv("RUNSTATS_SIGNAL_TERMINATED")
	childPID := os.Getenv("RUNSTATS_SIGNAL_CHILD_PID")
	resultPath := os.Getenv("RUNSTATS_SIGNAL_RESULT")
	command := `trap 'touch "$2"' TERM; echo $$ >"$3"; touch "$1"; while :; do sleep 1; done`
	code := run([]string{"-out", resultPath, "--", "/bin/sh", "-c", command, "sh", ready, terminated, childPID}, nil, &bytes.Buffer{}, &bytes.Buffer{}, maxRSSBytes)
	os.Exit(code)
}
