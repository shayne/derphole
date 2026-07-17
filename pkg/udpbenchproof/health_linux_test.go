// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxOpenFileIdentityUsesRealFileStat(t *testing.T) {
	path := t.TempDir() + "/executable"
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open executable: %v", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat executable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("real Linux FileInfo.Sys() has type %T, want *syscall.Stat_t", info.Sys())
	}
	want := fmt.Sprintf("dev:%d-ino:%d", uint64(stat.Dev), stat.Ino)

	got, err := linuxOpenFileIdentity(file)
	if err != nil {
		t.Fatalf("linuxOpenFileIdentity: %v", err)
	}
	if got != want {
		t.Fatalf("linuxOpenFileIdentity() = %q, want %q", got, want)
	}
}

func TestLinuxLiveHealthCollectors(t *testing.T) {
	if _, err := captureLinuxIdentity(); err != nil {
		t.Fatalf("capture Linux identity: %v", err)
	}
	if _, _, err := captureLinuxMemory(nil); err != nil {
		t.Fatalf("capture Linux memory: %v", err)
	}
	if _, err := linuxDiskFree(t.TempDir()); err != nil {
		t.Fatalf("capture Linux disk: %v", err)
	}
	if _, err := captureLinuxNetwork("lo"); err != nil {
		t.Fatalf("capture Linux loopback counters: %v", err)
	}

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("open fixture UDP socket: %v", err)
	}
	defer listener.Close()

	process := currentLinuxProcessRef(t)
	tables, err := readLinuxSocketTables()
	if err != nil {
		t.Fatalf("read Linux socket tables: %v", err)
	}
	present, sockets, err := captureLinuxOwnedProcess(process, tables)
	if err != nil || !present {
		t.Fatalf("capture current Linux process = present:%t sockets:%#v err:%v", present, sockets, err)
	}
	foundFixture := false
	for _, socket := range sockets {
		if socket.Network == "udp4" {
			foundFixture = true
		}
	}
	if !foundFixture {
		t.Fatalf("current process sockets = %#v, want fixture %s", sockets, listener.LocalAddr())
	}

	processRoot, matches, err := matchingLinuxProcessRoot(process)
	if err != nil || !matches {
		t.Fatalf("match current Linux process = root:%q matches:%t err:%v", processRoot, matches, err)
	}
	observed, candidate, err := observeScopedLinuxProcess(process, processRoot)
	if err != nil || !candidate || observed != process {
		t.Fatalf("observe current Linux process = %#v candidate:%t err:%v", observed, candidate, err)
	}

	wrongStart := process
	wrongStart.StartIdentity = "wrong-start-identity"
	if _, candidate, err := observeScopedLinuxProcess(wrongStart, processRoot); err != nil || candidate {
		t.Fatalf("wrong start identity = candidate:%t err:%v", candidate, err)
	}
	if _, candidate, err := observeScopedLinuxProcess(process, filepath.Join(t.TempDir(), "absent")); err != nil || candidate {
		t.Fatalf("absent process = candidate:%t err:%v", candidate, err)
	}

	options := HealthCaptureOptions{
		WorkDir:        t.TempDir(),
		Interface:      "lo",
		CleanupScope:   CleanupScope{Declared: true, Processes: []ProcessRef{process}, Cgroups: []CgroupRef{}},
		CommandTimeout: time.Second,
	}
	snapshot, err := capturePlatformHealth(context.Background(), options)
	if err != nil {
		if !strings.Contains(err.Error(), "/usr/bin/dmesg") {
			t.Fatalf("capture Linux platform health: %v", err)
		}
	} else if snapshot.Platform != "linux" || snapshot.BootID == "" || snapshot.OnlineCPUs <= 0 {
		t.Fatalf("Linux platform health = %#v", snapshot)
	}
}

func TestLinuxSocketFDParserRejectsOtherDescriptors(t *testing.T) {
	for _, target := range []string{"pipe:[123]", "anon_inode:[eventpoll]", "/tmp/fixture", "socket:[123"} {
		if _, _, socket, err := parseLinuxSocketFD(target); err != nil || socket {
			t.Fatalf("parse Linux descriptor %q = socket:%t err:%v", target, socket, err)
		}
	}
	inode, inodeText, socket, err := parseLinuxSocketFD("socket:[123]")
	if err != nil || !socket || inode != 123 || inodeText != "123" {
		t.Fatalf("parse Linux socket = inode:%d text:%q socket:%t err:%v", inode, inodeText, socket, err)
	}
	if _, _, _, err := parseLinuxSocketFD("socket:[invalid]"); err == nil {
		t.Fatal("malformed Linux socket inode accepted")
	}
}

func TestLinuxObservePlatformProcessFailsClosed(t *testing.T) {
	process := currentLinuxProcessRef(t)
	if got, err := observePlatformProcess(context.Background(), process.Name, process.PID, time.Second); err != nil || got != process {
		t.Fatalf("observe current process = %#v, %v", got, err)
	}
	if _, err := observePlatformProcess(context.Background(), "wrong-name", process.PID, time.Second); err == nil || !strings.Contains(err.Error(), "name does not match") {
		t.Fatalf("wrong-name observation error = %v", err)
	}
	if _, err := observePlatformProcess(context.Background(), process.Name, 1<<30, time.Second); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("absent-process observation error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observePlatformProcess(canceled, process.Name, process.PID, time.Second); err == nil {
		t.Fatal("canceled process observation succeeded")
	}
}

func currentLinuxProcessRef(t *testing.T) ProcessRef {
	t.Helper()
	pid := os.Getpid()
	processRoot := filepath.Join("/proc", strconv.Itoa(pid))
	statInput, err := readHealthFile(filepath.Join(processRoot, "stat"))
	if err != nil {
		t.Fatalf("read current process stat: %v", err)
	}
	name, startIdentity, err := parseLinuxProcessNameAndStartIdentity(statInput)
	if err != nil {
		t.Fatalf("parse current process stat: %v", err)
	}
	executableIdentity, err := linuxExecutableIdentityAt(processRoot, pid)
	if err != nil {
		t.Fatalf("identify current process executable: %v", err)
	}
	return ProcessRef{Name: name, PID: pid, StartIdentity: startIdentity, ExecutableIdentity: executableIdentity}
}
