// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDarwinHealthCaptureFromReadOnlyFixtures(t *testing.T) {
	t.Parallel()

	source := darwinHealthSource{
		command: func(_ context.Context, path string, args ...string) (string, error) {
			key := path
			if len(args) != 0 {
				key += " " + strings.Join(args, " ")
			}
			switch key {
			case "/usr/sbin/sysctl -n kern.boottime":
				return "{ sec = 1000, usec = 500000 } Thu Jan  1 00:00:00 1970\n", nil
			case "/usr/sbin/sysctl -n hw.activecpu":
				return "2\n", nil
			case "/usr/sbin/sysctl -n kern.memorystatus.kill_on_sustained_pressure_count":
				return "3\n", nil
			case "/usr/bin/vm_stat":
				return "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\nPages inactive: 20.\nPages speculative: 5.\n", nil
			case "/usr/sbin/sysctl -n vm.swapusage":
				return "total = 8.00M used = 2.50M free = 5.50M (encrypted)\n", nil
			case "/usr/bin/log show --last 15m --style compact --predicate " + darwinKernelErrorPredicate:
				return "Timestamp Thread Type Activity PID TTL\nnvme I/O error\n", nil
			case "/usr/sbin/netstat -ibn -I en0":
				return "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\nen0 1500 <Link#1> aa:bb 10 2 100 20 3 200 0\n", nil
			case "/usr/sbin/netstat -s -p udp":
				return darwinUDPFixture(), nil
			case "/usr/sbin/netstat -Q":
				return "en0 [ poll on requests: 1 errors: 4 ]\n", nil
			default:
				return "", fmt.Errorf("unexpected fixture command %q", key)
			}
		},
		diskFree: func(path string) (uint64, error) {
			if path != "/work" {
				return 0, fmt.Errorf("unexpected disk path %q", path)
			}
			return 9 << 30, nil
		},
		ownedState: func(_ context.Context, owned []ProcessRef) ([]ProcessRef, []SocketRef, error) {
			if len(owned) != 0 {
				return nil, nil, fmt.Errorf("unexpected owned state")
			}
			return []ProcessRef{}, []SocketRef{}, nil
		},
		now: func() time.Time { return time.Unix(1100, 500_000_000) },
	}
	snapshot, err := captureDarwinHealth(context.Background(), HealthCaptureOptions{WorkDir: "/work", Interface: "en0"}, source)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.BootID != "darwin-1000-500000" || snapshot.UptimeSeconds != 100 || snapshot.OnlineCPUs != 2 {
		t.Fatalf("identity = %#v", snapshot)
	}
	if snapshot.GlobalOOMKills != 3 || snapshot.AvailableMemoryBytes != 35*16384 || snapshot.SwapUsedBytes != 5<<19 {
		t.Fatalf("memory = %#v", snapshot)
	}
	if snapshot.DiskFreeBytes != 9<<30 || snapshot.InterfaceDrops != 5 || snapshot.UDPErrors != 15 || snapshot.SoftnetDrops != 4 {
		t.Fatalf("resource/network = %#v", snapshot)
	}
	if !reflect.DeepEqual(snapshot.KernelErrors, []string{"nvme I/O error"}) {
		t.Fatalf("kernel errors = %v", snapshot.KernelErrors)
	}
}

func TestDarwinHealthParsersFailClosed(t *testing.T) {
	t.Parallel()

	if _, _, err := parseDarwinBootTime("{ sec = 1000, usec = 42 } x\n"); err != nil {
		t.Fatalf("boot fixture: %v", err)
	}
	if _, _, err := parseDarwinBootTime("missing"); err == nil {
		t.Fatal("malformed boot time accepted")
	}
	if value, err := parseDarwinSwapUsed("total = 8.00M used = 2.50M free = 5.50M"); err != nil || value != 5<<19 {
		t.Fatalf("swap fixture = %d, %v", value, err)
	}
	if _, err := parseDarwinSwapUsed("used = nope"); err == nil {
		t.Fatal("malformed swap accepted")
	}
	for _, input := range []string{
		"total = 8.00M used = 2.50M free = 5.50M used = 1.00M",
		"total = 8.00M used = 0.10M free = 7.90M",
		"total = 8.00M used = 2.50G free = 5.50M",
	} {
		if _, err := parseDarwinSwapUsed(input); err == nil {
			t.Fatalf("ambiguous or inexact swap accepted: %q", input)
		}
	}
	interfaceFixture := "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\nen0 1500 link aa 1 2 3 4 5 6 0\n"
	if counters, err := parseDarwinInterfaceCounters(interfaceFixture, "en0"); err != nil || sumHealthFixtureCounters(counters) != 7 {
		value := sumHealthFixtureCounters(counters)
		t.Fatalf("interface fixture = %d, %v", value, err)
	}
	if _, err := parseDarwinInterfaceCounters("missing", "en0"); err == nil {
		t.Fatal("missing interface counters accepted")
	}
	if counters, err := parseDarwinUDPCounters(darwinUDPFixture()); err != nil || sumHealthFixtureCounters(counters) != 15 {
		value := sumHealthFixtureCounters(counters)
		t.Fatalf("UDP fixture = %d, %v", value, err)
	}
	if _, err := parseDarwinUDPCounters("1 with incomplete header\n"); err == nil {
		t.Fatal("incomplete UDP counters accepted")
	}
	if counters, err := parseDarwinSoftnetCounters("en0 [ poll on requests: 1 errors: 2 ]\n     [ poll off requests: 1 errors: 3 ]\n"); err != nil || sumHealthFixtureCounters(counters) != 5 {
		value := sumHealthFixtureCounters(counters)
		t.Fatalf("softnet fixture = %d, %v", value, err)
	}
	if _, err := parseDarwinSoftnetCounters("missing"); err == nil {
		t.Fatal("missing softnet counters accepted")
	}
	process := ProcessRef{Name: "derphole", PID: 2, StartIdentity: "start", ExecutableIdentity: "/tmp/derphole"}
	if _, err := parseDarwinLsofSockets("p2\nPBOGUS\n", process); err == nil {
		t.Fatal("malformed lsof protocol accepted")
	}
	for _, input := range []string{"", "p3\nPUDP\nn127.0.0.1:1\n", "p2\nXunknown\n", "p2\nPUDP\n"} {
		if _, err := parseDarwinLsofSockets(input, process); err == nil {
			t.Fatalf("malformed or truncated lsof accepted: %q", input)
		}
	}
}

func TestDarwinNetISRContinuationRowsFromCurrentMac(t *testing.T) {
	t.Parallel()

	// macOS prints the interface once for a netisr section. Subsequent rows are
	// indented continuations and inherit that interface identity.
	fixture := `en0  [ poll on requests:               11  errors:                           2 ]
     [ poll off requests:              12  errors:                           3 ]
     [ polled packets:                 23  per poll limit:                   0 ]
     [ polled bytes:                  101 ]
     [ poll interval:              200000 nsec ]
     [ sampled packets avg/min/max:            1 /            1 /           17 ]
     [ sampled bytes avg/min/max:            512 /           60 /        65536 ]
     [ sampled wakeups avg:                    0 ]
     [ packets lowat/hiwat threshold:         10 /         40 ]
     [ bytes lowat/hiwat threshold:         4096 /      65536 ]
     [ wakeups lowat/hiwat threshold:         10 /        100 ]
     [ mit mode:                        0  cfg idx:                          0 ]
     [ cfg packets lo/hi threshold:            0 /            0 ]
     [ cfg bytes lo/hi threshold:              0 /            0 ]
     [ cfg interval:               0 nsec ]
     [ mit interval:               0 nsec ]
     [ mit packets avg/min/max:               0 /            0 /            0 ]
     [ mit bytes avg/min/max:                 0 /            0 /            0 ]
`
	counters, err := parseDarwinSoftnetCounters(fixture)
	if err != nil {
		t.Fatal(err)
	}
	want := []NamedCounter{{Name: "en0/poll-on", Value: 2}, {Name: "en0/poll-off", Value: 3}}
	if !reflect.DeepEqual(counters, want) {
		t.Fatalf("netisr counters = %#v, want %#v", counters, want)
	}
}

func TestDarwinNetISRContinuationRowsRemainFailClosed(t *testing.T) {
	t.Parallel()

	validRows := "en0 [ poll on requests: 1 errors: 0 ]\n     [ poll off requests: 1 errors: 0 ]\n"
	tests := map[string]string{
		"continuation without interface":   "     [ poll off requests: 1 errors: 2 ]\n",
		"slash in interface identity":      "bad/name [ poll on requests: 1 errors: 2 ]\n",
		"backslash in interface identity":  `bad\name [ poll on requests: 1 errors: 2 ]` + "\n",
		"whitespace in interface identity": "bad name [ poll on requests: 1 errors: 2 ]\n",
		"interface identity over 64 bytes": strings.Repeat("e", 65) + " [ poll on requests: 1 errors: 2 ]\n",
		"malformed row identity":           "en0 [ poll on callbacks: 1 errors: 2 ]\n",
		"nonnumeric requests":              "en0 [ poll on requests: nope errors: 2 ]\n",
		"overflow requests":                "en0 [ poll on requests: 18446744073709551616 errors: 2 ]\n",
		"missing closing bracket":          "en0 [ poll on requests: 1 errors: 2\n",
		"trailing token":                   "en0 [ poll on requests: 1 errors: 2 ] extra\n",
		"wrong token count":                "en0 [ poll on requests: 1 unexpected errors: 2 ]\n",
		"poll-off header":                  "en0 [ poll off requests: 1 errors: 2 ]\n",
		"poll-on continuation":             "en0 [ poll on requests: 1 errors: 0 ]\n     [ poll on requests: 1 errors: 2 ]\n",
		"duplicate inherited row":          "en0 [ poll on requests: 1 errors: 0 ]\n     [ poll off requests: 1 errors: 2 ]\n     [ poll off requests: 1 errors: 3 ]\n",
		"overflow inherited value":         "en0 [ poll on requests: 1 errors: 0 ]\n     [ poll off requests: 1 errors: 18446744073709551616 ]\n",
		"unconsumed unexpected errors row": validRows + "en1 [ unexpected errors: 9 ]\n",
		"unconsumed errors token":          validRows + "statistics errors: 9\n",
		"interval row with errors":         validRows + "     [ poll interval: 200000 nsec errors: 9 ]\n",
		"interval row nonnumeric":          validRows + "     [ poll interval: nope nsec ]\n",
		"interval row wrong units":         validRows + "     [ poll interval: 200000 usec ]\n",
		"interval row missing bracket":     validRows + "     [ poll interval: 200000 nsec\n",
		"interval row trailing token":      validRows + "     [ poll interval: 200000 nsec ] extra\n",
	}
	for name, fixture := range tests {
		fixture := fixture
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseDarwinSoftnetCounters(fixture); err == nil {
				t.Fatalf("malformed netisr fixture accepted: %q", fixture)
			}
		})
	}
}

func TestDarwinNetISRIntervalCandidateClassification(t *testing.T) {
	t.Parallel()

	validRows := "en0 [ poll on requests: 1 errors: 0 ]\n     [ poll off requests: 1 errors: 0 ]\n"
	tests := map[string]struct {
		line    string
		wantErr bool
	}{
		"exact real interval":       {line: "     [ poll interval: 200000 nsec ]\n"},
		"unrelated sampled row":     {line: "     [ sampled wakeups avg: 0 ]\n"},
		"unrelated plural token":    {line: "summary poll intervals: 200000 nsec\n"},
		"missing opening bracket":   {line: "poll interval: 200000 nsec ]\n", wantErr: true},
		"missing both brackets":     {line: "poll interval: 200000 nsec\n", wantErr: true},
		"missing closing bracket":   {line: "[ poll interval: 200000 nsec\n", wantErr: true},
		"interface prefixed":        {line: "en0 [ poll interval: 200000 nsec ]\n", wantErr: true},
		"prefix without bracket":    {line: "en0 poll interval: 200000 nsec ]\n", wantErr: true},
		"non-bracket leading token": {line: "summary [ poll interval: 200000 nsec ]\n", wantErr: true},
		"nonadjacent opening":       {line: "[ summary poll interval: 200000 nsec ]\n", wantErr: true},
		"nonnumeric interval":       {line: "[ poll interval: nope nsec ]\n", wantErr: true},
		"wrong interval units":      {line: "[ poll interval: 200000 usec ]\n", wantErr: true},
		"trailing interval token":   {line: "[ poll interval: 200000 nsec ] extra\n", wantErr: true},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parseDarwinSoftnetCounters(validRows + test.line)
			if (err != nil) != test.wantErr {
				t.Fatalf("interval candidate error = %v, wantErr %t; line %q", err, test.wantErr, test.line)
			}
		})
	}
}

func TestDarwinHealthOwnedStateUsesExactPIDsAndSockets(t *testing.T) {
	t.Parallel()

	inspector := darwinProcessInspector{
		exists: func(pid int) (bool, error) { return pid == 2, nil },
		startIdentity: func(pid int) (string, error) {
			if pid != 2 {
				return "", fmt.Errorf("unexpected PID %d", pid)
			}
			return "darwin-1784210400-123456", nil
		},
		command: func(_ context.Context, path string, args ...string) (healthCommandResult, error) {
			switch path {
			case "/bin/ps":
				return healthCommandResult{Stdout: "/tmp/derphole\n"}, nil
			case "/usr/sbin/lsof":
				return healthCommandResult{Stdout: "p2\nPUDP\nn127.0.0.1:1234->127.0.0.1:5678\nPTCP\nn[::1]:99 (LISTEN)\n"}, nil
			default:
				return healthCommandResult{}, fmt.Errorf("unexpected command %q", path)
			}
		},
	}
	process := ProcessRef{Name: "derphole", PID: 2, StartIdentity: "darwin-1784210400-123456", ExecutableIdentity: "/tmp/derphole"}
	processes, sockets, err := captureDarwinOwnedStateWithInspector(context.Background(), []ProcessRef{
		{Name: "absent", PID: 1, StartIdentity: "old", ExecutableIdentity: "/tmp/absent"}, process,
	}, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(processes, []ProcessRef{process}) || len(sockets) != 2 {
		t.Fatalf("processes=%v sockets=%v", processes, sockets)
	}
	if sockets[0].Network != "udp4" || sockets[1].Network != "tcp6" {
		t.Fatalf("socket families = %v", sockets)
	}
	if sockets[0].StartIdentity != process.StartIdentity || sockets[0].ExecutableIdentity != process.ExecutableIdentity {
		t.Fatalf("socket process identity = %#v", sockets[0])
	}
}

func TestDarwinProcessIdentityUsesNativeMicroseconds(t *testing.T) {
	t.Parallel()

	expected := ProcessRef{Name: "derphole", PID: 2, StartIdentity: "darwin-1784210400-123456", ExecutableIdentity: "/tmp/derphole"}
	inspector := darwinProcessInspector{
		exists:        func(int) (bool, error) { return true, nil },
		startIdentity: func(int) (string, error) { return "darwin-1784210400-123457", nil },
		command: func(_ context.Context, path string, _ ...string) (healthCommandResult, error) {
			if path != "/bin/ps" {
				return healthCommandResult{}, fmt.Errorf("unexpected command %q", path)
			}
			return healthCommandResult{Stdout: "/tmp/derphole\n"}, nil
		},
	}
	matched, err := darwinProcessIdentityMatches(context.Background(), expected, inspector)
	if err != nil || matched {
		t.Fatalf("microsecond-distinct process = %t, %v", matched, err)
	}
}

func TestDarwinLsofExitOneFailsClosed(t *testing.T) {
	t.Parallel()

	process := ProcessRef{Name: "derphole", PID: 2, StartIdentity: "start", ExecutableIdentity: "/tmp/derphole"}
	for name, result := range map[string]healthCommandResult{
		"stderr":         {ExitCode: 1, Stderr: "permission denied\n"},
		"partial stdout": {ExitCode: 1, Stdout: "p2\n"},
		"unknown status": {ExitCode: 2},
		"empty success":  {ExitCode: 0},
	} {
		t.Run(name, func(t *testing.T) {
			inspector := darwinProcessInspector{
				exists:        func(int) (bool, error) { return true, nil },
				startIdentity: func(int) (string, error) { return "start", nil },
				command: func(_ context.Context, path string, args ...string) (healthCommandResult, error) {
					if path == "/bin/ps" {
						return healthCommandResult{Stdout: "/tmp/derphole\n"}, nil
					}
					return result, nil
				},
			}
			if _, _, err := captureDarwinOwnedStateWithInspector(context.Background(), []ProcessRef{process}, inspector); err == nil {
				t.Fatal("ambiguous lsof status accepted")
			}
		})
	}

	t.Run("proven empty no-match", func(t *testing.T) {
		inspector := darwinProcessInspector{
			exists:        func(int) (bool, error) { return true, nil },
			startIdentity: func(int) (string, error) { return "start", nil },
			command: func(_ context.Context, path string, args ...string) (healthCommandResult, error) {
				if path == "/bin/ps" {
					return healthCommandResult{Stdout: "/tmp/derphole\n"}, nil
				}
				return healthCommandResult{ExitCode: 1}, nil
			},
		}
		processes, sockets, err := captureDarwinOwnedStateWithInspector(context.Background(), []ProcessRef{process}, inspector)
		if err != nil || len(processes) != 1 || len(sockets) != 0 {
			t.Fatalf("proven empty result = %v, %v, %v", processes, sockets, err)
		}
	})
}

func darwinUDPFixture() string {
	return "udp:\n" +
		"  1 with incomplete header\n" +
		"  2 with bad data length field\n" +
		"  3 with bad checksum\n" +
		"  4 dropped due to no socket\n" +
		"  5 dropped due to full socket buffers\n"
}

func sumHealthFixtureCounters(counters []NamedCounter) uint64 {
	var total uint64
	for _, counter := range counters {
		total += counter.Value
	}
	return total
}
