// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompareHealthBindsDeclaredCleanupScopeAndProcessIdentity(t *testing.T) {
	t.Parallel()

	process := ProcessRef{
		Name: "derphole", PID: 123,
		StartIdentity: "start-100", ExecutableIdentity: "/opt/run/derphole",
	}
	scope := CleanupScope{Declared: true, Processes: []ProcessRef{process}, Cgroups: []CgroupRef{}}
	policy := HealthPolicy{
		ExpectedOnlineCPUs: 2, MinAvailableMemoryBytes: 1, MinDiskAvailableBytes: 1,
		MaxSwapUsedBytes: 1 << 30, MaxSwapIncreaseBytes: 0, ExpectedCleanupScope: scope,
	}

	for name, mutate := range map[string]func(*HealthSnapshot){
		"omitted":     func(snapshot *HealthSnapshot) { snapshot.CleanupScope = CleanupScope{} },
		"substituted": func(snapshot *HealthSnapshot) { snapshot.CleanupScope.Processes[0].PID++ },
	} {
		t.Run(name, func(t *testing.T) {
			before, after := healthyHealthSnapshot(), healthyHealthSnapshot()
			before.CleanupScope, after.CleanupScope = cloneCleanupScope(scope), cloneCleanupScope(scope)
			after.UptimeSeconds++
			mutate(&after)
			verdict := CompareHealth(before, after, policy)
			if verdict.Healthy || !healthReasonContains(verdict.Reasons, "cleanup scope") {
				t.Fatalf("verdict = %#v, want exact cleanup scope rejection", verdict)
			}
		})
	}

	t.Run("PID reuse is not the scoped process", func(t *testing.T) {
		before, after := healthyHealthSnapshot(), healthyHealthSnapshot()
		before.CleanupScope, after.CleanupScope = scope, scope
		before.Processes = []ProcessRef{process}
		after.UptimeSeconds++
		after.Processes = []ProcessRef{{
			Name: process.Name, PID: process.PID,
			StartIdentity: "start-200", ExecutableIdentity: process.ExecutableIdentity,
		}}
		verdict := CompareHealth(before, after, policy)
		if verdict.Healthy || !healthReasonContains(verdict.Reasons, "outside declared cleanup scope") {
			t.Fatalf("verdict = %#v, want identity mismatch rejection without false scoped leak", verdict)
		}
		if healthReasonContains(verdict.Reasons, "process leak") {
			t.Fatalf("PID reuse was misreported as old process leak: %#v", verdict)
		}
	})

	t.Run("explicit empty scope is valid", func(t *testing.T) {
		empty := CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{}}
		before, after := healthyHealthSnapshot(), healthyHealthSnapshot()
		before.CleanupScope, after.CleanupScope = empty, empty
		after.UptimeSeconds++
		policy.ExpectedCleanupScope = empty
		if verdict := CompareHealth(before, after, policy); !verdict.Healthy {
			t.Fatalf("explicit empty scope rejected: %#v", verdict)
		}
	})
}

func TestHealthCaptureRequiresBoundedDeclaredScope(t *testing.T) {
	t.Parallel()

	valid := HealthCaptureOptions{
		WorkDir: "/tmp", Interface: "en0",
		CleanupScope:   CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{}},
		CaptureTimeout: 30 * time.Second, CommandTimeout: 5 * time.Second,
	}
	if err := validateHealthCaptureOptions(valid); err != nil {
		t.Fatalf("valid explicit empty scope: %v", err)
	}
	for name, mutate := range map[string]func(*HealthCaptureOptions){
		"omitted scope":   func(options *HealthCaptureOptions) { options.CleanupScope = CleanupScope{} },
		"capture timeout": func(options *HealthCaptureOptions) { options.CaptureTimeout = 0 },
		"command timeout": func(options *HealthCaptureOptions) { options.CommandTimeout = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if err := validateHealthCaptureOptions(options); err == nil {
				t.Fatal("invalid capture options accepted")
			}
		})
	}
}

func TestCompareHealthUsesNamedVectorsAndSwapPolicy(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*HealthSnapshot){
		"interface component": func(after *HealthSnapshot) {
			after.InterfaceCounters[0].Value++
			after.InterfaceCounters[1].Value--
		},
		"UDP component": func(after *HealthSnapshot) {
			after.UDPCounters[0].Value++
			after.UDPCounters[1].Value--
		},
		"softnet component":  func(after *HealthSnapshot) { after.SoftnetCounters[0].Value++ },
		"missing vector key": func(after *HealthSnapshot) { after.UDPCounters = after.UDPCounters[1:] },
		"swap maximum":       func(after *HealthSnapshot) { after.SwapUsedBytes = 11 },
		"swap increase":      func(after *HealthSnapshot) { after.SwapUsedBytes = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			before, after := healthyHealthSnapshot(), healthyHealthSnapshot()
			before.SwapUsedBytes, after.SwapUsedBytes = 5, 5
			for index := range before.InterfaceCounters {
				before.InterfaceCounters[index].Value = 5
				after.InterfaceCounters[index].Value = 5
			}
			for index := range before.UDPCounters {
				before.UDPCounters[index].Value = 5
				after.UDPCounters[index].Value = 5
			}
			for index := range before.SoftnetCounters {
				before.SoftnetCounters[index].Value = 5
				after.SoftnetCounters[index].Value = 5
			}
			after.UptimeSeconds++
			mutate(&after)
			policy := healthyHealthPolicy()
			policy.MaxSwapUsedBytes = 10
			policy.MaxSwapIncreaseBytes = 0
			verdict := CompareHealth(before, after, policy)
			if verdict.Healthy {
				t.Fatalf("%s change passed: %#v", name, verdict)
			}
		})
	}
}

func TestCompareHealthUsesExactNamedCgroupVectors(t *testing.T) {
	t.Parallel()

	cgroup := CgroupRef{Path: "/sys/fs/cgroup/bench.scope", Identity: "dev:1-ino:2"}
	scope := CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{cgroup}}
	events := []NamedCounter{{Name: "low"}, {Name: "high"}, {Name: "max"}, {Name: "oom"}, {Name: "oom_kill"}, {Name: "oom_group_kill"}}
	before, after := healthyHealthSnapshot(), healthyHealthSnapshot()
	before.Platform, after.Platform = "linux", "linux"
	before.CleanupScope, after.CleanupScope = scope, scope
	before.InterfaceCounters = []NamedCounter{{Name: "rx_dropped"}, {Name: "rx_errors"}, {Name: "tx_dropped"}, {Name: "tx_errors"}}
	after.InterfaceCounters = append([]NamedCounter(nil), before.InterfaceCounters...)
	before.UDPCounters = []NamedCounter{{Name: "InCsumErrors"}, {Name: "InErrors"}, {Name: "NoPorts"}, {Name: "RcvbufErrors"}, {Name: "SndbufErrors"}}
	after.UDPCounters = append([]NamedCounter(nil), before.UDPCounters...)
	before.SoftnetCounters, after.SoftnetCounters = []NamedCounter{{Name: "cpu:0"}}, []NamedCounter{{Name: "cpu:0"}}
	before.Cgroups = []CgroupHealth{{Path: cgroup.Path, Identity: cgroup.Identity, MemoryEvents: append([]NamedCounter(nil), events...)}}
	after.Cgroups = []CgroupHealth{{Path: cgroup.Path, Identity: cgroup.Identity, MemoryEvents: append([]NamedCounter(nil), events...)}}
	after.Cgroups[0].MemoryEvents[4].Value++
	after.UptimeSeconds++
	policy := healthyHealthPolicy()
	policy.ExpectedCleanupScope = scope
	if verdict := CompareHealth(before, after, policy); verdict.Healthy || !healthReasonContains(verdict.Reasons, "oom_kill") {
		t.Fatalf("named cgroup OOM delta passed: %#v", verdict)
	}
}

func TestCanonicalBootUUID(t *testing.T) {
	t.Parallel()

	if got, err := canonicalBootUUID("550e8400-e29b-41d4-a716-446655440000\n"); err != nil || got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("canonical UUID = %q, %v", got, err)
	}
	for _, input := range []string{
		"550E8400-E29B-41D4-A716-446655440000", "550e8400e29b41d4a716446655440000",
		"550e8400-e29b-41d4-a716-44665544000z", "boot-a", "",
	} {
		if _, err := canonicalBootUUID(input); err == nil {
			t.Fatalf("noncanonical boot UUID %q accepted", input)
		}
	}
}

func TestLinuxOwnedScopeIdentityParsersFailClosed(t *testing.T) {
	t.Parallel()

	events := "low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\noom_group_kill 6\n"
	counters, err := parseLinuxMemoryEvents(events)
	if err != nil || len(counters) != 6 {
		t.Fatalf("memory.events = %v, %v", counters, err)
	}
	for _, input := range []string{
		"low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\n",
		events + "oom_kill 7\n",
		strings.Replace(events, "oom 4", "oom nope", 1),
	} {
		if _, err := parseLinuxMemoryEvents(input); err == nil {
			t.Fatalf("invalid memory.events accepted: %q", input)
		}
	}

	stat := "123 (derp hole) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999\n"
	if start, err := parseLinuxProcessStartIdentity(stat); err != nil || start != "999" {
		t.Fatalf("process start identity = %q, %v", start, err)
	}
	for _, input := range []string{"123 derphole S 1\n", "123 (derphole) S 1 2\n", strings.Replace(stat, "999", "nope", 1)} {
		if _, err := parseLinuxProcessStartIdentity(input); err == nil {
			t.Fatalf("invalid process stat accepted: %q", input)
		}
	}
}

func TestHealthCommandDeadlineCancelsBlockingRunner(t *testing.T) {
	t.Parallel()

	executor := func(ctx context.Context, _ string, _ ...string) (healthCommandResult, error) {
		<-ctx.Done()
		return healthCommandResult{}, ctx.Err()
	}
	started := time.Now()
	_, err := runHealthCommandResultWithExecutor(context.Background(), 20*time.Millisecond, executor, "/fixture/block")
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("blocking command error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocking command cancellation took %s", elapsed)
	}
}

func TestCaptureHealthPipelineBindsScopeAndTotalDeadline(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{}, 1)
	scope := CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{}}
	options := HealthCaptureOptions{
		WorkDir: "/tmp", Interface: "en0", CleanupScope: scope,
		CaptureTimeout: 100 * time.Millisecond, CommandTimeout: 50 * time.Millisecond,
	}
	snapshot, err := captureHealthWithPlatformAndGate(context.Background(), options, func(context.Context, HealthCaptureOptions) (HealthSnapshot, error) {
		return healthyHealthSnapshot(), nil
	}, gate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.CleanupScope, scope) || !reflect.DeepEqual(snapshot.CounterFamilies, requiredHealthCounterFamilies()) {
		t.Fatalf("capture did not bind canonical scope/families: %#v", snapshot)
	}

	options.CaptureTimeout = 20 * time.Millisecond
	options.CommandTimeout = 10 * time.Millisecond
	started := time.Now()
	_, err = captureHealthWithPlatformAndGate(context.Background(), options, func(ctx context.Context, _ HealthCaptureOptions) (HealthSnapshot, error) {
		<-ctx.Done()
		return HealthSnapshot{}, ctx.Err()
	}, gate)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("total deadline result = %v", err)
	}
	var nilContext context.Context
	if _, err := captureHealthWithPlatformAndGate(nilContext, options, nil, gate); err == nil {
		t.Fatal("nil capture inputs accepted")
	}
}

func TestCaptureHealthHardDeadlineBoundsUninterruptibleWorkers(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{}, 1)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	options := HealthCaptureOptions{
		WorkDir: "/tmp", Interface: "en0", CleanupScope: CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{}},
		CaptureTimeout: 20 * time.Millisecond, CommandTimeout: 10 * time.Millisecond,
	}
	var calls atomic.Int32
	capture := func(context.Context, HealthCaptureOptions) (HealthSnapshot, error) {
		calls.Add(1)
		<-block
		return healthyHealthSnapshot(), nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		started := time.Now()
		_, err := captureHealthWithPlatformAndGate(context.Background(), options, capture, gate)
		if err == nil || !strings.Contains(err.Error(), "deadline") {
			t.Fatalf("attempt %d blocking capture error = %v", attempt, err)
		}
		if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
			t.Fatalf("attempt %d blocking capture took %s", attempt, elapsed)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("uninterruptible capture workers = %d, want bounded at 1", calls.Load())
	}
}

func TestScopedProcessIdentityDistinguishesPIDReuseFromLiveMutation(t *testing.T) {
	t.Parallel()

	expected := ProcessRef{Name: "derphole", PID: 42, StartIdentity: "100", ExecutableIdentity: "dev:1-ino:2"}
	matched, err := matchScopedProcessIdentity(expected, expected)
	if err != nil || !matched {
		t.Fatalf("exact process identity = %t, %v", matched, err)
	}
	reused := expected
	reused.StartIdentity = "101"
	matched, err = matchScopedProcessIdentity(expected, reused)
	if err != nil || matched {
		t.Fatalf("PID reuse identity = %t, %v", matched, err)
	}
	mutated := expected
	mutated.ExecutableIdentity = "dev:1-ino:3"
	matched, err = matchScopedProcessIdentity(expected, mutated)
	if err == nil || matched || !strings.Contains(err.Error(), "same live process") {
		t.Fatalf("same-live-process mutation = %t, %v", matched, err)
	}
}

type fakeConfinedCgroupFilesystem struct {
	openDirectoryErr error
	identity         string
	memoryEvents     string
	openedRelative   string
	readName         string
	closed           []int
}

func (filesystem *fakeConfinedCgroupFilesystem) OpenRoot() (int, error) { return 10, nil }

func (filesystem *fakeConfinedCgroupFilesystem) OpenDirectory(_ int, relative string) (int, error) {
	filesystem.openedRelative = relative
	if filesystem.openDirectoryErr != nil {
		return -1, filesystem.openDirectoryErr
	}
	return 11, nil
}

func (filesystem *fakeConfinedCgroupFilesystem) Identity(_ int) (string, error) {
	return filesystem.identity, nil
}

func (filesystem *fakeConfinedCgroupFilesystem) ReadFile(_ int, name string) (string, error) {
	filesystem.readName = name
	return filesystem.memoryEvents, nil
}

func (filesystem *fakeConfinedCgroupFilesystem) Close(fd int) error {
	filesystem.closed = append(filesystem.closed, fd)
	return nil
}

func TestConfinedCgroupCaptureUsesOneRootedDirectoryIdentity(t *testing.T) {
	t.Parallel()

	events := "low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\noom_group_kill 6\n"
	expected := CgroupRef{Path: "/sys/fs/cgroup/bench.scope", Identity: "dev:1-ino:2"}
	filesystem := &fakeConfinedCgroupFilesystem{identity: expected.Identity, memoryEvents: events}
	health, kills, err := captureConfinedCgroup(expected, filesystem)
	if err != nil {
		t.Fatal(err)
	}
	if health.Path != expected.Path || kills != 5 || filesystem.openedRelative != "bench.scope" || filesystem.readName != "memory.events" {
		t.Fatalf("confined capture = %#v kills=%d fs=%#v", health, kills, filesystem)
	}
	if !reflect.DeepEqual(filesystem.closed, []int{11, 10}) {
		t.Fatalf("closed handles = %v", filesystem.closed)
	}

	for name, fixture := range map[string]*fakeConfinedCgroupFilesystem{
		"symlink or mount escape":    {openDirectoryErr: errors.New("openat2 resolve violation")},
		"directory identity changed": {identity: "dev:1-ino:3", memoryEvents: events},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := captureConfinedCgroup(expected, fixture); err == nil {
				t.Fatal("unsafe cgroup capture accepted")
			}
			if fixture.readName != "" {
				t.Fatalf("unsafe cgroup read %q", fixture.readName)
			}
		})
	}
}

func TestHealthLinuxPlatformParsersFailClosed(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		name  string
		parse func(string) error
		input string
	}{
		{"online CPUs", func(input string) error { _, err := parseLinuxOnlineCPUs(input); return err }, "0-1,4,6-7\n"},
		{"uptime", func(input string) error { _, err := parseLinuxUptime(input); return err }, "123.25 45.00\n"},
		{"vmstat OOM", func(input string) error {
			_, err := parseLinuxNamedUint(input, "oom_kill", "Linux global OOM counter")
			return err
		}, "pgfault 10\noom_kill 2\n"},
		{"softnet", func(input string) error { _, err := parseLinuxSoftnetCounters(input); return err }, "00000001 00000002 00000000\n00000003 00000004 00000000\n"},
		{"network sockets", func(input string) error {
			_, err := parseLinuxNetworkSocketTable(input, "udp4")
			return err
		}, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n   7: 0100007F:1FBB 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345 2 0000000000000000 0\n"},
		{"unix sockets", func(input string) error { _, err := parseLinuxUnixSocketTable(input); return err }, "Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 67890 /tmp/example.sock\n"},
	}
	for _, test := range validCases {
		t.Run(test.name+" valid", func(t *testing.T) {
			if err := test.parse(test.input); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
		})
		t.Run(test.name+" missing", func(t *testing.T) {
			if err := test.parse(""); err == nil {
				t.Fatal("missing fixture accepted")
			}
		})
		t.Run(test.name+" malformed", func(t *testing.T) {
			if err := test.parse("definitely malformed\n"); err == nil {
				t.Fatal("malformed fixture accepted")
			}
		})
	}
}

func TestLinuxNetworkSocketTableSkipsOwnerlessTCPTimeWaitRows(t *testing.T) {
	t.Parallel()

	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	header6 := "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	timeWaitOne := "   3: 0100007F:9C55 0100007F:1F90 06 00000000:00000000 03:0000176F 00000000 0 0 0 3 0000000000000000 0\n"
	timeWaitTwo := "   4: 0100007F:9C56 0100007F:1F90 06 00000000:00000000 03:00001770 00000000 0 0 0 3 0000000000000000 0\n"
	owned := "   5: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n"

	table, err := parseLinuxNetworkSocketTable(header+timeWaitOne+timeWaitTwo+owned, "tcp4")
	if err != nil {
		t.Fatal(err)
	}
	if len(table) != 1 || table[12345].Network != "tcp4" {
		t.Fatalf("socket table = %#v, want only owned inode 12345", table)
	}
	tcp6TimeWait := "   6: 00000000000000000000000001000000:9C55 00000000000000000000000001000000:1F90 06 00000000:00000000 03:0000176F 00000000 0 0 0 3 0000000000000000 0\n"
	if table, err := parseLinuxNetworkSocketTable(header6+tcp6TimeWait, "tcp6"); err != nil || len(table) != 0 {
		t.Fatalf("ownerless tcp6 TIME_WAIT table = %#v, %v", table, err)
	}

	for name, fixture := range map[string]string{
		"malformed zero-inode index":   strings.Replace(timeWaitOne, "3:", "bad:", 1),
		"malformed zero-inode address": strings.Replace(timeWaitOne, "0100007F:9C55", "malformed", 1),
		"non-TIME-WAIT TCP zero inode": strings.Replace(timeWaitOne, " 06 ", " 01 ", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLinuxNetworkSocketTable(header+fixture, "tcp4"); err == nil {
				t.Fatalf("invalid zero-inode TCP row accepted: %q", fixture)
			}
		})
	}
	if _, err := parseLinuxNetworkSocketTable(header+timeWaitOne, "udp4"); err == nil {
		t.Fatal("UDP zero inode accepted")
	}
	if _, err := parseLinuxNetworkSocketTable(header+owned+owned, "tcp4"); err == nil {
		t.Fatal("duplicate nonzero inode accepted")
	}
}

func TestLinuxLiveProcNetworkHeaders(t *testing.T) {
	t.Parallel()

	tcp4 := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	tcp6 := "sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	udp4 := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n"
	udp6 := "sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n"
	for network, header := range map[string]string{"tcp4": tcp4, "tcp6": tcp6, "udp4": udp4, "udp6": udp6} {
		network, header := network, header
		t.Run(network+" exact live header", func(t *testing.T) {
			t.Parallel()
			if table, err := parseLinuxNetworkSocketTable(header, network); err != nil || len(table) != 0 {
				t.Fatalf("exact %s header = %#v, %v", network, table, err)
			}
		})
	}

	invalid := map[string]struct{ network, header string }{
		"missing column":       {"tcp4", strings.Replace(tcp4, " timeout", "", 1)},
		"reordered columns":    {"tcp4", strings.Replace(tcp4, "local_address rem_address", "rem_address local_address", 1)},
		"unknown column":       {"udp4", strings.Replace(udp4, " drops", " mystery", 1)},
		"IPv4 remote spelling": {"tcp4", strings.Replace(tcp4, "rem_address", "remote_address", 1)},
		"IPv6 remote spelling": {"tcp6", strings.Replace(tcp6, "remote_address", "rem_address", 1)},
	}
	for name, test := range invalid {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseLinuxNetworkSocketTable(test.header, test.network); err == nil {
				t.Fatalf("invalid %s header accepted: %q", test.network, test.header)
			}
		})
	}

	unix := "Num RefCount Protocol Flags Type St Inode Path\n"
	if table, err := parseLinuxUnixSocketTable(unix); err != nil || len(table) != 0 {
		t.Fatalf("exact Unix header = %#v, %v", table, err)
	}
	for name, header := range map[string]string{
		"Unix missing column":    strings.Replace(unix, " St", "", 1),
		"Unix reordered columns": strings.Replace(unix, "Inode Path", "Path Inode", 1),
		"Unix unknown column":    strings.Replace(unix, "Path", "Unknown", 1),
	} {
		if _, err := parseLinuxUnixSocketTable(header); err == nil {
			t.Fatalf("%s accepted: %q", name, header)
		}
	}
}

func TestCompareHealthRejectsRebootOOMKernelAndLeak(t *testing.T) {
	t.Parallel()

	policy := healthyHealthPolicy()
	policy.MinAvailableMemoryBytes = 1 << 30
	policy.MinDiskAvailableBytes = 5 << 30
	tests := map[string]struct {
		mutate func(*HealthSnapshot)
		reason string
	}{
		"reboot":            {func(after *HealthSnapshot) { after.BootID = "boot-b" }, "boot ID changed"},
		"uptime regression": {func(after *HealthSnapshot) { after.UptimeSeconds = 99 }, "uptime did not advance"},
		"global OOM":        {func(after *HealthSnapshot) { after.GlobalOOMKills++ }, "global OOM"},
		"cgroup OOM":        {func(after *HealthSnapshot) { after.CgroupOOMKills++ }, "cgroup OOM"},
		"CPU count":         {func(after *HealthSnapshot) { after.OnlineCPUs = 1 }, "online CPU"},
		"memory pressure":   {func(after *HealthSnapshot) { after.AvailableMemoryBytes = (1 << 30) - 1 }, "available memory"},
		"low disk":          {func(after *HealthSnapshot) { after.DiskFreeBytes = (5 << 30) - 1 }, "disk free"},
		"kernel error":      {func(after *HealthSnapshot) { after.KernelErrors = []string{"nvme timeout"} }, "new kernel error"},
		"interface failure": {func(after *HealthSnapshot) { after.InterfaceCounters[0].Value++ }, "interface"},
		"UDP failure":       {func(after *HealthSnapshot) { after.UDPCounters[0].Value++ }, "UDP"},
		"softnet failure":   {func(after *HealthSnapshot) { after.SoftnetCounters[0].Value++ }, "softnet"},
		"exact process leak": {func(after *HealthSnapshot) {
			process := ProcessRef{Name: "derphole", PID: 123, StartIdentity: "start", ExecutableIdentity: "/bin/derphole"}
			after.CleanupScope = CleanupScope{Declared: true, Processes: []ProcessRef{process}, Cgroups: []CgroupRef{}}
			after.Processes = []ProcessRef{process}
		}, "process leak"},
		"exact socket leak": {func(after *HealthSnapshot) {
			process := ProcessRef{Name: "derphole", PID: 123, StartIdentity: "start", ExecutableIdentity: "/bin/derphole"}
			after.CleanupScope = CleanupScope{Declared: true, Processes: []ProcessRef{process}, Cgroups: []CgroupRef{}}
			after.Sockets = []SocketRef{{Network: "udp4", Local: "127.0.0.1:1000", Remote: "127.0.0.1:2000", PID: 123, StartIdentity: "start", ExecutableIdentity: "/bin/derphole"}}
		}, "socket leak"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			before := healthyHealthSnapshot()
			after := healthyHealthSnapshot()
			after.UptimeSeconds++
			test.mutate(&after)
			verdict := CompareHealth(before, after, policy)
			if verdict.Healthy || !healthReasonContains(verdict.Reasons, test.reason) {
				t.Fatalf("verdict = %#v, want unhealthy reason containing %q", verdict, test.reason)
			}
		})
	}

	before := healthyHealthSnapshot()
	after := healthyHealthSnapshot()
	after.UptimeSeconds++
	if verdict := CompareHealth(before, after, policy); !verdict.Healthy || len(verdict.Reasons) != 0 {
		t.Fatalf("unchanged healthy host = %#v", verdict)
	}
}

func TestHealthSnapshotRequiresEveryCounterFamily(t *testing.T) {
	t.Parallel()

	policy := healthyHealthPolicy()
	wantFamilies := requiredHealthCounterFamilies()
	for index, family := range wantFamilies {
		t.Run(family, func(t *testing.T) {
			before := healthyHealthSnapshot()
			after := healthyHealthSnapshot()
			after.UptimeSeconds++
			before.CounterFamilies = append(append([]string(nil), wantFamilies[:index]...), wantFamilies[index+1:]...)
			verdict := CompareHealth(before, after, policy)
			if verdict.Healthy || !healthReasonContains(verdict.Reasons, "counter families") {
				t.Fatalf("missing %q verdict = %#v", family, verdict)
			}
		})
	}
}

func TestHealthPlatformParsersFailClosedOnMissingOrMalformedRequiredData(t *testing.T) {
	t.Parallel()

	if _, err := parseLinuxMeminfo("MemAvailable: 1024 kB\nSwapTotal: 512 kB\nSwapFree: 256 kB\n"); err != nil {
		t.Fatalf("valid Linux meminfo: %v", err)
	}
	for _, value := range []string{
		"MemAvailable: 1024 kB\nSwapTotal: 512 kB\n",
		"MemAvailable: nope kB\nSwapTotal: 512 kB\nSwapFree: 256 kB\n",
	} {
		if _, err := parseLinuxMeminfo(value); err == nil {
			t.Fatalf("invalid Linux meminfo accepted: %q", value)
		}
	}

	validUDP := "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors\nUdp: 10 2 3 12 4 5 6\n"
	if _, err := parseLinuxUDPErrorCounters(validUDP); err != nil {
		t.Fatalf("valid Linux UDP counters: %v", err)
	}
	for _, value := range []string{
		"Udp: InDatagrams InErrors\n",
		"Udp: InDatagrams InErrors\nUdp: 1 nope\n",
		validUDP + validUDP,
		validUDP + "Udp: trailing duplicate",
	} {
		if _, err := parseLinuxUDPErrorCounters(value); err == nil {
			t.Fatalf("invalid Linux UDP counters accepted: %q", value)
		}
	}

	for _, value := range []string{
		"0-1,1-2\n",
		"2-1\n",
		"0--1\n",
	} {
		if _, err := parseLinuxOnlineCPUs(value); err == nil {
			t.Fatalf("invalid Linux online CPUs accepted: %q", value)
		}
	}
	for _, value := range []string{"NaN 1\n", "1 -Inf\n", "1\n"} {
		if _, err := parseLinuxUptime(value); err == nil {
			t.Fatalf("invalid Linux uptime accepted: %q", value)
		}
	}

	if _, err := parseDarwinVMStat("Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\nPages inactive: 20.\nPages speculative: 5.\n"); err != nil {
		t.Fatalf("valid Darwin vm_stat: %v", err)
	}
	for _, value := range []string{
		"Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\n",
		"Mach Virtual Memory Statistics: (page size of nope bytes)\nPages free: 10.\nPages inactive: 20.\nPages speculative: 5.\n",
	} {
		if _, err := parseDarwinVMStat(value); err == nil {
			t.Fatalf("invalid Darwin vm_stat accepted: %q", value)
		}
	}
}

func healthyHealthSnapshot() HealthSnapshot {
	return HealthSnapshot{
		Platform:             "darwin",
		BootID:               "boot-a",
		UptimeSeconds:        100,
		OnlineCPUs:           2,
		AvailableMemoryBytes: 2 << 30,
		DiskFreeBytes:        10 << 30,
		KernelErrors:         []string{},
		InterfaceCounters:    []NamedCounter{{Name: "input_errors"}, {Name: "output_errors"}},
		UDPCounters:          []NamedCounter{{Name: "bad_checksum"}, {Name: "bad_data_length"}, {Name: "full_socket_buffers"}, {Name: "incomplete_header"}, {Name: "no_socket"}},
		SoftnetCounters:      []NamedCounter{{Name: "en0/poll-on"}},
		Cgroups:              []CgroupHealth{},
		CleanupScope:         CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{}},
		Processes:            []ProcessRef{},
		Sockets:              []SocketRef{},
		CounterFamilies:      requiredHealthCounterFamilies(),
	}
}

func healthyHealthPolicy() HealthPolicy {
	return HealthPolicy{
		ExpectedOnlineCPUs: 2, MinAvailableMemoryBytes: 1, MinDiskAvailableBytes: 1,
		MaxSwapUsedBytes: 1 << 30, MaxSwapIncreaseBytes: 0,
		ExpectedCleanupScope: CleanupScope{Declared: true, Processes: []ProcessRef{}, Cgroups: []CgroupRef{}},
	}
}

func healthReasonContains(reasons []string, want string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, want) {
			return true
		}
	}
	return false
}

func TestHealthCounterFamiliesAreStableAndComplete(t *testing.T) {
	t.Parallel()

	want := []string{
		"uptime", "online-cpus", "global-oom", "cgroup-oom", "memory", "swap", "disk",
		"kernel", "interface", "udp", "softnet", "process", "socket",
	}
	if got := requiredHealthCounterFamilies(); !reflect.DeepEqual(got, want) {
		t.Fatalf("counter families = %v, want %v", got, want)
	}
}

func TestHealthOptionValidationAndNormalization(t *testing.T) {
	t.Parallel()

	valid := HealthCaptureOptions{
		WorkDir: "/tmp", Interface: "en0", CaptureTimeout: 30 * time.Second, CommandTimeout: 5 * time.Second,
		CleanupScope: CleanupScope{Declared: true, Cgroups: []CgroupRef{}, Processes: []ProcessRef{
			{Name: "derphole", PID: 10, StartIdentity: "one", ExecutableIdentity: "/bin/derphole"},
			{Name: "udppeak", PID: 20, StartIdentity: "two", ExecutableIdentity: "/bin/udppeak"},
		}},
	}
	if err := validateHealthCaptureOptions(valid); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	for name, mutate := range map[string]func(*HealthCaptureOptions){
		"workdir":              func(options *HealthCaptureOptions) { options.WorkDir = "" },
		"interface slash":      func(options *HealthCaptureOptions) { options.Interface = "bad/name" },
		"interface backslash":  func(options *HealthCaptureOptions) { options.Interface = `bad\name` },
		"interface whitespace": func(options *HealthCaptureOptions) { options.Interface = "bad name" },
		"interface tab":        func(options *HealthCaptureOptions) { options.Interface = "bad\tname" },
		"interface too long":   func(options *HealthCaptureOptions) { options.Interface = strings.Repeat("e", 65) },
		"PID":                  func(options *HealthCaptureOptions) { options.CleanupScope.Processes[0].PID = 0 },
		"name":                 func(options *HealthCaptureOptions) { options.CleanupScope.Processes[0].Name = "bad/name" },
		"duplicate":            func(options *HealthCaptureOptions) { options.CleanupScope.Processes[1].PID = 10 },
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			options.CleanupScope = cloneCleanupScope(valid.CleanupScope)
			mutate(&options)
			if err := validateHealthCaptureOptions(options); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}

	snapshot := healthyHealthSnapshot()
	snapshot.KernelErrors = []string{"z", "a", "a"}
	snapshot.Processes = []ProcessRef{
		{Name: "second", PID: 2, StartIdentity: "two", ExecutableIdentity: "/bin/second"},
		{Name: "first", PID: 1, StartIdentity: "one", ExecutableIdentity: "/bin/first"},
	}
	snapshot.Sockets = []SocketRef{
		{Network: "udp4", Local: "b", PID: 2, StartIdentity: "two", ExecutableIdentity: "/bin/second"},
		{Network: "tcp4", Local: "a", PID: 1, StartIdentity: "one", ExecutableIdentity: "/bin/first"},
	}
	normalizeHealthSnapshot(&snapshot)
	if !reflect.DeepEqual(snapshot.KernelErrors, []string{"a", "z"}) {
		t.Fatalf("kernel normalization = %v", snapshot.KernelErrors)
	}
	if snapshot.Processes[0].PID != 1 || snapshot.Sockets[0].PID != 1 {
		t.Fatalf("state was not sorted: processes=%v sockets=%v", snapshot.Processes, snapshot.Sockets)
	}

	snapshot.KernelErrors, snapshot.Processes, snapshot.Sockets = nil, nil, nil
	normalizeHealthSnapshot(&snapshot)
	if snapshot.KernelErrors == nil || snapshot.Processes == nil || snapshot.Sockets == nil {
		t.Fatal("nil counter families were not materialized")
	}
}
