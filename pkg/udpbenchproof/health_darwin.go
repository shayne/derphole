// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func capturePlatformHealth(ctx context.Context, options HealthCaptureOptions) (HealthSnapshot, error) {
	return captureDarwinHealth(ctx, options, defaultDarwinHealthSource(options.CommandTimeout))
}

type darwinHealthSource struct {
	command    func(context.Context, string, ...string) (string, error)
	diskFree   func(string) (uint64, error)
	ownedState func(context.Context, []ProcessRef) ([]ProcessRef, []SocketRef, error)
	now        func() time.Time
}

func defaultDarwinHealthSource(timeout time.Duration) darwinHealthSource {
	return darwinHealthSource{
		command: func(ctx context.Context, path string, args ...string) (string, error) {
			return runHealthCommand(ctx, timeout, path, args...)
		},
		diskFree: darwinDiskFree,
		ownedState: func(ctx context.Context, owned []ProcessRef) ([]ProcessRef, []SocketRef, error) {
			return captureDarwinOwnedState(ctx, owned, timeout)
		}, now: time.Now,
	}
}

func captureDarwinHealth(ctx context.Context, options HealthCaptureOptions, source darwinHealthSource) (HealthSnapshot, error) {
	identity, err := captureDarwinIdentity(ctx, source)
	if err != nil {
		return HealthSnapshot{}, err
	}
	memory, err := captureDarwinMemory(ctx, source)
	if err != nil {
		return HealthSnapshot{}, err
	}
	diskFree, err := source.diskFree(options.WorkDir)
	if err != nil {
		return HealthSnapshot{}, err
	}
	kernelOutput, err := source.command(ctx, "/usr/bin/log", "show", "--last", "15m", "--style", "compact", "--predicate", darwinKernelErrorPredicate)
	if err != nil {
		return HealthSnapshot{}, err
	}
	network, err := captureDarwinNetwork(ctx, options.Interface, source)
	if err != nil {
		return HealthSnapshot{}, err
	}
	processes, sockets, err := source.ownedState(ctx, options.CleanupScope.Processes)
	if err != nil {
		return HealthSnapshot{}, err
	}
	return HealthSnapshot{
		Platform: "darwin",
		BootID:   identity.bootID, UptimeSeconds: identity.uptime, OnlineCPUs: identity.onlineCPUs,
		GlobalOOMKills: memory.globalOOM, CgroupOOMKills: 0, AvailableMemoryBytes: memory.available,
		SwapUsedBytes: memory.swapUsed, DiskFreeBytes: diskFree, KernelErrors: parseKernelErrorLines(kernelOutput),
		InterfaceDrops: network.interfaceFailures, UDPErrors: network.udpErrors, SoftnetDrops: network.softnetDrops,
		InterfaceCounters: network.interfaceCounters, UDPCounters: network.udpCounters, SoftnetCounters: network.softnetCounters,
		Cgroups:   []CgroupHealth{},
		Processes: processes, Sockets: sockets,
	}, nil
}

type darwinIdentityHealth struct {
	bootID     string
	uptime     float64
	onlineCPUs int
}

func captureDarwinIdentity(ctx context.Context, source darwinHealthSource) (darwinIdentityHealth, error) {
	bootOutput, err := source.command(ctx, "/usr/sbin/sysctl", "-n", "kern.boottime")
	if err != nil {
		return darwinIdentityHealth{}, err
	}
	bootSeconds, bootID, err := parseDarwinBootTime(bootOutput)
	if err != nil {
		return darwinIdentityHealth{}, err
	}
	uptime := float64(source.now().UnixNano())/float64(time.Second) - bootSeconds
	if uptime <= 0 {
		return darwinIdentityHealth{}, fmt.Errorf("darwin uptime is invalid")
	}
	cpuOutput, err := source.command(ctx, "/usr/sbin/sysctl", "-n", "hw.activecpu")
	if err != nil {
		return darwinIdentityHealth{}, err
	}
	onlineCPUs, err := parsePositiveInt(cpuOutput, "darwin online CPU count")
	if err != nil {
		return darwinIdentityHealth{}, err
	}
	return darwinIdentityHealth{bootID: bootID, uptime: uptime, onlineCPUs: onlineCPUs}, nil
}

type darwinMemoryHealth struct {
	globalOOM uint64
	available uint64
	swapUsed  uint64
}

func captureDarwinMemory(ctx context.Context, source darwinHealthSource) (darwinMemoryHealth, error) {
	oomOutput, err := source.command(ctx, "/usr/sbin/sysctl", "-n", "kern.memorystatus.kill_on_sustained_pressure_count")
	if err != nil {
		return darwinMemoryHealth{}, err
	}
	globalOOM, err := parseSingleUint(oomOutput, 10, "darwin memorystatus kill counter")
	if err != nil {
		return darwinMemoryHealth{}, err
	}
	vmOutput, err := source.command(ctx, "/usr/bin/vm_stat")
	if err != nil {
		return darwinMemoryHealth{}, err
	}
	availableMemory, err := parseDarwinVMStat(vmOutput)
	if err != nil {
		return darwinMemoryHealth{}, err
	}
	swapOutput, err := source.command(ctx, "/usr/sbin/sysctl", "-n", "vm.swapusage")
	if err != nil {
		return darwinMemoryHealth{}, err
	}
	swapUsed, err := parseDarwinSwapUsed(swapOutput)
	if err != nil {
		return darwinMemoryHealth{}, err
	}
	return darwinMemoryHealth{globalOOM: globalOOM, available: availableMemory, swapUsed: swapUsed}, nil
}

type darwinNetworkHealth struct {
	interfaceFailures uint64
	udpErrors         uint64
	softnetDrops      uint64
	interfaceCounters []NamedCounter
	udpCounters       []NamedCounter
	softnetCounters   []NamedCounter
}

func captureDarwinNetwork(ctx context.Context, interfaceName string, source darwinHealthSource) (darwinNetworkHealth, error) {
	interfaceOutput, err := source.command(ctx, "/usr/sbin/netstat", "-ibn", "-I", interfaceName)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	interfaceCounters, err := parseDarwinInterfaceCounters(interfaceOutput, interfaceName)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	interfaceFailures, err := sumNamedCounters(interfaceCounters)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	udpOutput, err := source.command(ctx, "/usr/sbin/netstat", "-s", "-p", "udp")
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	udpCounters, err := parseDarwinUDPCounters(udpOutput)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	udpErrors, err := sumNamedCounters(udpCounters)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	softnetOutput, err := source.command(ctx, "/usr/sbin/netstat", "-Q")
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	softnetCounters, err := parseDarwinSoftnetCounters(softnetOutput)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	softnetDrops, err := sumNamedCounters(softnetCounters)
	if err != nil {
		return darwinNetworkHealth{}, err
	}
	return darwinNetworkHealth{interfaceFailures: interfaceFailures, udpErrors: udpErrors, softnetDrops: softnetDrops,
		interfaceCounters: interfaceCounters, udpCounters: udpCounters, softnetCounters: softnetCounters}, nil
}

const darwinKernelErrorPredicate = `process == "kernel" AND (eventMessage CONTAINS[c] "panic" OR eventMessage CONTAINS[c] "watchdog timeout" OR eventMessage CONTAINS[c] "I/O error" OR eventMessage CONTAINS[c] "out of memory" OR eventMessage CONTAINS[c] "memorystatus: killing")`

func parseDarwinBootTime(input string) (float64, string, error) {
	secondsText, microsecondsText, err := splitDarwinBootTime(input)
	if err != nil {
		return 0, "", err
	}
	seconds, err := strconv.ParseInt(secondsText, 10, 64)
	if err != nil || seconds <= 0 {
		return 0, "", fmt.Errorf("darwin boot seconds are malformed")
	}
	microseconds, err := strconv.ParseInt(microsecondsText, 10, 64)
	if err != nil || microseconds < 0 || microseconds >= 1_000_000 {
		return 0, "", fmt.Errorf("darwin boot microseconds are malformed")
	}
	return float64(seconds) + float64(microseconds)/1_000_000, fmt.Sprintf("darwin-%d-%06d", seconds, microseconds), nil
}

func splitDarwinBootTime(input string) (string, string, error) {
	start := strings.Index(input, "sec = ")
	separator := strings.Index(input, ", usec = ")
	end := strings.Index(input, " }")
	if start < 0 || separator < 0 || end < 0 {
		return "", "", fmt.Errorf("darwin boot time is malformed")
	}
	secondsStart := start + len("sec = ")
	microsecondsStart := separator + len(", usec = ")
	if separator <= secondsStart || end <= microsecondsStart {
		return "", "", fmt.Errorf("darwin boot time is malformed")
	}
	return strings.TrimSpace(input[secondsStart:separator]), strings.TrimSpace(input[microsecondsStart:end]), nil
}

func parsePositiveInt(input, label string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s is malformed", label)
	}
	return value, nil
}

func parseSingleUint(input string, base int, label string) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(input), base, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is malformed", label)
	}
	return value, nil
}

func parseDarwinSwapUsed(input string) (uint64, error) {
	fields := strings.Fields(input)
	var (
		used  uint64
		found bool
	)
	for index := 0; index+2 < len(fields); index++ {
		if fields[index] != "used" || fields[index+1] != "=" {
			continue
		}
		if found {
			return 0, fmt.Errorf("darwin swap usage used bytes are duplicated")
		}
		value, err := parseExactBinaryMegabytes(fields[index+2])
		if err != nil {
			return 0, fmt.Errorf("darwin swap usage is malformed")
		}
		used = value
		found = true
	}
	if !found {
		return 0, fmt.Errorf("darwin swap usage is missing used bytes")
	}
	return used, nil
}

func parseExactBinaryMegabytes(input string) (uint64, error) {
	if !strings.HasSuffix(input, "M") {
		return 0, fmt.Errorf("binary megabyte suffix is missing")
	}
	wholeText, fraction, err := splitExactDecimal(strings.TrimSuffix(input, "M"))
	if err != nil {
		return 0, err
	}
	whole, err := strconv.ParseUint(wholeText, 10, 64)
	if err != nil || whole > ^uint64(0)/(1<<20) {
		return 0, fmt.Errorf("binary megabytes are malformed")
	}
	bytes := whole * (1 << 20)
	if fraction == "" {
		return bytes, nil
	}
	fractionBytes, err := exactBinaryMegabyteFraction(fraction)
	if err != nil {
		return 0, err
	}
	if bytes > ^uint64(0)-fractionBytes {
		return 0, fmt.Errorf("binary megabytes are malformed")
	}
	return bytes + fractionBytes, nil
}

func splitExactDecimal(decimal string) (string, string, error) {
	parts := strings.Split(decimal, ".")
	if len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return "", "", fmt.Errorf("binary megabytes are malformed")
	}
	if len(parts) == 1 {
		return parts[0], "", nil
	}
	return parts[0], parts[1], nil
}

func exactBinaryMegabyteFraction(fraction string) (uint64, error) {
	if len(fraction) > 18 {
		return 0, fmt.Errorf("binary megabytes are malformed")
	}
	numerator, err := strconv.ParseUint(fraction, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("binary megabytes are malformed")
	}
	denominator := uint64(1)
	for range fraction {
		if denominator > ^uint64(0)/10 {
			return 0, fmt.Errorf("binary megabytes are malformed")
		}
		denominator *= 10
	}
	if numerator > ^uint64(0)/(1<<20) {
		return 0, fmt.Errorf("binary megabytes are malformed")
	}
	scaled := numerator * (1 << 20)
	if scaled%denominator != 0 {
		return 0, fmt.Errorf("binary megabytes are not an exact byte count")
	}
	return scaled / denominator, nil
}

func darwinDiskFree(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("darwin disk statfs: %w", err)
	}
	if stat.Bsize <= 0 {
		return 0, fmt.Errorf("darwin disk block size is invalid")
	}
	free, err := multiplyHealthUint64(stat.Bavail, uint64(stat.Bsize))
	if err != nil || free == 0 {
		return 0, fmt.Errorf("darwin disk free bytes are invalid")
	}
	return free, nil
}

func parseDarwinInterfaceCounters(input, interfaceName string) ([]NamedCounter, error) {
	lines := strings.Split(input, "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("darwin interface counters are missing")
	}
	headers := strings.Fields(lines[0])
	ierrs, oerrs := fieldIndex(headers, "Ierrs"), fieldIndex(headers, "Oerrs")
	if ierrs < 0 || oerrs < 0 {
		return nil, fmt.Errorf("darwin interface error columns are missing")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != interfaceName {
			continue
		}
		value, found, err := parseDarwinInterfaceRow(fields, ierrs, oerrs)
		if err != nil {
			return nil, err
		}
		if found {
			return []NamedCounter{{Name: "input_errors", Value: value[0]}, {Name: "output_errors", Value: value[1]}}, nil
		}
	}
	return nil, fmt.Errorf("darwin interface counters for %s are missing", interfaceName)
}

func parseDarwinInterfaceRow(fields []string, ierrs, oerrs int) ([2]uint64, bool, error) {
	if len(fields) <= ierrs || len(fields) <= oerrs {
		return [2]uint64{}, false, fmt.Errorf("darwin interface counter row is malformed")
	}
	if fields[ierrs] == "-" || fields[oerrs] == "-" {
		return [2]uint64{}, false, nil
	}
	incoming, err := parseSingleUint(fields[ierrs], 10, "darwin interface input errors")
	if err != nil {
		return [2]uint64{}, false, err
	}
	outgoing, err := parseSingleUint(fields[oerrs], 10, "darwin interface output errors")
	if err != nil {
		return [2]uint64{}, false, err
	}
	return [2]uint64{incoming, outgoing}, true, nil
}

func parseDarwinUDPCounters(input string) ([]NamedCounter, error) {
	want := map[string]string{
		"with incomplete header":             "incomplete_header",
		"with bad data length field":         "bad_data_length",
		"with bad checksum":                  "bad_checksum",
		"dropped due to no socket":           "no_socket",
		"dropped due to full socket buffers": "full_socket_buffers",
	}
	seen := make(map[string]bool, len(want))
	var counters []NamedCounter
	for _, line := range strings.Split(input, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		for suffix, name := range want {
			if !strings.HasSuffix(trimmed, suffix) {
				continue
			}
			if seen[suffix] {
				return nil, fmt.Errorf("darwin UDP counter %q is duplicated", suffix)
			}
			value, err := parseSingleUint(fields[0], 10, "darwin UDP counter")
			if err != nil {
				return nil, err
			}
			counters = append(counters, NamedCounter{Name: name, Value: value})
			seen[suffix] = true
		}
	}
	if len(seen) != len(want) {
		return nil, fmt.Errorf("darwin UDP error counters are incomplete")
	}
	normalizeNamedCounters(counters)
	return counters, nil
}

func parseDarwinSoftnetCounters(input string) ([]NamedCounter, error) {
	var counters []NamedCounter
	seen := make(map[string]bool)
	currentInterface := ""
	for _, line := range strings.Split(input, "\n") {
		row, value, found, err := parseDarwinNetISRLine(strings.Fields(line), currentInterface)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		currentInterface = row.interfaceName
		if seen[row.name] {
			return nil, fmt.Errorf("darwin netisr counter row is duplicated")
		}
		seen[row.name] = true
		counters = append(counters, NamedCounter{Name: row.name, Value: value})
	}
	if len(counters) == 0 {
		return nil, fmt.Errorf("darwin netisr error counters are missing")
	}
	return counters, nil
}

func parseDarwinNetISRLine(fields []string, inheritedInterface string) (darwinNetISRRow, uint64, bool, error) {
	if isExactDarwinNetISRIntervalRow(fields) {
		return darwinNetISRRow{}, 0, false, nil
	}
	if containsDarwinNetISRIntervalCandidate(fields) {
		return darwinNetISRRow{}, 0, false, fmt.Errorf("darwin netisr counter row identity is malformed")
	}
	if !containsDarwinNetISRPollRow(fields) {
		if containsDarwinNetISRToken(fields, "errors:") {
			return darwinNetISRRow{}, 0, false, fmt.Errorf("darwin netisr counter row identity is malformed")
		}
		return darwinNetISRRow{}, 0, false, nil
	}
	row, err := darwinNetISRRowIdentity(fields, inheritedInterface)
	if err != nil {
		return darwinNetISRRow{}, 0, false, err
	}
	if _, err := parseSingleUint(row.requests, 10, "darwin netisr request counter"); err != nil {
		return darwinNetISRRow{}, 0, false, err
	}
	value, err := parseSingleUint(row.errors, 10, "darwin netisr error counter")
	if err != nil {
		return darwinNetISRRow{}, 0, false, err
	}
	return row, value, true, nil
}

func containsDarwinNetISRIntervalCandidate(fields []string) bool {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "poll" && fields[index+1] == "interval:" {
			return true
		}
	}
	return false
}

func containsDarwinNetISRPollRow(fields []string) bool {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "[" && fields[index+1] == "poll" {
			return true
		}
	}
	return false
}

func isExactDarwinNetISRIntervalRow(fields []string) bool {
	if len(fields) != 6 || fields[0] != "[" || fields[1] != "poll" || fields[2] != "interval:" ||
		fields[4] != "nsec" || fields[5] != "]" {
		return false
	}
	_, err := parseSingleUint(fields[3], 10, "darwin netisr poll interval")
	return err == nil
}

func containsDarwinNetISRToken(fields []string, token string) bool {
	for _, field := range fields {
		if field == token {
			return true
		}
	}
	return false
}

type darwinNetISRRow struct {
	name          string
	interfaceName string
	requests      string
	errors        string
}

func darwinNetISRRowIdentity(fields []string, inheritedInterface string) (darwinNetISRRow, error) {
	if row, ok := darwinNetISRPollOnRow(fields); ok {
		return row, nil
	}
	if row, ok := darwinNetISRPollOffRow(fields, inheritedInterface); ok {
		return row, nil
	}
	return darwinNetISRRow{}, fmt.Errorf("darwin netisr counter row identity is malformed")
}

func darwinNetISRPollOnRow(fields []string) (darwinNetISRRow, bool) {
	if len(fields) != 9 {
		return darwinNetISRRow{}, false
	}
	if fields[1] != "[" || fields[2] != "poll" || fields[3] != "on" || fields[4] != "requests:" ||
		fields[6] != "errors:" || fields[8] != "]" || !validHealthInterfaceName(fields[0]) {
		return darwinNetISRRow{}, false
	}
	return darwinNetISRRow{
		name: fields[0] + "/poll-on", interfaceName: fields[0], requests: fields[5], errors: fields[7],
	}, true
}

func darwinNetISRPollOffRow(fields []string, inheritedInterface string) (darwinNetISRRow, bool) {
	if len(fields) != 8 {
		return darwinNetISRRow{}, false
	}
	if fields[0] != "[" || fields[1] != "poll" || fields[2] != "off" || fields[3] != "requests:" ||
		fields[5] != "errors:" || fields[7] != "]" || !validHealthInterfaceName(inheritedInterface) {
		return darwinNetISRRow{}, false
	}
	return darwinNetISRRow{
		name: inheritedInterface + "/poll-off", interfaceName: inheritedInterface, requests: fields[4], errors: fields[6],
	}, true
}

func captureDarwinOwnedState(ctx context.Context, owned []ProcessRef, timeout time.Duration) ([]ProcessRef, []SocketRef, error) {
	return captureDarwinOwnedStateWithInspector(ctx, owned, darwinProcessInspector{
		exists:        darwinProcessExists,
		startIdentity: darwinNativeProcessStartIdentity,
		command: func(ctx context.Context, path string, args ...string) (healthCommandResult, error) {
			return runHealthCommandResultWithExecutor(ctx, timeout, executeHealthCommand, path, args...)
		},
	})
}

type darwinProcessInspector struct {
	exists        func(int) (bool, error)
	startIdentity func(int) (string, error)
	command       func(context.Context, string, ...string) (healthCommandResult, error)
}

func darwinProcessExists(pid int) (bool, error) {
	if err := unix.Kill(pid, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func darwinNativeProcessStartIdentity(pid int) (string, error) {
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", fmt.Errorf("inspect Darwin process %d native start identity: %w", pid, err)
	}
	start := process.Proc.P_starttime
	if start.Sec <= 0 || start.Usec < 0 || start.Usec >= 1_000_000 {
		return "", fmt.Errorf("darwin process %d native start identity is malformed", pid)
	}
	return fmt.Sprintf("darwin-%d-%06d", start.Sec, start.Usec), nil
}

func captureDarwinOwnedStateWithInspector(ctx context.Context, owned []ProcessRef, inspector darwinProcessInspector) ([]ProcessRef, []SocketRef, error) {
	var processes []ProcessRef
	var sockets []SocketRef
	for _, expected := range owned {
		present, processSockets, err := captureDarwinOwnedProcess(ctx, expected, inspector)
		if err != nil {
			return nil, nil, err
		}
		if !present {
			continue
		}
		processes = append(processes, expected)
		sockets = append(sockets, processSockets...)
	}
	return processes, sockets, nil
}

func captureDarwinOwnedProcess(ctx context.Context, expected ProcessRef, inspector darwinProcessInspector) (bool, []SocketRef, error) {
	present, err := inspector.exists(expected.PID)
	if err != nil {
		return false, nil, fmt.Errorf("inspect Darwin process %d: %w", expected.PID, err)
	}
	if !present {
		return false, nil, nil
	}
	matches, err := darwinProcessIdentityMatches(ctx, expected, inspector)
	if err != nil || !matches {
		return matches, nil, err
	}
	sockets, err := captureDarwinProcessSockets(ctx, expected, inspector)
	if err != nil {
		return false, nil, err
	}
	stillMatches, err := darwinProcessIdentityMatches(ctx, expected, inspector)
	if err != nil {
		return false, nil, err
	}
	if !stillMatches {
		return false, nil, fmt.Errorf("darwin process %d changed during socket capture", expected.PID)
	}
	return true, sockets, nil
}

func darwinProcessIdentityMatches(ctx context.Context, expected ProcessRef, inspector darwinProcessInspector) (bool, error) {
	observed, err := observeDarwinProcess(ctx, expected.Name, expected.PID, inspector)
	if err != nil {
		return false, err
	}
	return matchScopedProcessIdentity(expected, observed)
}

func captureDarwinProcessSockets(ctx context.Context, expected ProcessRef, inspector darwinProcessInspector) ([]SocketRef, error) {
	result, err := inspector.command(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(expected.PID), "-i", "-F", "pPn")
	if err != nil {
		return nil, err
	}
	if result.ExitCode == 1 && result.Stdout == "" && result.Stderr == "" {
		return []SocketRef{}, nil
	}
	if result.ExitCode != 0 || result.Stderr != "" {
		return nil, fmt.Errorf("darwin lsof failed closed with exit %d: %s", result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	return parseDarwinLsofSockets(result.Stdout, expected)
}

type darwinLsofState struct {
	process  ProcessRef
	pidSeen  bool
	protocol string
	sockets  []SocketRef
}

func (state *darwinLsofState) consume(line string) error {
	switch line[0] {
	case 'p':
		return state.consumePID(line)
	case 'P':
		return state.consumeProtocol(line)
	case 'n':
		return state.consumeSocket(line)
	default:
		return fmt.Errorf("darwin lsof field is unknown")
	}
}

func (state *darwinLsofState) consumePID(line string) error {
	if state.pidSeen || line != "p"+strconv.Itoa(state.process.PID) {
		return fmt.Errorf("darwin lsof PID framing is malformed")
	}
	state.pidSeen = true
	return nil
}

func (state *darwinLsofState) consumeProtocol(line string) error {
	if !state.pidSeen || state.protocol != "" {
		return fmt.Errorf("darwin lsof protocol framing is malformed")
	}
	state.protocol = strings.ToLower(strings.TrimSpace(line[1:]))
	if state.protocol != "tcp" && state.protocol != "udp" {
		return fmt.Errorf("darwin lsof protocol is malformed")
	}
	return nil
}

func (state *darwinLsofState) consumeSocket(line string) error {
	socket, err := parseDarwinLsofSocket(state.protocol, line[1:], state.process.PID)
	if err != nil {
		return err
	}
	socket.StartIdentity, socket.ExecutableIdentity = state.process.StartIdentity, state.process.ExecutableIdentity
	state.sockets = append(state.sockets, socket)
	state.protocol = ""
	return nil
}

func parseDarwinLsofSockets(input string, process ProcessRef) ([]SocketRef, error) {
	state := darwinLsofState{process: process}
	for _, line := range strings.Split(input, "\n") {
		if line == "" {
			continue
		}
		if err := state.consume(line); err != nil {
			return nil, err
		}
	}
	if !state.pidSeen || state.protocol != "" || len(state.sockets) == 0 {
		return nil, fmt.Errorf("darwin lsof output is empty or truncated")
	}
	return state.sockets, nil
}

func parseDarwinLsofSocket(protocol, input string, pid int) (SocketRef, error) {
	if protocol == "" {
		return SocketRef{}, fmt.Errorf("darwin lsof socket lacks protocol")
	}
	address := strings.TrimSuffix(strings.TrimSpace(input), " (LISTEN)")
	local, remote, _ := strings.Cut(address, "->")
	if local == "" {
		return SocketRef{}, fmt.Errorf("darwin lsof socket lacks local address")
	}
	network := protocol + "4"
	if strings.Contains(local, "[") || strings.Count(local, ":") > 1 {
		network = protocol + "6"
	}
	return SocketRef{Network: network, Local: local, Remote: remote, PID: pid}, nil
}

func fieldIndex(fields []string, want string) int {
	for index, field := range fields {
		if field == want {
			return index
		}
	}
	return -1
}
