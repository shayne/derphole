// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func capturePlatformHealth(ctx context.Context, options HealthCaptureOptions) (HealthSnapshot, error) {
	identity, err := captureLinuxIdentity()
	if err != nil {
		return HealthSnapshot{}, err
	}
	memory, cgroups, err := captureLinuxMemory(options.CleanupScope.Cgroups)
	if err != nil {
		return HealthSnapshot{}, err
	}
	diskFree, err := linuxDiskFree(options.WorkDir)
	if err != nil {
		return HealthSnapshot{}, err
	}
	kernelOutput, err := runHealthCommand(ctx, options.CommandTimeout, "/usr/bin/dmesg", "--color=never", "--level=emerg,alert,crit,err")
	if err != nil {
		return HealthSnapshot{}, err
	}
	network, err := captureLinuxNetwork(options.Interface)
	if err != nil {
		return HealthSnapshot{}, err
	}
	processes, sockets, err := captureLinuxOwnedState(options.CleanupScope.Processes)
	if err != nil {
		return HealthSnapshot{}, err
	}
	return HealthSnapshot{
		Platform: "linux",
		BootID:   identity.bootID, UptimeSeconds: identity.uptime, OnlineCPUs: identity.onlineCPUs,
		GlobalOOMKills: memory.globalOOM, CgroupOOMKills: memory.cgroupOOM,
		AvailableMemoryBytes: memory.available, SwapUsedBytes: memory.swapUsed, DiskFreeBytes: diskFree,
		KernelErrors: parseKernelErrorLines(kernelOutput), InterfaceDrops: network.interfaceFailures,
		UDPErrors: network.udpErrors, SoftnetDrops: network.softnetDrops,
		InterfaceCounters: network.interfaceCounters, UDPCounters: network.udpCounters, SoftnetCounters: network.softnetCounters,
		Cgroups: cgroups, Processes: processes, Sockets: sockets,
	}, nil
}

type linuxIdentityHealth struct {
	bootID     string
	uptime     float64
	onlineCPUs int
}

func captureLinuxIdentity() (linuxIdentityHealth, error) {
	bootID, err := readLinuxSingleLine("/proc/sys/kernel/random/boot_id", "linux boot ID")
	if err != nil {
		return linuxIdentityHealth{}, err
	}
	bootID, err = canonicalBootUUID(bootID)
	if err != nil {
		return linuxIdentityHealth{}, err
	}
	uptimeOutput, err := readHealthFile("/proc/uptime")
	if err != nil {
		return linuxIdentityHealth{}, fmt.Errorf("read Linux uptime: %w", err)
	}
	uptime, err := parseLinuxUptime(uptimeOutput)
	if err != nil {
		return linuxIdentityHealth{}, err
	}
	cpuOutput, err := readHealthFile("/sys/devices/system/cpu/online")
	if err != nil {
		return linuxIdentityHealth{}, fmt.Errorf("read Linux online CPUs: %w", err)
	}
	onlineCPUs, err := parseLinuxOnlineCPUs(cpuOutput)
	if err != nil {
		return linuxIdentityHealth{}, err
	}
	return linuxIdentityHealth{bootID: bootID, uptime: uptime, onlineCPUs: onlineCPUs}, nil
}

type linuxMemoryHealth struct {
	globalOOM uint64
	cgroupOOM uint64
	available uint64
	swapUsed  uint64
}

func captureLinuxMemory(scope []CgroupRef) (linuxMemoryHealth, []CgroupHealth, error) {
	vmstatOutput, err := readHealthFile("/proc/vmstat")
	if err != nil {
		return linuxMemoryHealth{}, nil, fmt.Errorf("read Linux VM counters: %w", err)
	}
	globalOOM, err := parseLinuxNamedUint(vmstatOutput, "oom_kill", "linux global OOM counter")
	if err != nil {
		return linuxMemoryHealth{}, nil, err
	}
	cgroups, cgroupOOM, err := captureLinuxCgroups(scope)
	if err != nil {
		return linuxMemoryHealth{}, nil, err
	}
	meminfoOutput, err := readHealthFile("/proc/meminfo")
	if err != nil {
		return linuxMemoryHealth{}, nil, fmt.Errorf("read Linux memory counters: %w", err)
	}
	memory, err := parseLinuxMeminfo(meminfoOutput)
	if err != nil {
		return linuxMemoryHealth{}, nil, err
	}
	return linuxMemoryHealth{globalOOM: globalOOM, cgroupOOM: cgroupOOM, available: memory.Available, swapUsed: memory.SwapUsed}, cgroups, nil
}

func captureLinuxCgroups(scope []CgroupRef) ([]CgroupHealth, uint64, error) {
	result := make([]CgroupHealth, 0, len(scope))
	var totalOOM uint64
	for _, expected := range scope {
		cgroup, oomKills, err := captureLinuxCgroup(expected)
		if err != nil {
			return nil, 0, err
		}
		totalOOM, err = addHealthUint64(totalOOM, oomKills)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, cgroup)
	}
	return result, totalOOM, nil
}

func captureLinuxCgroup(expected CgroupRef) (CgroupHealth, uint64, error) {
	return captureConfinedCgroup(expected, linuxConfinedCgroupFilesystem{})
}

type linuxConfinedCgroupFilesystem struct{}

func (linuxConfinedCgroupFilesystem) OpenRoot() (int, error) {
	fd, err := unix.Open(linuxCgroupRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func (linuxConfinedCgroupFilesystem) OpenDirectory(root int, relative string) (int, error) {
	how := &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_XDEV,
	}
	return unix.Openat2(root, relative, how)
}

func (linuxConfinedCgroupFilesystem) Identity(directory int) (string, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(directory, &stat); err != nil {
		return "", err
	}
	return fmt.Sprintf("dev:%d-ino:%d", uint64(stat.Dev), stat.Ino), nil
}

func (linuxConfinedCgroupFilesystem) ReadFile(directory int, name string) (string, error) {
	how := &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_XDEV,
	}
	fd, err := unix.Openat2(directory, name, how)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return "", fmt.Errorf("wrap Linux cgroup file descriptor")
	}
	return readHealthOpenFile(file)
}

func (linuxConfinedCgroupFilesystem) Close(handle int) error { return unix.Close(handle) }

type linuxNetworkHealth struct {
	interfaceFailures uint64
	udpErrors         uint64
	softnetDrops      uint64
	interfaceCounters []NamedCounter
	udpCounters       []NamedCounter
	softnetCounters   []NamedCounter
}

func captureLinuxNetwork(interfaceName string) (linuxNetworkHealth, error) {
	interfaceCounters, err := captureLinuxInterfaceCounters(interfaceName)
	if err != nil {
		return linuxNetworkHealth{}, err
	}
	interfaceFailures, err := sumNamedCounters(interfaceCounters)
	if err != nil {
		return linuxNetworkHealth{}, err
	}
	udpOutput, err := readHealthFile("/proc/net/snmp")
	if err != nil {
		return linuxNetworkHealth{}, fmt.Errorf("read Linux UDP counters: %w", err)
	}
	udpCounters, err := parseLinuxUDPErrorCounters(udpOutput)
	if err != nil {
		return linuxNetworkHealth{}, err
	}
	udpErrors, err := sumNamedCounters(udpCounters)
	if err != nil {
		return linuxNetworkHealth{}, err
	}
	softnetOutput, err := readHealthFile("/proc/net/softnet_stat")
	if err != nil {
		return linuxNetworkHealth{}, fmt.Errorf("read Linux softnet counters: %w", err)
	}
	softnetCounters, err := parseLinuxSoftnetCounters(softnetOutput)
	if err != nil {
		return linuxNetworkHealth{}, err
	}
	softnetDrops, err := sumNamedCounters(softnetCounters)
	if err != nil {
		return linuxNetworkHealth{}, err
	}
	return linuxNetworkHealth{interfaceFailures: interfaceFailures, udpErrors: udpErrors, softnetDrops: softnetDrops,
		interfaceCounters: interfaceCounters, udpCounters: udpCounters, softnetCounters: softnetCounters}, nil
}

func readLinuxSingleLine(path, label string) (string, error) {
	input, err := readHealthFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	value := strings.TrimSpace(input)
	if value == "" || len(strings.Fields(value)) != 1 {
		return "", fmt.Errorf("%s is malformed", label)
	}
	return value, nil
}

func readHealthFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	return readHealthOpenFile(file)
}

func readHealthOpenFile(file *os.File) (string, error) {
	data, readErr := io.ReadAll(io.LimitReader(file, maximumHealthInputBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) > maximumHealthInputBytes {
		return "", fmt.Errorf("health input exceeds %d bytes", maximumHealthInputBytes)
	}
	return string(data), nil
}

func linuxDiskFree(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("linux disk statfs: %w", err)
	}
	if stat.Bsize <= 0 {
		return 0, fmt.Errorf("linux disk block size is invalid")
	}
	free, err := multiplyHealthUint64(stat.Bavail, uint64(stat.Bsize))
	if err != nil || free == 0 {
		return 0, fmt.Errorf("linux disk free bytes are invalid")
	}
	return free, nil
}

func captureLinuxInterfaceCounters(interfaceName string) ([]NamedCounter, error) {
	var counters []NamedCounter
	for _, counter := range []string{"rx_dropped", "tx_dropped", "rx_errors", "tx_errors"} {
		input, err := readHealthFile(filepath.Join("/sys/class/net", interfaceName, "statistics", counter))
		if err != nil {
			return nil, fmt.Errorf("read Linux interface %s: %w", counter, err)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(input), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("linux interface %s is malformed", counter)
		}
		counters = append(counters, NamedCounter{Name: counter, Value: value})
	}
	normalizeNamedCounters(counters)
	return counters, nil
}

func captureLinuxOwnedState(owned []ProcessRef) ([]ProcessRef, []SocketRef, error) {
	socketTables, err := readLinuxSocketTables()
	if err != nil {
		return nil, nil, err
	}
	var processes []ProcessRef
	var sockets []SocketRef
	for _, expected := range owned {
		present, processSockets, err := captureLinuxOwnedProcess(expected, socketTables)
		if err != nil {
			return nil, nil, err
		}
		if present {
			processes = append(processes, expected)
			sockets = append(sockets, processSockets...)
		}
	}
	return processes, sockets, nil
}

func captureLinuxOwnedProcess(expected ProcessRef, socketTables map[uint64]SocketRef) (bool, []SocketRef, error) {
	processRoot, present, err := matchingLinuxProcessRoot(expected)
	if err != nil || !present {
		return present, nil, err
	}
	fds, err := os.ReadDir(filepath.Join(processRoot, "fd"))
	if err != nil {
		return false, nil, fmt.Errorf("inspect Linux process %d file descriptors: %w", expected.PID, err)
	}
	sockets, err := captureLinuxProcessSockets(processRoot, expected, fds, socketTables)
	if err != nil {
		return false, nil, err
	}
	_, stillPresent, err := matchingLinuxProcessRoot(expected)
	if err != nil {
		return false, nil, err
	}
	if !stillPresent {
		return false, nil, fmt.Errorf("linux process %d changed during socket capture", expected.PID)
	}
	return true, sockets, nil
}

func matchingLinuxProcessRoot(expected ProcessRef) (string, bool, error) {
	processRoot := filepath.Join("/proc", strconv.Itoa(expected.PID))
	observed, candidate, err := observeScopedLinuxProcess(expected, processRoot)
	if err != nil || !candidate {
		return processRoot, candidate, err
	}
	matches, err := matchScopedProcessIdentity(expected, observed)
	if err != nil || !matches {
		return processRoot, matches, err
	}
	if err := verifyLinuxProcessStartIdentity(expected, processRoot); err != nil {
		return processRoot, false, err
	}
	return processRoot, true, nil
}

func observeScopedLinuxProcess(expected ProcessRef, processRoot string) (ProcessRef, bool, error) {
	startInput, err := readHealthFile(filepath.Join(processRoot, "stat"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProcessRef{}, false, nil
		}
		return ProcessRef{}, false, fmt.Errorf("inspect Linux process %d start identity: %w", expected.PID, err)
	}
	name, startIdentity, err := parseLinuxProcessNameAndStartIdentity(startInput)
	if err != nil {
		return ProcessRef{}, false, err
	}
	observed := ProcessRef{Name: name, PID: expected.PID, StartIdentity: startIdentity}
	if startIdentity != expected.StartIdentity {
		return observed, false, nil
	}
	observed.ExecutableIdentity, err = linuxExecutableIdentityAt(processRoot, expected.PID)
	if err != nil {
		return ProcessRef{}, false, err
	}
	return observed, true, nil
}

func linuxExecutableIdentityAt(processRoot string, pid int) (string, error) {
	executable, err := os.Open(filepath.Join(processRoot, "exe"))
	if err != nil {
		return "", fmt.Errorf("inspect Linux process %d executable identity: %w", pid, err)
	}
	identity, err := linuxOpenFileIdentity(executable)
	closeErr := executable.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", fmt.Errorf("close Linux process %d executable: %w", pid, closeErr)
	}
	return identity, nil
}

func verifyLinuxProcessStartIdentity(expected ProcessRef, processRoot string) error {
	verifyInput, err := readHealthFile(filepath.Join(processRoot, "stat"))
	if err != nil {
		return fmt.Errorf("reinspect Linux process %d start identity: %w", expected.PID, err)
	}
	verifyName, verifyStart, err := parseLinuxProcessNameAndStartIdentity(verifyInput)
	if err != nil {
		return err
	}
	if verifyName != expected.Name || verifyStart != expected.StartIdentity {
		return fmt.Errorf("linux process %d changed during identity capture", expected.PID)
	}
	return nil
}

func linuxOpenFileIdentity(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat Linux executable: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("linux executable stat identity is unavailable")
	}
	return fmt.Sprintf("dev:%d-ino:%d", uint64(stat.Dev), stat.Ino), nil
}

func captureLinuxProcessSockets(processRoot string, process ProcessRef, fds []os.DirEntry, socketTables map[uint64]SocketRef) ([]SocketRef, error) {
	seenInodes := make(map[uint64]bool)
	var sockets []SocketRef
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(processRoot, "fd", fd.Name()))
		if err != nil {
			return nil, fmt.Errorf("inspect Linux process %d socket: %w", process.PID, err)
		}
		inode, inodeText, socketFD, err := parseLinuxSocketFD(target)
		if err != nil {
			return nil, err
		}
		if !socketFD || seenInodes[inode] {
			continue
		}
		seenInodes[inode] = true
		socket, ok := socketTables[inode]
		if !ok {
			socket = SocketRef{Network: "other", Local: "inode:" + inodeText}
		}
		socket.PID = process.PID
		socket.StartIdentity = process.StartIdentity
		socket.ExecutableIdentity = process.ExecutableIdentity
		sockets = append(sockets, socket)
	}
	return sockets, nil
}

func parseLinuxSocketFD(target string) (uint64, string, bool, error) {
	inodeText := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if inodeText == target {
		return 0, "", false, nil
	}
	inode, err := strconv.ParseUint(inodeText, 10, 64)
	if err != nil {
		return 0, "", false, fmt.Errorf("linux process socket inode is malformed")
	}
	return inode, inodeText, true, nil
}

func readLinuxSocketTables() (map[uint64]SocketRef, error) {
	result := make(map[uint64]SocketRef)
	for _, source := range []struct{ path, network string }{
		{"/proc/net/tcp", "tcp4"}, {"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp4"}, {"/proc/net/udp6", "udp6"},
	} {
		input, err := readHealthFile(source.path)
		if err != nil {
			return nil, fmt.Errorf("read Linux %s sockets: %w", source.network, err)
		}
		table, err := parseLinuxNetworkSocketTable(input, source.network)
		if err != nil {
			return nil, err
		}
		if err := mergeLinuxSocketTable(result, table); err != nil {
			return nil, err
		}
	}
	input, err := readHealthFile("/proc/net/unix")
	if err != nil {
		return nil, fmt.Errorf("read Linux Unix sockets: %w", err)
	}
	table, err := parseLinuxUnixSocketTable(input)
	if err != nil {
		return nil, err
	}
	if err := mergeLinuxSocketTable(result, table); err != nil {
		return nil, err
	}
	return result, nil
}

func mergeLinuxSocketTable(destination, source map[uint64]SocketRef) error {
	for inode, socket := range source {
		if _, duplicate := destination[inode]; duplicate {
			return fmt.Errorf("linux socket inode %d appears in multiple tables", inode)
		}
		destination[inode] = socket
	}
	return nil
}
