// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package udpbenchproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maximumHealthInputBytes = 4 << 20

// ProcessRef identifies one exact harness-owned process.
type ProcessRef struct {
	Name               string `json:"name"`
	PID                int    `json:"pid"`
	StartIdentity      string `json:"start_identity"`
	ExecutableIdentity string `json:"executable_identity"`
}

// CgroupRef identifies one exact harness-owned Linux cgroup.
type CgroupRef struct {
	Path     string `json:"path"`
	Identity string `json:"identity"`
}

// CleanupScope is the independently declared process and cgroup query boundary.
type CleanupScope struct {
	Declared  bool         `json:"declared"`
	Processes []ProcessRef `json:"processes"`
	Cgroups   []CgroupRef  `json:"cgroups"`
}

// HealthCaptureOptions selects read-only state for one harness scope.
type HealthCaptureOptions struct {
	WorkDir        string
	Interface      string
	CleanupScope   CleanupScope
	CaptureTimeout time.Duration
	CommandTimeout time.Duration
}

// SocketRef identifies one socket owned by an exact process ID.
type SocketRef struct {
	Network            string `json:"network"`
	Local              string `json:"local"`
	Remote             string `json:"remote"`
	PID                int    `json:"pid"`
	StartIdentity      string `json:"start_identity"`
	ExecutableIdentity string `json:"executable_identity"`
}

// NamedCounter preserves one native counter component without lossy aggregation.
type NamedCounter struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

// CgroupHealth records named memory.events counters for one exact cgroup.
type CgroupHealth struct {
	Path         string         `json:"path"`
	Identity     string         `json:"identity"`
	MemoryEvents []NamedCounter `json:"memory_events"`
}

const linuxCgroupRoot = "/sys/fs/cgroup"

type confinedCgroupFilesystem interface {
	OpenRoot() (int, error)
	OpenDirectory(root int, relative string) (int, error)
	Identity(directory int) (string, error)
	ReadFile(directory int, name string) (string, error)
	Close(handle int) error
}

func captureConfinedCgroup(expected CgroupRef, filesystem confinedCgroupFilesystem) (health CgroupHealth, oomKills uint64, err error) {
	if filesystem == nil {
		return CgroupHealth{}, 0, fmt.Errorf("linux cgroup filesystem is nil")
	}
	relative, err := confinedLinuxCgroupRelativePath(expected.Path)
	if err != nil {
		return CgroupHealth{}, 0, err
	}
	root, err := filesystem.OpenRoot()
	if err != nil {
		return CgroupHealth{}, 0, fmt.Errorf("open trusted Linux cgroup root: %w", err)
	}
	defer func() { err = errors.Join(err, filesystem.Close(root)) }()
	directory, err := filesystem.OpenDirectory(root, relative)
	if err != nil {
		return CgroupHealth{}, 0, fmt.Errorf("open confined Linux cgroup %s: %w", expected.Path, err)
	}
	defer func() { err = errors.Join(err, filesystem.Close(directory)) }()
	return captureOpenedConfinedCgroup(expected, filesystem, directory)
}

func confinedLinuxCgroupRelativePath(path string) (string, error) {
	if path != linuxCgroupRoot && !strings.HasPrefix(path, linuxCgroupRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("linux cgroup path is outside %s", linuxCgroupRoot)
	}
	relative := strings.TrimPrefix(path, linuxCgroupRoot)
	relative = strings.TrimPrefix(relative, string(filepath.Separator))
	if relative == "" {
		relative = "."
	}
	return relative, nil
}

func captureOpenedConfinedCgroup(expected CgroupRef, filesystem confinedCgroupFilesystem, directory int) (CgroupHealth, uint64, error) {
	identity, err := filesystem.Identity(directory)
	if err != nil {
		return CgroupHealth{}, 0, fmt.Errorf("stat confined Linux cgroup %s: %w", expected.Path, err)
	}
	if identity != expected.Identity {
		return CgroupHealth{}, 0, fmt.Errorf("linux cgroup identity changed for %s", expected.Path)
	}
	input, err := filesystem.ReadFile(directory, "memory.events")
	if err != nil {
		return CgroupHealth{}, 0, fmt.Errorf("read confined Linux cgroup memory events: %w", err)
	}
	events, err := parseLinuxMemoryEvents(input)
	if err != nil {
		return CgroupHealth{}, 0, err
	}
	oomKills, ok := namedCounterValue(events, "oom_kill")
	if !ok {
		return CgroupHealth{}, 0, fmt.Errorf("linux cgroup memory.events is missing oom_kill")
	}
	return CgroupHealth{Path: expected.Path, Identity: expected.Identity, MemoryEvents: events}, oomKills, nil
}

func namedCounterValue(counters []NamedCounter, name string) (uint64, bool) {
	for _, counter := range counters {
		if counter.Name == name {
			return counter.Value, true
		}
	}
	return 0, false
}

// HealthSnapshot is one complete read-only host-state capture.
type HealthSnapshot struct {
	Platform             string         `json:"platform"`
	BootID               string         `json:"boot_id"`
	UptimeSeconds        float64        `json:"uptime_seconds"`
	OnlineCPUs           int            `json:"online_cpus"`
	GlobalOOMKills       uint64         `json:"global_oom_kills"`
	CgroupOOMKills       uint64         `json:"cgroup_oom_kills"`
	AvailableMemoryBytes uint64         `json:"available_memory_bytes"`
	SwapUsedBytes        uint64         `json:"swap_used_bytes"`
	DiskFreeBytes        uint64         `json:"disk_free_bytes"`
	KernelErrors         []string       `json:"kernel_errors"`
	InterfaceDrops       uint64         `json:"interface_drops"`
	UDPErrors            uint64         `json:"udp_errors"`
	SoftnetDrops         uint64         `json:"softnet_drops"`
	InterfaceCounters    []NamedCounter `json:"interface_counters"`
	UDPCounters          []NamedCounter `json:"udp_counters"`
	SoftnetCounters      []NamedCounter `json:"softnet_counters"`
	Cgroups              []CgroupHealth `json:"cgroups"`
	CleanupScope         CleanupScope   `json:"cleanup_scope"`
	Processes            []ProcessRef   `json:"processes"`
	Sockets              []SocketRef    `json:"sockets"`
	CounterFamilies      []string       `json:"counter_families"`
}

// HealthPolicy defines the hard post-capture host requirements.
type HealthPolicy struct {
	ExpectedOnlineCPUs      int          `json:"expected_online_cpus"`
	MinAvailableMemoryBytes int64        `json:"min_available_memory_bytes"`
	MinDiskAvailableBytes   int64        `json:"min_disk_available_bytes"`
	MaxSwapUsedBytes        int64        `json:"max_swap_used_bytes"`
	MaxSwapIncreaseBytes    int64        `json:"max_swap_increase_bytes"`
	ExpectedCleanupScope    CleanupScope `json:"expected_cleanup_scope"`
}

// HealthVerdict is the deterministic before/after host verdict.
type HealthVerdict struct {
	Healthy bool     `json:"healthy"`
	Reasons []string `json:"reasons"`
}

var healthCounterFamilies = [...]string{
	"uptime",
	"online-cpus",
	"global-oom",
	"cgroup-oom",
	"memory",
	"swap",
	"disk",
	"kernel",
	"interface",
	"udp",
	"softnet",
	"process",
	"socket",
}

var platformHealthCaptureGate = make(chan struct{}, 1)

// CaptureHealth reads complete platform state without mutating the host.
func CaptureHealth(ctx context.Context, options HealthCaptureOptions) (HealthSnapshot, error) {
	return captureHealthWithPlatform(ctx, options, capturePlatformHealth)
}

type platformHealthCaptureFunc func(context.Context, HealthCaptureOptions) (HealthSnapshot, error)

func captureHealthWithPlatform(ctx context.Context, options HealthCaptureOptions, capture platformHealthCaptureFunc) (HealthSnapshot, error) {
	return captureHealthWithPlatformAndGate(ctx, options, capture, platformHealthCaptureGate)
}

type platformHealthCaptureResult struct {
	snapshot HealthSnapshot
	err      error
}

func captureHealthWithPlatformAndGate(ctx context.Context, options HealthCaptureOptions, capture platformHealthCaptureFunc, gate chan struct{}) (HealthSnapshot, error) {
	if ctx == nil {
		return HealthSnapshot{}, fmt.Errorf("health capture context is nil")
	}
	if capture == nil {
		return HealthSnapshot{}, fmt.Errorf("health platform capture is nil")
	}
	if gate == nil {
		return HealthSnapshot{}, fmt.Errorf("health capture gate is nil")
	}
	if err := validateHealthCaptureOptions(options); err != nil {
		return HealthSnapshot{}, err
	}
	captureContext, cancel := context.WithTimeout(ctx, options.CaptureTimeout)
	defer cancel()
	captureResult, err := runBoundedPlatformHealthCapture(captureContext, options, capture, gate)
	if err != nil {
		return HealthSnapshot{}, err
	}
	if captureResult.err != nil {
		return HealthSnapshot{}, captureResult.err
	}
	snapshot := captureResult.snapshot
	snapshot.CleanupScope = cloneCleanupScope(options.CleanupScope)
	snapshot.CounterFamilies = requiredHealthCounterFamilies()
	normalizeHealthSnapshot(&snapshot)
	if err := validateHealthSnapshot(snapshot); err != nil {
		return HealthSnapshot{}, fmt.Errorf("captured health snapshot: %w", err)
	}
	return snapshot, nil
}

func runBoundedPlatformHealthCapture(captureContext context.Context, options HealthCaptureOptions, capture platformHealthCaptureFunc, gate chan struct{}) (platformHealthCaptureResult, error) {
	select {
	case gate <- struct{}{}:
	case <-captureContext.Done():
		return platformHealthCaptureResult{}, fmt.Errorf("health capture deadline waiting for bounded worker: %w", captureContext.Err())
	}
	result := make(chan platformHealthCaptureResult, 1)
	go func() {
		defer func() { <-gate }()
		captureResult := platformHealthCaptureResult{}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					captureResult.err = fmt.Errorf("health platform capture panic: %v", recovered)
				}
			}()
			captureResult.snapshot, captureResult.err = capture(captureContext, options)
		}()
		result <- captureResult
	}()
	var captureResult platformHealthCaptureResult
	select {
	case captureResult = <-result:
		if err := captureContext.Err(); err != nil {
			return platformHealthCaptureResult{}, fmt.Errorf("health capture deadline: %w", err)
		}
	case <-captureContext.Done():
		return platformHealthCaptureResult{}, fmt.Errorf("health capture deadline: %w", captureContext.Err())
	}
	return captureResult, nil
}

// CompareHealth rejects host changes and cleanup failures independently of a candidate.
func CompareHealth(before, after HealthSnapshot, policy HealthPolicy) HealthVerdict {
	reasons := validateHealthComparison(before, after, policy)
	reasons = append(reasons, healthIdentityReasons(before, after, policy)...)
	reasons = append(reasons, healthResourceReasons(before, after, policy)...)
	reasons = append(reasons, healthCounterReasons(before, after)...)
	reasons = append(reasons, healthLeakReasons(after)...)
	sort.Strings(reasons)
	reasons = compactHealthStrings(reasons)
	return HealthVerdict{Healthy: len(reasons) == 0, Reasons: reasons}
}

func validateHealthComparison(before, after HealthSnapshot, policy HealthPolicy) []string {
	var reasons []string
	if err := validateHealthSnapshot(before); err != nil {
		reasons = append(reasons, "before health snapshot: "+err.Error())
	}
	if err := validateHealthSnapshot(after); err != nil {
		reasons = append(reasons, "after health snapshot: "+err.Error())
	}
	if !validHealthPolicy(policy) {
		reasons = append(reasons, "health policy is invalid")
	}
	expectedScope := normalizedCleanupScope(policy.ExpectedCleanupScope)
	if !reflect.DeepEqual(normalizedCleanupScope(before.CleanupScope), expectedScope) ||
		!reflect.DeepEqual(normalizedCleanupScope(after.CleanupScope), expectedScope) {
		reasons = append(reasons, "cleanup scope does not match expected scope")
	}
	return reasons
}

func validHealthPolicy(policy HealthPolicy) bool {
	return policy.ExpectedOnlineCPUs > 0 && policy.MinAvailableMemoryBytes >= 0 && policy.MinDiskAvailableBytes >= 0 &&
		policy.MaxSwapUsedBytes >= 0 && policy.MaxSwapIncreaseBytes >= 0 && validateCleanupScope(policy.ExpectedCleanupScope) == nil
}

func healthIdentityReasons(before, after HealthSnapshot, policy HealthPolicy) []string {
	var reasons []string
	if before.BootID != after.BootID {
		reasons = append(reasons, "boot ID changed")
	}
	if after.UptimeSeconds <= before.UptimeSeconds {
		reasons = append(reasons, "uptime did not advance")
	}
	if before.OnlineCPUs != after.OnlineCPUs || (policy.ExpectedOnlineCPUs > 0 && after.OnlineCPUs != policy.ExpectedOnlineCPUs) {
		reasons = append(reasons, "online CPU count changed or violates policy")
	}
	return reasons
}

func healthResourceReasons(before, after HealthSnapshot, policy HealthPolicy) []string {
	var reasons []string
	reasons = append(reasons, monotonicFailureReason("global OOM kill", before.GlobalOOMKills, after.GlobalOOMKills)...)
	reasons = append(reasons, monotonicFailureReason("cgroup OOM kill", before.CgroupOOMKills, after.CgroupOOMKills)...)
	if policy.MinAvailableMemoryBytes >= 0 && after.AvailableMemoryBytes < uint64(policy.MinAvailableMemoryBytes) {
		reasons = append(reasons, "available memory is below policy")
	}
	if policy.MinDiskAvailableBytes >= 0 && after.DiskFreeBytes < uint64(policy.MinDiskAvailableBytes) {
		reasons = append(reasons, "disk free bytes are below policy")
	}
	reasons = append(reasons, healthSwapReasons(before.SwapUsedBytes, after.SwapUsedBytes, policy)...)
	for _, kernelError := range newHealthStrings(before.KernelErrors, after.KernelErrors) {
		reasons = append(reasons, "new kernel error: "+kernelError)
	}
	return reasons
}

func healthSwapReasons(before, after uint64, policy HealthPolicy) []string {
	var reasons []string
	if policy.MaxSwapUsedBytes >= 0 && after > uint64(policy.MaxSwapUsedBytes) {
		reasons = append(reasons, "swap used bytes exceed policy")
	}
	if policy.MaxSwapIncreaseBytes >= 0 && after > before && after-before > uint64(policy.MaxSwapIncreaseBytes) {
		reasons = append(reasons, "swap used bytes increased beyond policy")
	}
	return reasons
}

func healthCounterReasons(before, after HealthSnapshot) []string {
	var reasons []string
	reasons = append(reasons, namedVectorReasons("interface", before.InterfaceCounters, after.InterfaceCounters)...)
	reasons = append(reasons, namedVectorReasons("UDP", before.UDPCounters, after.UDPCounters)...)
	reasons = append(reasons, namedVectorReasons("softnet", before.SoftnetCounters, after.SoftnetCounters)...)
	reasons = append(reasons, cgroupCounterReasons(before.Cgroups, after.Cgroups)...)
	return reasons
}

func healthLeakReasons(after HealthSnapshot) []string {
	var reasons []string
	for _, process := range after.Processes {
		if cleanupScopeContainsProcess(after.CleanupScope, process) {
			reasons = append(reasons, fmt.Sprintf("process leak: %s pid %d", process.Name, process.PID))
		} else {
			reasons = append(reasons, fmt.Sprintf("process outside declared cleanup scope: %s pid %d", process.Name, process.PID))
		}
	}
	for _, socket := range after.Sockets {
		process := ProcessRef{Name: cleanupScopeProcessName(after.CleanupScope, socket), PID: socket.PID, StartIdentity: socket.StartIdentity, ExecutableIdentity: socket.ExecutableIdentity}
		if cleanupScopeContainsProcess(after.CleanupScope, process) {
			reasons = append(reasons, fmt.Sprintf("socket leak: %s %s %s pid %d", socket.Network, socket.Local, socket.Remote, socket.PID))
		} else {
			reasons = append(reasons, fmt.Sprintf("socket outside declared cleanup scope: %s %s pid %d", socket.Network, socket.Local, socket.PID))
		}
	}
	return reasons
}

func requiredHealthCounterFamilies() []string {
	return append([]string(nil), healthCounterFamilies[:]...)
}

func validateHealthCaptureOptions(options HealthCaptureOptions) error {
	if strings.TrimSpace(options.WorkDir) == "" {
		return fmt.Errorf("health capture work directory is required")
	}
	if !validHealthInterfaceName(options.Interface) {
		return fmt.Errorf("health capture interface is invalid")
	}
	if options.CaptureTimeout <= 0 || options.CommandTimeout <= 0 || options.CommandTimeout > options.CaptureTimeout {
		return fmt.Errorf("health capture deadlines are invalid")
	}
	return validateCleanupScope(options.CleanupScope)
}

func validHealthInterfaceName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsAny(name, "/\\\x00\r\n\t ")
}

func validateCleanupScope(scope CleanupScope) error {
	if !scope.Declared || scope.Processes == nil || scope.Cgroups == nil {
		return fmt.Errorf("health cleanup scope must be explicitly declared")
	}
	if err := validateOwnedProcessOptions(scope.Processes); err != nil {
		return err
	}
	return validateCleanupCgroups(scope.Cgroups)
}

func validateCleanupCgroups(cgroups []CgroupRef) error {
	seen := make(map[string]bool, len(cgroups))
	for _, cgroup := range cgroups {
		if invalidCleanupCgroup(cgroup) || seen[cgroup.Path] {
			return fmt.Errorf("health cleanup cgroup is invalid or duplicated")
		}
		seen[cgroup.Path] = true
	}
	return nil
}

func invalidCleanupCgroup(cgroup CgroupRef) bool {
	return cgroup.Path == "" || cgroup.Identity == "" || !filepath.IsAbs(cgroup.Path) ||
		filepath.Clean(cgroup.Path) != cgroup.Path || strings.ContainsAny(cgroup.Path+cgroup.Identity, "\x00\r\n")
}

// ValidateCleanupScope rejects omitted, malformed, or ambiguous cleanup scopes.
func ValidateCleanupScope(scope CleanupScope) error { return validateCleanupScope(scope) }

func validateOwnedProcessOptions(processes []ProcessRef) error {
	seen := make(map[int]bool, len(processes))
	for _, process := range processes {
		invalidName := process.Name == "" || len(process.Name) > 255 || strings.ContainsAny(process.Name, "/\\\x00\r\n")
		invalidIdentity := process.StartIdentity == "" || process.ExecutableIdentity == "" ||
			strings.ContainsAny(process.StartIdentity+process.ExecutableIdentity, "\x00\r\n")
		if process.PID <= 0 || invalidName || invalidIdentity || seen[process.PID] {
			return fmt.Errorf("health capture owned process is invalid or duplicated")
		}
		seen[process.PID] = true
	}
	return nil
}

func matchScopedProcessIdentity(expected, observed ProcessRef) (bool, error) {
	if observed.PID != expected.PID {
		return false, fmt.Errorf("observed process PID does not match scope")
	}
	if observed.StartIdentity != expected.StartIdentity {
		return false, nil
	}
	if observed.Name != expected.Name || observed.ExecutableIdentity != expected.ExecutableIdentity {
		return false, fmt.Errorf("same live process changed identity for pid %d", expected.PID)
	}
	return true, nil
}

func validateHealthSnapshot(snapshot HealthSnapshot) error {
	if err := validateHealthSnapshotGauges(snapshot); err != nil {
		return err
	}
	if err := validateHealthSnapshotFamilies(snapshot); err != nil {
		return err
	}
	if err := validateCleanupScope(snapshot.CleanupScope); err != nil {
		return err
	}
	if err := validateNamedCounterFamilies(snapshot); err != nil {
		return err
	}
	if err := validateProcessRefs(snapshot.Processes); err != nil {
		return err
	}
	return validateSocketRefs(snapshot.Sockets)
}

func validateHealthSnapshotGauges(snapshot HealthSnapshot) error {
	if err := validateHealthIdentityGauges(snapshot); err != nil {
		return err
	}
	if snapshot.AvailableMemoryBytes == 0 || snapshot.DiskFreeBytes == 0 {
		return fmt.Errorf("memory or disk gauge is missing")
	}
	return nil
}

func validateHealthIdentityGauges(snapshot HealthSnapshot) error {
	if snapshot.Platform != "linux" && snapshot.Platform != "darwin" {
		return fmt.Errorf("health platform is missing or invalid")
	}
	if snapshot.BootID == "" || strings.ContainsAny(snapshot.BootID, "\x00\r\n") {
		return fmt.Errorf("boot ID is missing or invalid")
	}
	if math.IsNaN(snapshot.UptimeSeconds) || math.IsInf(snapshot.UptimeSeconds, 0) || snapshot.UptimeSeconds <= 0 {
		return fmt.Errorf("uptime is missing or invalid")
	}
	if snapshot.OnlineCPUs <= 0 {
		return fmt.Errorf("online CPU count is missing or invalid")
	}
	return nil
}

func validateHealthSnapshotFamilies(snapshot HealthSnapshot) error {
	if !reflect.DeepEqual(snapshot.CounterFamilies, requiredHealthCounterFamilies()) {
		return fmt.Errorf("counter families are incomplete or noncanonical")
	}
	if snapshot.KernelErrors == nil || snapshot.Processes == nil || snapshot.Sockets == nil || snapshot.Cgroups == nil {
		return fmt.Errorf("kernel, process, or socket family is missing")
	}
	return nil
}

func validateProcessRefs(processes []ProcessRef) error {
	seen := make(map[int]bool, len(processes))
	for _, process := range processes {
		if process.PID <= 0 || process.Name == "" || process.StartIdentity == "" || process.ExecutableIdentity == "" || seen[process.PID] {
			return fmt.Errorf("process state contains invalid or duplicate exact PID")
		}
		seen[process.PID] = true
	}
	return nil
}

func validateSocketRefs(sockets []SocketRef) error {
	seen := make(map[string]bool, len(sockets))
	for _, socket := range sockets {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%d", socket.Network, socket.Local, socket.Remote, socket.PID)
		if socket.Network == "" || socket.Local == "" || socket.PID <= 0 || socket.StartIdentity == "" || socket.ExecutableIdentity == "" || seen[key] {
			return fmt.Errorf("socket state contains invalid or duplicate exact socket")
		}
		seen[key] = true
	}
	return nil
}

func normalizeHealthSnapshot(snapshot *HealthSnapshot) {
	snapshot.KernelErrors = materializeHealthSlice(snapshot.KernelErrors)
	snapshot.Processes = materializeHealthSlice(snapshot.Processes)
	snapshot.Sockets = materializeHealthSlice(snapshot.Sockets)
	snapshot.Cgroups = materializeHealthSlice(snapshot.Cgroups)
	snapshot.InterfaceCounters = materializeHealthSlice(snapshot.InterfaceCounters)
	snapshot.UDPCounters = materializeHealthSlice(snapshot.UDPCounters)
	snapshot.SoftnetCounters = materializeHealthSlice(snapshot.SoftnetCounters)
	normalizeCleanupScope(&snapshot.CleanupScope)
	normalizeNamedCounters(snapshot.InterfaceCounters)
	normalizeNamedCounters(snapshot.UDPCounters)
	normalizeNamedCounters(snapshot.SoftnetCounters)
	for index := range snapshot.Cgroups {
		normalizeNamedCounters(snapshot.Cgroups[index].MemoryEvents)
	}
	sort.Strings(snapshot.KernelErrors)
	snapshot.KernelErrors = compactHealthStrings(snapshot.KernelErrors)
	sort.Slice(snapshot.Processes, func(i, j int) bool { return snapshot.Processes[i].PID < snapshot.Processes[j].PID })
	sort.Slice(snapshot.Sockets, func(i, j int) bool {
		left, right := snapshot.Sockets[i], snapshot.Sockets[j]
		if left.PID != right.PID {
			return left.PID < right.PID
		}
		if left.Network != right.Network {
			return left.Network < right.Network
		}
		if left.Local != right.Local {
			return left.Local < right.Local
		}
		return left.Remote < right.Remote
	})
	sort.Slice(snapshot.Cgroups, func(i, j int) bool { return snapshot.Cgroups[i].Path < snapshot.Cgroups[j].Path })
}

func materializeHealthSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func cloneCleanupScope(scope CleanupScope) CleanupScope {
	return CleanupScope{
		Declared:  scope.Declared,
		Processes: append([]ProcessRef(nil), scope.Processes...),
		Cgroups:   append([]CgroupRef(nil), scope.Cgroups...),
	}
}

func normalizedCleanupScope(scope CleanupScope) CleanupScope {
	result := cloneCleanupScope(scope)
	normalizeCleanupScope(&result)
	return result
}

func normalizeCleanupScope(scope *CleanupScope) {
	if scope.Processes == nil && scope.Declared {
		scope.Processes = []ProcessRef{}
	}
	if scope.Cgroups == nil && scope.Declared {
		scope.Cgroups = []CgroupRef{}
	}
	sort.Slice(scope.Processes, func(i, j int) bool { return scope.Processes[i].PID < scope.Processes[j].PID })
	sort.Slice(scope.Cgroups, func(i, j int) bool { return scope.Cgroups[i].Path < scope.Cgroups[j].Path })
}

func cleanupScopeContainsProcess(scope CleanupScope, process ProcessRef) bool {
	for _, expected := range scope.Processes {
		if expected.PID == process.PID && expected.StartIdentity == process.StartIdentity && expected.ExecutableIdentity == process.ExecutableIdentity {
			return true
		}
	}
	return false
}

func cleanupScopeProcessName(scope CleanupScope, socket SocketRef) string {
	for _, process := range scope.Processes {
		if process.PID == socket.PID && process.StartIdentity == socket.StartIdentity && process.ExecutableIdentity == socket.ExecutableIdentity {
			return process.Name
		}
	}
	return "unknown"
}

func normalizeNamedCounters(counters []NamedCounter) {
	sort.Slice(counters, func(i, j int) bool { return counters[i].Name < counters[j].Name })
}

func sumNamedCounters(counters []NamedCounter) (uint64, error) {
	var total uint64
	for _, counter := range counters {
		var err error
		total, err = addHealthUint64(total, counter.Value)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func validateNamedCounters(counters []NamedCounter, required []string, label string) error {
	if counters == nil {
		return fmt.Errorf("%s counter vector is missing", label)
	}
	want := append([]string(nil), required...)
	sort.Strings(want)
	got, err := validatedCounterNames(counters, label)
	if err != nil {
		return err
	}
	if required != nil && !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s counter vector has incomplete or substituted keys", label)
	}
	if required == nil && len(got) == 0 {
		return fmt.Errorf("%s counter vector is empty", label)
	}
	return nil
}

func validatedCounterNames(counters []NamedCounter, label string) ([]string, error) {
	result := make([]string, len(counters))
	for index, counter := range counters {
		if counter.Name == "" || strings.ContainsAny(counter.Name, "\x00\r\n") {
			return nil, fmt.Errorf("%s counter vector contains invalid key", label)
		}
		result[index] = counter.Name
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, fmt.Errorf("%s counter vector contains duplicate key", label)
		}
	}
	return result, nil
}

func validateNamedCounterFamilies(snapshot HealthSnapshot) error {
	interfaceKeys, udpKeys, err := platformCounterKeys(snapshot.Platform)
	if err != nil {
		return err
	}
	if err := validateNamedCounters(snapshot.InterfaceCounters, interfaceKeys, "interface"); err != nil {
		return err
	}
	if err := validateNamedCounters(snapshot.UDPCounters, udpKeys, "UDP"); err != nil {
		return err
	}
	if err := validateNamedCounters(snapshot.SoftnetCounters, nil, "softnet"); err != nil {
		return err
	}
	return validateCgroupCounterFamilies(snapshot)
}

func platformCounterKeys(platform string) ([]string, []string, error) {
	switch platform {
	case "linux":
		return []string{"rx_dropped", "rx_errors", "tx_dropped", "tx_errors"}, []string{"InCsumErrors", "InErrors", "NoPorts", "RcvbufErrors", "SndbufErrors"}, nil
	case "darwin":
		return []string{"input_errors", "output_errors"}, []string{"bad_checksum", "bad_data_length", "full_socket_buffers", "incomplete_header", "no_socket"}, nil
	default:
		return nil, nil, fmt.Errorf("health platform is missing or invalid")
	}
}

func validateCgroupCounterFamilies(snapshot HealthSnapshot) error {
	if snapshot.Platform == "darwin" {
		if len(snapshot.Cgroups) != 0 || len(snapshot.CleanupScope.Cgroups) != 0 {
			return fmt.Errorf("darwin cgroup state must be empty")
		}
		return nil
	}
	if len(snapshot.Cgroups) != len(snapshot.CleanupScope.Cgroups) {
		return fmt.Errorf("cgroup evidence does not match cleanup scope")
	}
	for index, cgroup := range snapshot.Cgroups {
		if cgroup.Path != snapshot.CleanupScope.Cgroups[index].Path || cgroup.Identity != snapshot.CleanupScope.Cgroups[index].Identity {
			return fmt.Errorf("cgroup evidence does not match cleanup scope")
		}
		if err := validateNamedCounters(cgroup.MemoryEvents, []string{"high", "low", "max", "oom", "oom_group_kill", "oom_kill"}, "cgroup memory.events"); err != nil {
			return err
		}
	}
	return nil
}

func namedVectorReasons(label string, before, after []NamedCounter) []string {
	beforeValues := make(map[string]uint64, len(before))
	for _, counter := range before {
		beforeValues[counter.Name] = counter.Value
	}
	var reasons []string
	for _, counter := range after {
		prior, ok := beforeValues[counter.Name]
		if !ok {
			reasons = append(reasons, label+" counter vector keys changed")
			continue
		}
		if counter.Value > prior {
			reasons = append(reasons, fmt.Sprintf("%s counter %s increased", label, counter.Name))
		}
		if counter.Value < prior {
			reasons = append(reasons, fmt.Sprintf("%s counter %s regressed", label, counter.Name))
		}
		delete(beforeValues, counter.Name)
	}
	if len(beforeValues) != 0 {
		reasons = append(reasons, label+" counter vector keys changed")
	}
	return reasons
}

func cgroupCounterReasons(before, after []CgroupHealth) []string {
	prior := make(map[string]CgroupHealth, len(before))
	for _, cgroup := range before {
		prior[cgroup.Path+"\x00"+cgroup.Identity] = cgroup
	}
	var reasons []string
	for _, cgroup := range after {
		key := cgroup.Path + "\x00" + cgroup.Identity
		beforeCgroup, ok := prior[key]
		if !ok {
			reasons = append(reasons, "cgroup identity changed")
			continue
		}
		reasons = append(reasons, namedVectorReasons("cgroup "+cgroup.Path+" memory.events", beforeCgroup.MemoryEvents, cgroup.MemoryEvents)...)
		delete(prior, key)
	}
	if len(prior) != 0 {
		reasons = append(reasons, "cgroup identity changed")
	}
	return reasons
}

func monotonicFailureReason(name string, before, after uint64) []string {
	if after > before {
		return []string{name + " counter increased"}
	}
	if after < before {
		return []string{name + " counter regressed"}
	}
	return nil
}

func newHealthStrings(before, after []string) []string {
	prior := make(map[string]bool, len(before))
	for _, value := range before {
		prior[value] = true
	}
	var result []string
	for _, value := range after {
		if !prior[value] {
			result = append(result, value)
		}
	}
	return result
}

func compactHealthStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func canonicalBootUUID(input string) (string, error) {
	value := strings.TrimSpace(input)
	if len(value) != 36 {
		return "", fmt.Errorf("linux boot ID is not a canonical UUID")
	}
	for index, character := range value {
		if uuidHyphenIndex(index) {
			if character != '-' {
				return "", fmt.Errorf("linux boot ID is not a canonical UUID")
			}
			continue
		}
		if !lowerHex(character) {
			return "", fmt.Errorf("linux boot ID is not a canonical UUID")
		}
	}
	return value, nil
}

func uuidHyphenIndex(index int) bool { return index == 8 || index == 13 || index == 18 || index == 23 }

func lowerHex(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}

type linuxMemoryCounters struct {
	Available uint64
	SwapUsed  uint64
}

func parseLinuxMeminfo(input string) (linuxMemoryCounters, error) {
	values, err := parseLinuxMeminfoFields(input)
	if err != nil {
		return linuxMemoryCounters{}, err
	}
	for _, key := range []string{"MemAvailable", "SwapTotal", "SwapFree"} {
		if _, ok := values[key]; !ok {
			return linuxMemoryCounters{}, fmt.Errorf("linux meminfo is missing %s", key)
		}
	}
	if values["MemAvailable"] == 0 || values["SwapFree"] > values["SwapTotal"] {
		return linuxMemoryCounters{}, fmt.Errorf("linux meminfo gauges are invalid")
	}
	return linuxMemoryCounters{Available: values["MemAvailable"], SwapUsed: values["SwapTotal"] - values["SwapFree"]}, nil
}

func parseLinuxMeminfoFields(input string) (map[string]uint64, error) {
	values := make(map[string]uint64)
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if !map[string]bool{"MemAvailable": true, "SwapTotal": true, "SwapFree": true}[key] {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return nil, fmt.Errorf("linux meminfo %s is malformed", key)
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return nil, fmt.Errorf("linux meminfo %s is malformed", key)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("linux meminfo %s is duplicated", key)
		}
		values[key] = value * 1024
	}
	return values, nil
}

func parseLinuxUDPErrorCounters(input string) ([]NamedCounter, error) {
	parsed, err := parseLinuxUDPCounters(input)
	if err != nil {
		return nil, err
	}
	var counters []NamedCounter
	for _, key := range []string{"NoPorts", "InErrors", "RcvbufErrors", "SndbufErrors", "InCsumErrors"} {
		value, ok := parsed[key]
		if !ok {
			return nil, fmt.Errorf("linux UDP counters are missing %s", key)
		}
		counters = append(counters, NamedCounter{Name: key, Value: value})
	}
	normalizeNamedCounters(counters)
	return counters, nil
}

func parseLinuxUDPCounters(input string) (map[string]uint64, error) {
	records := linuxUDPRecords(input)
	if len(records) == 0 {
		return nil, fmt.Errorf("linux UDP counters are missing")
	}
	if len(records) != 2 {
		return nil, fmt.Errorf("linux UDP counters are duplicated or malformed")
	}
	return parseLinuxUDPRecordPair(records[0], records[1])
}

func linuxUDPRecords(input string) [][]string {
	var records [][]string
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "Udp:" {
			records = append(records, fields)
		}
	}
	return records
}

func parseLinuxUDPRecordPair(headers, values []string) (map[string]uint64, error) {
	if len(values) != len(headers) || len(values) < 2 {
		return nil, fmt.Errorf("linux UDP counters are malformed")
	}
	parsed := make(map[string]uint64, len(headers)-1)
	for field := 1; field < len(headers); field++ {
		if _, duplicate := parsed[headers[field]]; duplicate {
			return nil, fmt.Errorf("linux UDP counter %s is duplicated", headers[field])
		}
		value, err := strconv.ParseUint(values[field], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("linux UDP counter %s is malformed", headers[field])
		}
		parsed[headers[field]] = value
	}
	return parsed, nil
}

func parseLinuxUptime(input string) (float64, error) {
	fields := strings.Fields(input)
	if len(fields) != 2 {
		return 0, fmt.Errorf("linux uptime is malformed")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
		return 0, fmt.Errorf("linux uptime is malformed")
	}
	idle, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || math.IsNaN(idle) || math.IsInf(idle, 0) || idle < 0 {
		return 0, fmt.Errorf("linux idle time is malformed")
	}
	return value, nil
}

func parseLinuxOnlineCPUs(input string) (int, error) {
	value := strings.TrimSpace(input)
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return 0, fmt.Errorf("linux online CPU list is malformed")
	}
	seen := make(map[int]bool)
	for _, segment := range strings.Split(value, ",") {
		first, last, err := parseLinuxCPUSegment(segment)
		if err != nil {
			return 0, err
		}
		for cpu := first; cpu <= last; cpu++ {
			if seen[cpu] {
				return 0, fmt.Errorf("linux online CPU list overlaps")
			}
			seen[cpu] = true
		}
	}
	if len(seen) == 0 {
		return 0, fmt.Errorf("linux online CPU list is empty")
	}
	return len(seen), nil
}

func parseLinuxCPUSegment(segment string) (int, int, error) {
	firstText, lastText, hasRange := strings.Cut(segment, "-")
	first, err := strconv.Atoi(firstText)
	if err != nil || first < 0 {
		return 0, 0, fmt.Errorf("linux online CPU list is malformed")
	}
	last := first
	if hasRange {
		if strings.Contains(lastText, "-") {
			return 0, 0, fmt.Errorf("linux online CPU list is malformed")
		}
		last, err = strconv.Atoi(lastText)
		if err != nil || last < first {
			return 0, 0, fmt.Errorf("linux online CPU list is malformed")
		}
	}
	if last-first > 1_000_000 {
		return 0, 0, fmt.Errorf("linux online CPU range is unreasonable")
	}
	return first, last, nil
}

func parseLinuxNamedUint(input, name, label string) (uint64, error) {
	found := false
	var result uint64
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != name {
			continue
		}
		if found || len(fields) != 2 {
			return 0, fmt.Errorf("%s is duplicated or malformed", label)
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s is malformed", label)
		}
		result, found = value, true
	}
	if !found {
		return 0, fmt.Errorf("%s is missing", label)
	}
	return result, nil
}

func parseLinuxMemoryEvents(input string) ([]NamedCounter, error) {
	required := []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}
	values := make(map[string]uint64)
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("linux cgroup memory.events is malformed")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("linux cgroup memory.events %s is malformed", fields[0])
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return nil, fmt.Errorf("linux cgroup memory.events %s is duplicated", fields[0])
		}
		values[fields[0]] = value
	}
	counters := make([]NamedCounter, 0, len(required))
	for _, name := range required {
		value, ok := values[name]
		if !ok {
			return nil, fmt.Errorf("linux cgroup memory.events is missing %s", name)
		}
		counters = append(counters, NamedCounter{Name: name, Value: value})
	}
	normalizeNamedCounters(counters)
	return counters, nil
}

func parseLinuxProcessStartIdentity(input string) (string, error) {
	_, startIdentity, err := parseLinuxProcessNameAndStartIdentity(input)
	return startIdentity, err
}

func parseLinuxProcessNameAndStartIdentity(input string) (string, string, error) {
	openIndex := strings.Index(input, " (")
	closeIndex := strings.LastIndex(input, ") ")
	if openIndex < 0 || closeIndex <= openIndex+2 {
		return "", "", fmt.Errorf("linux process stat is malformed")
	}
	name := input[openIndex+2 : closeIndex]
	if name == "" || strings.ContainsAny(name, "/\\\x00\r\n") {
		return "", "", fmt.Errorf("linux process name is malformed")
	}
	fields := strings.Fields(input[closeIndex+2:])
	const startTimeIndexAfterComm = 19
	if len(fields) <= startTimeIndexAfterComm {
		return "", "", fmt.Errorf("linux process stat is truncated")
	}
	if _, err := strconv.ParseUint(fields[startTimeIndexAfterComm], 10, 64); err != nil {
		return "", "", fmt.Errorf("linux process start identity is malformed")
	}
	return name, fields[startTimeIndexAfterComm], nil
}

func parseLinuxSoftnetCounters(input string) ([]NamedCounter, error) {
	var counters []NamedCounter
	count := 0
	for _, line := range strings.Split(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("linux softnet counters are malformed")
		}
		for _, field := range fields {
			if _, err := strconv.ParseUint(field, 16, 64); err != nil {
				return nil, fmt.Errorf("linux softnet counters are malformed")
			}
		}
		dropped, _ := strconv.ParseUint(fields[1], 16, 64)
		counters = append(counters, NamedCounter{Name: fmt.Sprintf("cpu:%d", count), Value: dropped})
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("linux softnet counters are missing")
	}
	return counters, nil
}

func parseLinuxNetworkSocketTable(input, network string) (map[uint64]SocketRef, error) {
	if !map[string]bool{"tcp4": true, "tcp6": true, "udp4": true, "udp6": true}[network] {
		return nil, fmt.Errorf("linux socket network is invalid")
	}
	lines := strings.Split(strings.TrimSuffix(input, "\n"), "\n")
	if err := validateLinuxNetworkSocketHeader(lines, network); err != nil {
		return nil, fmt.Errorf("linux %s socket header is malformed", network)
	}
	result := make(map[uint64]SocketRef)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		inode, socket, err := parseLinuxNetworkSocketRow(fields, network)
		if err != nil {
			return nil, err
		}
		if inode == 0 {
			continue
		}
		mergeLinuxSocketRef(result, inode, socket)
	}
	return result, nil
}

func mergeLinuxSocketRef(destination map[uint64]SocketRef, inode uint64, socket SocketRef) {
	existing, duplicate := destination[inode]
	if !duplicate {
		destination[inode] = socket
		return
	}
	if existing != socket {
		destination[inode] = SocketRef{Network: "other", Local: "inode:" + strconv.FormatUint(inode, 10)}
	}
}

func validateLinuxNetworkSocketHeader(lines []string, network string) error {
	if len(lines) == 0 {
		return fmt.Errorf("socket table is empty")
	}
	remoteColumn := "rem_address"
	if network == "tcp6" || network == "udp6" {
		remoteColumn = "remote_address"
	}
	want := []string{"sl", "local_address", remoteColumn, "st", "tx_queue", "rx_queue", "tr", "tm->when", "retrnsmt", "uid", "timeout", "inode"}
	if network == "udp4" || network == "udp6" {
		want = append(want, "ref", "pointer", "drops")
	}
	if !reflect.DeepEqual(strings.Fields(lines[0]), want) {
		return fmt.Errorf("socket header columns are malformed")
	}
	return nil
}

func parseLinuxNetworkSocketRow(fields []string, network string) (uint64, SocketRef, error) {
	if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") {
		return 0, SocketRef{}, fmt.Errorf("linux %s socket row is malformed", network)
	}
	if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 10, 64); err != nil {
		return 0, SocketRef{}, fmt.Errorf("linux %s socket index is malformed", network)
	}
	if !validLinuxSocketAddress(fields[1], network) || !validLinuxSocketAddress(fields[2], network) {
		return 0, SocketRef{}, fmt.Errorf("linux %s socket address is malformed", network)
	}
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil || (inode == 0 && !isOwnerlessLinuxTCPTimeWait(network, fields[3])) {
		return 0, SocketRef{}, fmt.Errorf("linux %s socket inode is malformed", network)
	}
	return inode, SocketRef{Network: network, Local: fields[1], Remote: fields[2]}, nil
}

func isOwnerlessLinuxTCPTimeWait(network, state string) bool {
	// Linux keeps completed TCP TIME_WAIT rows (state 06) in /proc/net/tcp{,6}
	// after their process-owned socket inode is gone. UDP has no TIME_WAIT state,
	// so inode zero remains malformed for both UDP tables and other TCP states.
	return (network == "tcp4" || network == "tcp6") && state == "06"
}

func validLinuxSocketAddress(value, network string) bool {
	address, port, ok := strings.Cut(value, ":")
	if !ok || len(port) != 4 {
		return false
	}
	wantAddressLength := 8
	if strings.HasSuffix(network, "6") {
		wantAddressLength = 32
	}
	if len(address) != wantAddressLength {
		return false
	}
	_, addressErr := strconv.ParseUint(address, 16, 64)
	if wantAddressLength == 32 {
		for offset := 0; offset < len(address); offset += 16 {
			if _, err := strconv.ParseUint(address[offset:offset+16], 16, 64); err != nil {
				return false
			}
		}
		addressErr = nil
	}
	_, portErr := strconv.ParseUint(port, 16, 16)
	return addressErr == nil && portErr == nil
}

func parseLinuxUnixSocketTable(input string) (map[uint64]SocketRef, error) {
	lines := strings.Split(strings.TrimSuffix(input, "\n"), "\n")
	if len(lines) == 0 || !reflect.DeepEqual(strings.Fields(lines[0]), []string{"Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"}) {
		return nil, fmt.Errorf("linux Unix socket header is malformed")
	}
	result := make(map[uint64]SocketRef)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		inode, socket, err := parseLinuxUnixSocketRow(fields)
		if err != nil {
			return nil, err
		}
		mergeLinuxSocketRef(result, inode, socket)
	}
	return result, nil
}

func parseLinuxUnixSocketRow(fields []string) (uint64, SocketRef, error) {
	if len(fields) < 7 || !strings.HasSuffix(fields[0], ":") {
		return 0, SocketRef{}, fmt.Errorf("linux Unix socket row is malformed")
	}
	if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 16, 64); err != nil {
		return 0, SocketRef{}, fmt.Errorf("linux Unix socket address is malformed")
	}
	inode, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil || inode == 0 {
		return 0, SocketRef{}, fmt.Errorf("linux Unix socket inode is malformed")
	}
	local := "inode:" + fields[6]
	if len(fields) > 7 {
		local = strings.Join(fields[7:], " ")
	}
	return inode, SocketRef{Network: "unix", Local: local}, nil
}

func parseDarwinVMStat(input string) (uint64, error) {
	lines := strings.Split(input, "\n")
	pageSize, err := parseDarwinVMPageSize(lines)
	if err != nil {
		return 0, err
	}
	values, err := parseDarwinVMPageCounts(lines[1:])
	if err != nil {
		return 0, err
	}
	var pages uint64
	for _, key := range []string{"Pages free", "Pages inactive", "Pages speculative"} {
		value, ok := values[key]
		if !ok {
			return 0, fmt.Errorf("darwin vm_stat is missing %s", key)
		}
		pages, err = addHealthUint64(pages, value)
		if err != nil {
			return 0, fmt.Errorf("darwin vm_stat page sum: %w", err)
		}
	}
	if pages == 0 || pages > math.MaxUint64/pageSize {
		return 0, fmt.Errorf("darwin vm_stat available memory overflows or is zero")
	}
	return pages * pageSize, nil
}

func parseDarwinVMPageSize(lines []string) (uint64, error) {
	if len(lines) == 0 {
		return 0, fmt.Errorf("darwin vm_stat is empty")
	}
	const prefix = "Mach Virtual Memory Statistics: (page size of "
	if !strings.HasPrefix(lines[0], prefix) || !strings.HasSuffix(lines[0], " bytes)") {
		return 0, fmt.Errorf("darwin vm_stat page size is malformed")
	}
	pageText := strings.TrimSuffix(strings.TrimPrefix(lines[0], prefix), " bytes)")
	pageSize, err := strconv.ParseUint(pageText, 10, 64)
	if err != nil || pageSize == 0 {
		return 0, fmt.Errorf("darwin vm_stat page size is malformed")
	}
	return pageSize, nil
}

func parseDarwinVMPageCounts(lines []string) (map[string]uint64, error) {
	want := map[string]bool{"Pages free": true, "Pages inactive": true, "Pages speculative": true}
	values := make(map[string]uint64, len(want))
	for _, line := range lines {
		key, valueText, found := strings.Cut(line, ":")
		if !found || !want[key] {
			continue
		}
		valueText = strings.TrimSuffix(strings.TrimSpace(valueText), ".")
		value, parseErr := strconv.ParseUint(valueText, 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("darwin vm_stat %s is malformed", key)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("darwin vm_stat %s is duplicated", key)
		}
		values[key] = value
	}
	return values, nil
}

func parseKernelErrorLines(input string) []string {
	var result []string
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Timestamp ") {
			continue
		}
		result = append(result, line)
	}
	return result
}

type healthCommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type healthCommandExecutor func(context.Context, string, ...string) (healthCommandResult, error)

func runHealthCommand(ctx context.Context, timeout time.Duration, path string, args ...string) (string, error) {
	result, err := runHealthCommandResultWithExecutor(ctx, timeout, executeHealthCommand, path, args...)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 || result.Stderr != "" {
		return "", fmt.Errorf("read-only health command %s failed with exit %d: %s", path, result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	return result.Stdout, nil
}

func runHealthCommandResultWithExecutor(ctx context.Context, timeout time.Duration, executor healthCommandExecutor, path string, args ...string) (healthCommandResult, error) {
	if ctx == nil || timeout <= 0 || executor == nil {
		return healthCommandResult{}, fmt.Errorf("read-only health command deadline is invalid")
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := executor(commandContext, path, args...)
	if err != nil {
		if commandContext.Err() != nil {
			return result, fmt.Errorf("read-only health command %s deadline: %w", path, commandContext.Err())
		}
		return result, fmt.Errorf("read-only health command %s failed: %w", path, err)
	}
	if commandContext.Err() != nil {
		return result, fmt.Errorf("read-only health command %s deadline: %w", path, commandContext.Err())
	}
	return result, nil
}

func executeHealthCommand(ctx context.Context, path string, args ...string) (healthCommandResult, error) {
	command := exec.CommandContext(ctx, path, args...)
	stdout := &healthBoundedBuffer{limit: maximumHealthInputBytes}
	stderr := &healthBoundedBuffer{limit: 64 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return healthCommandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitError.ExitCode()}, nil
		}
		return healthCommandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1}, err
	}
	return healthCommandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: 0}, nil
}

type healthBoundedBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *healthBoundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 || len(data) > remaining {
		return 0, fmt.Errorf("health command output exceeds %d bytes", buffer.limit)
	}
	return buffer.Buffer.Write(data)
}

func addHealthUint64(left, right uint64) (uint64, error) {
	if right > math.MaxUint64-left {
		return 0, fmt.Errorf("health counter sum overflows uint64")
	}
	return left + right, nil
}

func multiplyHealthUint64(left, right uint64) (uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, fmt.Errorf("health gauge multiplication overflows uint64")
	}
	return left * right, nil
}
