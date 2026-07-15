// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/udpbenchproof"
)

func TestHealthSnapshotAndWatchWriteCanonicalImmutableEvidence(t *testing.T) {
	t.Parallel()

	snapshot := cliHealthSnapshot()
	var captured udpbenchproof.HealthCaptureOptions
	capture := func(_ context.Context, options udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
		captured = options
		return snapshot, nil
	}
	dir := t.TempDir()
	scope := udpbenchproof.CleanupScope{Declared: true, Processes: []udpbenchproof.ProcessRef{{Name: "derphole", PID: 123, StartIdentity: "start-123", ExecutableIdentity: "/opt/derphole"}}, Cgroups: []udpbenchproof.CgroupRef{}}
	scopePath := writeCanonicalCLIJSON(t, dir, "scope.json", scope)
	snapshotPath := filepath.Join(dir, "health.json")
	var stdout, stderr bytes.Buffer
	args := []string{"-workdir", dir, "-interface", "en0", "-scope", scopePath, "-out", snapshotPath}
	if err := runHealthSnapshotWithCapture(args, &stdout, &stderr, capture); err != nil {
		t.Fatalf("health-snapshot: %v (stderr %q)", err, stderr.String())
	}
	if captured.WorkDir != dir || captured.Interface != "en0" || !reflect.DeepEqual(captured.CleanupScope, scope) || captured.CaptureTimeout != 30*time.Second || captured.CommandTimeout != 5*time.Second {
		t.Fatalf("capture options = %#v", captured)
	}
	assertCLICanonicalArtifactDigest(t, snapshotPath, stdout.String())

	stdout.Reset()
	if err := runHealthSnapshotWithCapture(args, &stdout, &bytes.Buffer{}, capture); err == nil {
		t.Fatal("health-snapshot replaced existing evidence")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed health-snapshot printed success: %q", stdout.String())
	}

	watchPath := filepath.Join(dir, "health.jsonl")
	stopPath := filepath.Join(dir, "stop")
	watches := 0
	watchCapture := func(_ context.Context, _ udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
		watches++
		if err := os.WriteFile(stopPath, []byte("stop\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return snapshot, nil
	}
	stdout.Reset()
	if err := runHealthWatchWithCapture([]string{
		"-workdir", dir, "-interface", "en0", "-scope", scopePath, "-interval", "1s", "-stop-file", stopPath, "-out", watchPath,
	}, &stdout, &stderr, watchCapture); err != nil {
		t.Fatalf("health-watch: %v", err)
	}
	if watches != 1 {
		t.Fatalf("watch captures = %d, want 1", watches)
	}
	assertCLICanonicalArtifactDigest(t, watchPath, stdout.String())
	data, err := os.ReadFile(watchPath)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, append(canonical, '\n')) {
		t.Fatalf("health-watch bytes = %q", data)
	}
	if err := os.Remove(stopPath); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runHealthWatchWithCapture([]string{
		"-workdir", dir, "-interface", "en0", "-scope", scopePath, "-interval", "1s", "-stop-file", stopPath, "-out", watchPath,
	}, &stdout, &bytes.Buffer{}, watchCapture); err == nil {
		t.Fatal("health-watch replaced existing evidence")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed health-watch printed success: %q", stdout.String())
	}
	unchanged, err := os.ReadFile(watchPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, data) {
		t.Fatal("health-watch existing evidence changed")
	}
}

func TestHealthSnapshotRealDarwinCaptureWritesArtifact(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real health snapshot is specific to Darwin")
	}

	routeOutput, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		t.Fatalf("read default route: %v", err)
	}
	fields := strings.Fields(string(routeOutput))
	interfaceName := ""
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "interface:" {
			interfaceName = fields[index+1]
			break
		}
	}
	if interfaceName == "" {
		t.Fatalf("default route omitted interface: %q", routeOutput)
	}

	dir := t.TempDir()
	scope := udpbenchproof.CleanupScope{
		Declared:  true,
		Processes: []udpbenchproof.ProcessRef{},
		Cgroups:   []udpbenchproof.CgroupRef{},
	}
	scopePath := writeCanonicalCLIJSON(t, dir, "scope.json", scope)
	snapshotPath := filepath.Join(dir, "health.json")
	var stdout, stderr bytes.Buffer
	if err := runHealthSnapshot([]string{
		"-workdir", dir,
		"-interface", interfaceName,
		"-scope", scopePath,
		"-capture-timeout", "60s",
		"-command-timeout", "15s",
		"-out", snapshotPath,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("real health-snapshot: %v (stderr %q)", err, stderr.String())
	}
	assertCLICanonicalArtifactDigest(t, snapshotPath, stdout.String())

	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot udpbenchproof.HealthSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Platform != "darwin" || !reflect.DeepEqual(snapshot.CleanupScope, scope) {
		t.Fatalf("real snapshot identity = %#v", snapshot)
	}
	want := map[string]bool{
		interfaceName + "/poll-on":  false,
		interfaceName + "/poll-off": false,
	}
	for _, counter := range snapshot.SoftnetCounters {
		if _, ok := want[counter.Name]; ok {
			want[counter.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("real snapshot omitted %s from softnet counters: %#v", name, snapshot.SoftnetCounters)
		}
	}
}

func TestProcessIdentifyWritesStrictImmutableIdentity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "process.json")
	want := udpbenchproof.ProcessRef{Name: "derphole", PID: 42, StartIdentity: "100", ExecutableIdentity: "dev:1-ino:2"}
	identify := func(_ context.Context, name string, pid int, timeout time.Duration) (udpbenchproof.ProcessRef, error) {
		if name != want.Name || pid != want.PID || timeout != 5*time.Second {
			return udpbenchproof.ProcessRef{}, fmt.Errorf("unexpected identify request")
		}
		return want, nil
	}
	var stdout bytes.Buffer
	if err := runProcessIdentifyWithIdentify([]string{"-name", want.Name, "-pid", "42", "-out", path}, &stdout, &bytes.Buffer{}, identify); err != nil {
		t.Fatal(err)
	}
	assertCLICanonicalArtifactDigest(t, path, stdout.String())
	var got udpbenchproof.ProcessRef
	if _, err := loadCanonicalJSON(path, &got); err != nil || got != want {
		t.Fatalf("process identity = %#v, %v", got, err)
	}
	stdout.Reset()
	if err := runProcessIdentifyWithIdentify([]string{"-name", want.Name, "-pid", "42", "-out", path}, &stdout, &bytes.Buffer{}, identify); err == nil {
		t.Fatal("process identity replaced immutable output")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed process identity printed success: %q", stdout.String())
	}
}

func TestProcessIdentifyFailureDoesNotCreateEvidence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "process.json")
	identify := func(context.Context, string, int, time.Duration) (udpbenchproof.ProcessRef, error) {
		return udpbenchproof.ProcessRef{}, errors.New("process is absent")
	}
	var stdout bytes.Buffer
	if err := runProcessIdentifyWithIdentify([]string{"-name", "derphole", "-pid", "42", "-out", path}, &stdout, &bytes.Buffer{}, identify); err == nil {
		t.Fatal("absent process identified")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed process identity printed success: %q", stdout.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed process identity artifact exists: %v", err)
	}
}

func TestHealthWatchStopsDuringWaitWithoutExtraCapture(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stopPath := filepath.Join(dir, "stop")
	file, err := os.OpenFile(filepath.Join(dir, "watch.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	captures := 0
	capture := func(context.Context, udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
		captures++
		if captures == 1 {
			go func() {
				time.Sleep(5 * time.Millisecond)
				_ = os.WriteFile(stopPath, []byte("stop\n"), 0o600)
			}()
		}
		return cliHealthSnapshot(), nil
	}
	options := healthWatchOptions{interval: time.Second, stopPath: stopPath}
	if err := writeHealthWatch(file, options, capture); err != nil {
		t.Fatal(err)
	}
	if captures != 1 {
		t.Fatalf("captures after stop during wait = %d, want 1", captures)
	}
}

func TestHealthWatchRejectsZeroSampleStopAndRetainsPartial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "watch.jsonl")
	stopPath := filepath.Join(dir, "stop")
	if err := os.WriteFile(stopPath, []byte("stop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	captures := 0
	err = writeHealthWatch(file, healthWatchOptions{interval: time.Second, stopPath: stopPath}, func(context.Context, udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
		captures++
		return cliHealthSnapshot(), nil
	})
	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err == nil || !strings.Contains(err.Error(), "before first complete sample") {
		t.Fatalf("zero-sample stop error = %v", err)
	}
	if captures != 0 {
		t.Fatalf("zero-sample stop captures = %d", captures)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || len(data) != 0 {
		t.Fatalf("retained zero-sample partial = %q, %v", data, readErr)
	}
}

func TestHealthWatchRejectsNormalizedAndSymlinkedPathAliases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for name, paths := range map[string][2]string{
		"normalized": {
			filepath.Join(dir, "nested", "..", "watch.jsonl"),
			filepath.Join(dir, "watch.jsonl"),
		},
		"symlinked parent": func() [2]string {
			realDir := filepath.Join(dir, "real")
			if err := os.Mkdir(realDir, 0o700); err != nil {
				t.Fatal(err)
			}
			aliasDir := filepath.Join(dir, "alias")
			if err := os.Symlink(realDir, aliasDir); err != nil {
				t.Fatal(err)
			}
			return [2]string{filepath.Join(aliasDir, "watch.jsonl"), filepath.Join(realDir, "watch.jsonl")}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := rejectHealthWatchPathAlias(paths[0], paths[1]); err == nil {
				t.Fatal("aliased stop/output paths accepted")
			}
		})
	}
}

func TestHealthWatchUsesStartToStartCadenceAndRejectsOverrun(t *testing.T) {
	t.Parallel()

	t.Run("start-to-start", func(t *testing.T) {
		dir := t.TempDir()
		stopPath := filepath.Join(dir, "stop")
		file, err := os.OpenFile(filepath.Join(dir, "watch.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		var starts []time.Time
		capture := func(context.Context, udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
			starts = append(starts, time.Now())
			time.Sleep(15 * time.Millisecond)
			if len(starts) == 2 {
				_ = os.WriteFile(stopPath, []byte("stop\n"), 0o600)
			}
			return cliHealthSnapshot(), nil
		}
		if err := writeHealthWatch(file, healthWatchOptions{interval: time.Second, stopPath: stopPath}, capture); err != nil {
			t.Fatal(err)
		}
		if len(starts) != 2 {
			t.Fatalf("capture starts = %d", len(starts))
		}
		delta := starts[1].Sub(starts[0])
		if delta < 900*time.Millisecond || delta > 1100*time.Millisecond {
			t.Fatalf("start-to-start cadence = %s", delta)
		}
	})

	t.Run("overrun retains evidence", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "watch.jsonl")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		capture := func(context.Context, udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
			time.Sleep(35 * time.Millisecond)
			_ = os.WriteFile(filepath.Join(dir, "stop"), []byte("stop\n"), 0o600)
			return cliHealthSnapshot(), nil
		}
		err = writeHealthWatch(file, healthWatchOptions{interval: 20 * time.Millisecond, stopPath: filepath.Join(dir, "stop")}, capture)
		if closeErr := file.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err == nil || !strings.Contains(err.Error(), "overrun") {
			t.Fatalf("overrun error = %v", err)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil || len(bytes.TrimSpace(data)) == 0 {
			t.Fatalf("retained evidence = %q, %v", data, readErr)
		}
	})
}

func TestHealthCompareAndCapacityCheckAreStrictAndSuccessOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	before := cliHealthSnapshot()
	after := cliHealthSnapshot()
	after.UptimeSeconds++
	beforePath := writeCanonicalCLIJSON(t, dir, "before.json", before)
	afterPath := writeCanonicalCLIJSON(t, dir, "after.json", after)
	scopePath := writeCanonicalCLIJSON(t, dir, "scope.json", before.CleanupScope)
	verdictPath := filepath.Join(dir, "verdict.json")
	var stdout bytes.Buffer
	if err := run([]string{
		"health-compare", "-before", beforePath, "-after", afterPath,
		"-scope", scopePath, "-expected-online-cpus", "2", "-min-available-memory-bytes", "1", "-min-disk-available-bytes", "1", "-max-swap-used-bytes", "1073741824", "-max-swap-increase-bytes", "0", "-out", verdictPath,
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("health-compare: %v", err)
	}
	assertCLICanonicalArtifactDigest(t, verdictPath, stdout.String())

	unhealthy := after
	unhealthy.Processes = []udpbenchproof.ProcessRef{{Name: "derphole", PID: 321, StartIdentity: "start", ExecutableIdentity: "/opt/derphole"}}
	unhealthyPath := writeCanonicalCLIJSON(t, dir, "unhealthy.json", unhealthy)
	unhealthyVerdict := filepath.Join(dir, "unhealthy-verdict.json")
	stdout.Reset()
	if err := run([]string{
		"health-compare", "-before", beforePath, "-after", unhealthyPath,
		"-scope", scopePath, "-expected-online-cpus", "2", "-min-available-memory-bytes", "1", "-min-disk-available-bytes", "1", "-max-swap-used-bytes", "1073741824", "-max-swap-increase-bytes", "0", "-out", unhealthyVerdict,
	}, &stdout, &bytes.Buffer{}); err == nil {
		t.Fatal("unhealthy comparison succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatalf("unhealthy comparison printed success: %q", stdout.String())
	}
	var unhealthyRecord udpbenchproof.HealthVerdict
	if _, err := loadCanonicalJSON(unhealthyVerdict, &unhealthyRecord); err != nil || unhealthyRecord.Healthy {
		t.Fatalf("unhealthy verdict = %#v, err %v", unhealthyRecord, err)
	}

	capacityPath := filepath.Join(dir, "capacity.json")
	stdout.Reset()
	capacityArgs := []string{
		"capacity-check", "-free-bytes", "1000", "-payload-bytes", "100", "-binary-bytes", "50",
		"-evidence-reserve-bytes", "50", "-additional-payload-copies", "1", "-out", capacityPath,
	}
	if err := run(capacityArgs, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("capacity-check: %v", err)
	}
	assertCLICanonicalArtifactDigest(t, capacityPath, stdout.String())

	lowPath := filepath.Join(dir, "capacity-low.json")
	stdout.Reset()
	capacityArgs[2] = "299"
	capacityArgs[len(capacityArgs)-1] = lowPath
	if err := run(capacityArgs, &stdout, &bytes.Buffer{}); err == nil {
		t.Fatal("insufficient capacity succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatalf("insufficient capacity printed success: %q", stdout.String())
	}
	assertCLICanonicalFile(t, lowPath)
}

func TestHealthCommandsRejectMalformedScopesAndNoncanonicalInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	called := false
	capture := func(context.Context, udpbenchproof.HealthCaptureOptions) (udpbenchproof.HealthSnapshot, error) {
		called = true
		return cliHealthSnapshot(), nil
	}
	malformedScope := writeCanonicalCLIJSON(t, dir, "malformed-scope.json", udpbenchproof.CleanupScope{})
	if err := runHealthSnapshotWithCapture([]string{
		"-workdir", dir, "-interface", "en0", "-scope", malformedScope, "-out", filepath.Join(dir, "malformed.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}, capture); err == nil {
		t.Fatal("malformed scope accepted")
	}
	if called {
		t.Fatal("malformed process reached capture")
	}

	noncanonical := filepath.Join(dir, "noncanonical.json")
	data, err := json.MarshalIndent(cliHealthSnapshot(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noncanonical, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	after := cliHealthSnapshot()
	after.UptimeSeconds++
	afterPath := writeCanonicalCLIJSON(t, dir, "canonical-after.json", after)
	out := filepath.Join(dir, "should-not-exist.json")
	if err := run([]string{
		"health-compare", "-before", noncanonical, "-after", afterPath,
		"-scope", writeCanonicalCLIJSON(t, dir, "scope.json", after.CleanupScope), "-expected-online-cpus", "2", "-min-available-memory-bytes", "1", "-min-disk-available-bytes", "1", "-max-swap-used-bytes", "1", "-max-swap-increase-bytes", "0", "-out", out,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("noncanonical snapshot accepted")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("invalid comparison created output: %v", err)
	}
}

func TestManifestCreateWritesDeterministicImmutableBytes(t *testing.T) {
	t.Parallel()

	input := loadValidManifestInput(t)
	inputBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	var outputs [][]byte
	var stdoutValues []string
	for range 2 {
		dir := t.TempDir()
		inputPath := filepath.Join(dir, "input.json")
		outputPath := filepath.Join(dir, "manifest.json")
		if err := os.WriteFile(inputPath, inputBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if err := run([]string{"manifest-create", "-input", inputPath, "-out", outputPath}, &stdout, &stderr); err != nil {
			t.Fatalf("manifest-create: %v (stderr %q)", err, stderr.String())
		}
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, data)
		stdoutValues = append(stdoutValues, stdout.String())
		if stdout.String() != string(udpbenchproof.DigestBytes(data))+"\n" {
			t.Fatalf("stdout = %q, want exact digest", stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr = %q", stderr.String())
		}
	}
	if !bytes.Equal(outputs[0], outputs[1]) || stdoutValues[0] != stdoutValues[1] {
		t.Fatalf("outputs differ across roots: bytes_equal=%t stdout=%q/%q", bytes.Equal(outputs[0], outputs[1]), stdoutValues[0], stdoutValues[1])
	}
}

func TestManifestCreateRefusesExistingOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := writeManifestInput(t, dir, loadValidManifestInput(t))
	outputPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(outputPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"manifest-create", "-input", inputPath, "-out", outputPath}, &stdout, &bytes.Buffer{}); err == nil {
		t.Fatal("existing output was replaced")
	}
	if stdout.Len() != 0 {
		t.Fatalf("failure printed success output: %q", stdout.String())
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatalf("existing output changed: %q", got)
	}
}

func TestManifestCreatePreservesPublishedDigestRecovery(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := writeManifestInput(t, dir, loadValidManifestInput(t))
	outputPath := filepath.Join(dir, "manifest.json")
	digest := udpbenchproof.SHA256Digest(strings.Repeat("a", 64))
	writer := func(string, any) (udpbenchproof.SHA256Digest, error) {
		return digest, &udpbenchproof.PublishedArtifactError{Digest: digest}
	}
	var stdout bytes.Buffer
	err := runManifestCreateWithWriter(
		[]string{"-input", inputPath, "-out", outputPath},
		&stdout,
		&bytes.Buffer{},
		writer,
	)
	var published *udpbenchproof.PublishedArtifactError
	if !errors.As(err, &published) || published.Digest != digest {
		t.Fatalf("manifest-create error = %v, want published digest %q", err, digest)
	}
	if !strings.Contains(err.Error(), string(digest)) {
		t.Fatalf("manifest-create error %q omits digest recovery text", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed manifest-create printed success: %q", stdout.String())
	}
}

func TestManifestCreateRejectsUnknownFieldsExtraValuesFlagsAndArguments(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valid, err := json.Marshal(loadValidManifestInput(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		data []byte
		args []string
	}{
		"unknown JSON field":   {data: []byte(`{"unknown":true}`)},
		"extra JSON value":     {data: append(append([]byte(nil), valid...), []byte("\n{}\n")...)},
		"duplicate JSON field": {data: append([]byte(`{"kind":"production",`), valid[1:]...)},
		"unknown flag":         {data: valid, args: []string{"-mystery"}},
		"trailing argument":    {data: valid, args: []string{"unexpected"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			inputPath := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(inputPath, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+"-out.json")
			args := []string{"manifest-create", "-input", inputPath, "-out", outputPath}
			args = append(args, test.args...)
			var stdout bytes.Buffer
			if err := run(args, &stdout, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid invocation accepted")
			}
			if stdout.Len() != 0 {
				t.Fatalf("failure printed success output: %q", stdout.String())
			}
			if _, err := os.Lstat(outputPath); !os.IsNotExist(err) {
				t.Fatalf("invalid invocation created output: %v", err)
			}
		})
	}
}

func TestManifestArtifactVerifyAndValidateExactBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := writeManifestInput(t, dir, loadValidManifestInput(t))
	manifestPath := filepath.Join(dir, "manifest.json")
	var createOut bytes.Buffer
	if err := run([]string{"manifest-create", "-input", inputPath, "-out", manifestPath}, &createOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimSpace(createOut.String())

	for _, command := range [][]string{
		{"artifact-verify", "-path", manifestPath, "-sha256", digest},
		{"validate", "-manifest", manifestPath, "-sha256", digest},
	} {
		var stdout bytes.Buffer
		if err := run(command, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatalf("%s: %v", command[0], err)
		}
		if stdout.String() != digest+"\n" {
			t.Fatalf("%s stdout = %q", command[0], stdout.String())
		}
	}

	if err := os.WriteFile(manifestPath, []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"artifact-verify", "-path", manifestPath, "-sha256", digest},
		{"validate", "-manifest", manifestPath, "-sha256", digest},
	} {
		if err := run(command, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("%s accepted mutated artifact", command[0])
		}
	}
}

func TestManifestValidateRejectsNoncanonicalOrUnknownJSON(t *testing.T) {
	t.Parallel()

	manifest, err := udpbenchproof.NewManifest(loadValidManifestInput(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	canonical = append(canonical, '\n')

	var indented bytes.Buffer
	if err := json.Indent(&indented, canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(`{"unknown":true,"manifest":`), canonical...)
	unknown = append(unknown, '}')
	duplicate := append([]byte(`{"schema_version":999,`), canonical[1:]...)
	for name, data := range map[string][]byte{
		"noncanonical": indented.Bytes(),
		"unknown":      unknown,
		"extra value":  append(append([]byte(nil), canonical...), []byte("{}\n")...),
		"duplicate":    duplicate,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := udpbenchproof.DigestBytes(data)
			if err := run([]string{"validate", "-manifest", path, "-sha256", string(digest)}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid manifest JSON accepted with its exact digest")
			}
		})
	}
}

func TestManifestCommandsRejectMalformedDigestAndTrailingArguments(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"artifact-verify", "-path", path, "-sha256", "bad"},
		{"artifact-verify", "-path", path, "-sha256", strings.Repeat("a", 64), "extra"},
		{"validate", "-manifest", path, "-sha256", strings.Repeat("A", 64)},
		{"validate", "-manifest", path, "-sha256", strings.Repeat("a", 64), "extra"},
		{"unknown-command"},
	} {
		var stdout bytes.Buffer
		if err := run(command, &stdout, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid command accepted: %v", command)
		}
		if stdout.Len() != 0 {
			t.Fatalf("invalid command printed success: %q", stdout.String())
		}
	}
}

func TestDependentCommandsBindExactCanonicalPriorArtifact(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	decision := udpbenchproof.Decision{
		SchemaVersion:     1,
		ManifestSHA256:    stringsDigest('a'),
		Stage:             udpbenchproof.StageScreening,
		Passed:            true,
		SelectedCandidate: "control",
		PeakFrontier:      []string{"control"},
		Reasons:           []string{},
		InputDecisionRefs: []udpbenchproof.ArtifactRef{},
		SampleRefs:        []udpbenchproof.ArtifactRef{},
		Statistics:        []udpbenchproof.CandidateStatistics{},
		MaterialEdges:     []udpbenchproof.MaterialEdge{},
		ClosedCandidates:  []string{},
	}
	path, digest := writeCLIJSON(t, dir, "decisions/screening.json", decision)
	loaded, err := loadPriorDecision(udpbenchproof.StagePreliminary, path, dir)
	if err != nil {
		t.Fatal(err)
	}
	wantRef := udpbenchproof.ArtifactRef{Role: "screening", Path: "decisions/screening.json", SHA256: digest}
	if loaded.Artifact != wantRef || loaded.EvidenceRoot != dir {
		t.Fatalf("prior binding = %#v root %q, want %#v root %q", loaded.Artifact, loaded.EvidenceRoot, wantRef, dir)
	}

	if _, err := loadPriorDecision(udpbenchproof.StagePreliminary, "", dir); err == nil {
		t.Fatal("dependent stage accepted missing prior")
	}
	if _, err := loadPriorDecision(udpbenchproof.StageScreening, path, dir); err == nil {
		t.Fatal("screening accepted a prior artifact")
	}
	noncanonical := filepath.Join(dir, "noncanonical.json")
	pretty, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noncanonical, pretty, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPriorDecision(udpbenchproof.StagePreliminary, noncanonical, dir); err == nil {
		t.Fatal("dependent stage accepted differently encoded prior decision")
	}

	err = run([]string{"evaluate", "-stage", "preliminary", "-manifest", "unused", "-results", "unused", "-out", "unused"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "requires -prior") {
		t.Fatalf("evaluate missing-prior error = %v", err)
	}
}

func TestParseStageAcceptsFrozenFinalistRerun(t *testing.T) {
	t.Parallel()

	stage, err := parseStage("finalist-rerun")
	if err != nil || stage != udpbenchproof.StageFinalistRerun {
		t.Fatalf("parse finalist-rerun = %q, %v", stage, err)
	}
}

func TestEvaluateLoadsImmutableSampleArtifactReferences(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifest := mustCLIManifest(t, loadValidManifestInput(t))
	manifestPath, _ := writeCLIJSON(t, dir, "manifest.json", manifest)
	refs := make([]udpbenchproof.ArtifactRef, len(manifest.ManifestInput.Schedules[0].RunIDs))
	for index := range refs {
		sample := cliSample(t, dir, manifest, index, 2100)
		relative := filepath.ToSlash(filepath.Join("samples", sample.Run.ID+".json"))
		_, digest := writeCLIJSON(t, dir, relative, sample)
		refs[index] = udpbenchproof.ArtifactRef{Role: "sample", Path: relative, SHA256: digest}
	}
	resultsPath := writeCLIJSONL(t, dir, "sample-refs.jsonl", refs)
	out := filepath.Join(dir, "decision.json")
	if err := run([]string{"evaluate", "-stage", "screening", "-manifest", manifestPath, "-results", resultsPath, "-out", out}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("evaluate immutable sample refs: %v", err)
	}

	missing := append([]udpbenchproof.ArtifactRef(nil), refs...)
	missing[0].Path = "samples/missing.json"
	missingPath := writeCLIJSONL(t, dir, "missing-sample-refs.jsonl", missing)
	if err := run([]string{"evaluate", "-stage", "screening", "-manifest", manifestPath, "-results", missingPath, "-out", filepath.Join(dir, "missing-decision.json")}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("evaluate accepted a missing immutable sample artifact")
	}
}

func TestVerifyPrerequisiteReopensAllExactSampleArtifacts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	localBin := filepath.Join(dir, "darwin-bin")
	linuxBin := filepath.Join(dir, "linux-bin")
	if err := os.WriteFile(localBin, []byte("darwin binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linuxBin, []byte("linux binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	experiment := mustCLIManifest(t, loadValidManifestInput(t))
	experimentPath, _ := writeCLIJSON(t, dir, "manifest.json", experiment)
	_, peakDigest := buildCLIPeakProof(t, dir, experimentPath, experiment)
	productionInput := cliProductionInput(t, experiment, localBin, linuxBin)
	productionInput.ParentDecisionRefs[0].SHA256 = peakDigest
	production := mustCLIManifest(t, productionInput)
	manifestPath, manifestDigest := writeCLIJSON(t, dir, "production.json", production)
	samples := make([]udpbenchproof.Sample, 6)
	for index := range samples {
		samples[index] = cliSample(t, dir, production, index, 2100+float64(index%3)*10)
	}
	resultsPath := writeCLISampleRefs(t, dir, "production-refs.jsonl", samples)
	decisionPath := filepath.Join(dir, "prerequisite.json")
	if err := run([]string{"prerequisite-decide", "-manifest", manifestPath, "-results", resultsPath, "-out", decisionPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	decisionDigest, err := udpbenchproof.FileDigest(decisionPath)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](resultsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(refs[0].Path)), []byte("mutated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifyArgs := []string{
		"verify-prerequisite", "-manifest", manifestPath, "-manifest-sha256", string(manifestDigest),
		"-decision", decisionPath, "-decision-sha256", string(decisionDigest), "-local-bin", localBin, "-linux-bin", linuxBin,
	}
	if err := run(verifyArgs, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("prerequisite verification trusted a decision after an exact sample artifact mutated")
	}
}

func TestTask8BCommandsEndToEndAndRefuseReplacement(t *testing.T) {
	dir := t.TempDir()
	experiment := mustCLIManifest(t, loadValidManifestInput(t))
	experimentPath, experimentDigest := writeCLIJSON(t, dir, "experiment.json", experiment)
	experimentSamples := make([]udpbenchproof.Sample, len(experiment.ManifestInput.Schedules[0].RunIDs))
	for index := range experimentSamples {
		experimentSamples[index] = cliSample(t, dir, experiment, index, 2100)
	}
	experimentResults := writeCLISampleRefs(t, dir, "experiment.jsonl", experimentSamples)
	experimentSample := experimentSamples[0]
	experimentSamplePath, _ := writeCLIJSON(t, dir, "sample.json", experimentSample)

	outputCommands := []struct {
		name string
		args func(string) []string
	}{
		{"schedule", func(out string) []string {
			return []string{"schedule", "-stage", "screening", "-manifest", experimentPath, "-manifest-sha256", string(experimentDigest), "-out", out}
		}},
		{"evaluate", func(out string) []string {
			return []string{"evaluate", "-stage", "screening", "-manifest", experimentPath, "-results", experimentResults, "-out", out}
		}},
	}
	for _, command := range outputCommands {
		t.Run(command.name, func(t *testing.T) {
			assertImmutableCLIOutput(t, filepath.Join(dir, command.name+".json"), command.args)
		})
	}
	var sampleOut, sampleErr bytes.Buffer
	if err := run([]string{"sample-validate", "-manifest", experimentPath, "-sample", experimentSamplePath}, &sampleOut, &sampleErr); err != nil {
		t.Fatalf("sample-validate: %v (stderr %q)", err, sampleErr.String())
	}
	if sampleOut.String() != "valid\n" || sampleErr.Len() != 0 {
		t.Fatalf("sample-validate output = %q / %q", sampleOut.String(), sampleErr.String())
	}

	localBin := filepath.Join(dir, "darwin-bin")
	linuxBin := filepath.Join(dir, "linux-bin")
	if err := os.WriteFile(localBin, []byte("darwin binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linuxBin, []byte("linux binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	productionInput := cliProductionInput(t, experiment, localBin, linuxBin)
	writeCLIJSON(t, dir, "manifest.json", experiment)
	peakPath, peakDigest := buildCLIPeakProof(t, dir, experimentPath, experiment)
	productionInput.ParentDecisionRefs[0].SHA256 = peakDigest
	production := mustCLIManifest(t, productionInput)
	productionPath, productionDigest := writeCLIJSON(t, dir, "production.json", production)
	writeCLIJSON(t, dir, "production-manifest.json", production)
	assertImmutableCLIOutput(t, filepath.Join(dir, "production-schedule.json"), func(out string) []string {
		return []string{"schedule", "-stage", "production", "-manifest", productionPath, "-manifest-sha256", string(productionDigest), "-prior", peakPath, "-out", out}
	})
	productionSamples := make([]udpbenchproof.Sample, 6)
	for index := range productionSamples {
		productionSamples[index] = cliSample(t, dir, production, index, 2100+float64(index%3)*10)
	}
	productionResults := writeCLISampleRefs(t, dir, "production.jsonl", productionSamples)
	if err := os.MkdirAll(filepath.Join(dir, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	prerequisitePath := filepath.Join(dir, "decisions", "prerequisite.json")
	assertImmutableCLIOutput(t, prerequisitePath, func(out string) []string {
		return []string{"prerequisite-decide", "-manifest", productionPath, "-results", productionResults, "-out", out}
	})
	prerequisiteDigest, err := udpbenchproof.FileDigest(prerequisitePath)
	if err != nil {
		t.Fatal(err)
	}
	var prerequisiteDecision udpbenchproof.PrerequisiteDecision
	readCLIJSON(t, prerequisitePath, &prerequisiteDecision)
	if !prerequisiteDecision.Passed {
		t.Fatalf("prerequisite command did not pass exact production authorization: %#v", prerequisiteDecision)
	}
	var verifyOut, verifyErr bytes.Buffer
	if err := run([]string{
		"verify-prerequisite", "-manifest", productionPath, "-manifest-sha256", string(productionDigest),
		"-decision", prerequisitePath, "-decision-sha256", string(prerequisiteDigest), "-local-bin", localBin, "-linux-bin", linuxBin,
	}, &verifyOut, &verifyErr); err != nil {
		t.Fatalf("verify-prerequisite: %v (stderr %q)", err, verifyErr.String())
	}
	if verifyOut.String() != string(prerequisiteDigest)+"\n" || verifyErr.Len() != 0 {
		t.Fatalf("verify-prerequisite output = %q / %q", verifyOut.String(), verifyErr.String())
	}
	assertImmutableCLIOutput(t, filepath.Join(dir, "fleet-schedule.json"), func(out string) []string {
		return []string{"schedule", "-stage", "fleet", "-manifest", productionPath, "-manifest-sha256", string(productionDigest), "-prerequisite", prerequisitePath, "-out", out}
	})

	prerequisiteRef := udpbenchproof.ArtifactRef{Role: "prerequisite", Path: "decisions/prerequisite.json", SHA256: prerequisiteDigest}
	var fleetProbeRefs []udpbenchproof.ArtifactRef
	for _, host := range production.ManifestInput.FleetInventory {
		if host.Role == udpbenchproof.HostRolePrimary {
			continue
		}
		for phaseIndex, phase := range []string{"initial", "recheck"} {
			path := filepath.ToSlash(filepath.Join("probes", host.ID+"-"+phase+".json"))
			ref := cliEvidenceRef(t, dir, "fleet-probe", path, cliFleetProbeRecord{1, "fleet-probe", host.ID, phase, true, time.Date(2026, 7, 16, 2, phaseIndex, 0, 0, time.UTC).Format(time.RFC3339)})
			fleetProbeRefs = append(fleetProbeRefs, ref)
		}
	}
	fleetProbesPath := writeCLIJSONL(t, dir, "fleet-probes.jsonl", fleetProbeRefs)
	fleetSchedule := production.ManifestInput.Schedules[1]
	fleetSamples := make([]udpbenchproof.Sample, len(fleetSchedule.RunIDs))
	for index := range fleetSamples {
		fleetSamples[index] = cliSampleForSchedule(t, dir, production, 1, index, 2100)
		fleetSamples[index].Run.PriorDecisionRef = prerequisiteRef
	}
	fleetResultsPath := writeCLISampleRefs(t, dir, "fleet.jsonl", fleetSamples)
	fleetPath := filepath.Join(dir, "decisions", "fleet.json")
	assertImmutableCLIOutput(t, fleetPath, func(out string) []string {
		return []string{"fleet-decide", "-manifest", productionPath, "-prerequisite", prerequisitePath, "-probes", fleetProbesPath, "-results", fleetResultsPath, "-out", out}
	})
	var fleet udpbenchproof.Decision
	readCLIJSON(t, fleetPath, &fleet)
	if !fleet.Passed || fleet.Stage != udpbenchproof.StageFleet {
		t.Fatalf("fleet command did not pass exact proof graph: %#v", fleet)
	}
	fleetDigest, err := udpbenchproof.FileDigest(fleetPath)
	if err != nil {
		t.Fatal(err)
	}
	var passedPeak udpbenchproof.Decision
	readCLIJSON(t, filepath.Join(dir, "decisions", "finalist.json"), &passedPeak)
	passedPeakPath, _ := writeCLIJSON(t, dir, "decisions/peak.json", passedPeak)
	passedCeiling := mustCLIManifest(t, cliCeilingInput(t, production, peakDigest, fleetDigest))
	passedCeilingPath, passedCeilingDigest := writeCLIJSON(t, dir, "passed-ceiling.json", passedCeiling)
	if err := run([]string{
		"schedule", "-stage", "ceiling", "-manifest", passedCeilingPath, "-manifest-sha256", string(passedCeilingDigest),
		"-prior", passedPeakPath, "-prerequisite", prerequisitePath, "-fleet", fleetPath,
		"-out", filepath.Join(dir, "passed-ceiling-schedule.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("public ceiling schedule accepted an ordinary passed prerequisite instead of exact throughput-only failed fleet authorization")
	}

	acceptanceInput := cliAcceptanceInput(t, production, prerequisiteDigest, fleetDigest)
	acceptance := mustCLIManifest(t, acceptanceInput)
	acceptancePath, acceptanceDigest := writeCLIJSON(t, dir, "acceptance.json", acceptance)
	assertImmutableCLIOutput(t, filepath.Join(dir, "acceptance-schedule.json"), func(out string) []string {
		return []string{"schedule", "-stage", "acceptance", "-manifest", acceptancePath, "-manifest-sha256", string(acceptanceDigest), "-prerequisite", prerequisitePath, "-fleet", fleetPath, "-out", out}
	})
	acceptanceSamples := make([]udpbenchproof.Sample, 6)
	for index := range acceptanceSamples {
		acceptanceSamples[index] = cliSample(t, dir, acceptance, index, 2100+float64(index%3)*10)
		acceptanceSamples[index].Run.PriorDecisionRef = udpbenchproof.ArtifactRef{Role: "fleet", Path: "decisions/fleet.json", SHA256: fleetDigest}
	}
	acceptanceResults := writeCLISampleRefs(t, dir, "acceptance.jsonl", acceptanceSamples)
	assertImmutableCLIOutput(t, filepath.Join(dir, "acceptance-decision.json"), func(out string) []string {
		return []string{"acceptance-decide", "-manifest", acceptancePath, "-prerequisite", prerequisitePath, "-fleet", fleetPath, "-results", acceptanceResults, "-out", out}
	})
	var acceptanceDecision udpbenchproof.Decision
	readCLIJSON(t, filepath.Join(dir, "acceptance-decision.json"), &acceptanceDecision)
	if !acceptanceDecision.Passed || !acceptanceDecision.AcceptanceMet {
		t.Fatalf("acceptance command did not pass exact fleet proof: %#v", acceptanceDecision)
	}

	hardProductionSamples := make([]udpbenchproof.Sample, 6)
	for index := range hardProductionSamples {
		hardProductionSamples[index] = cliSample(t, dir, production, index, 1900+float64(index%3)*5)
	}
	hardProductionResults := writeCLISampleRefs(t, dir, "hard-production.jsonl", hardProductionSamples)
	hardPrerequisitePath := filepath.Join(dir, "decisions", "ceiling", "prerequisite.json")
	if err := os.MkdirAll(filepath.Dir(hardPrerequisitePath), 0o700); err != nil {
		t.Fatal(err)
	}
	assertImmutableCLIOutput(t, hardPrerequisitePath, func(out string) []string {
		return []string{"prerequisite-decide", "-manifest", productionPath, "-results", hardProductionResults, "-out", out}
	})
	var hardPrerequisite udpbenchproof.PrerequisiteDecision
	readCLIJSON(t, hardPrerequisitePath, &hardPrerequisite)
	if hardPrerequisite.Passed || !reflect.DeepEqual(hardPrerequisite.Reasons, []string{"sample does not exceed 2.0 Gbps"}) {
		t.Fatalf("hard-ceiling prerequisite did not fail only the WAN target: %#v", hardPrerequisite)
	}
	hardPrerequisiteDigest, err := udpbenchproof.FileDigest(hardPrerequisitePath)
	if err != nil {
		t.Fatal(err)
	}
	assertImmutableCLIOutput(t, filepath.Join(dir, "hard-fleet-schedule.json"), func(out string) []string {
		return []string{"schedule", "-stage", "fleet", "-manifest", productionPath, "-manifest-sha256", string(productionDigest), "-prerequisite", hardPrerequisitePath, "-out", out}
	})
	hardPrerequisiteRef := udpbenchproof.ArtifactRef{Role: "prerequisite", Path: "decisions/ceiling/prerequisite.json", SHA256: hardPrerequisiteDigest}
	hardFleetSamples := make([]udpbenchproof.Sample, len(fleetSchedule.RunIDs))
	for index := range hardFleetSamples {
		hardFleetSamples[index] = cliSampleForSchedule(t, dir, production, 1, index, 2100)
		hardFleetSamples[index].Run.PriorDecisionRef = hardPrerequisiteRef
	}
	hardFleetResults := writeCLISampleRefs(t, dir, "results/ceiling/hard-fleet.jsonl", hardFleetSamples)
	if err := os.Remove(fleetPath); err != nil {
		t.Fatal(err)
	}
	hardFleetPath := fleetPath
	assertImmutableCLIOutput(t, hardFleetPath, func(out string) []string {
		return []string{"fleet-decide", "-manifest", productionPath, "-prerequisite", hardPrerequisitePath, "-probes", fleetProbesPath, "-results", hardFleetResults, "-out", out}
	})
	var hardFleet udpbenchproof.Decision
	readCLIJSON(t, hardFleetPath, &hardFleet)
	if !hardFleet.Passed {
		t.Fatalf("hard-ceiling fleet did not replay exact throughput-only guard: %#v", hardFleet)
	}
	hardFleetDigest, err := udpbenchproof.FileDigest(hardFleetPath)
	if err != nil {
		t.Fatal(err)
	}

	ceilingInput := cliCeilingInput(t, production, peakDigest, hardFleetDigest)
	var peakDecision udpbenchproof.Decision
	readCLIJSON(t, filepath.Join(dir, "decisions", "finalist.json"), &peakDecision)
	peakAliasPath, _ := writeCLIJSON(t, dir, "decisions/peak.json", peakDecision)
	ceiling := mustCLIManifest(t, ceilingInput)
	ceilingPath, ceilingDigest := writeCLIJSON(t, dir, "ceiling.json", ceiling)
	assertImmutableCLIOutput(t, filepath.Join(dir, "ceiling-schedule.json"), func(out string) []string {
		return []string{"schedule", "-stage", "ceiling", "-manifest", ceilingPath, "-manifest-sha256", string(ceilingDigest), "-prior", peakAliasPath, "-prerequisite", hardPrerequisitePath, "-fleet", hardFleetPath, "-out", out}
	})
	sweeps := cliCeilingSweeps()
	profiles := cliCeilingProfiles()
	bindCLICeilingRawArtifacts(t, dir, ceiling, sweeps, profiles)
	sweepsPath := writeCLIJSONL(t, dir, "results/ceiling/sweeps.jsonl", cliCeilingSweepRefs(sweeps))
	profilesPath := writeCLIJSONL(t, dir, "results/ceiling/profiles.jsonl", cliCeilingProfileRefs(profiles))
	winnerPath := writeCLIJSONL(t, dir, "results/ceiling/winner.jsonl", cliExactCeilingWinnerRefs(t, dir, peakDecision, hardPrerequisite))
	assertImmutableCLIOutput(t, filepath.Join(dir, "ceiling-decision.json"), func(out string) []string {
		return []string{"ceiling-decide", "-manifest", ceilingPath, "-sweeps", sweepsPath, "-profiles", profilesPath, "-winner-samples", winnerPath, "-out", out}
	})
	var ceilingDecision udpbenchproof.CeilingDecision
	readCLIJSON(t, filepath.Join(dir, "ceiling-decision.json"), &ceilingDecision)
	if !ceilingDecision.Passed {
		t.Fatalf("ceiling command did not pass exact proof graph: %#v", ceilingDecision)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(sweeps[0].Artifact.Path)), []byte("mutated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var replacedOut bytes.Buffer
	if err := run([]string{"ceiling-decide", "-manifest", ceilingPath, "-sweeps", sweepsPath, "-profiles", profilesPath, "-winner-samples", winnerPath, "-out", filepath.Join(dir, "replaced-ceiling.json")}, &replacedOut, &bytes.Buffer{}); err == nil {
		t.Fatal("ceiling command accepted a replaced typed sweep point artifact")
	}
	if replacedOut.Len() != 0 {
		t.Fatalf("replaced ceiling artifact printed success: %q", replacedOut.String())
	}

}

func TestCommandsUseManifestCampaignRootForNestedInputsAndReplay(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	experiment := mustCLIManifest(t, loadValidManifestInput(t))
	manifestPath, _ := writeCLIJSON(t, root, "manifest.json", experiment)
	samples := make([]udpbenchproof.Sample, len(experiment.ManifestInput.Schedules[0].RunIDs))
	for index := range samples {
		samples[index] = cliSample(t, root, experiment, index, 1900)
	}
	refs := writeCLISampleArtifacts(t, root, "nested-screening", samples)
	resultsDir := filepath.Join(root, "results", "screening")
	if err := os.MkdirAll(resultsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	resultsPath := writeCLIJSONL(t, resultsDir, "refs.jsonl", refs)
	decisionPath := filepath.Join(root, "results", "decisions", "screening.json")
	if err := os.MkdirAll(filepath.Dir(decisionPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"evaluate", "-stage", "screening", "-manifest", manifestPath, "-results", resultsPath, "-out", decisionPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("nested evaluate did not resolve sample refs from campaign root: %v", err)
	}
	var sampleOut bytes.Buffer
	if err := run([]string{"sample-validate", "-manifest", manifestPath, "-sample", filepath.Join(root, filepath.FromSlash(refs[0].Path))}, &sampleOut, &bytes.Buffer{}); err != nil {
		t.Fatalf("nested sample-validate did not resolve raw refs from campaign root: %v", err)
	}
	if sampleOut.String() != "valid\n" {
		t.Fatalf("sample-validate output = %q", sampleOut.String())
	}
	var decision udpbenchproof.Decision
	readCLIJSON(t, decisionPath, &decision)
	digest, err := udpbenchproof.FileDigest(decisionPath)
	if err != nil {
		t.Fatal(err)
	}
	decision.Artifact = udpbenchproof.ArtifactRef{Role: "screening", Path: "results/decisions/screening.json", SHA256: digest}
	decision.EvidenceRoot = root
	experiment.EvidenceRoot = root
	if err := udpbenchproof.ReplayDecision(experiment, decision); err != nil {
		t.Fatalf("nested emitted decision did not recursively replay from campaign root: %v", err)
	}

	screeningRef := decision.Artifact
	preliminarySchedule := experiment.ManifestInput.Schedules[1]
	preliminarySamples := make([]udpbenchproof.Sample, len(preliminarySchedule.RunIDs))
	for index := range preliminarySamples {
		preliminarySamples[index] = cliSampleForSchedule(t, root, experiment, 1, index, 1900)
		preliminarySamples[index].Run.PriorDecisionRef = screeningRef
	}
	preliminaryRefs := writeCLISampleArtifacts(t, root, "nested-preliminary", preliminarySamples)
	preliminaryResults := writeCLIJSONL(t, resultsDir, "preliminary-refs.jsonl", preliminaryRefs)
	preliminaryPath := filepath.Join(root, "results", "decisions", "preliminary.json")
	if err := run([]string{"evaluate", "-stage", "preliminary", "-manifest", manifestPath, "-prior", decisionPath, "-results", preliminaryResults, "-out", preliminaryPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("nested preliminary did not load nested prior and root-relative samples: %v", err)
	}
	var preliminary udpbenchproof.Decision
	readCLIJSON(t, preliminaryPath, &preliminary)
	preliminaryDigest, err := udpbenchproof.FileDigest(preliminaryPath)
	if err != nil {
		t.Fatal(err)
	}
	preliminary.Artifact = udpbenchproof.ArtifactRef{Role: "preliminary", Path: "results/decisions/preliminary.json", SHA256: preliminaryDigest}
	preliminary.EvidenceRoot = root
	if err := udpbenchproof.ReplayDecision(experiment, preliminary); err != nil {
		t.Fatalf("nested emitted dependent decision did not recursively replay: %v", err)
	}
}

func buildCLIPeakProof(t *testing.T, dir, manifestPath string, experiment udpbenchproof.Manifest) (string, udpbenchproof.SHA256Digest) {
	return buildCLIPeakProofMode(t, dir, manifestPath, experiment, false)
}

func buildCLIPeakProofMode(t *testing.T, dir, manifestPath string, experiment udpbenchproof.Manifest, forceRerun bool) (string, udpbenchproof.SHA256Digest) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	screeningSamples := make([]udpbenchproof.Sample, len(experiment.ManifestInput.Schedules[0].RunIDs))
	for index := range screeningSamples {
		screeningSamples[index] = cliSampleForSchedule(t, dir, experiment, 0, index, 2100)
	}
	screeningResults := writeCLISampleRefs(t, dir, "peak-screening.jsonl", screeningSamples)
	screeningPath := filepath.Join(dir, "decisions", "screening.json")
	assertImmutableCLIOutput(t, screeningPath, func(out string) []string {
		return []string{"evaluate", "-stage", "screening", "-manifest", manifestPath, "-results", screeningResults, "-out", out}
	})
	screeningDigest, err := udpbenchproof.FileDigest(screeningPath)
	if err != nil {
		t.Fatal(err)
	}
	screeningRef := udpbenchproof.ArtifactRef{Role: "screening", Path: "decisions/screening.json", SHA256: screeningDigest}
	preliminarySchedule := experiment.ManifestInput.Schedules[1]
	preliminarySamples := make([]udpbenchproof.Sample, len(preliminarySchedule.RunIDs))
	for index, candidateID := range preliminarySchedule.CandidateOrder {
		goodput := 2100.0
		if candidateID == "challenger" {
			goodput = 2200
		}
		preliminarySamples[index] = cliSampleForSchedule(t, dir, experiment, 1, index, goodput)
		preliminarySamples[index].Run.PriorDecisionRef = screeningRef
	}
	preliminaryResults := writeCLISampleRefs(t, dir, "peak-preliminary.jsonl", preliminarySamples)
	preliminaryPath := filepath.Join(dir, "decisions", "preliminary.json")
	assertImmutableCLIOutput(t, preliminaryPath, func(out string) []string {
		return []string{"evaluate", "-stage", "preliminary", "-manifest", manifestPath, "-prior", screeningPath, "-results", preliminaryResults, "-out", out}
	})
	preliminaryDigest, err := udpbenchproof.FileDigest(preliminaryPath)
	if err != nil {
		t.Fatal(err)
	}
	preliminaryRef := udpbenchproof.ArtifactRef{Role: "preliminary", Path: "decisions/preliminary.json", SHA256: preliminaryDigest}
	preliminaryRefs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](preliminaryResults)
	if err != nil {
		t.Fatal(err)
	}
	var finalistSamples []udpbenchproof.Sample
	finalistSchedule := experiment.ManifestInput.Schedules[2]
	for index, candidateID := range finalistSchedule.CandidateOrder {
		goodput := 2100.0
		if candidateID == "challenger" {
			goodput = 2200
		}
		sample := cliSampleForSchedule(t, dir, experiment, 2, index, goodput)
		sample.Run.PriorDecisionRef = preliminaryRef
		if forceRerun {
			capacity := 2050.0
			if index%3 == 0 {
				capacity = 3000
			}
			sample.Capacity.Mbps = capacity
			sample.Capacity.Valid = true
			sample.Capacity.Artifact = cliEvidenceRef(t, dir, "capacity", sample.Capacity.Artifact.Path, cliCapacityEvidence{1, "capacity", sample.Run.ID, sample.Run.Direction, capacity, true})
		}
		finalistSamples = append(finalistSamples, sample)
	}
	finalistRefs := writeCLISampleArtifacts(t, dir, "peak-finalist", finalistSamples)
	finalistResults := writeCLIJSONL(t, dir, "peak-finalist.jsonl", append(preliminaryRefs, finalistRefs...))
	peakPath := filepath.Join(dir, "decisions", "finalist.json")
	assertImmutableCLIOutput(t, peakPath, func(out string) []string {
		return []string{"evaluate", "-stage", "finalist", "-manifest", manifestPath, "-prior", preliminaryPath, "-results", finalistResults, "-out", out}
	})
	peakDigest, err := udpbenchproof.FileDigest(peakPath)
	if err != nil {
		t.Fatal(err)
	}
	return peakPath, peakDigest
}

func TestFinalistRerunCLIConsumesCompletePooledEvidence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	experiment := mustCLIManifest(t, loadValidManifestInput(t))
	manifestPath, _ := writeCLIJSON(t, dir, "manifest.json", experiment)
	finalistPath, finalistDigest := buildCLIPeakProofMode(t, dir, manifestPath, experiment, true)
	var first udpbenchproof.Decision
	readCLIJSON(t, finalistPath, &first)
	if !first.Passed || !first.RerunRequired || first.Stage != udpbenchproof.StageFinalist {
		t.Fatalf("first finalist did not provisionally authorize one rerun: %#v", first)
	}
	assertImmutableCLIOutput(t, filepath.Join(dir, "rerun-schedule.json"), func(out string) []string {
		return []string{"schedule", "-stage", "finalist-rerun", "-manifest", manifestPath, "-manifest-sha256", string(cliCanonicalDigest(t, experiment)), "-prior", finalistPath, "-out", out}
	})
	priorRefs, err := loadCanonicalJSONL[udpbenchproof.ArtifactRef](filepath.Join(dir, "peak-finalist.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	rrerunSchedule := experiment.ManifestInput.Schedules[3]
	rrerunSamples := make([]udpbenchproof.Sample, len(rrerunSchedule.RunIDs))
	finalistRef := udpbenchproof.ArtifactRef{Role: "finalist", Path: "decisions/finalist.json", SHA256: finalistDigest}
	for index := range rrerunSamples {
		goodput := 2200.0
		if rrerunSchedule.CandidateOrder[index] == "control" {
			goodput = 2150
		}
		rrerunSamples[index] = cliSampleForSchedule(t, dir, experiment, 3, index, goodput)
		rrerunSamples[index].Run.PriorDecisionRef = finalistRef
	}
	rrerunRefs := writeCLISampleArtifacts(t, dir, "rerun", rrerunSamples)
	results := writeCLIJSONL(t, dir, "rerun.jsonl", append(priorRefs, rrerunRefs...))
	out := filepath.Join(dir, "decisions", "finalist-rerun.json")
	if err := run([]string{"evaluate", "-stage", "finalist-rerun", "-manifest", manifestPath, "-prior", finalistPath, "-results", results, "-out", out}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("finalist-rerun CLI: %v", err)
	}
	var rerun udpbenchproof.Decision
	readCLIJSON(t, out, &rerun)
	if !rerun.Passed || rerun.Stage != udpbenchproof.StageFinalistRerun || rerun.SelectedCandidate != first.SelectedCandidate {
		t.Fatalf("completed rerun decision = %#v", rerun)
	}
}

type cliFleetProbeRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	HostID        string `json:"host_id"`
	Phase         string `json:"phase"`
	Available     bool   `json:"available"`
	ObservedAtUTC string `json:"observed_at_utc"`
}

func assertImmutableCLIOutput(t *testing.T, path string, command func(string) []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run(command(path), &stdout, &stderr); err != nil {
		t.Fatalf("%s: %v (stderr %q)", command(path)[0], err, stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != string(udpbenchproof.DigestBytes(data))+"\n" || stderr.Len() != 0 {
		t.Fatalf("%s output = %q / %q", command(path)[0], stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := run(command(path), &stdout, &stderr); err == nil {
		t.Fatalf("%s replaced immutable output", command(path)[0])
	}
	if stdout.Len() != 0 {
		t.Fatalf("%s failure printed success: %q", command(path)[0], stdout.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, after) {
		t.Fatalf("%s changed immutable output", command(path)[0])
	}
}

func mustCLIManifest(t *testing.T, input udpbenchproof.ManifestInput) udpbenchproof.Manifest {
	t.Helper()
	manifest, err := udpbenchproof.NewManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeCLIJSON(t *testing.T, dir, name string, value any) (string, udpbenchproof.SHA256Digest) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, udpbenchproof.DigestBytes(data)
}

func writeCLIJSONL[T any](t *testing.T, dir, name string, values []T) string {
	t.Helper()
	var data []byte
	for _, value := range values {
		line, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, line...)
		data = append(data, '\n')
	}
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLISampleRefs(t *testing.T, dir, name string, samples []udpbenchproof.Sample) string {
	t.Helper()
	prefix := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
	refs := writeCLISampleArtifacts(t, dir, prefix, samples)
	return writeCLIJSONL(t, dir, name, refs)
}

func writeCLISampleArtifacts(t *testing.T, dir, prefix string, samples []udpbenchproof.Sample) []udpbenchproof.ArtifactRef {
	t.Helper()
	refs := make([]udpbenchproof.ArtifactRef, 0, len(samples))
	for _, sample := range samples {
		relative := filepath.ToSlash(filepath.Join("samples", prefix+"-"+sample.Run.ID+".json"))
		_, digest := writeCLIJSON(t, dir, relative, sample)
		refs = append(refs, udpbenchproof.ArtifactRef{Role: "sample", Path: relative, SHA256: digest})
	}
	return refs
}

func readCLIJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func cliProductionInput(t *testing.T, parent udpbenchproof.Manifest, localBin, linuxBin string) udpbenchproof.ManifestInput {
	t.Helper()
	input := cloneCLIInput(t, parent.ManifestInput)
	input.Kind = udpbenchproof.ManifestProduction
	parentDigest := cliCanonicalDigest(t, parent)
	input.ParentManifest = &udpbenchproof.ArtifactRef{Role: "manifest", Path: "manifest.json", SHA256: parentDigest}
	input.ParentDecisionRefs = []udpbenchproof.ArtifactRef{{Role: "finalist", Path: "decisions/finalist.json", SHA256: stringsDigest('b')}}
	input.Payload = udpbenchproof.PayloadIdentity{Bytes: 1 << 30, SHA256: stringsDigest('c')}
	candidate := input.Candidates[0]
	candidate.ID = "production"
	candidate.Commit = strings.Repeat("7", 40)
	candidate.Darwin.VCSRevision = candidate.Commit
	candidate.Linux.VCSRevision = candidate.Commit
	candidate.Config = map[string]string{"mode": "source-default"}
	localDigest, err := udpbenchproof.FileDigest(localBin)
	if err != nil {
		t.Fatal(err)
	}
	linuxDigest, err := udpbenchproof.FileDigest(linuxBin)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Darwin.SHA256 = localDigest
	candidate.Linux.SHA256 = linuxDigest
	input.Candidates = []udpbenchproof.CandidateIdentity{candidate}
	input.Schedules = cliRepeatedSchedule("production", candidate.ID, "prod", 3)
	input.Schedules = append(input.Schedules, cliFleetSchedule(input, candidate.ID))
	bindCLIBaseline(t, &input, 2, "2026-07-16T00:01:00Z")
	return input
}

func cliAcceptanceInput(t *testing.T, parent udpbenchproof.Manifest, prerequisite, fleet udpbenchproof.SHA256Digest) udpbenchproof.ManifestInput {
	t.Helper()
	input := cloneCLIInput(t, parent.ManifestInput)
	input.Kind = udpbenchproof.ManifestAcceptance
	input.ParentManifest = &udpbenchproof.ArtifactRef{Role: "manifest", Path: "production-manifest.json", SHA256: cliCanonicalDigest(t, parent)}
	input.ParentDecisionRefs = []udpbenchproof.ArtifactRef{
		{Role: "prerequisite", Path: "decisions/prerequisite.json", SHA256: prerequisite},
		{Role: "fleet", Path: "decisions/fleet.json", SHA256: fleet},
	}
	input.Payload = udpbenchproof.PayloadIdentity{Bytes: 3 << 30, SHA256: stringsDigest('f')}
	input.Schedules = cliRepeatedSchedule("acceptance", input.Candidates[0].ID, "accept", 3)
	bindCLIBaseline(t, &input, 3, "2026-07-16T00:02:00Z")
	return input
}

func cliCeilingInput(t *testing.T, parent udpbenchproof.Manifest, peak, fleet udpbenchproof.SHA256Digest) udpbenchproof.ManifestInput {
	t.Helper()
	input := cloneCLIInput(t, parent.ManifestInput)
	input.Kind = udpbenchproof.ManifestCeiling
	input.ParentManifest = &udpbenchproof.ArtifactRef{Role: "manifest", Path: "production-manifest.json", SHA256: cliCanonicalDigest(t, parent)}
	input.ParentDecisionRefs = []udpbenchproof.ArtifactRef{
		{Role: "peak", Path: "decisions/peak.json", SHA256: peak},
		{Role: "fleet", Path: "decisions/fleet.json", SHA256: fleet},
	}
	diagnostic := input.Candidates[0]
	diagnostic.ID = "diagnostic"
	diagnostic.Darwin.SHA256 = stringsDigest('d')
	diagnostic.Linux.SHA256 = stringsDigest('e')
	diagnostic.Config = map[string]string{"mode": "diagnostic"}
	input.Candidates = []udpbenchproof.CandidateIdentity{diagnostic}
	input.Schedules = cliCeilingSchedules(diagnostic.ID)
	bindCLIBaseline(t, &input, 3, "2026-07-16T00:02:00Z")
	return input
}

func cloneCLIInput(t *testing.T, input udpbenchproof.ManifestInput) udpbenchproof.ManifestInput {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var result udpbenchproof.ManifestInput
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func cliRepeatedSchedule(stage, candidate, prefix string, repetitions int) []udpbenchproof.FrozenSchedule {
	schedule := udpbenchproof.FrozenSchedule{Stage: stage, Repetitions: repetitions}
	for _, item := range []struct{ short, direction string }{{"h2m", "hetz-to-mac"}, {"m2h", "mac-to-hetz"}} {
		for repetition := 1; repetition <= repetitions; repetition++ {
			schedule.RunIDs = append(schedule.RunIDs, fmt.Sprintf("%s-%s-%d", prefix, item.short, repetition))
			schedule.CandidateOrder = append(schedule.CandidateOrder, candidate)
			schedule.DirectionOrder = append(schedule.DirectionOrder, item.direction)
			schedule.HostOrder = append(schedule.HostOrder, "primary")
			schedule.BlockOrder = append(schedule.BlockOrder, repetition-1)
			schedule.RunRoles = append(schedule.RunRoles, "file")
		}
	}
	return []udpbenchproof.FrozenSchedule{schedule}
}

func cliFleetSchedule(input udpbenchproof.ManifestInput, candidate string) udpbenchproof.FrozenSchedule {
	schedule := udpbenchproof.FrozenSchedule{Stage: "fleet", Repetitions: 3}
	for _, host := range input.FleetInventory {
		if host.Role == udpbenchproof.HostRolePrimary {
			continue
		}
		for _, item := range []struct{ short, direction string }{{"h2m", "hetz-to-mac"}, {"m2h", "mac-to-hetz"}} {
			for repetition := 1; repetition <= schedule.Repetitions; repetition++ {
				schedule.RunIDs = append(schedule.RunIDs, fmt.Sprintf("fleet-%s-%s-%d", host.ID, item.short, repetition))
				schedule.CandidateOrder = append(schedule.CandidateOrder, candidate)
				schedule.DirectionOrder = append(schedule.DirectionOrder, item.direction)
				schedule.HostOrder = append(schedule.HostOrder, host.ID)
				schedule.BlockOrder = append(schedule.BlockOrder, repetition-1)
				schedule.RunRoles = append(schedule.RunRoles, "file")
			}
		}
	}
	return schedule
}

func cliCeilingSchedules(candidate string) []udpbenchproof.FrozenSchedule {
	loadsUp := []float64{1200, 1500, 1800, 2100, 2400}
	loadsDown := []float64{2400, 2100, 1800, 1500, 1200}
	var schedules []udpbenchproof.FrozenSchedule
	for _, item := range []struct {
		stage, direction string
		loads            []float64
	}{
		{"ceiling-sweep-ascending-hetz-to-mac", "hetz-to-mac", loadsUp},
		{"ceiling-sweep-descending-hetz-to-mac", "hetz-to-mac", loadsDown},
		{"ceiling-sweep-ascending-mac-to-hetz", "mac-to-hetz", loadsUp},
		{"ceiling-sweep-descending-mac-to-hetz", "mac-to-hetz", loadsDown},
	} {
		schedule := udpbenchproof.FrozenSchedule{Stage: item.stage, OfferedLoadMbps: item.loads, Repetitions: 1}
		for index := range item.loads {
			schedule.RunIDs = append(schedule.RunIDs, fmt.Sprintf("%s-%d", item.stage, index+1))
			schedule.CandidateOrder = append(schedule.CandidateOrder, candidate)
			schedule.DirectionOrder = append(schedule.DirectionOrder, item.direction)
			schedule.HostOrder = append(schedule.HostOrder, "primary")
			schedule.BlockOrder = append(schedule.BlockOrder, index)
			schedule.RunRoles = append(schedule.RunRoles, "ceiling-sweep")
		}
		schedules = append(schedules, schedule)
	}
	schedules = append(schedules, udpbenchproof.FrozenSchedule{
		Stage: "ceiling-profile", RunIDs: []string{"profile-h2m-1", "profile-h2m-2", "profile-m2h-1", "profile-m2h-2"},
		CandidateOrder: []string{candidate, candidate, candidate, candidate},
		DirectionOrder: []string{"hetz-to-mac", "hetz-to-mac", "mac-to-hetz", "mac-to-hetz"},
		HostOrder:      []string{"primary", "primary", "primary", "primary"},
		BlockOrder:     []int{0, 1, 0, 1},
		RunRoles:       []string{"ceiling-profile", "ceiling-profile", "ceiling-profile", "ceiling-profile"}, Repetitions: 2,
	})
	return schedules
}

func bindCLIBaseline(t *testing.T, input *udpbenchproof.ManifestInput, sequence uint64, captured string) {
	t.Helper()
	record := udpbenchproof.BaselineHealthRecord{
		SchemaVersion: 1,
		Kind:          input.Kind,
		CapturedAtUTC: captured,
		Sequence:      sequence,
		HostID:        "primary",
		BootID:        input.RemoteBootID,
		Counters:      input.BaselineHealthCounters,
	}
	digest := cliCanonicalDigest(t, record)
	input.BaselineHealthIdentity = udpbenchproof.BaselineHealthIdentity{
		Artifact:      udpbenchproof.ArtifactRef{Role: "baseline-" + string(input.Kind), Path: "baselines/" + string(input.Kind) + ".json", SHA256: digest},
		CapturedAtUTC: captured,
		Sequence:      sequence,
		HostID:        "primary",
		BootID:        input.RemoteBootID,
	}
}

func cliCanonicalDigest(t *testing.T, value any) udpbenchproof.SHA256Digest {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return udpbenchproof.DigestBytes(append(data, '\n'))
}

func stringsDigest(value byte) udpbenchproof.SHA256Digest {
	return udpbenchproof.SHA256Digest(strings.Repeat(string(value), 64))
}

func cliHealthSnapshot() udpbenchproof.HealthSnapshot {
	return udpbenchproof.HealthSnapshot{
		Platform: "darwin",
		BootID:   "boot-a", UptimeSeconds: 100, OnlineCPUs: 2,
		AvailableMemoryBytes: 2 << 30, DiskFreeBytes: 10 << 30,
		InterfaceCounters: []udpbenchproof.NamedCounter{{Name: "input_errors"}, {Name: "output_errors"}},
		UDPCounters:       []udpbenchproof.NamedCounter{{Name: "bad_checksum"}, {Name: "bad_data_length"}, {Name: "full_socket_buffers"}, {Name: "incomplete_header"}, {Name: "no_socket"}},
		SoftnetCounters:   []udpbenchproof.NamedCounter{{Name: "row:0"}}, Cgroups: []udpbenchproof.CgroupHealth{},
		CleanupScope: udpbenchproof.CleanupScope{Declared: true, Processes: []udpbenchproof.ProcessRef{}, Cgroups: []udpbenchproof.CgroupRef{}},
		KernelErrors: []string{}, Processes: []udpbenchproof.ProcessRef{}, Sockets: []udpbenchproof.SocketRef{},
		CounterFamilies: []string{
			"uptime", "online-cpus", "global-oom", "cgroup-oom", "memory", "swap", "disk",
			"kernel", "interface", "udp", "softnet", "process", "socket",
		},
	}
}

func writeCanonicalCLIJSON(t *testing.T, dir, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertCLICanonicalArtifactDigest(t *testing.T, path, stdout string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertCLICanonicalFile(t, path)
	if stdout != string(udpbenchproof.DigestBytes(data))+"\n" {
		t.Fatalf("stdout = %q, want exact digest", stdout)
	}
}

func assertCLICanonicalFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Contains(data[:len(data)-1], []byte{'\n'}) {
		t.Fatalf("artifact is not one-line canonical JSON: %q", data)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data[:len(data)-1]); err != nil {
		t.Fatalf("artifact JSON: %v", err)
	}
	if !bytes.Equal(data[:len(data)-1], compact.Bytes()) {
		t.Fatalf("artifact bytes are not canonical: %q", data)
	}
}

func cliSample(t *testing.T, dir string, manifest udpbenchproof.Manifest, index int, goodput float64) udpbenchproof.Sample {
	t.Helper()
	return cliSampleForSchedule(t, dir, manifest, 0, index, goodput)
}

func cliSampleForSchedule(t *testing.T, dir string, manifest udpbenchproof.Manifest, scheduleIndex, index int, goodput float64) udpbenchproof.Sample {
	t.Helper()
	schedule := manifest.ManifestInput.Schedules[scheduleIndex]
	if len(schedule.RunIDs) <= index {
		t.Fatalf("schedule index %d out of range", index)
	}
	candidateID := schedule.CandidateOrder[index]
	var candidate udpbenchproof.CandidateIdentity
	for _, item := range manifest.ManifestInput.Candidates {
		if item.ID == candidateID {
			candidate = item
			break
		}
	}
	direction := udpbenchproof.DirectionRemoteToLocal
	if schedule.DirectionOrder[index] == "mac-to-hetz" {
		direction = udpbenchproof.DirectionLocalToRemote
	}
	run := udpbenchproof.ScheduledRun{
		ID:               schedule.RunIDs[index],
		Stage:            udpbenchproof.Stage(schedule.Stage),
		CandidateID:      candidate.ID,
		HostID:           schedule.HostOrder[index],
		Direction:        direction,
		SizeBytes:        manifest.ManifestInput.Payload.Bytes,
		Order:            index + 1,
		CapacityRequired: true,
		Block:            schedule.BlockOrder[index],
		Schedule:         schedule.Stage,
		Role:             schedule.RunRoles[index],
	}
	for _, ref := range manifest.ManifestInput.ParentDecisionRefs {
		if manifest.ManifestInput.Kind == udpbenchproof.ManifestProduction && ref.Role == "finalist" ||
			manifest.ManifestInput.Kind == udpbenchproof.ManifestAcceptance && ref.Role == "fleet" {
			run.PriorDecisionRef = ref
		}
	}
	prefix := "evidence/" + run.ID
	sample := udpbenchproof.Sample{
		SchemaVersion:   1,
		ManifestSHA256:  cliCanonicalDigest(t, manifest),
		CandidateID:     candidate.ID,
		BinarySet:       udpbenchproof.BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux},
		Run:             run,
		ObservedAtUTC:   fmt.Sprintf("2026-07-16T01:00:%02dZ", index),
		GoodputMbps:     goodput,
		WallGoodputMbps: goodput - 10,
		RecoveryRatio:   0.01,
		ScanPerPacket:   1,
		FlatlineSeconds: 0.2,
		Started:         true,
	}
	sample.Payload = udpbenchproof.PayloadEvidence{
		SourceSHA256:     manifest.ManifestInput.Payload.SHA256,
		SinkSHA256:       manifest.ManifestInput.Payload.SHA256,
		SourceSHAReports: 1,
		SinkSHAReports:   1,
		SinkSizeBytes:    manifest.ManifestInput.Payload.Bytes,
	}
	sourceHost := run.HostID
	receiverHost := "local-mac"
	if run.Direction == udpbenchproof.DirectionLocalToRemote {
		sourceHost = "local-mac"
		receiverHost = run.HostID
	}
	sample.Payload.SourceHashArtifact = cliEvidenceRef(t, dir, "source-sha", prefix+"-source.json", cliHashEvidence{
		SchemaVersion: 1, Kind: "hash-observation", RunID: run.ID, ObserverHostID: sourceHost, ObserverRole: "source",
		SHA256: sample.Payload.SourceSHA256, Reports: 1,
	})
	sample.Payload.SinkHashArtifact = cliEvidenceRef(t, dir, "sink-sha", prefix+"-sink.json", cliHashEvidence{
		SchemaVersion: 1, Kind: "hash-observation", RunID: run.ID, ObserverHostID: receiverHost, ObserverRole: "sink",
		SHA256: sample.Payload.SinkSHA256, Reports: 1,
	})
	sample.Payload.SinkSizeArtifact = cliEvidenceRef(t, dir, "sink-size", prefix+"-size.json", cliSizeEvidence{1, "size", run.ID, sample.Payload.SinkSizeBytes})
	sample.Capacity = udpbenchproof.CapacityEvidence{Direction: direction, Mbps: 2200, Valid: true}
	sample.Capacity.Artifact = cliEvidenceRef(t, dir, "capacity", prefix+"-capacity.json", cliCapacityEvidence{1, "capacity", run.ID, direction, 2200, true})
	sample.Trace = udpbenchproof.TraceEvidence{Engine: "bulk-packets-v1", PublicUDP: true, StrictValid: true}
	sample.Trace.Sender = cliEvidenceRef(t, dir, "trace-sender", prefix+"-trace-sender.json", cliTraceEvidence{1, "trace", run.ID, "sender", direction, sample.Trace.Engine, true, true})
	sample.Trace.Receiver = cliEvidenceRef(t, dir, "trace-receiver", prefix+"-trace-receiver.json", cliTraceEvidence{1, "trace", run.ID, "receiver", direction, sample.Trace.Engine, true, true})
	sample.Resource = udpbenchproof.ResourceEvidence{SenderUserSeconds: 2, SenderSystemSeconds: 2, ReceiverUserSeconds: 2, ReceiverSystemSeconds: 2}
	sample.Resource.Sender = cliEvidenceRef(t, dir, "resource-sender", prefix+"-resource-sender.json", cliResourceEvidence{1, "resource", run.ID, "sender", 2, 2})
	sample.Resource.Receiver = cliEvidenceRef(t, dir, "resource-receiver", prefix+"-resource-receiver.json", cliResourceEvidence{1, "resource", run.ID, "receiver", 2, 2})
	sample.Health = udpbenchproof.HealthEvidence{Healthy: true}
	sample.Health.Before = cliEvidenceRef(t, dir, "health-before", prefix+"-health-before.json", cliHealthEvidence{1, "health", run.ID, "before", true})
	sample.Health.After = cliEvidenceRef(t, dir, "health-after", prefix+"-health-after.json", cliHealthEvidence{1, "health", run.ID, "after", true})
	sample.Cleanup = udpbenchproof.CleanupEvidence{ScopedRootRemoved: true, ProcessesRemoved: true, SocketsRemoved: true, PayloadsRemoved: true}
	sample.Cleanup.Artifact = cliEvidenceRef(t, dir, "cleanup", prefix+"-cleanup.json", cliCleanupEvidence{1, "cleanup", run.ID, true, true, true, true})
	sample.ReceiverResult = cliEvidenceRef(t, dir, "receiver-result", prefix+"-receiver-result.json", cliReceiverResultEvidence{
		SchemaVersion: 1, Kind: "file-result", RunID: run.ID, ObserverRole: "receiver", ObserverHostID: receiverHost,
		CommittedBytes: run.SizeBytes, PayloadSeconds: cliSecondsForMbps(run.SizeBytes, sample.GoodputMbps),
		WallSeconds: cliSecondsForMbps(run.SizeBytes, sample.WallGoodputMbps), MaxFlatlineSeconds: sample.FlatlineSeconds,
		Started: sample.Started, ObservedAtUTC: sample.ObservedAtUTC,
	})
	sample.MechanismResult = cliEvidenceRef(t, dir, "mechanism-result", prefix+"-mechanism-result.json", cliMechanismResultEvidence{
		SchemaVersion: 1, Kind: "mechanism-result", RunID: run.ID, ObserverRole: "receiver", ObserverHostID: receiverHost,
		Engine: sample.Trace.Engine, PublicUDP: sample.Trace.PublicUDP, StrictValid: sample.Trace.StrictValid,
		RecoveredUnits: 1, TotalUnits: 100, ScanChecks: 100, PayloadPackets: 100,
	})
	return sample
}

func cliSecondsForMbps(sizeBytes int64, mbps float64) float64 {
	return float64(sizeBytes) * 8 / (mbps * 1e6)
}

func cliEvidenceRef(t *testing.T, dir, role, path string, value any) udpbenchproof.ArtifactRef {
	t.Helper()
	_, digest := writeCLIJSON(t, dir, path, value)
	return udpbenchproof.ArtifactRef{Role: role, Path: path, SHA256: digest}
}

func cliCeilingSweeps() []udpbenchproof.CeilingSweepPoint {
	offered := []float64{1.2, 1.5, 1.8, 2.1, 2.4}
	delivered := []float64{1.15, 1.38, 1.42, 1.44, 1.44}
	loss := []float64{0.01, 0.04, 0.18, 0.31, 0.40}
	var result []udpbenchproof.CeilingSweepPoint
	ref := 1
	for _, direction := range []udpbenchproof.Direction{udpbenchproof.DirectionRemoteToLocal, udpbenchproof.DirectionLocalToRemote} {
		for _, order := range []string{"ascending", "descending"} {
			for index := range offered {
				point := index
				if order == "descending" {
					point = len(offered) - 1 - index
				}
				result = append(result, udpbenchproof.CeilingSweepPoint{
					Direction: direction, Order: order, Sequence: index + 1, ObservedAtUTC: time.Date(2026, 7, 16, 3, 0, ref*3, 0, time.UTC).Format(time.RFC3339), OfferedGbps: offered[point], DeliveredGbps: delivered[point], LossRatio: loss[point], QueuePressure: loss[point],
					CapacityMbps: 2200, DatagramBytes: 1400, PublicUDP: true, Healthy: true,
					CounterFamilies: []string{"cpu", "interface", "softnet", "udp"},
					Capacity:        cliNumberedRef("capacity", fmt.Sprintf("capacity-before-%d.json", ref), ref),
					CapacityAfter:   cliNumberedRef("capacity", fmt.Sprintf("capacity-after-%d.json", ref), ref+1000),
					UDPResult:       cliNumberedRef("udp-result", fmt.Sprintf("udp-%d.json", ref), ref+100),
					Health:          cliNumberedRef("health", fmt.Sprintf("health-%d.json", ref), ref+200),
				})
				ref++
			}
		}
	}
	return result
}

func cliCeilingProfiles() []udpbenchproof.CeilingProfile {
	var result []udpbenchproof.CeilingProfile
	index := 400
	for _, direction := range []udpbenchproof.Direction{udpbenchproof.DirectionLocalToRemote, udpbenchproof.DirectionRemoteToLocal} {
		for range 2 {
			result = append(result, udpbenchproof.CeilingProfile{
				Direction: direction, Artifact: cliNumberedRef("ceiling-profile", fmt.Sprintf("profile-%d.json", index), index),
				HetzCPUUtilization: 0.95, KernelPacketCPUUtilization: 0.92, LimitingMechanism: "kernel-packet-processing", Independent: true,
				CounterFamilies: []string{"cpu", "interface", "softnet", "udp"},
			})
			index++
		}
	}
	return result
}

func bindCLICeilingRawArtifacts(t *testing.T, dir string, manifest udpbenchproof.Manifest, sweeps []udpbenchproof.CeilingSweepPoint, profiles []udpbenchproof.CeilingProfile) {
	t.Helper()
	for index := range sweeps {
		point := &sweeps[index]
		bindCLICeilingSweepIdentity(t, manifest, point)
		pointTime, err := time.Parse(time.RFC3339, point.ObservedAtUTC)
		if err != nil {
			t.Fatal(err)
		}
		point.Capacity = cliEvidenceRef(t, dir, "capacity", point.Capacity.Path, cliCeilingCapacityRecord{1, "capacity", "before", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps, point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, pointTime.Add(-time.Second).Format(time.RFC3339)})
		point.CapacityAfter = cliEvidenceRef(t, dir, "capacity", point.CapacityAfter.Path, cliCeilingCapacityRecord{1, "capacity", "after", point.Direction, point.Order, point.OfferedGbps, point.CapacityMbps, point.CapacityTCPPort, point.CapacityParallelFlows, point.CapacityDurationSeconds, pointTime.Add(time.Second).Format(time.RFC3339)})
		point.UDPResult = cliEvidenceRef(t, dir, "udp-result", point.UDPResult.Path, cliCeilingUDPResultRecord{1, "udp-result", point.Direction, point.Order, point.OfferedGbps, point.DeliveredGbps, point.LossRatio, point.QueuePressure, point.DatagramBytes, point.PublicUDP, point.CounterFamilies})
		point.Health = cliEvidenceRef(t, dir, "health", point.Health.Path, cliCeilingHealthRecord{1, "health", point.Direction, point.Order, point.OfferedGbps, point.Healthy})
		point.Artifact = cliEvidenceRef(t, dir, "ceiling-sweep", fmt.Sprintf("sweep-point-%d.json", index+1), cliCeilingSweepPointRecord{1, "ceiling-sweep", *point})
	}
	for index := range profiles {
		profile := &profiles[index]
		bindCLICeilingProfileIdentity(t, manifest, profile, index)
		bindCLICeilingProfileToSweep(t, profile, sweeps, index%2)
		profile.Artifact = cliEvidenceRef(t, dir, "ceiling-profile", profile.Artifact.Path, cliCeilingProfileRecord{
			SchemaVersion: 1, Kind: "ceiling-profile", RunID: profile.RunID, HostID: profile.HostID, CandidateID: profile.CandidateID,
			BinarySet: profile.BinarySet, ObservedAtUTC: profile.ObservedAtUTC, Direction: profile.Direction, OfferedGbps: profile.OfferedGbps,
			SweepPoint: profile.SweepPoint, HetzCPUUtilization: profile.HetzCPUUtilization, KernelPacketCPUUtilization: profile.KernelPacketCPUUtilization,
			LimitingMechanism: profile.LimitingMechanism, Independent: profile.Independent, CounterFamilies: profile.CounterFamilies,
		})
	}
}

func bindCLICeilingProfileToSweep(t *testing.T, profile *udpbenchproof.CeilingProfile, sweeps []udpbenchproof.CeilingSweepPoint, repetition int) {
	t.Helper()
	wantLoad := []float64{1.5, 1.8}[repetition]
	for _, point := range sweeps {
		if point.Direction != profile.Direction || point.Order != "ascending" || point.OfferedGbps != wantLoad {
			continue
		}
		profile.HostID = point.HostID
		profile.CandidateID = point.CandidateID
		profile.BinarySet = point.BinarySet
		profile.ObservedAtUTC = point.ObservedAtUTC
		profile.OfferedGbps = point.OfferedGbps
		profile.SweepPoint = point.Artifact
		profile.CounterFamilies = append([]string(nil), point.CounterFamilies...)
		return
	}
	t.Fatalf("missing CLI plateau point for direction %s load %.1f", profile.Direction, wantLoad)
}

func bindCLICeilingSweepIdentity(t *testing.T, manifest udpbenchproof.Manifest, point *udpbenchproof.CeilingSweepPoint) {
	t.Helper()
	direction := "hetz-to-mac"
	if point.Direction == udpbenchproof.DirectionLocalToRemote {
		direction = "mac-to-hetz"
	}
	stage := "ceiling-sweep-" + point.Order + "-" + direction
	for _, schedule := range manifest.ManifestInput.Schedules {
		if schedule.Stage != stage {
			continue
		}
		index := point.Sequence - 1
		point.RunID = schedule.RunIDs[index]
		point.HostID = schedule.HostOrder[index]
		point.CandidateID = schedule.CandidateOrder[index]
		point.BinarySet = cliCandidateBinarySet(t, manifest, point.CandidateID)
		point.CapacityTCPPort = manifest.ManifestInput.CapacityTCPPort
		point.CapacityParallelFlows = 8
		point.CapacityDurationSeconds = 20
		return
	}
	t.Fatalf("missing CLI ceiling schedule %s", stage)
}

func bindCLICeilingProfileIdentity(t *testing.T, manifest udpbenchproof.Manifest, profile *udpbenchproof.CeilingProfile, index int) {
	t.Helper()
	schedule := manifest.ManifestInput.Schedules[len(manifest.ManifestInput.Schedules)-1]
	row := index + 2
	if profile.Direction == udpbenchproof.DirectionRemoteToLocal {
		row = index - 2
	}
	profile.RunID = schedule.RunIDs[row]
	profile.HostID = schedule.HostOrder[row]
	profile.CandidateID = schedule.CandidateOrder[row]
	profile.BinarySet = cliCandidateBinarySet(t, manifest, profile.CandidateID)
	profile.ObservedAtUTC = time.Date(2026, 7, 16, 4, 0, index+1, 0, time.UTC).Format(time.RFC3339)
}

func cliCandidateBinarySet(t *testing.T, manifest udpbenchproof.Manifest, id string) udpbenchproof.BinarySet {
	t.Helper()
	for _, candidate := range manifest.ManifestInput.Candidates {
		if candidate.ID == id {
			return udpbenchproof.BinarySet{Darwin: candidate.Darwin, Linux: candidate.Linux}
		}
	}
	t.Fatalf("missing CLI candidate %s", id)
	return udpbenchproof.BinarySet{}
}

func cliCeilingSweepRefs(sweeps []udpbenchproof.CeilingSweepPoint) []udpbenchproof.ArtifactRef {
	refs := make([]udpbenchproof.ArtifactRef, len(sweeps))
	for index := range sweeps {
		refs[index] = sweeps[index].Artifact
	}
	return refs
}

func cliCeilingProfileRefs(profiles []udpbenchproof.CeilingProfile) []udpbenchproof.ArtifactRef {
	refs := make([]udpbenchproof.ArtifactRef, len(profiles))
	for index := range profiles {
		refs[index] = profiles[index].Artifact
	}
	return refs
}

type cliCeilingSweepPointRecord struct {
	SchemaVersion int                             `json:"schema_version"`
	Kind          string                          `json:"kind"`
	Point         udpbenchproof.CeilingSweepPoint `json:"point"`
}

type cliCeilingCapacityRecord struct {
	SchemaVersion   int                     `json:"schema_version"`
	Kind            string                  `json:"kind"`
	Phase           string                  `json:"phase"`
	Direction       udpbenchproof.Direction `json:"direction"`
	Order           string                  `json:"order"`
	OfferedGbps     float64                 `json:"offered_gbps"`
	Mbps            float64                 `json:"mbps"`
	TCPPort         int                     `json:"tcp_port"`
	ParallelFlows   int                     `json:"parallel_flows"`
	DurationSeconds int                     `json:"duration_seconds"`
	ObservedAtUTC   string                  `json:"observed_at_utc"`
}

type cliCeilingUDPResultRecord struct {
	SchemaVersion   int                     `json:"schema_version"`
	Kind            string                  `json:"kind"`
	Direction       udpbenchproof.Direction `json:"direction"`
	Order           string                  `json:"order"`
	OfferedGbps     float64                 `json:"offered_gbps"`
	DeliveredGbps   float64                 `json:"delivered_gbps"`
	LossRatio       float64                 `json:"loss_ratio"`
	QueuePressure   float64                 `json:"queue_pressure"`
	DatagramBytes   int                     `json:"datagram_bytes"`
	PublicUDP       bool                    `json:"public_udp"`
	CounterFamilies []string                `json:"counter_families"`
}

type cliCeilingHealthRecord struct {
	SchemaVersion int                     `json:"schema_version"`
	Kind          string                  `json:"kind"`
	Direction     udpbenchproof.Direction `json:"direction"`
	Order         string                  `json:"order"`
	OfferedGbps   float64                 `json:"offered_gbps"`
	Healthy       bool                    `json:"healthy"`
}

type cliCeilingProfileRecord struct {
	SchemaVersion              int                       `json:"schema_version"`
	Kind                       string                    `json:"kind"`
	RunID                      string                    `json:"run_id"`
	HostID                     string                    `json:"host_id"`
	CandidateID                string                    `json:"candidate_id"`
	BinarySet                  udpbenchproof.BinarySet   `json:"binary_set"`
	ObservedAtUTC              string                    `json:"observed_at_utc"`
	Direction                  udpbenchproof.Direction   `json:"direction"`
	OfferedGbps                float64                   `json:"offered_gbps"`
	SweepPoint                 udpbenchproof.ArtifactRef `json:"sweep_point"`
	HetzCPUUtilization         float64                   `json:"hetz_cpu_utilization"`
	KernelPacketCPUUtilization float64                   `json:"kernel_packet_cpu_utilization"`
	LimitingMechanism          string                    `json:"limiting_mechanism"`
	Independent                bool                      `json:"independent"`
	CounterFamilies            []string                  `json:"counter_families"`
}

func cliExactCeilingWinnerRefs(t *testing.T, root string, peak udpbenchproof.Decision, prerequisite udpbenchproof.PrerequisiteDecision) []udpbenchproof.ArtifactRef {
	t.Helper()
	refs := append([]udpbenchproof.ArtifactRef(nil), prerequisite.Samples...)
	for _, ref := range peak.SampleRefs {
		sample, err := udpbenchproof.LoadSampleArtifact(root, ref)
		if err != nil {
			t.Fatal(err)
		}
		if sample.Run.CandidateID == peak.SelectedCandidate {
			refs = append(refs, ref)
		}
	}
	return refs
}

func cliNumberedRef(role, path string, number int) udpbenchproof.ArtifactRef {
	return udpbenchproof.ArtifactRef{Role: role, Path: path, SHA256: udpbenchproof.SHA256Digest(fmt.Sprintf("%064x", number))}
}

type cliHashEvidence struct {
	SchemaVersion  int                        `json:"schema_version"`
	Kind           string                     `json:"kind"`
	RunID          string                     `json:"run_id"`
	ObserverHostID string                     `json:"observer_host_id"`
	ObserverRole   string                     `json:"observer_role"`
	SHA256         udpbenchproof.SHA256Digest `json:"sha256"`
	Reports        int                        `json:"reports"`
}

type cliSizeEvidence struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	RunID         string `json:"run_id"`
	SizeBytes     int64  `json:"size_bytes"`
}

type cliCapacityEvidence struct {
	SchemaVersion int                     `json:"schema_version"`
	Kind          string                  `json:"kind"`
	RunID         string                  `json:"run_id"`
	Direction     udpbenchproof.Direction `json:"direction"`
	Mbps          float64                 `json:"mbps"`
	Valid         bool                    `json:"valid"`
}

type cliTraceEvidence struct {
	SchemaVersion int                     `json:"schema_version"`
	Kind          string                  `json:"kind"`
	RunID         string                  `json:"run_id"`
	Role          string                  `json:"role"`
	Direction     udpbenchproof.Direction `json:"direction"`
	Engine        string                  `json:"engine"`
	PublicUDP     bool                    `json:"public_udp"`
	StrictValid   bool                    `json:"strict_valid"`
}

type cliResourceEvidence struct {
	SchemaVersion int     `json:"schema_version"`
	Kind          string  `json:"kind"`
	RunID         string  `json:"run_id"`
	Role          string  `json:"role"`
	UserSeconds   float64 `json:"user_seconds"`
	SystemSeconds float64 `json:"system_seconds"`
}

type cliHealthEvidence struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	RunID         string `json:"run_id"`
	Phase         string `json:"phase"`
	Healthy       bool   `json:"healthy"`
}

type cliCleanupEvidence struct {
	SchemaVersion     int    `json:"schema_version"`
	Kind              string `json:"kind"`
	RunID             string `json:"run_id"`
	ScopedRootRemoved bool   `json:"scoped_root_removed"`
	ProcessesRemoved  bool   `json:"processes_removed"`
	SocketsRemoved    bool   `json:"sockets_removed"`
	PayloadsRemoved   bool   `json:"payloads_removed"`
}

type cliReceiverResultEvidence struct {
	SchemaVersion      int     `json:"schema_version"`
	Kind               string  `json:"kind"`
	RunID              string  `json:"run_id"`
	ObserverRole       string  `json:"observer_role"`
	ObserverHostID     string  `json:"observer_host_id"`
	CommittedBytes     int64   `json:"committed_bytes"`
	PayloadSeconds     float64 `json:"payload_seconds"`
	WallSeconds        float64 `json:"wall_seconds"`
	MaxFlatlineSeconds float64 `json:"max_flatline_seconds"`
	Started            bool    `json:"started"`
	ObservedAtUTC      string  `json:"observed_at_utc"`
}

type cliMechanismResultEvidence struct {
	SchemaVersion  int    `json:"schema_version"`
	Kind           string `json:"kind"`
	RunID          string `json:"run_id"`
	ObserverRole   string `json:"observer_role"`
	ObserverHostID string `json:"observer_host_id"`
	Engine         string `json:"engine"`
	PublicUDP      bool   `json:"public_udp"`
	StrictValid    bool   `json:"strict_valid"`
	RecoveredUnits int64  `json:"recovered_units"`
	TotalUnits     int64  `json:"total_units"`
	ScanChecks     int64  `json:"scan_checks"`
	PayloadPackets int64  `json:"payload_packets"`
}

func loadValidManifestInput(t *testing.T) udpbenchproof.ManifestInput {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "pkg", "udpbenchproof", "testdata", "manifest-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest udpbenchproof.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.ManifestInput
}

func writeManifestInput(t *testing.T, dir string, input udpbenchproof.ManifestInput) string {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "input.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
