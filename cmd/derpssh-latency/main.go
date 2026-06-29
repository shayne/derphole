// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
)

const defaultTimeout = 45 * time.Second

type scenarioRunner func(context.Context, string, string, string, string, int, int, int, func(sample)) ([]time.Duration, error)

type scenarioSpec struct {
	name string
	run  scenarioRunner
}

type runDeps struct {
	detectTarget func(string) (string, string, error)
	buildHelper  func(string, string, string) error
	uploadHelper func(string, string, string) error
	removeRemote func(string, string)
	now          func() time.Time
	gitCommit    func() string
	scenarios    []scenarioSpec
}

type runConfig struct {
	remote       string
	outDir       string
	samples      int
	warmup       int
	payloadBytes int
	timeout      time.Duration
	keepRemote   bool
}

type remoteTarget struct {
	goos       string
	goarch     string
	helperPath string
}

type eventLogger func(string, map[string]any)

type sample struct {
	Scenario      string `json:"scenario"`
	Seq           int    `json:"seq"`
	Warmup        bool   `json:"warmup"`
	StartedUnixNS int64  `json:"started_unix_ns"`
	DurationUS    int64  `json:"duration_us"`
	PayloadBytes  int    `json:"payload_bytes"`
}

type stats struct {
	Count  int     `json:"count"`
	MinUS  int64   `json:"min_us"`
	P50US  int64   `json:"p50_us"`
	P90US  int64   `json:"p90_us"`
	P95US  int64   `json:"p95_us"`
	P99US  int64   `json:"p99_us"`
	MaxUS  int64   `json:"max_us"`
	MeanUS float64 `json:"mean_us"`
	StdUS  float64 `json:"std_us"`
}

type summary struct {
	Remote       string             `json:"remote"`
	StartedAt    time.Time          `json:"started_at"`
	CompletedAt  time.Time          `json:"completed_at"`
	Samples      int                `json:"samples"`
	Warmup       int                `json:"warmup"`
	PayloadBytes int                `json:"payload_bytes"`
	LocalGOOS    string             `json:"local_goos"`
	LocalGOARCH  string             `json:"local_goarch"`
	RemoteGOOS   string             `json:"remote_goos"`
	RemoteGOARCH string             `json:"remote_goarch"`
	GitCommit    string             `json:"git_commit,omitempty"`
	Results      map[string]stats   `json:"results"`
	Ratios       map[string]float64 `json:"ratios"`
}

type event struct {
	At      time.Time      `json:"at"`
	Name    string         `json:"name"`
	Details map[string]any `json:"details,omitempty"`
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stderr))
}

func runCLI(args []string, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "run":
		err = run(args[1:])
	case "compare":
		err = compare(args[1:])
	case "ssh-helper":
		err = sshHelper()
	case "mux-peer":
		err = muxPeer()
	default:
		usage(stderr)
		return 2
	}
	if err != nil {
		writef(stderr, "derpssh-latency: %v\n", err)
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	writeln(w, "usage:")
	writeln(w, "  derpssh-latency run --remote ubuntu@derphole-testing --samples 200 --warmup 20 --out .tmp/latency/latest")
	writeln(w, "  derpssh-latency compare <before-dir-or-summary.json> <after-dir-or-summary.json>")
}

func writeln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func run(args []string) error {
	return runWithDeps(args, defaultRunDeps(), os.Stdout, os.Stderr)
}

func defaultRunDeps() runDeps {
	return runDeps{
		detectTarget: detectRemoteGoTarget,
		buildHelper:  buildHelper,
		uploadHelper: uploadHelper,
		removeRemote: func(remote, path string) {
			_ = remoteCommand(context.Background(), remote, "rm", "-f", path).Run()
		},
		now:       time.Now,
		gitCommit: gitCommit,
		scenarios: []scenarioSpec{
			{name: "ssh-stdio", run: runSSHStdio},
			{name: "derptun-mux-over-ssh", run: runMuxOverSSH},
		},
	}
}

func normalizeRunDeps(deps runDeps) runDeps {
	defaults := defaultRunDeps()
	if deps.detectTarget == nil {
		deps.detectTarget = defaults.detectTarget
	}
	if deps.buildHelper == nil {
		deps.buildHelper = defaults.buildHelper
	}
	if deps.uploadHelper == nil {
		deps.uploadHelper = defaults.uploadHelper
	}
	if deps.removeRemote == nil {
		deps.removeRemote = defaults.removeRemote
	}
	if deps.now == nil {
		deps.now = defaults.now
	}
	if deps.gitCommit == nil {
		deps.gitCommit = defaults.gitCommit
	}
	if deps.scenarios == nil {
		deps.scenarios = defaults.scenarios
	}
	return deps
}

func runWithDeps(args []string, deps runDeps, stdout, stderr io.Writer) error {
	deps = normalizeRunDeps(deps)
	cfg, err := parseRunConfig(args, stderr, deps.now)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.outDir, 0o755); err != nil {
		return err
	}
	logEvent, closeEvents, err := openEventLogger(cfg.outDir)
	if err != nil {
		return err
	}
	defer closeEvents()

	started := deps.now().UTC()
	logEvent("run-start", map[string]any{
		"remote":        cfg.remote,
		"samples":       cfg.samples,
		"warmup":        cfg.warmup,
		"payload_bytes": cfg.payloadBytes,
	})

	remote, err := prepareRemoteHelper(deps, cfg, logEvent)
	if err != nil {
		return err
	}
	if !cfg.keepRemote {
		defer deps.removeRemote(cfg.remote, remote.helperPath)
	}

	recordSample, closeSamples, err := openSampleRecorder(cfg.outDir)
	if err != nil {
		return err
	}
	defer closeSamples()

	results, err := runScenarioSet(deps, cfg, remote.helperPath, recordSample, logEvent)
	if err != nil {
		return err
	}

	resultStats, ratios := summarizeResults(results)
	sum := summary{
		Remote:       cfg.remote,
		StartedAt:    started,
		CompletedAt:  deps.now().UTC(),
		Samples:      cfg.samples,
		Warmup:       cfg.warmup,
		PayloadBytes: cfg.payloadBytes,
		LocalGOOS:    runtime.GOOS,
		LocalGOARCH:  runtime.GOARCH,
		RemoteGOOS:   remote.goos,
		RemoteGOARCH: remote.goarch,
		GitCommit:    deps.gitCommit(),
		Results:      resultStats,
		Ratios:       ratios,
	}
	if err := writeJSON(filepath.Join(cfg.outDir, "summary.json"), sum); err != nil {
		return err
	}

	printSummary(stdout, sum)
	return nil
}

func parseRunConfig(args []string, stderr io.Writer, now func() time.Time) (runConfig, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "", "SSH target for the remote latency peer")
	outDir := fs.String("out", filepath.Join(".tmp", "latency", now().UTC().Format("20060102T150405Z")), "output directory")
	sampleCount := fs.Int("samples", 200, "measured samples per scenario")
	warmupCount := fs.Int("warmup", 20, "warmup samples per scenario")
	payloadBytes := fs.Int("payload-bytes", 16, "payload bytes per echo sample, excluding sequence prefix")
	timeout := fs.Duration("timeout", defaultTimeout, "timeout per scenario")
	keepRemote := fs.Bool("keep-remote", false, "leave uploaded helper binary on remote host")
	if err := fs.Parse(args); err != nil {
		return runConfig{}, err
	}
	cfg := runConfig{
		remote:       *remote,
		outDir:       *outDir,
		samples:      *sampleCount,
		warmup:       *warmupCount,
		payloadBytes: *payloadBytes,
		timeout:      *timeout,
		keepRemote:   *keepRemote,
	}
	if err := validateRunConfig(cfg); err != nil {
		return runConfig{}, err
	}
	return cfg, nil
}

func validateRunConfig(cfg runConfig) error {
	if cfg.remote == "" {
		return errors.New("--remote is required")
	}
	if cfg.samples <= 0 {
		return errors.New("--samples must be greater than zero")
	}
	if cfg.warmup < 0 {
		return errors.New("--warmup must be zero or greater")
	}
	if cfg.payloadBytes < 0 {
		return errors.New("--payload-bytes must be zero or greater")
	}
	return nil
}

func openEventLogger(outDir string) (eventLogger, func(), error) {
	eventsFile, err := os.Create(filepath.Join(outDir, "events.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	logEvent := func(name string, details map[string]any) {
		_ = json.NewEncoder(eventsFile).Encode(event{At: time.Now().UTC(), Name: name, Details: details})
	}
	closeEvents := func() {
		_ = eventsFile.Close()
	}
	return logEvent, closeEvents, nil
}

func prepareRemoteHelper(deps runDeps, cfg runConfig, logEvent eventLogger) (remoteTarget, error) {
	remoteGOOS, remoteGOARCH, err := deps.detectTarget(cfg.remote)
	if err != nil {
		return remoteTarget{}, err
	}
	helperPath := filepath.Join(cfg.outDir, "bin", "derpssh-latency")
	if err := deps.buildHelper(helperPath, remoteGOOS, remoteGOARCH); err != nil {
		return remoteTarget{}, err
	}
	remotePath := fmt.Sprintf("/tmp/derpssh-latency-%d", deps.now().UnixNano())
	logEvent("helper-built", map[string]any{"local_path": helperPath, "goos": remoteGOOS, "goarch": remoteGOARCH})
	if err := deps.uploadHelper(cfg.remote, helperPath, remotePath); err != nil {
		return remoteTarget{}, err
	}
	logEvent("helper-uploaded", map[string]any{"remote_path": remotePath})
	return remoteTarget{goos: remoteGOOS, goarch: remoteGOARCH, helperPath: remotePath}, nil
}

func openSampleRecorder(outDir string) (func(sample), func(), error) {
	sampleFile, err := os.Create(filepath.Join(outDir, "samples.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	sampleEncoder := json.NewEncoder(sampleFile)
	recordSample := func(s sample) {
		_ = sampleEncoder.Encode(s)
	}
	closeSamples := func() {
		_ = sampleFile.Close()
	}
	return recordSample, closeSamples, nil
}

func runScenarioSet(deps runDeps, cfg runConfig, remotePath string, recordSample func(sample), logEvent eventLogger) (map[string][]time.Duration, error) {
	results := make(map[string][]time.Duration)
	for _, scenario := range deps.scenarios {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
		logEvent("scenario-start", map[string]any{"scenario": scenario.name})
		durations, err := scenario.run(ctx, scenario.name, cfg.remote, remotePath, cfg.outDir, cfg.warmup, cfg.samples, cfg.payloadBytes, recordSample)
		cancel()
		if err != nil {
			logEvent("scenario-error", map[string]any{"scenario": scenario.name, "error": err.Error()})
			return nil, err
		}
		results[scenario.name] = durations
		logEvent("scenario-complete", map[string]any{"scenario": scenario.name, "samples": len(durations)})
	}
	return results, nil
}

func summarizeResults(results map[string][]time.Duration) (map[string]stats, map[string]float64) {
	resultStats := make(map[string]stats, len(results))
	for name, durations := range results {
		resultStats[name] = calculateStats(durations)
	}
	ratios := map[string]float64{}
	base, ok := resultStats["ssh-stdio"]
	if !ok || base.P50US <= 0 {
		return resultStats, ratios
	}
	for name, candidate := range resultStats {
		if name == "ssh-stdio" {
			continue
		}
		ratios[name+"_p50_vs_ssh"] = float64(candidate.P50US) / float64(base.P50US)
		ratios[name+"_p95_vs_ssh"] = float64(candidate.P95US) / float64(base.P95US)
	}
	return resultStats, ratios
}

func compare(args []string) error {
	return compareWithOutput(args, os.Stdout, os.Stderr)
}

func compareWithOutput(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("compare requires before and after summary paths or output directories")
	}

	before, err := readSummary(fs.Arg(0))
	if err != nil {
		return err
	}
	after, err := readSummary(fs.Arg(1))
	if err != nil {
		return err
	}

	writef(stdout, "%-24s %12s %12s %12s %12s\n", "scenario", "before p50", "after p50", "before p95", "after p95")
	names := make([]string, 0, len(after.Results))
	for name := range after.Results {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := before.Results[name]
		a := after.Results[name]
		writef(stdout, "%-24s %12s %12s %12s %12s\n", name, formatUS(b.P50US), formatUS(a.P50US), formatUS(b.P95US), formatUS(a.P95US))
	}
	return nil
}

func runSSHStdio(ctx context.Context, scenario, remote, remotePath, outDir string, warmup, samples, payloadBytes int, record func(sample)) ([]time.Duration, error) {
	peer, err := startRemoteScenario(ctx, scenario, remote, remotePath, outDir, "ssh-helper")
	if err != nil {
		return nil, err
	}
	defer peer.closeLog()
	defer waitOrKill(peer.cmd)

	endpoint := lineEndpoint{reader: bufio.NewReader(peer.stdout), writer: peer.stdin}
	durations, err := measureEcho(ctx, scenario, endpoint, warmup, samples, payloadBytes, record)
	_ = peer.stdin.Close()
	return durations, err
}

func runMuxOverSSH(ctx context.Context, scenario, remote, remotePath, outDir string, warmup, samples, payloadBytes int, record func(sample)) ([]time.Duration, error) {
	peer, err := startRemoteScenario(ctx, scenario, remote, remotePath, outDir, "mux-peer")
	if err != nil {
		return nil, err
	}
	defer peer.closeLog()
	carrier := &cmdCarrier{reader: peer.stdout, writer: peer.stdin, closeFn: func() {
		_ = peer.stdin.Close()
		if peer.cmd.Process != nil {
			_ = peer.cmd.Process.Kill()
		}
	}}
	defer waitOrKill(peer.cmd)
	defer func() {
		_ = carrier.Close()
	}()

	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleClient, ReconnectTimeout: 5 * time.Second})
	defer func() {
		_ = mux.Close()
	}()
	mux.ReplaceCarrier(carrier)

	conn, err := mux.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	endpoint := lineEndpoint{reader: bufio.NewReader(conn), writer: conn}
	return measureEcho(ctx, scenario, endpoint, warmup, samples, payloadBytes, record)
}

type remoteScenario struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.Reader
	log    *os.File
}

func startRemoteScenario(ctx context.Context, scenario, remote, remotePath, outDir, mode string) (remoteScenario, error) {
	cmd := remoteCommand(ctx, remote, remotePath, mode)
	log, err := scenarioLog(outDir, scenario)
	if err != nil {
		return remoteScenario{}, err
	}
	cmd.Stderr = log
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = log.Close()
		return remoteScenario{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = log.Close()
		return remoteScenario{}, err
	}
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		return remoteScenario{}, err
	}
	return remoteScenario{cmd: cmd, stdin: stdin, stdout: stdout, log: log}, nil
}

func (s remoteScenario) closeLog() {
	if s.log != nil {
		_ = s.log.Close()
	}
}

type lineEndpoint struct {
	reader *bufio.Reader
	writer io.Writer
}

func measureEcho(ctx context.Context, scenario string, endpoint lineEndpoint, warmup, samples, payloadBytes int, record func(sample)) ([]time.Duration, error) {
	total := warmup + samples
	durations := make([]time.Duration, 0, samples)
	for i := 0; i < total; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		payload := probePayload(i, payloadBytes)
		line := payload + "\n"
		start := time.Now()
		if _, err := io.WriteString(endpoint.writer, line); err != nil {
			return nil, fmt.Errorf("%s write sample %d: %w", scenario, i, err)
		}
		got, err := endpoint.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("%s read sample %d: %w", scenario, i, err)
		}
		elapsed := time.Since(start)
		if got != line {
			return nil, fmt.Errorf("%s sample %d echoed %q, want %q", scenario, i, strings.TrimSpace(got), payload)
		}
		warm := i < warmup
		record(sample{
			Scenario:      scenario,
			Seq:           i,
			Warmup:        warm,
			StartedUnixNS: start.UnixNano(),
			DurationUS:    elapsed.Microseconds(),
			PayloadBytes:  len(payload),
		})
		if !warm {
			durations = append(durations, elapsed)
		}
	}
	return durations, nil
}

func probePayload(seq, payloadBytes int) string {
	prefix := fmt.Sprintf("%08d:", seq)
	if payloadBytes <= len(prefix) {
		return prefix
	}
	return prefix + strings.Repeat("x", payloadBytes-len(prefix))
}

func sshHelper() error {
	return echoLines(os.Stdin, os.Stdout)
}

func echoLines(input io.Reader, output io.Writer) error {
	reader := bufio.NewReader(input)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			if _, writeErr := io.WriteString(output, line); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func muxPeer() error {
	carrier := stdioCarrier{reader: os.Stdin, writer: os.Stdout}
	mux := derptun.NewMux(derptun.MuxConfig{Role: derptun.MuxRoleServer, ReconnectTimeout: 5 * time.Second})
	defer func() {
		_ = mux.Close()
	}()
	mux.ReplaceCarrier(carrier)

	conn, err := mux.Accept(context.Background())
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()

	_, err = io.Copy(conn, conn)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type stdioCarrier struct {
	reader io.Reader
	writer io.Writer
}

func (c stdioCarrier) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c stdioCarrier) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c stdioCarrier) Close() error {
	return nil
}

type cmdCarrier struct {
	reader  io.Reader
	writer  io.WriteCloser
	closeFn func()
	once    sync.Once
}

func (c *cmdCarrier) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *cmdCarrier) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *cmdCarrier) Close() error {
	c.once.Do(func() {
		if c.closeFn != nil {
			c.closeFn()
		}
	})
	return nil
}

func detectRemoteGoTarget(remote string) (string, string, error) {
	output, err := remoteCommand(context.Background(), remote, "uname", "-s", "-m").Output()
	if err != nil {
		return "", "", fmt.Errorf("detect remote target: %w", err)
	}
	return parseUnameTarget(string(output))
}

func parseUnameTarget(output string) (string, string, error) {
	fields := strings.Fields(output)
	if len(fields) < 2 {
		return "", "", fmt.Errorf("unexpected uname output %q", strings.TrimSpace(output))
	}
	goos := strings.ToLower(fields[0])
	switch goos {
	case "darwin", "linux":
	default:
		return "", "", fmt.Errorf("unsupported remote OS %q", fields[0])
	}

	var goarch string
	switch fields[1] {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	default:
		return "", "", fmt.Errorf("unsupported remote arch %q", fields[1])
	}
	return goos, goarch, nil
}

func buildHelper(path, goos, goarch string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cmd := exec.Command("go", "build", "-o", path, "./cmd/derpssh-latency")
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build helper: %w", err)
	}
	return nil
}

func uploadHelper(remote, localPath, remotePath string) error {
	if err := exec.Command("scp", "-q", localPath, remote+":"+remotePath).Run(); err != nil {
		return fmt.Errorf("upload helper: %w", err)
	}
	if err := remoteCommand(context.Background(), remote, "chmod", "+x", remotePath).Run(); err != nil {
		return fmt.Errorf("chmod helper: %w", err)
	}
	return nil
}

func remoteCommand(ctx context.Context, remote string, args ...string) *exec.Cmd {
	sshArgs := append([]string{"-T", remote}, args...)
	return exec.CommandContext(ctx, "ssh", sshArgs...)
}

func scenarioLog(outDir, scenario string) (*os.File, error) {
	dir := filepath.Join(outDir, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.Create(filepath.Join(dir, scenario+".stderr.log"))
}

func waitOrKill(cmd *exec.Cmd) {
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}
}

func calculateStats(durations []time.Duration) stats {
	if len(durations) == 0 {
		return stats{}
	}
	values := make([]int64, len(durations))
	var sum float64
	for i, duration := range durations {
		us := duration.Microseconds()
		values[i] = us
		sum += float64(us)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	mean := sum / float64(len(values))
	var variance float64
	for _, value := range values {
		delta := float64(value) - mean
		variance += delta * delta
	}
	variance /= float64(len(values))
	return stats{
		Count:  len(values),
		MinUS:  values[0],
		P50US:  percentile(values, 0.50),
		P90US:  percentile(values, 0.90),
		P95US:  percentile(values, 0.95),
		P99US:  percentile(values, 0.99),
		MaxUS:  values[len(values)-1],
		MeanUS: mean,
		StdUS:  math.Sqrt(variance),
	}
}

func percentile(values []int64, p float64) int64 {
	if len(values) == 0 {
		return 0
	}
	if len(values) == 1 {
		return values[0]
	}
	rank := p * float64(len(values)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		return values[lower]
	}
	weight := rank - float64(lower)
	return int64(math.Round(float64(values[lower])*(1-weight) + float64(values[upper])*weight))
}

func writeJSON(path string, value any) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func readSummary(path string) (summary, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, "summary.json")
	}
	file, err := os.Open(path)
	if err != nil {
		return summary{}, err
	}
	defer func() {
		_ = file.Close()
	}()
	var sum summary
	if err := json.NewDecoder(file).Decode(&sum); err != nil {
		return summary{}, err
	}
	return sum, nil
}

func printSummary(w io.Writer, sum summary) {
	writef(w, "derpssh latency run: %s\n", sum.CompletedAt.Format(time.RFC3339))
	writef(w, "remote: %s (%s/%s), samples: %d, warmup: %d\n", sum.Remote, sum.RemoteGOOS, sum.RemoteGOARCH, sum.Samples, sum.Warmup)
	names := make([]string, 0, len(sum.Results))
	for name := range sum.Results {
		names = append(names, name)
	}
	sort.Strings(names)
	writef(w, "%-24s %10s %10s %10s %10s\n", "scenario", "p50", "p90", "p95", "max")
	for _, name := range names {
		stat := sum.Results[name]
		writef(w, "%-24s %10s %10s %10s %10s\n", name, formatUS(stat.P50US), formatUS(stat.P90US), formatUS(stat.P95US), formatUS(stat.MaxUS))
	}
	if len(sum.Ratios) > 0 {
		writeln(w, "ratios:")
		ratioNames := make([]string, 0, len(sum.Ratios))
		for name := range sum.Ratios {
			ratioNames = append(ratioNames, name)
		}
		sort.Strings(ratioNames)
		for _, name := range ratioNames {
			writef(w, "  %s %.2fx\n", name, sum.Ratios[name])
		}
	}
}

func formatUS(us int64) string {
	if us == 0 {
		return "-"
	}
	if us >= 1000 {
		return fmt.Sprintf("%.1fms", float64(us)/1000.0)
	}
	return fmt.Sprintf("%dus", us)
}

func gitCommit() string {
	output, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
