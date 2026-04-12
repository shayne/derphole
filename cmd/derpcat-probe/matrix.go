package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

const defaultMatrixHosts = "ktzlxc,canlxc,uklxc,november-oscar.exe.xyz,eric@eric-nuc"
const defaultMatrixTools = "derpcat"

type matrixConfig struct {
	Hosts      []string `json:"hosts"`
	Tools      []string `json:"tools,omitempty"`
	Iterations int      `json:"iterations"`
	SizeMiB    int      `json:"size_mib"`
	Baseline   string   `json:"baseline,omitempty"`
}

type matrixFlags struct {
	Hosts      string `flag:"hosts" help:"Comma-separated remote hosts" default:"ktzlxc,canlxc,uklxc,november-oscar.exe.xyz,eric@eric-nuc"`
	Tools      string `flag:"tools" help:"Comma-separated benchmark tools: derpcat, derphole, iperf" default:"derpcat"`
	Iterations int    `flag:"iterations" help:"Runs per host per direction" default:"10"`
	SizeMiB    int    `flag:"size-mib" help:"Payload size in MiB" default:"1024"`
	Out        string `flag:"out" help:"Write the JSON report to this path"`
	Baseline   string `flag:"baseline" help:"Compare the current run against a prior matrix JSON report"`
}

type matrixSeries struct {
	Tool      string              `json:"tool,omitempty"`
	Host      string              `json:"host"`
	Direction string              `json:"direction"`
	Summary   probe.SeriesSummary `json:"summary"`
}

type matrixReport struct {
	Config      matrixConfig       `json:"config"`
	Runs        []probe.RunReport  `json:"runs"`
	Summaries   []matrixSeries     `json:"summaries"`
	Comparisons []matrixComparison `json:"comparisons,omitempty"`
}

type matrixComparison struct {
	Tool      string                 `json:"tool,omitempty"`
	Host      string                 `json:"host"`
	Direction string                 `json:"direction"`
	Result    probe.RegressionResult `json:"result"`
}

type matrixCase struct {
	tool      string
	script    string
	direction string
}

var runMatrixCommand = func(ctx context.Context, script string, host string, sizeMiB int) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "bash", script, host, strconv.Itoa(sizeMiB))
	return cmd.CombinedOutput()
}

func runMatrixCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 0
	}

	parsed, err := yargs.ParseKnownFlags[matrixFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 2
	}
	if len(parsed.RemainingArgs) != 0 {
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 2
	}

	cfg := matrixConfig{
		Hosts:      splitMatrixHosts(parsed.Flags.Hosts),
		Tools:      splitMatrixTools(parsed.Flags.Tools),
		Iterations: parsed.Flags.Iterations,
		SizeMiB:    parsed.Flags.SizeMiB,
		Baseline:   strings.TrimSpace(parsed.Flags.Baseline),
	}
	if len(cfg.Hosts) == 0 {
		fmt.Fprintln(stderr, "at least one host is required")
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 2
	}
	if len(cfg.Tools) == 0 {
		fmt.Fprintln(stderr, "at least one tool is required")
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 2
	}
	if cfg.Iterations <= 0 {
		fmt.Fprintln(stderr, "iterations must be positive")
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 2
	}
	if cfg.SizeMiB <= 0 {
		fmt.Fprintln(stderr, "size-mib must be positive")
		fmt.Fprint(stderr, subcommandUsageLine("matrix"))
		return 2
	}

	runs, err := runMatrix(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	report := matrixReport{
		Config:    cfg,
		Runs:      runs,
		Summaries: summarizeMatrixRuns(runs),
	}
	if cfg.Baseline != "" {
		comparisons, err := loadMatrixBaselineComparisons(cfg.Baseline, report.Summaries)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		report.Comparisons = comparisons
	}

	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if parsed.Flags.Out != "" {
		if err := os.WriteFile(parsed.Flags.Out, encoded.Bytes(), 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if _, err := stdout.Write(encoded.Bytes()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if matrixHasFailures(runs) || matrixHasRegressions(report.Comparisons) {
		return 1
	}
	return 0
}

func runMatrix(ctx context.Context, cfg matrixConfig) ([]probe.RunReport, error) {
	var runs []probe.RunReport
	if len(cfg.Tools) == 0 {
		cfg.Tools = splitMatrixTools("")
	}
	cases, err := matrixCases(cfg.Tools)
	if err != nil {
		return nil, err
	}

	for _, host := range cfg.Hosts {
		for i := 0; i < cfg.Iterations; i++ {
			for _, tc := range cases {
				raw, err := runMatrixCommand(ctx, tc.script, host, cfg.SizeMiB)
				report, parseErr := parsePromotionSummary(raw)
				if parseErr != nil {
					if err != nil {
						failed := false
						runs = append(runs, probe.RunReport{
							Host:      host,
							Mode:      tc.tool,
							Direction: tc.direction,
							SizeBytes: int64(cfg.SizeMiB) * 1024 * 1024,
							Success:   &failed,
							Error:     strings.TrimSpace(err.Error()),
						})
						continue
					}
					return nil, parseErr
				}
				report.Host = host
				report.Mode = tc.tool
				report.Direction = tc.direction
				runs = append(runs, report)
			}
		}
	}
	return runs, nil
}

func parsePromotionSummary(raw []byte) (probe.RunReport, error) {
	var out probe.RunReport
	var (
		haveHost      bool
		haveDirection bool
		haveSize      bool
		haveDuration  bool
		haveGoodput   bool
		havePeak      bool
		haveFirstByte bool
		haveSuccess   bool
	)
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		text := string(bytes.TrimSpace(line))
		switch {
		case strings.HasPrefix(text, "benchmark-host="):
			out.Host = strings.TrimPrefix(text, "benchmark-host=")
			haveHost = true
		case strings.HasPrefix(text, "benchmark-direction="):
			out.Direction = strings.TrimPrefix(text, "benchmark-direction=")
			haveDirection = true
		case strings.HasPrefix(text, "benchmark-size-bytes="):
			value := strings.TrimPrefix(text, "benchmark-size-bytes=")
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return probe.RunReport{}, fmt.Errorf("parse benchmark-size-bytes: %w", err)
			}
			out.SizeBytes = parsed
			haveSize = true
		case strings.HasPrefix(text, "benchmark-total-duration-ms="):
			value := strings.TrimPrefix(text, "benchmark-total-duration-ms=")
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return probe.RunReport{}, fmt.Errorf("parse benchmark-total-duration-ms: %w", err)
			}
			out.DurationMS = parsed
			haveDuration = true
		case strings.HasPrefix(text, "benchmark-goodput-mbps="):
			value := strings.TrimPrefix(text, "benchmark-goodput-mbps=")
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return probe.RunReport{}, fmt.Errorf("parse benchmark-goodput-mbps: %w", err)
			}
			out.GoodputMbps = parsed
			haveGoodput = true
		case strings.HasPrefix(text, "benchmark-peak-goodput-mbps="):
			value := strings.TrimPrefix(text, "benchmark-peak-goodput-mbps=")
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return probe.RunReport{}, fmt.Errorf("parse benchmark-peak-goodput-mbps: %w", err)
			}
			out.PeakGoodputMbps = parsed
			havePeak = true
		case strings.HasPrefix(text, "benchmark-first-byte-ms="):
			value := strings.TrimPrefix(text, "benchmark-first-byte-ms=")
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return probe.RunReport{}, fmt.Errorf("parse benchmark-first-byte-ms: %w", err)
			}
			out.FirstByteMS = parsed
			haveFirstByte = true
		case strings.HasPrefix(text, "benchmark-success="):
			value := strings.TrimPrefix(text, "benchmark-success=")
			if value != "true" && value != "false" {
				return probe.RunReport{}, fmt.Errorf("parse benchmark-success: invalid value %q", value)
			}
			success := value == "true"
			out.Success = &success
			haveSuccess = true
		case strings.HasPrefix(text, "benchmark-error="):
			out.Error = strings.TrimPrefix(text, "benchmark-error=")
		}
	}
	if !haveHost || !haveDirection || !haveSize || !haveDuration || !haveGoodput || !havePeak || !haveFirstByte || !haveSuccess {
		return probe.RunReport{}, fmt.Errorf("missing benchmark footer in output")
	}
	return out, nil
}

func splitMatrixHosts(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		raw = defaultMatrixHosts
	}
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		host := strings.TrimSpace(part)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func splitMatrixTools(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		raw = defaultMatrixTools
	}
	parts := strings.Split(raw, ",")
	tools := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		tool := strings.TrimSpace(part)
		if tool == "" || seen[tool] {
			continue
		}
		tools = append(tools, tool)
		seen[tool] = true
	}
	return tools
}

func matrixCases(tools []string) ([]matrixCase, error) {
	var cases []matrixCase
	for _, tool := range tools {
		switch tool {
		case "derpcat":
			cases = append(cases,
				matrixCase{tool: tool, script: "./scripts/promotion-test.sh", direction: "forward"},
				matrixCase{tool: tool, script: "./scripts/promotion-test-reverse.sh", direction: "reverse"},
			)
		case "derphole":
			cases = append(cases,
				matrixCase{tool: tool, script: "./scripts/derphole-promotion-test.sh", direction: "forward"},
				matrixCase{tool: tool, script: "./scripts/derphole-promotion-test-reverse.sh", direction: "reverse"},
			)
		case "iperf":
			cases = append(cases,
				matrixCase{tool: tool, script: "./scripts/iperf-benchmark.sh", direction: "forward"},
				matrixCase{tool: tool, script: "./scripts/iperf-benchmark-reverse.sh", direction: "reverse"},
			)
		default:
			return nil, fmt.Errorf("unsupported matrix tool %q", tool)
		}
	}
	return cases, nil
}

func summarizeMatrixRuns(runs []probe.RunReport) []matrixSeries {
	grouped := make(map[string][]probe.RunReport)
	for _, run := range runs {
		key := run.Mode + "\x00" + run.Host + "\x00" + run.Direction
		grouped[key] = append(grouped[key], run)
	}

	out := make([]matrixSeries, 0, len(grouped))
	for key, group := range grouped {
		tool, rest, _ := strings.Cut(key, "\x00")
		host, direction, _ := strings.Cut(rest, "\x00")
		out = append(out, matrixSeries{
			Tool:      tool,
			Host:      host,
			Direction: direction,
			Summary:   probe.SummarizeRuns(group),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Direction < out[j].Direction
	})
	return out
}

func matrixHasFailures(runs []probe.RunReport) bool {
	for _, run := range runs {
		if run.Error != "" {
			return true
		}
		if run.Success != nil && !*run.Success {
			return true
		}
	}
	return false
}

func loadMatrixBaselineComparisons(path string, head []matrixSeries) ([]matrixComparison, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline matrixReport
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return nil, err
	}
	return compareMatrixSummaries(baseline.Summaries, head), nil
}

func compareMatrixSummaries(base, head []matrixSeries) []matrixComparison {
	baseByKey := make(map[string]matrixSeries, len(base))
	headByKey := make(map[string]matrixSeries, len(head))
	keys := make(map[string]struct{}, len(base)+len(head))
	for _, series := range base {
		series = normalizeMatrixSeries(series)
		key := series.Tool + "\x00" + series.Host + "\x00" + series.Direction
		baseByKey[key] = series
		keys[key] = struct{}{}
	}
	for _, series := range head {
		series = normalizeMatrixSeries(series)
		key := series.Tool + "\x00" + series.Host + "\x00" + series.Direction
		headByKey[key] = series
		keys[key] = struct{}{}
	}

	orderedKeys := make([]string, 0, len(keys))
	for key := range keys {
		orderedKeys = append(orderedKeys, key)
	}
	sort.Strings(orderedKeys)

	comparisons := make([]matrixComparison, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		tool, rest, _ := strings.Cut(key, "\x00")
		host, direction, _ := strings.Cut(rest, "\x00")
		baseSeries, haveBase := baseByKey[key]
		headSeries, haveHead := headByKey[key]
		comparison := matrixComparison{
			Tool:      tool,
			Host:      host,
			Direction: direction,
		}
		switch {
		case haveBase && haveHead:
			comparison.Result = probe.CompareSummaries(baseSeries.Summary, headSeries.Summary)
		case haveBase:
			comparison.Result = probe.RegressionResult{
				Base:   baseSeries.Summary,
				Reason: "missing candidate summary for host/direction",
			}
		default:
			comparison.Result = probe.RegressionResult{
				Head:   headSeries.Summary,
				Reason: "missing baseline summary for host/direction",
			}
		}
		comparisons = append(comparisons, comparison)
	}
	return comparisons
}

func matrixHasRegressions(comparisons []matrixComparison) bool {
	for _, comparison := range comparisons {
		if !comparison.Result.Comparable || comparison.Result.IsRegression {
			return true
		}
	}
	return false
}

func normalizeMatrixSeries(series matrixSeries) matrixSeries {
	if series.Tool == "" {
		series.Tool = defaultMatrixTools
	}
	return series
}
