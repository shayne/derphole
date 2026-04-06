package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
)

type iperf3Result struct {
	Bytes         int64
	DurationMS    int64
	BitsPerSecond float64
}

type iperf3Report struct {
	End struct {
		SumSent     *iperf3Sum `json:"sum_sent"`
		SumReceived *iperf3Sum `json:"sum_received"`
	} `json:"end"`
}

type iperf3Sum struct {
	Seconds       float64 `json:"seconds"`
	Bytes         int64   `json:"bytes"`
	BitsPerSecond float64 `json:"bits_per_second"`
}

type iperf3ServerHandle struct {
	cmd    *exec.Cmd
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

type iperf3ClientConfig struct {
	BindAddr  string
	Target    string
	Port      int
	SizeBytes int64
	Parallel  int
	Reverse   bool
}

func parseIperf3Result(data []byte) (iperf3Result, error) {
	var report iperf3Report
	if err := json.Unmarshal(data, &report); err != nil {
		return iperf3Result{}, err
	}
	sum := report.End.SumReceived
	if sum == nil || sum.Bytes <= 0 {
		sum = report.End.SumSent
	}
	if sum == nil || sum.Bytes <= 0 {
		return iperf3Result{}, errors.New("iperf3 report missing transfer totals")
	}
	return iperf3Result{
		Bytes:         sum.Bytes,
		DurationMS:    int64(math.Round(sum.Seconds * 1000)),
		BitsPerSecond: sum.BitsPerSecond,
	}, nil
}

func startIperf3Server(ctx context.Context, bindAddr string, port int) (*iperf3ServerHandle, error) {
	argv, err := iperf3BaseArgs()
	if err != nil {
		return nil, err
	}
	argv = append(argv,
		"-s",
		"-1",
		"--json",
		"-4",
		"-B", bindAddr,
		"-p", strconv.Itoa(port),
	)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &iperf3ServerHandle{cmd: cmd, stdout: &stdout, stderr: &stderr}, nil
}

func (h *iperf3ServerHandle) Wait() (iperf3Result, error) {
	if h == nil || h.cmd == nil {
		return iperf3Result{}, errors.New("nil iperf3 server handle")
	}
	if err := h.cmd.Wait(); err != nil {
		msg := strings.TrimSpace(h.stderr.String())
		if msg == "" {
			return iperf3Result{}, err
		}
		return iperf3Result{}, fmt.Errorf("%w: %s", err, msg)
	}
	return parseIperf3Result(h.stdout.Bytes())
}

func runIperf3Client(ctx context.Context, cfg iperf3ClientConfig) (iperf3Result, error) {
	if strings.TrimSpace(cfg.BindAddr) == "" {
		return iperf3Result{}, errors.New("iperf3 bind addr is required")
	}
	if strings.TrimSpace(cfg.Target) == "" {
		return iperf3Result{}, errors.New("iperf3 target is required")
	}
	if cfg.Port <= 0 {
		return iperf3Result{}, errors.New("iperf3 port is required")
	}
	argv, err := iperf3BaseArgs()
	if err != nil {
		return iperf3Result{}, err
	}
	argv = append(argv,
		"-c", cfg.Target,
		"--json",
		"-4",
		"-B", cfg.BindAddr,
		"-p", strconv.Itoa(cfg.Port),
	)
	if cfg.SizeBytes > 0 {
		argv = append(argv, "-n", strconv.FormatInt(cfg.SizeBytes, 10))
	}
	if cfg.Parallel > 1 {
		argv = append(argv, "-P", strconv.Itoa(cfg.Parallel))
	}
	if cfg.Reverse {
		argv = append(argv, "-R")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return iperf3Result{}, err
		}
		return iperf3Result{}, fmt.Errorf("%w: %s", err, msg)
	}
	return parseIperf3Result(stdout.Bytes())
}

func iperf3BaseArgs() ([]string, error) {
	if path, err := exec.LookPath("iperf3"); err == nil {
		return []string{path}, nil
	}
	if path, err := exec.LookPath("nix"); err == nil {
		return []string{path, "shell", "nixpkgs#iperf3", "-c", "iperf3"}, nil
	}
	return nil, errors.New("iperf3 not found in PATH and nix is unavailable")
}
