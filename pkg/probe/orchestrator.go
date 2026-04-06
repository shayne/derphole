package probe

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const defaultProbeRemotePath = "/tmp/derpcat-probe"

type OrchestrateConfig struct {
	Host       string
	User       string
	RemotePath string
	ListenAddr string
	Mode       string
	Direction  string
	SizeBytes  int64
}

type ServerConfig struct {
	ListenAddr string
	Mode       string
}

type ClientConfig struct {
	Host string
	Mode string
}

type SSHRunner struct {
	User       string
	Host       string
	RemotePath string
}

func (r SSHRunner) target() string {
	if r.User == "" {
		return r.Host
	}
	return r.User + "@" + r.Host
}

func (r SSHRunner) binaryPath() string {
	if r.RemotePath != "" {
		return r.RemotePath
	}
	return defaultProbeRemotePath
}

func (r SSHRunner) ServerCommand(cfg ServerConfig) []string {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	mode := cfg.Mode
	if mode == "" {
		mode = "raw"
	}
	return []string{
		"ssh",
		r.target(),
		fmt.Sprintf("%s server --listen %s --mode %s", r.binaryPath(), listenAddr, mode),
	}
}

func (r SSHRunner) ClientCommand(cfg ClientConfig) []string {
	mode := cfg.Mode
	if mode == "" {
		mode = "raw"
	}
	return []string{
		"ssh",
		r.target(),
		fmt.Sprintf("%s client --host %s --mode %s", r.binaryPath(), cfg.Host, mode),
	}
}

func RunOrchestrate(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
	if ctx == nil {
		return RunReport{}, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return RunReport{}, err
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return RunReport{}, errors.New("host is required")
	}
	if cfg.RemotePath == "" {
		cfg.RemotePath = defaultProbeRemotePath
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	if cfg.Mode == "" {
		cfg.Mode = "raw"
	}
	if cfg.Direction == "" {
		cfg.Direction = "forward"
	}
	if cfg.SizeBytes < 0 {
		return RunReport{}, errors.New("size bytes must be non-negative")
	}
	if cfg.Mode != "raw" && cfg.Mode != "aead" {
		return RunReport{}, fmt.Errorf("unsupported mode %q", cfg.Mode)
	}
	if cfg.Direction != "forward" && cfg.Direction != "reverse" {
		return RunReport{}, fmt.Errorf("unsupported direction %q", cfg.Direction)
	}

	runner := SSHRunner{
		User:       cfg.User,
		Host:       cfg.Host,
		RemotePath: cfg.RemotePath,
	}
	serverCmd := runner.ServerCommand(ServerConfig{ListenAddr: cfg.ListenAddr, Mode: cfg.Mode})
	clientCmd := runner.ClientCommand(ClientConfig{Host: cfg.Host, Mode: cfg.Mode})

	return RunReport{
		Host:          cfg.Host,
		User:          cfg.User,
		RemotePath:    cfg.RemotePath,
		Mode:          cfg.Mode,
		Direction:     cfg.Direction,
		SizeBytes:     cfg.SizeBytes,
		Direct:        false,
		ListenAddr:    cfg.ListenAddr,
		ServerCommand: serverCmd,
		ClientCommand: clientCmd,
	}, nil
}
