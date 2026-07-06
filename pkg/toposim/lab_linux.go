// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && toposim

package toposim

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type LinuxLab struct {
	Prefix     string
	mu         sync.Mutex
	seq        int
	namespaces map[string]LinuxNamespace
	cleanup    sync.Once
	cleanupErr error
}

func RunLinuxScenario(ctx context.Context, scenario Scenario) (Result, error) {
	lab := NewLinuxLab(scenario.Name)
	defer func() {
		_ = lab.Cleanup()
	}()

	endpoints, err := lab.BuildScenario(ctx, scenario)
	if err != nil {
		return Result{}, err
	}
	coordinator := NewCoordinatorForTest(scenario.Name, endpoints...)
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	runErr := make(chan error, 1)
	go func() {
		runErr <- coordinator.Run(runCtx)
	}()

	for _, action := range scenario.Actions {
		action := action
		go func() {
			timer := time.NewTimer(action.After)
			defer timer.Stop()
			select {
			case <-runCtx.Done():
				return
			case <-timer.C:
			}
			_ = applyScenarioAction(runCtx, coordinator, action)
		}()
	}

	for _, expect := range scenario.Expect {
		if err := coordinator.WaitForPath(ctx, expect); err != nil {
			cancelRun()
			<-runErr
			return coordinator.Result(), err
		}
	}

	cancelRun()
	if err := <-runErr; err != nil && ctx.Err() == nil {
		return coordinator.Result(), err
	}
	return coordinator.Result(), nil
}

func (l *LinuxLab) BuildScenario(ctx context.Context, scenario Scenario) ([]nodeEndpoint, error) {
	namespaces := make(map[string]LinuxNamespace, len(scenario.Nodes))
	for _, node := range scenario.Nodes {
		namespace, err := l.AddNamespace(node.Namespace)
		if err != nil {
			return nil, err
		}
		namespaces[node.Name] = namespace
	}

	for _, link := range scenario.Links {
		left := namespaces[link.From]
		right := namespaces[link.To]
		if left.Name == "" || right.Name == "" {
			return nil, fmt.Errorf("%s: link %s references unknown namespace", scenario.Name, link.Name)
		}
		built, err := l.AddVeth(left, right, link.Name, link.IPv4CIDR, link.IPv6CIDR)
		if err != nil {
			return nil, err
		}
		if link.Latency > 0 || link.LossPercent > 0 {
			if err := l.SetNetem(left, built.LeftIf, link.Latency, link.LossPercent); err != nil {
				return nil, err
			}
			if err := l.SetNetem(right, built.RightIf, link.Latency, link.LossPercent); err != nil {
				return nil, err
			}
		}
	}

	helper, err := toposimNodePath()
	if err != nil {
		return nil, err
	}
	endpoints := make([]nodeEndpoint, 0, len(scenario.Nodes))
	for _, node := range scenario.Nodes {
		namespace := namespaces[node.Name]
		command := []string{
			"ip", "netns", "exec", namespace.Name, helper,
			"-name", node.Name,
			"-direct-port", strconv.Itoa(node.DirectPort),
		}
		candidates := expandNodeCandidates(node)
		if len(candidates) > 0 {
			command = append(command, "-candidates", strings.Join(candidates, ","))
		}
		if len(node.PortmapCandidates) > 0 {
			command = append(command, "-portmap-candidates", strings.Join(node.PortmapCandidates, ","))
		}
		endpoint, err := StartProcessEndpoint(ctx, node.Name, command)
		if err != nil {
			for _, started := range endpoints {
				_ = started.Stop()
			}
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func applyScenarioAction(ctx context.Context, coordinator *Coordinator, action ScenarioAction) error {
	switch action.Type {
	case ActionSetCandidates:
		return coordinator.SendNode(ctx, action.Node, NodeCommand{Type: CommandSetCandidates, Candidates: action.Candidates})
	case ActionSetPortmap:
		return coordinator.SendNode(ctx, action.Node, NodeCommand{Type: CommandSetPortmap, PortmapCandidates: action.PortmapCandidates})
	case ActionSendDatagram:
		return coordinator.SendNode(ctx, action.Node, NodeCommand{Type: CommandSendPeerDatagram, Payload: action.Payload})
	case ActionSetLink:
		return nil
	default:
		return fmt.Errorf("unknown scenario action %q", action.Type)
	}
}

func expandNodeCandidates(node NodeSpec) []string {
	candidates := append([]string(nil), node.InitialCandidates...)
	if node.ManyAddressCount <= len(candidates) {
		return candidates
	}
	for i := len(candidates); i < node.ManyAddressCount; i++ {
		candidates = append(candidates, fmt.Sprintf("10.250.%d.%d:%d", i/250, (i%250)+4, node.DirectPort))
	}
	return candidates
}

func toposimNodePath() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(wd, ".tmp", "toposim", "toposimnode")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("could not locate repository root for toposimnode")
		}
		wd = parent
	}
}

type LinuxNamespace struct {
	Logical string
	Name    string
}

type LinuxLink struct {
	Name      string
	Left      LinuxNamespace
	Right     LinuxNamespace
	LeftIf    string
	RightIf   string
	LeftIPv4  string
	RightIPv4 string
	LeftIPv6  string
	RightIPv6 string
}

func NewLinuxLab(label string) *LinuxLab {
	return &LinuxLab{
		Prefix:     fmt.Sprintf("derphole-ts-%d-%s-", os.Getpid(), sanitizeLinuxName(label, 18)),
		namespaces: make(map[string]LinuxNamespace),
	}
}

func (l *LinuxLab) AddNamespace(logical string) (LinuxNamespace, error) {
	l.mu.Lock()
	if namespace, ok := l.namespaces[logical]; ok {
		l.mu.Unlock()
		return namespace, nil
	}
	name := l.Prefix + sanitizeLinuxName(logical, 24)
	namespace := LinuxNamespace{Logical: logical, Name: name}
	l.namespaces[logical] = namespace
	l.mu.Unlock()

	if err := runLinuxTool("ip", "netns", "add", namespace.Name); err != nil {
		return LinuxNamespace{}, err
	}
	if err := runLinuxTool("ip", "-n", namespace.Name, "link", "set", "lo", "up"); err != nil {
		return LinuxNamespace{}, err
	}
	return namespace, nil
}

func (l *LinuxLab) AddVeth(left, right LinuxNamespace, name, ipv4CIDR, ipv6CIDR string) (LinuxLink, error) {
	l.mu.Lock()
	l.seq++
	seq := l.seq
	l.mu.Unlock()

	hostLeft := linuxIfaceName(seq, "a")
	hostRight := linuxIfaceName(seq, "b")
	leftIf := linuxIfaceName(seq, "l")
	rightIf := linuxIfaceName(seq, "r")

	if err := runLinuxTool("ip", "link", "add", hostLeft, "type", "veth", "peer", "name", hostRight); err != nil {
		return LinuxLink{}, err
	}
	if err := runLinuxTool("ip", "link", "set", hostLeft, "netns", left.Name); err != nil {
		return LinuxLink{}, err
	}
	if err := runLinuxTool("ip", "link", "set", hostRight, "netns", right.Name); err != nil {
		return LinuxLink{}, err
	}
	if err := runLinuxTool("ip", "-n", left.Name, "link", "set", hostLeft, "name", leftIf); err != nil {
		return LinuxLink{}, err
	}
	if err := runLinuxTool("ip", "-n", right.Name, "link", "set", hostRight, "name", rightIf); err != nil {
		return LinuxLink{}, err
	}

	link := LinuxLink{Name: name, Left: left, Right: right, LeftIf: leftIf, RightIf: rightIf}
	if ipv4CIDR != "" {
		leftAddr, rightAddr, err := labAddrPair(ipv4CIDR)
		if err != nil {
			return LinuxLink{}, err
		}
		link.LeftIPv4 = leftAddr
		link.RightIPv4 = rightAddr
		if err := runLinuxTool("ip", "-n", left.Name, "addr", "add", leftAddr, "dev", leftIf); err != nil {
			return LinuxLink{}, err
		}
		if err := runLinuxTool("ip", "-n", right.Name, "addr", "add", rightAddr, "dev", rightIf); err != nil {
			return LinuxLink{}, err
		}
	}
	if ipv6CIDR != "" {
		leftAddr, rightAddr, err := labAddrPair(ipv6CIDR)
		if err != nil {
			return LinuxLink{}, err
		}
		link.LeftIPv6 = leftAddr
		link.RightIPv6 = rightAddr
		if err := runLinuxTool("ip", "-n", left.Name, "-6", "addr", "add", leftAddr, "dev", leftIf); err != nil {
			return LinuxLink{}, err
		}
		if err := runLinuxTool("ip", "-n", right.Name, "-6", "addr", "add", rightAddr, "dev", rightIf); err != nil {
			return LinuxLink{}, err
		}
	}
	if err := l.SetLink(left, leftIf, true); err != nil {
		return LinuxLink{}, err
	}
	if err := l.SetLink(right, rightIf, true); err != nil {
		return LinuxLink{}, err
	}
	return link, nil
}

func (l *LinuxLab) SetLink(namespace LinuxNamespace, linkName string, up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	return runLinuxTool("ip", "-n", namespace.Name, "link", "set", "dev", linkName, state)
}

func (l *LinuxLab) AddNAT(namespace LinuxNamespace, outInterface string) error {
	if err := runLinuxTool("ip", "netns", "exec", namespace.Name, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	return runLinuxTool("ip", "netns", "exec", namespace.Name, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", outInterface, "-j", "MASQUERADE")
}

func (l *LinuxLab) SetNetem(namespace LinuxNamespace, linkName string, latency time.Duration, lossPercent int) error {
	if latency <= 0 && lossPercent <= 0 {
		err := runLinuxTool("ip", "netns", "exec", namespace.Name, "tc", "qdisc", "del", "dev", linkName, "root")
		if err != nil && !strings.Contains(err.Error(), "No such file or directory") {
			return err
		}
		return nil
	}

	args := []string{"netns", "exec", namespace.Name, "tc", "qdisc", "replace", "dev", linkName, "root", "netem"}
	if latency > 0 {
		args = append(args, "delay", fmt.Sprintf("%dms", latency.Milliseconds()))
	}
	if lossPercent > 0 {
		args = append(args, "loss", fmt.Sprintf("%d%%", lossPercent))
	}
	return runLinuxTool("ip", args...)
}

func (l *LinuxLab) Cleanup() error {
	l.cleanup.Do(func() {
		out, err := exec.Command("ip", "netns", "list").CombinedOutput()
		if err != nil {
			l.cleanupErr = fmt.Errorf("ip netns list: %w: %s", err, strings.TrimSpace(string(out)))
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			name := strings.Fields(line)
			if len(name) == 0 || !strings.HasPrefix(name[0], l.Prefix) {
				continue
			}
			if err := runLinuxTool("ip", "netns", "delete", name[0]); err != nil && l.cleanupErr == nil {
				l.cleanupErr = err
			}
		}
	})
	return l.cleanupErr
}

func labAddrPair(cidr string) (string, string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", "", err
	}
	left, err := prefixAddr(prefix, 2)
	if err != nil {
		return "", "", err
	}
	right, err := prefixAddr(prefix, 3)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%s/%d", left, prefix.Bits()), fmt.Sprintf("%s/%d", right, prefix.Bits()), nil
}

func prefixAddr(prefix netip.Prefix, host byte) (netip.Addr, error) {
	addr := prefix.Addr()
	if addr.Is4() {
		raw := addr.As4()
		raw[3] = host
		return netip.AddrFrom4(raw), nil
	}
	if addr.Is6() {
		raw := addr.As16()
		raw[15] = host
		return netip.AddrFrom16(raw), nil
	}
	return netip.Addr{}, fmt.Errorf("unsupported prefix address %s", prefix)
}

func linuxIfaceName(seq int, suffix string) string {
	return "dts" + strconv.Itoa(seq) + suffix
}

func sanitizeLinuxName(value string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteByte('-')
		default:
			b.WriteByte('-')
		}
		if b.Len() >= max {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "lab"
	}
	return out
}

func runLinuxTool(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("%s %s timed out", name, strings.Join(args, " "))
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
