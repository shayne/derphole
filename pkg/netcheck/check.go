// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"tailscale.com/net/stun"
)

const defaultTimeout = 5 * time.Second

var (
	defaultSTUNServers = []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
		"stun.cloudflare.com:3478",
	}
	probeSTUNServer = defaultProbeSTUNServer
	interfaceAddrs  = net.InterfaceAddrs
)

type Config struct {
	Timeout           time.Duration
	STUNServers       []string
	FreshSocketChecks int
}

func Run(ctx context.Context, cfg Config) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("nil context")
	}
	cfg = normalizeConfig(cfg)
	if cfg.Timeout <= 0 {
		return Report{}, errors.New("timeout must be positive")
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	basePort := chooseProbePort()
	var results []STUNServerResult
	for _, server := range cfg.STUNServers {
		results = append(results, probeSTUNServer(runCtx, server, basePort))
	}
	for i := 0; i < cfg.FreshSocketChecks && len(cfg.STUNServers) > 0; i++ {
		results = append(results, probeSTUNServer(runCtx, cfg.STUNServers[0], chooseProbePort()))
	}

	successes := successfulSTUNResults(results)
	publicEndpoints := uniqueMappedEndpoints(successes)
	candidates, ifaceErr := localCandidates(publicEndpoints)

	report := Report{
		UDP: UDPReport{
			Outbound:        len(successes) > 0,
			STUN:            len(successes) > 0,
			PublicEndpoints: publicEndpoints,
			MappingStable:   mappingStable(successes),
			PortPreserving:  portPreserving(successes),
		},
		Candidates: candidates,
		STUN: STUNReport{
			Servers: results,
		},
	}
	if ifaceErr != nil {
		report.STUN.Servers = append(report.STUN.Servers, STUNServerResult{
			Server: "local-interfaces",
			Error:  ifaceErr.Error(),
		})
	}
	report.Verdict = Classify(report)
	report.Recommendation = Recommendation(report.Verdict)
	return report, nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if len(cfg.STUNServers) == 0 {
		cfg.STUNServers = append([]string(nil), defaultSTUNServers...)
	}
	if cfg.FreshSocketChecks < 0 {
		cfg.FreshSocketChecks = 0
	}
	if cfg.FreshSocketChecks == 0 {
		cfg.FreshSocketChecks = 3
	}
	return cfg
}

func chooseProbePort() int {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return 0
	}
	defer func() { _ = conn.Close() }()
	if udp, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udp.Port
	}
	return 0
}

func defaultProbeSTUNServer(ctx context.Context, server string, localPort int) STUNServerResult {
	result := STUNServerResult{Server: server}
	conn, err := listenSTUNProbe(localPort)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer func() { _ = conn.Close() }()
	result.LocalEndpoint = conn.LocalAddr().String()

	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	txID := stun.NewTxID()
	if _, err := conn.WriteTo(stun.Request(txID), serverAddr); err != nil {
		result.Error = err.Error()
		return result
	}

	mapped, err := readSTUNResponse(ctx, conn, txID)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.MappedEndpoint = mapped
	return result
}

func listenSTUNProbe(localPort int) (net.PacketConn, error) {
	return net.ListenPacket("udp4", stunListenAddress(localPort))
}

func stunListenAddress(localPort int) string {
	if localPort <= 0 {
		return "0.0.0.0:0"
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(localPort))
}

func readSTUNResponse(ctx context.Context, conn net.PacketConn, txID stun.TxID) (string, error) {
	buf := make([]byte, 2048)
	for {
		mapped, done, err := readSTUNResponseOnce(ctx, conn, txID, buf)
		if err != nil || done {
			return mapped, err
		}
	}
}

func readSTUNResponseOnce(ctx context.Context, conn net.PacketConn, txID stun.TxID, buf []byte) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	packet, ok, err := readSTUNPacket(ctx, conn, buf)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	mapped, ok := matchingSTUNResponse(packet, txID)
	return mapped, ok, nil
}

func readSTUNPacket(ctx context.Context, conn net.PacketConn, buf []byte) ([]byte, bool, error) {
	if err := conn.SetReadDeadline(stunReadDeadline(ctx, time.Now())); err != nil {
		return nil, false, err
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		if isTimeoutError(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return buf[:n], true, nil
}

func matchingSTUNResponse(packet []byte, txID stun.TxID) (string, bool) {
	gotTxID, mapped, err := stun.ParseResponse(packet)
	if err != nil || gotTxID != txID {
		return "", false
	}
	return mapped.String(), true
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func stunReadDeadline(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(250 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func successfulSTUNResults(results []STUNServerResult) []STUNServerResult {
	var successes []STUNServerResult
	for _, result := range results {
		if result.Error == "" && result.MappedEndpoint != "" {
			successes = append(successes, result)
		}
	}
	return successes
}

func uniqueMappedEndpoints(results []STUNServerResult) []string {
	var endpoints []string
	for _, result := range results {
		endpoints = appendUnique(endpoints, result.MappedEndpoint)
	}
	sort.Strings(endpoints)
	return endpoints
}

func mappingStable(results []STUNServerResult) bool {
	if len(results) == 0 {
		return false
	}
	if stable, ok := mappingStableForSharedLocalEndpoint(results); ok {
		return stable
	}
	return allMappedEndpointsEqual(results)
}

func mappingStableForSharedLocalEndpoint(results []STUNServerResult) (bool, bool) {
	groups := make(map[string][]string)
	for _, result := range results {
		if result.LocalEndpoint == "" || result.MappedEndpoint == "" {
			continue
		}
		groups[result.LocalEndpoint] = append(groups[result.LocalEndpoint], result.MappedEndpoint)
	}
	for _, endpoints := range groups {
		if len(endpoints) < 2 {
			continue
		}
		return allStringsEqual(endpoints), true
	}
	return false, false
}

func allMappedEndpointsEqual(results []STUNServerResult) bool {
	firstEndpoint := results[0].MappedEndpoint
	for _, result := range results[1:] {
		if result.MappedEndpoint != firstEndpoint {
			return false
		}
	}
	return true
}

func allStringsEqual(values []string) bool {
	for _, value := range values[1:] {
		if value != values[0] {
			return false
		}
	}
	return true
}

func portPreserving(results []STUNServerResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		localPort, ok := endpointPort(result.LocalEndpoint)
		if !ok {
			return false
		}
		mappedPort, ok := endpointPort(result.MappedEndpoint)
		if !ok || mappedPort != localPort {
			return false
		}
	}
	return true
}

func endpointPort(endpoint string) (uint16, bool) {
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return 0, false
	}
	return addrPort.Port(), true
}

func localCandidates(publicEndpoints []string) (CandidateReport, error) {
	var raw []string
	addrs, err := interfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			raw = append(raw, addr.String())
		}
	}
	raw = append(raw, publicEndpoints...)
	return CategorizeCandidateAddresses(raw), err
}

func (r STUNServerResult) String() string {
	parts := []string{r.Server}
	if r.LocalEndpoint != "" {
		parts = append(parts, "local="+r.LocalEndpoint)
	}
	if r.MappedEndpoint != "" {
		parts = append(parts, "mapped="+r.MappedEndpoint)
	}
	if r.Error != "" {
		parts = append(parts, "error="+r.Error)
	}
	return strings.Join(parts, " ")
}
