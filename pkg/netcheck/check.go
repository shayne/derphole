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
	defer conn.Close()
	if udp, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udp.Port
	}
	return 0
}

func defaultProbeSTUNServer(ctx context.Context, server string, localPort int) STUNServerResult {
	result := STUNServerResult{Server: server}
	address := "0.0.0.0:0"
	if localPort > 0 {
		address = net.JoinHostPort("0.0.0.0", strconv.Itoa(localPort))
	}
	conn, err := net.ListenPacket("udp4", address)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
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

	buf := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			return result
		}
		deadline := time.Now().Add(250 * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			result.Error = err.Error()
			return result
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			result.Error = err.Error()
			return result
		}
		gotTxID, mapped, err := stun.ParseResponse(buf[:n])
		if err != nil || gotTxID != txID {
			continue
		}
		result.MappedEndpoint = mapped.String()
		return result
	}
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
		first := endpoints[0]
		for _, endpoint := range endpoints[1:] {
			if endpoint != first {
				return false
			}
		}
		return true
	}
	firstEndpoint := results[0].MappedEndpoint
	for _, result := range results[1:] {
		if result.MappedEndpoint != firstEndpoint {
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
