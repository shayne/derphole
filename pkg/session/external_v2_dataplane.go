// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/probe"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/transport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	externalV2DataPlaneReadyWait        = 5 * time.Second
	externalV2DataPlaneRetry            = 250 * time.Millisecond
	externalV2DataPlaneReinforce        = 1 * time.Second
	externalV2DataPlaneReinforceTick    = 100 * time.Millisecond
	externalV2DataPlaneCandidateWait    = 750 * time.Millisecond
	externalV2DataPlaneSenderPunchDelay = 350 * time.Millisecond

	externalV2DataPlanePhaseCandidates = "candidates"
	externalV2DataPlanePhaseSelection  = "selection"
)

type externalV2DirectPacketPath struct {
	conn    net.PacketConn
	addr    net.Addr
	conns   []net.PacketConn
	addrs   []net.Addr
	raw     bool
	cleanup func()
}

var externalV2InterfaceAddrs = net.InterfaceAddrs
var externalV2DefaultRouteIPv4 = defaultRouteIPv4

func (p externalV2DirectPacketPath) Close() {
	if p.cleanup != nil {
		p.cleanup()
	}
}

func negotiateExternalV2DirectPacketPath(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, manager *transport.Manager, dm *tailcfg.DERPMap, auth externalPeerControlAuth, emitter *telemetry.Emitter, streamCount int, punchDelay time.Duration) (externalV2DirectPacketPath, error) {
	if !externalV2CanUseRawDirect(manager) {
		return externalV2DirectPacketPath{}, nil
	}
	var local externalV2DataPacketPath
	localRawDirect := false
	if externalV2RawDirectEnabled() {
		var ok bool
		local, ok = openExternalV2RawDirectLocal(ctx, dm, emitter, streamCount)
		localRawDirect = ok
	} else {
		emitExternalV2Debug(emitter, "v2-raw-direct-local=false disabled=true")
	}
	readyCh, unsubscribe := subscribeExternalV2DataPlaneReady(client, peerDERP)
	defer unsubscribe()

	peerReady, peerCandidates, err := exchangeExternalV2RawDirectPeer(ctx, client, peerDERP, readyCh, localRawDirect, local.candidates, local.candidateSets, auth, emitter)
	if err != nil {
		local.Close()
		return externalV2DirectPacketPath{}, err
	}
	path := selectExternalV2RawDirectPath(ctx, local, peerReady, peerCandidates, emitter, punchDelay)
	peerSelected, err := exchangeExternalV2RawDirectSelection(ctx, client, peerDERP, readyCh, path.raw, auth)
	if err != nil {
		path.Close()
		return externalV2DirectPacketPath{}, err
	}
	return finalizeExternalV2RawDirectPath(path, peerSelected, emitter), nil
}

func externalV2CanUseRawDirect(manager *transport.Manager) bool {
	return manager != nil
}

func openExternalV2RawDirectLocal(ctx context.Context, dm *tailcfg.DERPMap, emitter *telemetry.Emitter, streamCount int) (externalV2DataPacketPath, bool) {
	local, err := openExternalV2DataPacketPath(ctx, dm, emitter, streamCount)
	if err != nil {
		emitExternalV2Debug(emitter, "v2-raw-direct-open-error="+err.Error())
		return externalV2DataPacketPath{}, false
	}
	if len(local.conns) == 0 || len(local.candidates) == 0 {
		local.Close()
		emitExternalV2Debug(emitter, "v2-raw-direct-local=false")
		return externalV2DataPacketPath{}, false
	}
	emitExternalV2Debug(emitter, "v2-raw-direct-local=true candidates="+strconv.Itoa(len(local.candidates)))
	return local, true
}

func subscribeExternalV2DataPlaneReady(client *derpbind.Client, peerDERP key.NodePublic) (<-chan derpbind.Packet, func()) {
	return client.SubscribeLossless(func(pkt derpbind.Packet) bool {
		return pkt.From == peerDERP && isV2DataPlaneReadyPayload(pkt.Payload)
	})
}

func exchangeExternalV2RawDirectPeer(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, readyCh <-chan derpbind.Packet, rawDirect bool, candidates []string, candidateSets [][]string, auth externalPeerControlAuth, emitter *telemetry.Emitter) (externalV2DataPlaneReady, []net.Addr, error) {
	peerReady, err := exchangeExternalV2DataPlaneReady(ctx, client, peerDERP, readyCh, externalV2DataPlanePhaseCandidates, rawDirect, candidates, candidateSets, auth)
	if err != nil {
		return externalV2DataPlaneReady{}, nil, err
	}
	peerReady.Candidates = filterExternalV2DataPacketCandidateStrings(peerReady.Candidates)
	peerReady.CandidateSets = filterExternalV2DataPacketCandidateSets(peerReady.CandidateSets)
	peerCandidates := parseCandidateStrings(peerReady.Candidates)
	emitExternalV2Debug(emitter, "v2-raw-direct-peer="+boolString(peerReady.RawDirect)+" candidates="+strconv.Itoa(len(peerCandidates)))
	return peerReady, peerCandidates, nil
}

func exchangeExternalV2RawDirectSelection(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, readyCh <-chan derpbind.Packet, selected bool, auth externalPeerControlAuth) (bool, error) {
	peerReady, err := exchangeExternalV2DataPlaneReady(ctx, client, peerDERP, readyCh, externalV2DataPlanePhaseSelection, selected, nil, nil, auth)
	if err != nil {
		return false, err
	}
	return peerReady.RawDirect, nil
}

func selectExternalV2RawDirectPath(ctx context.Context, local externalV2DataPacketPath, peerReady externalV2DataPlaneReady, peerCandidates []net.Addr, emitter *telemetry.Emitter, punchDelay time.Duration) externalV2DirectPacketPath {
	if len(local.conns) == 0 {
		emitExternalV2Debug(emitter, "v2-raw-direct-local-selection=false")
		return externalV2DirectPacketPath{}
	}
	if !peerReady.RawDirect || len(peerCandidates) == 0 {
		local.Close()
		emitExternalV2Debug(emitter, "v2-raw-direct-local-selection=false")
		return externalV2DirectPacketPath{}
	}

	addrs := selectExternalV2DataPacketAddrs(ctx, local.conns, peerReady.CandidateSets, peerCandidates, emitter, punchDelay)
	if len(addrs) == 0 {
		local.Close()
		emitExternalV2Debug(emitter, "v2-raw-direct-local-selection=false")
		return externalV2DirectPacketPath{}
	}
	for _, conn := range local.conns {
		_ = conn.SetDeadline(time.Time{})
	}
	emitExternalV2Debug(emitter, "v2-raw-direct-addr="+joinNetAddrs(addrs))
	emitExternalV2Debug(emitter, "v2-raw-direct-active="+strconv.Itoa(len(addrs)))
	emitExternalV2Debug(emitter, "v2-raw-direct-local-selection=true")
	return externalV2DirectPacketPath{conn: local.conns[0], addr: addrs[0], conns: local.conns[:len(addrs)], addrs: addrs, raw: true, cleanup: local.cleanup}
}

func finalizeExternalV2RawDirectPath(path externalV2DirectPacketPath, peerSelected bool, emitter *telemetry.Emitter) externalV2DirectPacketPath {
	if !path.raw {
		emitExternalV2Debug(emitter, "v2-data-plane=manager")
		return externalV2DirectPacketPath{}
	}
	if !peerSelected {
		path.Close()
		emitExternalV2Debug(emitter, "v2-raw-direct-peer-selection=false")
		emitExternalV2Debug(emitter, "v2-data-plane=manager")
		return externalV2DirectPacketPath{}
	}
	emitExternalV2Debug(emitter, "v2-raw-direct-peer-selection=true")
	emitExternalV2Debug(emitter, "v2-data-plane=raw-direct")
	return path
}

func externalV2RawDirectEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DERPHOLE_V2_RAW_DIRECT"))) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

type externalV2DataPacketPath struct {
	conns         []net.PacketConn
	candidates    []string
	candidateSets [][]string
	cleanup       func()
}

func (p externalV2DataPacketPath) Close() {
	if p.cleanup != nil {
		p.cleanup()
	}
}

func openExternalV2DataPacketPath(ctx context.Context, dm *tailcfg.DERPMap, emitter *telemetry.Emitter, streamCount int) (externalV2DataPacketPath, error) {
	count := externalV2RawDirectSocketCount(streamCount)
	conns := make([]net.PacketConn, 0, count)
	portmaps := make([]publicPortmap, 0, count)
	listenAddr := externalV2DataPacketListenAddr()
	for range count {
		conn, err := net.ListenPacket("udp4", listenAddr)
		if err != nil && listenAddr != ":0" {
			conn, err = net.ListenPacket("udp4", ":0")
		}
		if err != nil {
			closeExternalV2DataPacketResources(conns, portmaps)
			return externalV2DataPacketPath{}, err
		}
		conns = append(conns, conn)
		portmaps = append(portmaps, newBoundPublicPortmap(conn, emitter))
		_ = probe.PreviewTransportCaps(conn, "batched")
	}
	cleanup := func() {
		closeExternalV2DataPacketResources(conns, portmaps)
	}
	candidateSets := externalV2DataPacketCandidates(ctx, conns, portmaps, dm)
	var candidates []string
	for _, set := range candidateSets {
		candidates = append(candidates, set...)
	}
	return externalV2DataPacketPath{conns: conns, candidates: candidates, candidateSets: candidateSets, cleanup: cleanup}, nil
}

func externalV2DataPacketListenAddr() string {
	ip := externalV2DefaultRouteIPv4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.To4() == nil {
		return ":0"
	}
	return net.JoinHostPort(ip.String(), "0")
}

func defaultRouteIPv4() net.IP {
	conn, err := net.DialTimeout("udp4", "198.51.100.1:9", 100*time.Millisecond)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return nil
	}
	return addr.IP.To4()
}

func externalV2RawDirectSocketCount(streamCount int) int {
	if streamCount < 1 {
		return 1
	}
	if streamCount > MaxParallelStripes {
		return MaxParallelStripes
	}
	return streamCount
}

func closeExternalV2DataPacketResources(conns []net.PacketConn, portmaps []publicPortmap) {
	for _, pm := range portmaps {
		if pm != nil {
			_ = pm.Close()
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func externalV2DataPacketCandidates(ctx context.Context, conns []net.PacketConn, portmaps []publicPortmap, dm *tailcfg.DERPMap) [][]string {
	sets := externalDirectUDPCandidateSetsWithTimeout(ctx, conns, dm, portmaps, externalV2DataPlaneCandidateWait)
	return externalDirectUDPInferWANPerPort(sets)
}

func selectExternalV2DataPacketAddrs(ctx context.Context, conns []net.PacketConn, peerCandidateSets [][]string, peerCandidates []net.Addr, emitter *telemetry.Emitter, punchDelay time.Duration) []net.Addr {
	switch {
	case len(conns) == 0:
		return nil
	case len(peerCandidateSets) > 0:
		return selectExternalV2DataPacketAddrsBySet(ctx, conns, peerCandidateSets, emitter, punchDelay)
	case len(peerCandidates) == 0:
		return nil
	default:
		return selectExternalV2DataPacketAddrsByFlatCandidates(ctx, conns, peerCandidates, emitter, punchDelay)
	}
}

func selectExternalV2DataPacketAddrsByFlatCandidates(ctx context.Context, conns []net.PacketConn, peerCandidates []net.Addr, emitter *telemetry.Emitter, punchDelay time.Duration) []net.Addr {
	peerCandidates = filterExternalV2DataPacketAddrs(peerCandidates)
	if len(peerCandidates) == 0 {
		return nil
	}
	fallback := externalDirectUDPParallelCandidateStringsForPeer(peerCandidates, len(conns), nil)
	fallback = externalDirectUDPFilterFallbackAddrsForSelectedScope(nil, fallback)
	if addrs := externalV2DataPacketCleanPrivateFallbackAddrs(conns, fallback, true); len(addrs) > 0 {
		emitExternalV2CleanPrivateFallbackSelection(emitter, fallback)
		return addrs
	}
	punchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	startExternalV2DataPacketPunching(punchCtx, conns, peerCandidates, punchDelay)

	observedByConn := externalDirectUDPObservePunchAddrsByConn(ctx, conns, externalDirectUDPPunchWait)
	observedByConn = filterExternalV2DataPacketObservedAddrs(observedByConn)
	if emitter != nil {
		emitter.Debug("v2-raw-direct-observed-addrs=" + externalDirectUDPFormatObservedAddrsByConn(observedByConn))
	}
	selected := externalDirectUDPSelectRemoteAddrsByConn(observedByConn, conns, len(conns), nil)
	if emitter != nil {
		emitter.Debug("v2-raw-direct-selected-addrs=" + formatExternalV2SelectedAddrs(selected))
	}
	fallback = externalDirectUDPFilterFallbackAddrsForSelectedScope(selected, fallback)
	if emitter != nil {
		emitter.Debug("v2-raw-direct-fallback-addrs=" + strings.Join(fallback, ","))
	}
	if !externalV2DataPacketSelectionAllowed(ctx, conns, selected, fallback, true, emitter) {
		return nil
	}
	return selectedExternalV2DataPacketAddrs(conns, selected, fallback, true)
}

func selectExternalV2DataPacketAddrsBySet(ctx context.Context, conns []net.PacketConn, peerCandidateSets [][]string, emitter *telemetry.Emitter, punchDelay time.Duration) []net.Addr {
	peerCandidateSets = filterExternalV2DataPacketCandidateSets(peerCandidateSets)
	count := externalV2DataPacketSetCount(conns, peerCandidateSets)
	if count == 0 {
		return nil
	}
	peerAddrsBySet, ok := externalV2DataPacketPeerAddrsBySet(peerCandidateSets, count)
	if !ok {
		return nil
	}
	fallback := fallbackExternalV2DataPacketSetAddrs(conns, peerAddrsBySet, count)
	if addrs := externalV2DataPacketCleanPrivateFallbackAddrs(conns[:count], fallback, false); len(addrs) > 0 {
		emitExternalV2CleanPrivateFallbackSelection(emitter, fallback)
		return addrs
	}
	punchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := range count {
		startExternalV2DataPacketPunching(punchCtx, []net.PacketConn{conns[i]}, peerAddrsBySet[i], punchDelay)
	}
	observedByConn := externalDirectUDPObservePunchAddrsByConn(ctx, conns[:count], externalDirectUDPPunchWait)
	observedByConn = filterExternalV2DataPacketObservedAddrs(observedByConn)
	if emitter != nil {
		emitter.Debug("v2-raw-direct-observed-addrs=" + externalDirectUDPFormatObservedAddrsByConn(observedByConn))
	}
	selected := selectedExternalV2DataPacketSetAddrs(observedByConn, count)
	if emitter != nil {
		emitter.Debug("v2-raw-direct-selected-addrs=" + formatExternalV2SelectedAddrs(selected))
	}
	if emitter != nil {
		emitter.Debug("v2-raw-direct-fallback-addrs=" + strings.Join(fallback, ","))
	}
	if !externalV2DataPacketSelectionAllowed(ctx, conns[:count], selected, fallback, false, emitter) {
		return nil
	}
	return selectedExternalV2DataPacketAddrs(conns[:count], selected, fallback, false)
}

func emitExternalV2CleanPrivateFallbackSelection(emitter *telemetry.Emitter, fallback []string) {
	if emitter == nil {
		return
	}
	emitter.Debug("v2-raw-direct-observed-addrs=none")
	emitter.Debug("v2-raw-direct-selected-addrs=none")
	emitter.Debug("v2-raw-direct-fallback-addrs=" + strings.Join(fallback, ","))
	emitter.Debug("v2-raw-direct-clean-private-fallback=true")
}

func startExternalV2DataPacketPunching(ctx context.Context, conns []net.PacketConn, peerCandidates []net.Addr, delay time.Duration) {
	if delay <= 0 {
		externalDirectUDPStartPunching(ctx, conns, peerCandidates)
		return
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			externalDirectUDPStartPunching(ctx, conns, peerCandidates)
		}
	}()
}

func filterExternalV2DataPacketObservedAddrs(observedByConn [][]net.Addr) [][]net.Addr {
	filtered := make([][]net.Addr, len(observedByConn))
	for i, observed := range observedByConn {
		filtered[i] = filterExternalV2DataPacketAddrs(observed)
	}
	return filtered
}

func filterExternalV2DataPacketAddrs(addrs []net.Addr) []net.Addr {
	if len(addrs) == 0 {
		return nil
	}
	filtered := make([]net.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addrPort, ok := externalDirectUDPAddrPort(addr)
		if !ok || !publicProbeCandidateAllowed(addrPort.Addr()) {
			continue
		}
		filtered = append(filtered, addr)
	}
	return filtered
}

func filterExternalV2DataPacketCandidateSets(candidateSets [][]string) [][]string {
	if len(candidateSets) == 0 {
		return nil
	}
	filtered := make([][]string, len(candidateSets))
	for i, candidates := range candidateSets {
		filtered[i] = filterExternalV2DataPacketCandidateStrings(candidates)
	}
	return filtered
}

func filterExternalV2DataPacketCandidateStrings(candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
		if !ok || !publicProbeCandidateAllowed(addrPort.Addr()) {
			continue
		}
		filtered = append(filtered, addrPort.String())
	}
	return filtered
}

func externalV2DataPacketSetCount(conns []net.PacketConn, peerCandidateSets [][]string) int {
	if len(peerCandidateSets) < len(conns) {
		return len(peerCandidateSets)
	}
	return len(conns)
}

func externalV2DataPacketPeerAddrsBySet(peerCandidateSets [][]string, count int) ([][]net.Addr, bool) {
	peerAddrsBySet := make([][]net.Addr, count)
	for i := range count {
		peerAddrsBySet[i] = parseCandidateStrings(peerCandidateSets[i])
		if len(peerAddrsBySet[i]) == 0 {
			return nil, false
		}
	}
	return peerAddrsBySet, true
}

func selectedExternalV2DataPacketSetAddrs(observedByConn [][]net.Addr, count int) []string {
	selected := make([]string, count)
	for i := range count {
		if i >= len(observedByConn) || len(observedByConn[i]) == 0 {
			continue
		}
		observed := externalDirectUDPParallelCandidateStrings(observedByConn[i], 1)
		if len(observed) > 0 {
			selected[i] = observed[0]
		}
	}
	return selected
}

func fallbackExternalV2DataPacketSetAddrs(conns []net.PacketConn, peerAddrsBySet [][]net.Addr, count int) []string {
	fallback := make([]string, count)
	for i := range count {
		if i < len(conns) {
			if candidate := externalV2DataPacketRoutablePrivateFallback(conns[i], peerAddrsBySet[i]); candidate != "" {
				fallback[i] = candidate
				continue
			}
		}
		candidates := externalDirectUDPParallelCandidateStringsForPeer(peerAddrsBySet[i], 1, nil)
		if len(candidates) > 0 {
			fallback[i] = candidates[0]
		}
	}
	return fallback
}

func externalV2DataPacketCleanPrivateFallbackAddrs(conns []net.PacketConn, fallback []string, allowFallbackPool bool) []net.Addr {
	addrs := make([]net.Addr, 0, len(conns))
	seenEndpoint := make(map[string]bool)
	for i, conn := range conns {
		candidate := externalV2DataPacketCleanPrivateFallbackCandidate(conn, i, fallback, allowFallbackPool, seenEndpoint)
		if candidate == "" {
			break
		}
		parsed := parseCandidateStrings([]string{candidate})
		if len(parsed) != 1 {
			break
		}
		addrs = append(addrs, parsed[0])
		seenEndpoint[externalDirectUDPEndpointKey(candidate)] = true
	}
	return addrs
}

func externalV2DataPacketCleanPrivateFallbackCandidate(conn net.PacketConn, index int, fallback []string, allowFallbackPool bool, seenEndpoint map[string]bool) string {
	_ = conn
	for _, candidate := range externalV2DataPacketFallbackCandidatesForLane(index, fallback, allowFallbackPool) {
		if !externalV2DataPacketUsablePrivateFallback(candidate) {
			continue
		}
		endpoint := externalDirectUDPEndpointKey(candidate)
		if seenEndpoint[endpoint] {
			continue
		}
		return candidate
	}
	return ""
}

func externalV2DataPacketRoutablePrivateFallback(conn net.PacketConn, candidates []net.Addr) string {
	_ = conn
	for _, candidate := range externalDirectUDPOrderedCandidateStringsForPeer(candidates, nil) {
		if !externalV2DataPacketUsablePrivateFallback(candidate) {
			continue
		}
		return candidate
	}
	return ""
}

func selectedExternalV2DataPacketAddrs(conns []net.PacketConn, selected []string, fallback []string, allowFallbackPool bool) []net.Addr {
	addrs := make([]net.Addr, 0, len(conns))
	for i, conn := range conns {
		candidate := selectExternalV2DataPacketCandidate(conn, i, selected, fallback, allowFallbackPool)
		if candidate == "" {
			break
		}
		parsed := parseCandidateStrings([]string{candidate})
		if len(parsed) != 1 {
			break
		}
		addrs = append(addrs, parsed[0])
	}
	return addrs
}

func externalV2DataPacketSelectionObserved(ctx context.Context, selected []string, emitter *telemetry.Emitter) bool {
	if externalDirectUDPSelectedAddrCount(selected) > 0 || externalDirectUDPAllowUnverifiedFallback(ctx) {
		return true
	}
	if emitter != nil {
		emitter.Debug("v2-raw-direct-no-observed-addrs")
	}
	return false
}

func externalV2DataPacketSelectionAllowed(ctx context.Context, conns []net.PacketConn, selected []string, fallback []string, allowFallbackPool bool, emitter *telemetry.Emitter) bool {
	if externalV2DataPacketSelectionObserved(ctx, selected, nil) {
		return true
	}
	if externalV2DataPacketHasRoutablePrivateFallback(conns, fallback, allowFallbackPool) {
		return true
	}
	if emitter != nil {
		emitter.Debug("v2-raw-direct-no-observed-addrs")
	}
	return false
}

func externalV2DataPacketHasRoutablePrivateFallback(conns []net.PacketConn, fallback []string, allowFallbackPool bool) bool {
	for i, conn := range conns {
		_ = conn
		for _, candidate := range externalV2DataPacketFallbackCandidatesForLane(i, fallback, allowFallbackPool) {
			if !externalV2DataPacketUsablePrivateFallback(candidate) {
				continue
			}
			return true
		}
	}
	return false
}

func externalV2DataPacketFallbackCandidatesForLane(index int, fallback []string, allowFallbackPool bool) []string {
	candidates := make([]string, 0, 1+len(fallback))
	if index >= 0 && index < len(fallback) && fallback[index] != "" {
		candidates = append(candidates, fallback[index])
	}
	if allowFallbackPool {
		candidates = append(candidates, fallback...)
	}
	return candidates
}

func externalV2DataPacketUsablePrivateFallback(candidate string) bool {
	addrPort, ok := externalDirectUDPParsedCandidateAddrPort(candidate)
	return ok && externalV2DataPacketOnLinkPrivateAddr(addrPort.Addr())
}

func externalV2DataPacketOnLinkPrivateAddr(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.Is4() || !addr.IsPrivate() {
		return false
	}
	prefixes, err := externalV2InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, rawPrefix := range prefixes {
		if externalV2DataPacketPrefixContainsPrivatePeer(rawPrefix, addr) {
			return true
		}
	}
	return false
}

func externalV2DataPacketPrefixContainsPrivatePeer(rawPrefix net.Addr, addr netip.Addr) bool {
	prefix, err := netip.ParsePrefix(rawPrefix.String())
	if err != nil {
		return false
	}
	local := prefix.Addr()
	if !local.IsValid() || !local.IsPrivate() || local.IsLoopback() || local == addr {
		return false
	}
	return prefix.Contains(addr)
}

func selectExternalV2DataPacketCandidate(conn net.PacketConn, index int, selected []string, fallback []string, allowFallbackPool bool) string {
	candidates := make([]string, 0, 1+len(fallback))
	if index < len(selected) && selected[index] != "" {
		return selected[index]
	}
	if index < len(fallback) && fallback[index] != "" {
		candidates = append(candidates, fallback[index])
	}
	if allowFallbackPool {
		candidates = append(candidates, fallback...)
	}
	for _, candidate := range candidates {
		if candidate == "" || !externalDirectUDPRouteCandidate(conn, candidate) {
			continue
		}
		return candidate
	}
	return ""
}

func joinNetAddrs(addrs []net.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr != nil {
			parts = append(parts, addr.String())
		}
	}
	return strings.Join(parts, ",")
}

func formatExternalV2SelectedAddrs(selected []string) string {
	parts := make([]string, 0, len(selected))
	for _, addr := range selected {
		if addr != "" {
			parts = append(parts, addr)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func exchangeExternalV2DataPlaneReady(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, readyCh <-chan derpbind.Packet, phase string, rawDirect bool, candidates []string, candidateSets [][]string, auth externalPeerControlAuth) (externalV2DataPlaneReady, error) {
	readyCtx, cancel := context.WithTimeout(ctx, externalV2DataPlaneReadyWait)
	defer cancel()
	if err := sendExternalV2DataPlaneReady(readyCtx, client, peerDERP, phase, rawDirect, candidates, candidateSets, auth); err != nil {
		return externalV2DataPlaneReady{}, err
	}
	ticker := time.NewTicker(externalV2DataPlaneRetry)
	defer ticker.Stop()
	for {
		select {
		case pkt, ok := <-readyCh:
			ready, ok, err := externalV2DataPlaneReadyFromPacket(pkt, ok, phase, auth)
			if err != nil {
				return externalV2DataPlaneReady{}, err
			}
			if ok {
				reinforceExternalV2DataPlaneReady(ctx, client, peerDERP, phase, rawDirect, candidates, candidateSets, auth)
				return ready, nil
			}
		case <-ticker.C:
			if err := sendExternalV2DataPlaneReady(readyCtx, client, peerDERP, phase, rawDirect, candidates, candidateSets, auth); err != nil {
				return externalV2DataPlaneReady{}, err
			}
		case <-readyCtx.Done():
			return externalV2DataPlaneReady{}, readyCtx.Err()
		}
	}
}

func externalV2DataPlaneReadyFromPacket(pkt derpbind.Packet, packetOK bool, phase string, auth externalPeerControlAuth) (externalV2DataPlaneReady, bool, error) {
	if !packetOK {
		return externalV2DataPlaneReady{}, false, ErrPeerDisconnected
	}
	ready, ok, err := externalV2DataPlaneReadyFromPayload(pkt.Payload, auth)
	if err != nil || !ok || !externalV2DataPlaneReadyPhaseMatches(ready.Phase, phase) {
		return externalV2DataPlaneReady{}, false, err
	}
	return ready, true, nil
}

func externalV2DataPlaneReadyPhaseMatches(got string, want string) bool {
	return got == want || (got == "" && want == externalV2DataPlanePhaseCandidates)
}

func reinforceExternalV2DataPlaneReady(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, phase string, rawDirect bool, candidates []string, candidateSets [][]string, auth externalPeerControlAuth) {
	_ = sendExternalV2DataPlaneReady(ctx, client, peerDERP, phase, rawDirect, candidates, candidateSets, auth)
	go func() {
		deadline := time.NewTimer(externalV2DataPlaneReinforce)
		defer deadline.Stop()
		ticker := time.NewTicker(externalV2DataPlaneReinforceTick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
				_ = sendExternalV2DataPlaneReady(ctx, client, peerDERP, phase, rawDirect, candidates, candidateSets, auth)
			}
		}
	}()
}

func sendExternalV2DataPlaneReady(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, phase string, rawDirect bool, candidates []string, candidateSets [][]string, auth externalPeerControlAuth) error {
	ready := externalV2DataPlaneReady{Protocol: externalV2Protocol, Phase: phase, RawDirect: rawDirect, Candidates: candidates, CandidateSets: candidateSets}
	return sendAuthenticatedEnvelope(ctx, client, peerDERP, envelope{
		Type:             envelopeV2DataPlaneReady,
		V2DataPlaneReady: &ready,
	}, auth)
}

func externalV2DataPlaneReadyFromPayload(payload []byte, auth externalPeerControlAuth) (externalV2DataPlaneReady, bool, error) {
	env, ok, err := externalV2EnvelopeFromPayload(payload, auth)
	if err != nil || !ok || env.Type != envelopeV2DataPlaneReady || env.V2DataPlaneReady == nil {
		return externalV2DataPlaneReady{}, false, err
	}
	if env.V2DataPlaneReady.Protocol != externalV2Protocol {
		return externalV2DataPlaneReady{}, false, errExternalV2Unsupported
	}
	return *env.V2DataPlaneReady, true, nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
