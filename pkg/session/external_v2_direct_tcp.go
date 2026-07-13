// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
	"github.com/shayne/derphole/pkg/telemetry"
	"tailscale.com/types/key"
)

const (
	externalV2DirectTCPLaneCount       = 8
	externalV2DirectTCPLaneRequestSize = 60
	externalV2DirectTCPChunkSize       = 1 << 20
	externalV2DirectTCPEstablishWait   = 5 * time.Second
	externalV2DirectTCPDialWait        = 750 * time.Millisecond
	externalV2DirectTCPProtocol        = "derphole-direct-tcp-files-v1"
	externalV2DataPlanePhaseDirectTCP  = "direct-tcp-files"
)

var externalV2DirectTCPLaneMagic = [4]byte{'D', 'H', 'T', 'R'}
var externalV2DirectTCPLaneAuthDomain = []byte("derphole-direct-tcp-lane-auth-v1")

type externalV2DirectTCPAdvertisement struct {
	Candidates        []string `json:"candidates"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	TransferID        string   `json:"transfer_id"`
}

type externalV2DirectTCPListener struct {
	listener  net.Listener
	tlsConfig *tls.Config
	ad        externalV2DirectTCPAdvertisement
	closeOnce sync.Once
}

type externalV2DirectTCPPath struct {
	conns     []*tls.Conn
	selected  []string
	closeOnce sync.Once
}

func (p *externalV2DirectTCPPath) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		for _, conn := range p.conns {
			if conn != nil {
				raw := conn.NetConn()
				_ = raw.SetDeadline(time.Now())
				_ = raw.Close()
			}
		}
	})
}

func (p *externalV2DirectTCPPath) writers() []io.WriteCloser {
	result := make([]io.WriteCloser, len(p.conns))
	for i, conn := range p.conns {
		result[i] = conn
	}
	return result
}

func (p *externalV2DirectTCPPath) readers() []io.ReadCloser {
	result := make([]io.ReadCloser, len(p.conns))
	for i, conn := range p.conns {
		result[i] = conn
	}
	return result
}

func externalV2DirectTCPAdvertisementUsable(ad *externalV2DirectTCPAdvertisement) bool {
	return validateExternalV2DirectTCPAdvertisement(ad) == nil
}

func validateExternalV2DirectTCPAdvertisement(ad *externalV2DirectTCPAdvertisement) error {
	if ad == nil {
		return errors.New("direct TCP advertisement is absent")
	}
	if err := validateExternalV2DirectTCPCandidateList(ad.Candidates); err != nil {
		return err
	}
	if !externalV2DirectTCPHexLength(ad.FingerprintSHA256, sha256.Size) {
		return errors.New("direct TCP fingerprint must be 64 hexadecimal characters")
	}
	if !externalV2DirectTCPHexLength(ad.TransferID, 16) {
		return errors.New("direct TCP transfer ID must be 32 hexadecimal characters")
	}
	return nil
}

func validateExternalV2DirectTCPCandidateList(candidates []string) error {
	if len(candidates) == 0 || len(candidates) > externalV2DirectTCPLaneCount {
		return fmt.Errorf("direct TCP candidate count %d is outside [1,%d]", len(candidates), externalV2DirectTCPLaneCount)
	}
	seen := make(map[netip.AddrPort]struct{}, len(candidates))
	for _, candidate := range candidates {
		addr, err := netip.ParseAddrPort(candidate)
		if err != nil || !addr.IsValid() || addr.Addr().IsUnspecified() || addr.Port() == 0 {
			return fmt.Errorf("invalid direct TCP candidate %q", candidate)
		}
		if _, ok := seen[addr]; ok {
			return fmt.Errorf("duplicate direct TCP candidate %q", candidate)
		}
		seen[addr] = struct{}{}
	}
	return nil
}

func externalV2DirectTCPHexLength(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size
}

func externalV2DirectTCPCandidates(udpCandidates []string, port int) []string {
	if port <= 0 || port > 65535 {
		return nil
	}
	seen := make(map[string]struct{}, len(udpCandidates))
	result := make([]string, 0, min(len(udpCandidates), externalV2DirectTCPLaneCount))
	for _, candidate := range udpCandidates {
		addrPort, err := netip.ParseAddrPort(candidate)
		if err != nil || !addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified() {
			continue
		}
		candidate = netip.AddrPortFrom(addrPort.Addr().Unmap(), uint16(port)).String()
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	slices.SortStableFunc(result, compareExternalV2DirectTCPCandidates)
	if len(result) > externalV2DirectTCPLaneCount {
		result = result[:externalV2DirectTCPLaneCount]
	}
	return result
}

func compareExternalV2DirectTCPCandidates(a, b string) int {
	ra, rb := externalV2RawDirectCandidateRank(a), externalV2RawDirectCandidateRank(b)
	if ra != rb {
		return ra - rb
	}
	return strings.Compare(a, b)
}

func openConfiguredExternalV2DirectTCPListener(port int, udpCandidates []string, emitter *telemetry.Emitter) *externalV2DirectTCPListener {
	if port == 0 {
		return nil
	}
	if port < 0 || port > 65535 {
		emitExternalV2Debug(emitter, fmt.Sprintf("v2-direct-tcp-listen-error=invalid port %d", port))
		return nil
	}
	candidates := externalV2DirectTCPCandidates(udpCandidates, port)
	if len(candidates) == 0 {
		emitExternalV2Debug(emitter, "v2-direct-tcp-listen-error=no candidates")
		return nil
	}
	listener, err := openExternalV2DirectTCPListener(fmt.Sprintf("0.0.0.0:%d", port), candidates)
	if err != nil {
		emitExternalV2Debug(emitter, "v2-direct-tcp-listen-error="+err.Error())
		return nil
	}
	emitExternalV2Debug(emitter, "v2-direct-tcp-listen=true candidates="+fmt.Sprint(len(candidates)))
	return listener
}

func openExternalV2DirectTCPListener(listenAddr string, candidates []string) (*externalV2DirectTCPListener, error) {
	certificate, fingerprint, err := newExternalV2DirectTCPCertificate(time.Now())
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		candidates = []string{listener.Addr().String()}
	}
	var transferID [16]byte
	if _, err := rand.Read(transferID[:]); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("generate direct TCP transfer ID: %w", err)
	}
	result := &externalV2DirectTCPListener{
		listener: listener,
		ad: externalV2DirectTCPAdvertisement{
			Candidates:        append([]string(nil), candidates...),
			FingerprintSHA256: fingerprint,
			TransferID:        hex.EncodeToString(transferID[:]),
		},
		tlsConfig: &tls.Config{
			Certificates:                []tls.Certificate{certificate},
			MinVersion:                  tls.VersionTLS13,
			MaxVersion:                  tls.VersionTLS13,
			NextProtos:                  []string{externalV2DirectTCPProtocol},
			DynamicRecordSizingDisabled: true,
		},
	}
	if err := validateExternalV2DirectTCPAdvertisement(&result.ad); err != nil {
		result.Close()
		return nil, err
	}
	return result, nil
}

func (l *externalV2DirectTCPListener) Close() {
	if l == nil {
		return
	}
	l.closeOnce.Do(func() { _ = l.listener.Close() })
}

func (l *externalV2DirectTCPListener) accept(ctx context.Context, auth externalPeerControlAuth) (*externalV2DirectTCPPath, error) {
	transferID, err := decodeExternalV2DirectTCPTransferID(l.ad.TransferID)
	if err != nil {
		return nil, err
	}
	lanes := make([]*tls.Conn, externalV2DirectTCPLaneCount)
	selected := make([]string, externalV2DirectTCPLaneCount)
	defer l.Close()
	if tcpListener, ok := l.listener.(*net.TCPListener); ok {
		if deadline, ok := ctx.Deadline(); ok {
			_ = tcpListener.SetDeadline(deadline)
		}
	}
	for accepted := 0; accepted < externalV2DirectTCPLaneCount; accepted++ {
		conn, lane, err := l.acceptLane(ctx, transferID, auth)
		if err != nil {
			closeExternalV2DirectTCPConns(lanes)
			return nil, err
		}
		if lanes[lane] != nil {
			_ = conn.Close()
			closeExternalV2DirectTCPConns(lanes)
			return nil, fmt.Errorf("duplicate direct TCP lane %d", lane)
		}
		_ = conn.SetDeadline(time.Time{})
		lanes[lane] = conn
		selected[lane] = conn.RemoteAddr().String()
	}
	return &externalV2DirectTCPPath{conns: lanes, selected: selected}, nil
}

func (l *externalV2DirectTCPListener) acceptLane(ctx context.Context, transferID [16]byte, auth externalPeerControlAuth) (*tls.Conn, int, error) {
	raw, err := l.listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, err
	}
	tuneExternalV2DirectTCPConn(raw)
	conn := tls.Server(raw, l.tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	lane, err := readExternalV2DirectTCPLaneRequest(conn, transferID, auth)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	return conn, lane, nil
}

func dialExternalV2DirectTCP(ctx context.Context, ad externalV2DirectTCPAdvertisement, auth externalPeerControlAuth) (*externalV2DirectTCPPath, error) {
	if err := validateExternalV2DirectTCPAdvertisement(&ad); err != nil {
		return nil, err
	}
	transferID, err := decodeExternalV2DirectTCPTransferID(ad.TransferID)
	if err != nil {
		return nil, err
	}
	clientConfig, err := newExternalV2DirectTCPClientConfig(ad.FingerprintSHA256)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	path := &externalV2DirectTCPPath{conns: make([]*tls.Conn, externalV2DirectTCPLaneCount), selected: make([]string, externalV2DirectTCPLaneCount)}
	errCh := make(chan error, externalV2DirectTCPLaneCount)
	var wg sync.WaitGroup
	for lane := 0; lane < externalV2DirectTCPLaneCount; lane++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, selected, err := dialExternalV2DirectTCPLane(ctx, ad.Candidates, clientConfig, transferID, lane, auth)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("direct TCP lane %d: %w", lane, err):
				default:
				}
				cancel()
				return
			}
			path.conns[lane] = conn
			path.selected[lane] = selected
		}()
	}
	wg.Wait()
	close(errCh)
	if err := errors.Join(readExternalV2DirectTCPErrors(errCh)...); err != nil {
		path.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		path.Close()
		return nil, err
	}
	return path, nil
}

func dialExternalV2DirectTCPLane(ctx context.Context, candidates []string, config *tls.Config, transferID [16]byte, lane int, auth externalPeerControlAuth) (*tls.Conn, string, error) {
	var errs []error
	for _, candidate := range candidates {
		dialer := net.Dialer{Timeout: externalV2DirectTCPDialWait}
		raw, err := dialer.DialContext(ctx, "tcp", candidate)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		tuneExternalV2DirectTCPConn(raw)
		conn := tls.Client(raw, config)
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			errs = append(errs, err)
			continue
		}
		if conn.ConnectionState().NegotiatedProtocol != externalV2DirectTCPProtocol {
			_ = conn.Close()
			errs = append(errs, errors.New("direct TCP ALPN mismatch"))
			continue
		}
		if err := writeExternalV2DirectTCPLaneRequest(conn, transferID, lane, auth); err != nil {
			_ = conn.Close()
			errs = append(errs, err)
			continue
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, candidate, nil
	}
	return nil, "", errors.Join(errs...)
}

func tuneExternalV2DirectTCPConn(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

func writeExternalV2DirectTCPLaneRequest(w io.Writer, transferID [16]byte, lane int, auth externalPeerControlAuth) error {
	var raw [externalV2DirectTCPLaneRequestSize]byte
	copy(raw[0:4], externalV2DirectTCPLaneMagic[:])
	raw[4] = 1
	copy(raw[8:24], transferID[:])
	binary.BigEndian.PutUint16(raw[24:26], uint16(lane))
	binary.BigEndian.PutUint16(raw[26:28], externalV2DirectTCPLaneCount)
	proof := externalV2DirectTCPLaneProof(auth, transferID, lane)
	copy(raw[28:], proof[:])
	return writeExternalV2BlockFrameBytes(w, raw[:])
}

func readExternalV2DirectTCPLaneRequest(r io.Reader, transferID [16]byte, auth externalPeerControlAuth) (int, error) {
	var raw [externalV2DirectTCPLaneRequestSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, err
	}
	if !bytes.Equal(raw[0:4], externalV2DirectTCPLaneMagic[:]) {
		return 0, errors.New("invalid direct TCP lane magic")
	}
	if !bytes.Equal(raw[4:8], []byte{1, 0, 0, 0}) {
		return 0, errors.New("invalid direct TCP lane version")
	}
	if subtle.ConstantTimeCompare(raw[8:24], transferID[:]) != 1 {
		return 0, errors.New("direct TCP transfer ID mismatch")
	}
	lane := int(binary.BigEndian.Uint16(raw[24:26]))
	lanes := int(binary.BigEndian.Uint16(raw[26:28]))
	if lanes != externalV2DirectTCPLaneCount || lane >= lanes {
		return 0, errors.New("invalid direct TCP lane identity")
	}
	wantProof := externalV2DirectTCPLaneProof(auth, transferID, lane)
	if subtle.ConstantTimeCompare(raw[28:], wantProof[:]) != 1 {
		return 0, errors.New("direct TCP lane authentication failed")
	}
	return lane, nil
}

func externalV2DirectTCPLaneProof(auth externalPeerControlAuth, transferID [16]byte, lane int) [sha256.Size]byte {
	mac := hmac.New(sha256.New, auth.EnvelopeKey[:])
	_, _ = mac.Write(externalV2DirectTCPLaneAuthDomain)
	_, _ = mac.Write(transferID[:])
	var identity [4]byte
	binary.BigEndian.PutUint16(identity[:2], uint16(lane))
	binary.BigEndian.PutUint16(identity[2:], externalV2DirectTCPLaneCount)
	_, _ = mac.Write(identity[:])
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func newExternalV2DirectTCPCertificate(now time.Time) (tls.Certificate, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "derphole direct file transfer"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}
	fingerprint := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return certificate, hex.EncodeToString(fingerprint[:]), nil
}

func newExternalV2DirectTCPClientConfig(fingerprintHex string) (*tls.Config, error) {
	expected, err := hex.DecodeString(fingerprintHex)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("direct TCP fingerprint must be 64 hexadecimal characters")
	}
	return &tls.Config{
		MinVersion:                  tls.VersionTLS13,
		MaxVersion:                  tls.VersionTLS13,
		NextProtos:                  []string{externalV2DirectTCPProtocol},
		InsecureSkipVerify:          true,
		DynamicRecordSizingDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("direct TCP peer certificate count is invalid")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return errors.New("direct TCP certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}

func decodeExternalV2DirectTCPTransferID(value string) ([16]byte, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		return [16]byte{}, errors.New("direct TCP transfer ID must be 32 hexadecimal characters")
	}
	var result [16]byte
	copy(result[:], raw)
	return result, nil
}

func closeExternalV2DirectTCPConns(conns []*tls.Conn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func readExternalV2DirectTCPErrors(ch <-chan error) []error {
	var errs []error
	for err := range ch {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func negotiateExternalV2DirectTCP(ctx context.Context, client *derpbind.Client, peerDERP key.NodePublic, auth externalPeerControlAuth, local *externalV2DirectTCPListener, peer *externalV2DirectTCPAdvertisement, useLocal bool, emitter *telemetry.Emitter) (*externalV2DirectTCPPath, bool, error) {
	readyCh, unsubscribe := subscribeExternalV2DataPlaneReady(client, peerDERP)
	defer unsubscribe()
	establishCtx, cancel := context.WithTimeout(ctx, externalV2DirectTCPEstablishWait)
	defer cancel()
	path, establishErr := establishExternalV2DirectTCP(establishCtx, local, peer, useLocal, auth)
	localReady := establishErr == nil && path != nil
	peerReady, exchangeErr := exchangeExternalV2DataPlaneReady(ctx, client, peerDERP, readyCh, externalV2DataPlanePhaseDirectTCP, localReady, nil, nil, auth)
	if exchangeErr != nil {
		if path != nil {
			path.Close()
		}
		return nil, false, exchangeErr
	}
	if !localReady || !peerReady.RawDirect {
		if path != nil {
			path.Close()
		}
		if establishErr != nil {
			emitExternalV2Debug(emitter, "v2-direct-tcp-establish-error="+establishErr.Error())
		}
		emitExternalV2Debug(emitter, "v2-direct-tcp-selected=false")
		return nil, false, nil
	}
	emitExternalV2Debug(emitter, "v2-direct-tcp-selected-addrs="+formatExternalV2SelectedAddrs(path.selected))
	emitExternalV2Debug(emitter, "v2-direct-tcp-selected=true")
	emitExternalV2Debug(emitter, "v2-data-plane=direct-tcp-files")
	return path, true, nil
}

func establishExternalV2DirectTCP(ctx context.Context, local *externalV2DirectTCPListener, peer *externalV2DirectTCPAdvertisement, useLocal bool, auth externalPeerControlAuth) (*externalV2DirectTCPPath, error) {
	if useLocal {
		if local == nil {
			return nil, errors.New("direct TCP listener is unavailable")
		}
		return local.accept(ctx, auth)
	}
	if peer == nil {
		return nil, errors.New("direct TCP peer advertisement is unavailable")
	}
	return dialExternalV2DirectTCP(ctx, *peer, auth)
}

func (rt *externalV2SendRuntime) sendDirectTCPBlock(ctx context.Context, accept externalV2Accept, tr externalV2ListenTransport, metrics *externalTransferMetrics, progress *externalV2PeerProgressState, pathEmitter *transportPathEmitter) (bool, error) {
	useLocal := !externalV2DirectTCPAdvertisementUsable(accept.DirectTCPFile)
	path, selected, err := negotiateExternalV2DirectTCP(ctx, rt.derp, rt.listenerDERP, rt.auth, rt.directTCP, accept.DirectTCPFile, useLocal, rt.cfg.Emitter)
	if err != nil {
		return false, err
	}
	if !selected {
		return false, nil
	}
	defer path.Close()
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, path.Close)
	defer stopAbortWatch()
	tr.ActivateRawDirect()
	metrics.SetDirectStreamTransport("tls-tcp")
	emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=direct-tcp-files")
	if err := sendExternalV2DirectTCPBlock(ctx, rt.cfg.BlockSource, path, metrics); err != nil {
		return true, externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}
	recordExternalV2DirectTCPStats(path, metrics, rt.cfg.Emitter)
	complete, err := rt.receiveComplete(ctx, abortErrCh, rt.cfg.StdioExpectedBytes, progress)
	if err != nil {
		return true, err
	}
	if err := recordExternalV2Completion(ctx, complete, metrics, progress, rt.cfg.Progress, peerProgressFinalTimeout); err != nil {
		return true, err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return true, nil
}

func (rt *externalV2ListenRuntime) receiveDirectTCPBlock(ctx context.Context, accepted externalV2AcceptedClaim, tr externalV2ListenTransport, sink *countingBlockReceiveSink, blockCfg externalV2BlockReceiveConfig, progressSender *externalV2PeerProgressSender, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) (bool, error) {
	useLocal := rt.directTCP != nil
	path, selected, err := negotiateExternalV2DirectTCP(ctx, rt.session.derp, accepted.peerDERP, rt.auth, rt.directTCP, accepted.claim.DirectTCPFile, useLocal, rt.cfg.Emitter)
	if err != nil {
		return false, err
	}
	if !selected {
		return false, nil
	}
	defer path.Close()
	abortErrCh, stopAbortWatch := rt.watchAbort(ctx, accepted.peerDERP, path.Close)
	defer stopAbortWatch()
	tr.ActivateRawDirect()
	metrics.SetDirectStreamTransport("tls-tcp")
	emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=direct-tcp-files")
	bytesReceived, err := receiveExternalV2DirectTCPBlock(ctx, sink, blockCfg, path, metrics)
	if err != nil {
		return true, externalV2PreferPeerAbort(ctx, abortErrCh, err)
	}
	recordExternalV2DirectTCPStats(path, metrics, rt.cfg.Emitter)
	if err := rt.sendComplete(ctx, accepted.peerDERP, bytesReceived, progressSender); err != nil {
		return true, err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return true, nil
}

func (rt *externalV2OfferRuntime) sendDirectTCPBlock(preferenceCtx, ctx context.Context, accepted externalV2AcceptedClaim, tr externalV2ListenTransport, metrics *externalTransferMetrics, progress *externalV2PeerProgressState, pathEmitter *transportPathEmitter, abortErrCh <-chan error) (bool, error) {
	useLocal := !externalV2DirectTCPAdvertisementUsable(accepted.claim.DirectTCPFile)
	path, selected, err := negotiateExternalV2DirectTCP(ctx, rt.session.derp, accepted.peerDERP, rt.auth, rt.directTCP, accepted.claim.DirectTCPFile, useLocal, rt.cfg.Emitter)
	if err != nil {
		return false, externalV2PreferPeerAbort(preferenceCtx, abortErrCh, err)
	}
	if !selected {
		return false, nil
	}
	defer path.Close()
	tr.ActivateRawDirect()
	metrics.SetDirectStreamTransport("tls-tcp")
	emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=direct-tcp-files")
	if err := sendExternalV2DirectTCPBlock(ctx, rt.cfg.BlockSource, path, metrics); err != nil {
		return true, externalV2PreferPeerAbort(preferenceCtx, abortErrCh, err)
	}
	recordExternalV2DirectTCPStats(path, metrics, rt.cfg.Emitter)
	complete, err := rt.receiveComplete(ctx, accepted.peerDERP, abortErrCh)
	if err != nil {
		return true, err
	}
	if err := recordExternalV2Completion(ctx, complete, metrics, progress, rt.cfg.Progress, peerProgressFinalTimeout); err != nil {
		return true, err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return true, nil
}

func (rt *externalV2OfferReceiveRuntime) receiveDirectTCPBlock(ctx context.Context, accept externalV2Accept, tr externalV2ListenTransport, sink *countingBlockReceiveSink, blockCfg externalV2BlockReceiveConfig, progressSender *externalV2PeerProgressSender, metrics *externalTransferMetrics, pathEmitter *transportPathEmitter) (bool, error) {
	useLocal := rt.directTCP != nil
	path, selected, err := negotiateExternalV2DirectTCP(ctx, rt.derp, rt.listenerDERP, rt.auth, rt.directTCP, accept.DirectTCPFile, useLocal, rt.cfg.Emitter)
	if err != nil {
		return false, err
	}
	if !selected {
		return false, nil
	}
	defer path.Close()
	tr.ActivateRawDirect()
	metrics.SetDirectStreamTransport("tls-tcp")
	emitExternalV2Debug(rt.cfg.Emitter, "v2-block-transfer=direct-tcp-files")
	bytesReceived, err := receiveExternalV2DirectTCPBlock(ctx, sink, blockCfg, path, metrics)
	if err != nil {
		return true, err
	}
	recordExternalV2DirectTCPStats(path, metrics, rt.cfg.Emitter)
	if err := rt.sendComplete(ctx, bytesReceived, progressSender); err != nil {
		return true, err
	}
	metrics.Complete(time.Now())
	pathEmitter.Complete(tr.manager)
	return true, nil
}

func sendExternalV2DirectTCPBlock(ctx context.Context, src *BlockSource, path *externalV2DirectTCPPath, metrics *externalTransferMetrics) error {
	if !validExternalV2BlockSource(src) || path == nil || len(path.conns) != externalV2DirectTCPLaneCount {
		return errors.New("invalid direct TCP block sender")
	}
	stopCancelClose := context.AfterFunc(ctx, path.Close)
	defer stopCancelClose()
	chunkSize := externalV2BlockChunkSize(src.ChunkSize)
	var next atomic.Int64
	errCh := make(chan error, len(path.conns))
	var workers sync.WaitGroup
	for _, conn := range path.conns {
		workers.Add(1)
		go func(conn *tls.Conn) {
			defer workers.Done()
			defer func() { _ = conn.CloseWrite() }()
			if err := sendExternalV2DirectTCPLane(ctx, conn, src, chunkSize, &next, metrics); err != nil {
				offerTLSError(errCh, err)
				path.Close()
			}
		}(conn)
	}
	workers.Wait()
	close(errCh)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := errors.Join(readExternalV2DirectTCPErrors(errCh)...); err != nil {
		return err
	}
	return nil
}

func sendExternalV2DirectTCPLane(ctx context.Context, conn io.Writer, src *BlockSource, chunkSize int, next *atomic.Int64, metrics *externalTransferMetrics) error {
	frame := make([]byte, externalV2BlockFrameSize+chunkSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		offset := next.Add(int64(chunkSize)) - int64(chunkSize)
		if offset >= src.PayloadSize {
			return nil
		}
		want := min(chunkSize, int(src.PayloadSize-offset))
		read, readErr := src.Payload.ReadAt(frame[externalV2BlockFrameSize:externalV2BlockFrameSize+want], offset)
		if err := externalV2BlockReadError(readErr, read, want, offset+int64(read), src.PayloadSize); err != nil {
			return err
		}
		binary.BigEndian.PutUint64(frame[:8], uint64(offset))
		binary.BigEndian.PutUint32(frame[8:externalV2BlockFrameSize], uint32(read))
		if err := writeExternalV2BlockFrameBytes(conn, frame[:externalV2BlockFrameSize+read]); err != nil {
			return err
		}
		if metrics != nil {
			metrics.RecordDirectPathSend(int64(read), time.Now())
		}
	}
}

func receiveExternalV2DirectTCPBlock(ctx context.Context, sink BlockReceiveSink, cfg externalV2BlockReceiveConfig, path *externalV2DirectTCPPath, metrics *externalTransferMetrics) (int64, error) {
	if sink == nil || path == nil || len(path.conns) != externalV2DirectTCPLaneCount {
		return 0, errors.New("invalid direct TCP block receiver")
	}
	stopCancelClose := context.AfterFunc(ctx, path.Close)
	defer stopCancelClose()
	chunkSize := externalV2BlockChunkSize(cfg.ChunkSize)
	tracker, err := newExternalV2BlockReceiveTracker(cfg.PayloadSize, chunkSize)
	if err != nil {
		return 0, err
	}
	errCh := make(chan error, len(path.conns))
	var workers sync.WaitGroup
	for _, conn := range path.conns {
		workers.Add(1)
		go func(conn *tls.Conn) {
			defer workers.Done()
			if err := receiveExternalV2DirectTCPLane(conn, sink, tracker, chunkSize, metrics); err != nil {
				offerTLSError(errCh, err)
				path.Close()
			}
		}(conn)
	}
	workers.Wait()
	close(errCh)
	if err := ctx.Err(); err != nil {
		return cfg.HeaderBytes + tracker.receivedBytes(), err
	}
	if err := errors.Join(readExternalV2DirectTCPErrors(errCh)...); err != nil {
		return cfg.HeaderBytes + tracker.receivedBytes(), err
	}
	if err := tracker.complete(); err != nil {
		return cfg.HeaderBytes + tracker.receivedBytes(), err
	}
	return cfg.HeaderBytes + tracker.receivedBytes(), nil
}

func receiveExternalV2DirectTCPLane(conn io.Reader, sink BlockReceiveSink, tracker *externalV2BlockReceiveTracker, chunkSize int, metrics *externalTransferMetrics) error {
	buffer := make([]byte, chunkSize)
	for {
		chunk, done, err := readExternalV2DirectTCPChunk(conn, buffer)
		if err != nil || done {
			return err
		}
		if err := tracker.writeChunk(sink, chunk, metrics); err != nil {
			return err
		}
	}
}

func readExternalV2DirectTCPChunk(r io.Reader, buffer []byte) (externalV2BlockChunk, bool, error) {
	var header [externalV2BlockFrameSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return externalV2BlockChunk{}, true, nil
		}
		return externalV2BlockChunk{}, false, err
	}
	n := int(binary.BigEndian.Uint32(header[8:]))
	if n <= 0 || n > len(buffer) {
		return externalV2BlockChunk{}, false, io.ErrUnexpectedEOF
	}
	if _, err := io.ReadFull(r, buffer[:n]); err != nil {
		return externalV2BlockChunk{}, false, err
	}
	return externalV2BlockChunk{offset: int64(binary.BigEndian.Uint64(header[:8])), data: buffer[:n]}, false, nil
}

func offerTLSError(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func recordExternalV2DirectTCPStats(path *externalV2DirectTCPPath, metrics *externalTransferMetrics, emitter *telemetry.Emitter) {
	retransmits, supported := externalV2DirectTCPRetransmits(path)
	if supported {
		metrics.SetDirectDiagnostics(externalDirectTransferDiagnostics{Retransmits: retransmits}, time.Now())
	}
	emitExternalV2Debug(emitter, fmt.Sprintf("v2-direct-tcp-stats=tcp_info:%t retransmits:%d", supported, retransmits))
}
