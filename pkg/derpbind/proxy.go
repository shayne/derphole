// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/http/httpproxy"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

const maxProxyErrorBody = 4 << 10

type ProxyInfo struct {
	Scheme     string
	ProxyAddr  string
	TargetAddr string
}

func (i ProxyInfo) DebugString() string {
	if i.Scheme == "" || i.ProxyAddr == "" || i.TargetAddr == "" {
		return ""
	}
	return "derp-proxy=" + i.Scheme + "://" + i.ProxyAddr + " target=" + i.TargetAddr
}

func newProxyInfo(proxyURL *url.URL, target string) ProxyInfo {
	return ProxyInfo{
		Scheme:     proxyURL.Scheme,
		ProxyAddr:  canonicalProxyAddr(proxyURL),
		TargetAddr: target,
	}
}

func canonicalProxyAddr(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		if proxyURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(proxyURL.Hostname(), port)
}

var derpProxyFromEnvironment = uncachedDERPProxyFromEnvironment

func uncachedDERPProxyFromEnvironment(target *url.URL) (*url.URL, error) {
	config := httpproxy.FromEnvironment()
	probe := *config
	var proxyValue string
	switch target.Scheme {
	case "http":
		proxyValue = config.HTTPProxy
		probe.HTTPProxy = "http://proxy.invalid"
	case "https":
		proxyValue = config.HTTPSProxy
		probe.HTTPSProxy = "http://proxy.invalid"
	default:
		return nil, nil
	}
	if proxyValue == "" {
		return nil, nil
	}

	proxyURL, err := probe.ProxyFunc()(target)
	if err != nil || proxyURL == nil {
		return proxyURL, err
	}
	return parseDERPProxy(proxyValue)
}

func parseDERPProxy(proxyValue string) (*url.URL, error) {
	proxyURL, err := url.Parse(proxyValue)
	if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
		if withScheme, withSchemeErr := url.Parse("http://" + proxyValue); withSchemeErr == nil {
			return withScheme, nil
		}
	}
	if err != nil {
		return nil, errors.New("invalid DERP proxy configuration")
	}
	return proxyURL, nil
}

func derpProxyForURL(target *url.URL) (*url.URL, error) {
	if target == nil {
		return nil, errors.New("nil DERP URL")
	}
	proxyURL, err := derpProxyFromEnvironment(target)
	if err != nil {
		return nil, fmt.Errorf("resolve DERP proxy: %w", err)
	}
	if proxyURL == nil {
		return nil, nil
	}
	if err := validateDERPProxyURL(proxyURL); err != nil {
		return nil, err
	}
	return proxyURL, nil
}

func validateDERPProxyURL(proxyURL *url.URL) error {
	if proxyURL == nil {
		return errors.New("nil DERP proxy URL")
	}
	switch proxyURL.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported DERP proxy scheme %q", proxyURL.Scheme)
	}
	if proxyURL.Hostname() == "" {
		return errors.New("DERP proxy URL has no hostname")
	}
	return nil
}

var proxyTLSConfig = func(host string) *tls.Config {
	return &tls.Config{ServerName: host}
}

func dialDERPThroughProxy(ctx context.Context, proxyURL *url.URL, target string, logf logger.Logf, netMon *netmon.Monitor) (_ net.Conn, _ ProxyInfo, retErr error) {
	ctx, cancel := derpDialContextWithTimeout(ctx)
	defer cancel()

	proxyAddr := canonicalProxyAddr(proxyURL)
	raw, err := derpDialContext(ctx, logf, netMon, "tcp", proxyAddr)
	if err != nil {
		return nil, ProxyInfo{}, fmt.Errorf("dial DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, err)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopClose()

	conn := raw
	defer func() {
		if retErr != nil {
			_ = conn.Close()
		}
	}()
	setProxySetupDeadline(ctx, conn)
	proxyConn, err := proxyTLSConnection(ctx, raw, proxyURL, proxyAddr)
	if err != nil {
		return nil, ProxyInfo{}, err
	}
	conn = proxyConn

	req, err := newProxyConnectRequest(proxyURL, target)
	if err != nil {
		return nil, ProxyInfo{}, err
	}
	if err := req.Write(conn); err != nil {
		return nil, ProxyInfo{}, fmt.Errorf("write CONNECT to DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ProxyInfo{}, fmt.Errorf("read CONNECT from DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, ctxErr)
		}
		return nil, ProxyInfo{}, fmt.Errorf("read CONNECT from DERP proxy %s://%s: invalid HTTP response", proxyURL.Scheme, proxyAddr)
	}
	if res.StatusCode != http.StatusOK {
		return nil, ProxyInfo{}, proxyConnectRejectionError(ctx, res.Body, proxyURL, target, proxyAddr, res.StatusCode)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, ProxyInfo{}, fmt.Errorf("clear DERP proxy setup deadline: %w", err)
	}
	return &bufferedProxyConn{Conn: conn, reader: br}, newProxyInfo(proxyURL, target), nil
}

func setProxySetupDeadline(ctx context.Context, conn net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
}

func proxyTLSConnection(ctx context.Context, raw net.Conn, proxyURL *url.URL, proxyAddr string) (net.Conn, error) {
	if proxyURL.Scheme != "https" {
		return raw, nil
	}
	tlsConn := tls.Client(raw, proxyTLSConfig(proxyURL.Hostname()))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS to DERP proxy https://%s: %w", proxyAddr, err)
	}
	return tlsConn, nil
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func newProxyConnectRequest(proxyURL *url.URL, target string) (*http.Request, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxyURL.User == nil {
		return req, nil
	}
	username := proxyURL.User.Username()
	password, ok := proxyURL.User.Password()
	if username == "" || !ok {
		return nil, errors.New("DERP proxy credentials require username and password")
	}
	raw := username + ":" + password
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(raw)))
	return req, nil
}

func safeProxyResponseSummary(body io.Reader, proxyURL *url.URL, limit int64) (string, error) {
	if body == nil || limit < 1 {
		return "", nil
	}
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	truncated := int64(len(b)) > limit
	if truncated {
		b = b[:limit]
	}
	summary := normalizeProxyResponseSummary(string(b))
	summary = redactProxyResponseSummary(summary, proxyURL)
	summary = strings.TrimSpace(summary)
	if truncated {
		summary += "..."
	}
	return summary, err
}

func proxyConnectRejectionError(ctx context.Context, body io.ReadCloser, proxyURL *url.URL, target, proxyAddr string, statusCode int) error {
	summary, bodyErr := safeProxyResponseSummary(body, proxyURL, maxProxyErrorBody)
	_ = body.Close()
	ctxErr := ctx.Err()
	var timeoutErr net.Error
	if ctxErr == nil && errors.As(bodyErr, &timeoutErr) && timeoutErr.Timeout() {
		ctxErr = context.DeadlineExceeded
	}
	if ctxErr != nil {
		return fmt.Errorf("read CONNECT rejection body from DERP proxy %s://%s: %w", proxyURL.Scheme, proxyAddr, ctxErr)
	}
	return proxyConnectStatusError(proxyURL, target, statusCode, summary)
}

func normalizeProxyResponseSummary(summary string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, summary)
}

func redactProxyResponseSummary(summary string, proxyURL *url.URL) string {
	if proxyURL.User == nil {
		return summary
	}
	username := proxyURL.User.Username()
	password, hasPassword := proxyURL.User.Password()
	candidates := []string{username, password}
	if username != "" && hasPassword {
		candidates = append(candidates, base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
	secrets := make([]string, 0, len(candidates)*2)
	seen := make(map[string]struct{}, len(candidates)*2)
	for _, candidate := range candidates {
		for _, secret := range []string{candidate, normalizeProxyResponseSummary(candidate)} {
			if secret == "" {
				continue
			}
			if _, ok := seen[secret]; ok {
				continue
			}
			seen[secret] = struct{}{}
			secrets = append(secrets, secret)
		}
	}
	sort.Slice(secrets, func(i, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	replacements := make([]string, 0, len(secrets)*2)
	for _, secret := range secrets {
		replacements = append(replacements, secret, "[redacted]")
	}
	return strings.NewReplacer(replacements...).Replace(summary)
}

func proxyConnectStatusError(proxyURL *url.URL, target string, statusCode int, summary string) error {
	status := fmt.Sprintf("%d", statusCode)
	if text := http.StatusText(statusCode); text != "" {
		status += " " + text
	}
	detail := ""
	if summary != "" {
		detail = ": " + summary
	}
	if statusCode == http.StatusProxyAuthRequired {
		return fmt.Errorf("DERP proxy %s://%s rejected authentication for CONNECT to %s: %s%s", proxyURL.Scheme, canonicalProxyAddr(proxyURL), target, status, detail)
	}
	return fmt.Errorf("DERP proxy %s://%s rejected CONNECT to %s: %s%s", proxyURL.Scheme, canonicalProxyAddr(proxyURL), target, status, detail)
}
