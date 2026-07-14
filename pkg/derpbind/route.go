// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"tailscale.com/tailcfg"
)

const (
	CustomDERPServerEnv = "DERPHOLE_DERP_SERVER"
	DefaultDERPPort     = uint16(443)
	DefaultSTUNPort     = uint16(3478)
	CustomDERPRegionID  = 900
)

type Route struct {
	Host     string `json:"host"`
	DERPPort uint16 `json:"derp_port"`
	STUNPort uint16 `json:"stun_port"`
}

type customDERPConnectError struct {
	authority string
	detail    string
	cause     error
}

func (e *customDERPConnectError) Error() string {
	return fmt.Sprintf("connect custom DERP %s: %s", e.authority, e.detail)
}

func (e *customDERPConnectError) Unwrap() error {
	return e.cause
}

func RouteFromEnvironment() (Route, error) {
	raw, ok := os.LookupEnv(CustomDERPServerEnv)
	if !ok || raw == "" {
		return Route{}, nil
	}
	return ParseCustomRoute(raw)
}

func ParseCustomRoute(raw string) (Route, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Route{}, invalidCustomRoute("malformed URL")
	}
	if err := validateCustomDERPURL(u, raw); err != nil {
		return Route{}, invalidCustomRoute(err.Error())
	}

	host, err := canonicalRouteHost(u.Hostname())
	if err != nil {
		return Route{}, invalidCustomRoute(err.Error())
	}
	port, err := customDERPPort(u)
	if err != nil {
		return Route{}, invalidCustomRoute(err.Error())
	}
	route, err := NewCustomRoute(host, port, DefaultSTUNPort)
	if err != nil {
		return Route{}, invalidCustomRoute(err.Error())
	}
	return route, nil
}

func NewCustomRoute(host string, derpPort, stunPort uint16) (Route, error) {
	host, err := canonicalRouteHost(host)
	if err != nil {
		return Route{}, err
	}
	route := Route{Host: host, DERPPort: derpPort, STUNPort: stunPort}
	if err := route.Validate(); err != nil {
		return Route{}, err
	}
	return route, nil
}

func (r Route) IsCustom() bool {
	return r != (Route{})
}

func (r Route) Validate() error {
	if !r.IsCustom() {
		return nil
	}
	if r.Host == "" {
		return errors.New("host is required")
	}
	if r.DERPPort == 0 {
		return errors.New("DERP port must be non-zero")
	}
	if r.STUNPort == 0 {
		return errors.New("STUN port must be non-zero")
	}
	host, err := canonicalRouteHost(r.Host)
	if err != nil {
		return err
	}
	if host != r.Host {
		return errors.New("host is not canonical")
	}
	return nil
}

func (r Route) DERPAuthority() string {
	if !r.IsCustom() || r.Validate() != nil {
		return ""
	}
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.DERPPort)))
}

func (r Route) STUNAuthority() string {
	if !r.IsCustom() || r.Validate() != nil {
		return ""
	}
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.STUNPort)))
}

func (r Route) ServerURL() string {
	if !r.IsCustom() || r.Validate() != nil {
		return ""
	}
	authority := r.Host
	addr, _ := netip.ParseAddr(r.Host)
	if r.DERPPort != DefaultDERPPort || addr.Is6() {
		authority = r.DERPAuthority()
	}
	return "https://" + authority + "/derp"
}

// WrapCustomDERPConnectError keeps connection diagnostics and the original
// cause while replacing final DERP URLs with the canonical embedded authority.
func WrapCustomDERPConnectError(route Route, finalServerURL string, cause error) error {
	if cause == nil || !route.IsCustom() {
		return cause
	}
	authority := route.DERPAuthority()
	if authority == "" {
		return cause
	}
	detail := cause.Error()
	for _, serverURL := range []string{finalServerURL, route.ServerURL()} {
		if serverURL != "" {
			detail = strings.ReplaceAll(detail, serverURL, authority)
		}
	}
	return &customDERPConnectError{authority: authority, detail: detail, cause: cause}
}

func (r Route) DERPMap() *tailcfg.DERPMap {
	if !r.IsCustom() || r.Validate() != nil {
		return nil
	}
	node := &tailcfg.DERPNode{
		Name:     "custom",
		RegionID: CustomDERPRegionID,
		HostName: r.Host,
		DERPPort: int(r.DERPPort),
		STUNPort: int(r.STUNPort),
	}
	return &tailcfg.DERPMap{
		OmitDefaultRegions: true,
		Regions: map[int]*tailcfg.DERPRegion{
			CustomDERPRegionID: {
				RegionID:   CustomDERPRegionID,
				RegionCode: "custom",
				RegionName: "Custom DERP",
				Nodes:      []*tailcfg.DERPNode{node},
			},
		},
	}
}

func (r Route) AppendWire(dst []byte) ([]byte, error) {
	if !r.IsCustom() {
		return nil, errors.New("public route has no wire encoding")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if len(r.Host) == 0 || len(r.Host) > 253 {
		return nil, errors.New("host length is invalid")
	}

	dst = append(dst, byte(len(r.Host)))
	dst = append(dst, r.Host...)
	dst = binary.BigEndian.AppendUint16(dst, r.DERPPort)
	dst = binary.BigEndian.AppendUint16(dst, r.STUNPort)
	return dst, nil
}

func ParseRouteWire(src []byte) (Route, int, error) {
	if len(src) == 0 {
		return Route{}, 0, errors.New("route wire is empty")
	}
	hostLen := int(src[0])
	if hostLen == 0 || hostLen > 253 {
		return Route{}, 0, errors.New("route host length is invalid")
	}
	consumed := 1 + hostLen + 4
	if len(src) < consumed {
		return Route{}, 0, errors.New("route wire is truncated")
	}

	host := string(src[1 : 1+hostLen])
	derpPort := binary.BigEndian.Uint16(src[1+hostLen : 3+hostLen])
	stunPort := binary.BigEndian.Uint16(src[3+hostLen : consumed])
	route, err := NewCustomRoute(host, derpPort, stunPort)
	if err != nil {
		return Route{}, 0, fmt.Errorf("invalid route wire: %w", err)
	}
	if route.Host != host {
		return Route{}, 0, errors.New("invalid route wire: host is not canonical")
	}
	return route, consumed, nil
}

func invalidCustomRoute(reason string) error {
	return fmt.Errorf("invalid %s: %s", CustomDERPServerEnv, reason)
}

func validateCustomDERPURL(u *url.URL, raw string) error {
	if u.Scheme != "https" {
		return errors.New("scheme must be https")
	}
	if u.User != nil {
		return errors.New("userinfo is not allowed")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("query is not allowed")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("fragment is not allowed")
	}
	if !validCustomDERPPath(u.Path) || !validCustomDERPPath(u.EscapedPath()) {
		return errors.New("path must be empty, /, or /derp")
	}
	return nil
}

func validCustomDERPPath(path string) bool {
	return path == "" || path == "/" || path == "/derp"
}

func customDERPPort(u *url.URL) (uint16, error) {
	port := u.Port()
	if port == "" {
		if customDERPURLHasEmptyPort(u.Host) {
			return 0, errors.New("DERP port is invalid")
		}
		return DefaultDERPPort, nil
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("DERP port is invalid")
	}
	return uint16(n), nil
}

func customDERPURLHasEmptyPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndexByte(host, ']')
		return end >= 0 && host[end+1:] == ":"
	}
	return strings.HasSuffix(host, ":")
}

func canonicalRouteHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("host is required")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", errors.New("IPv6 zones are not allowed")
		}
		return addr.String(), nil
	}

	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return "", errors.New("DNS host length is invalid")
	}
	host = strings.ToLower(host)
	for _, label := range strings.Split(host, ".") {
		if err := validateDNSLabel(label); err != nil {
			return "", err
		}
	}
	return host, nil
}

func validateDNSLabel(label string) error {
	if len(label) == 0 || len(label) > 63 {
		return errors.New("DNS label length is invalid")
	}
	for i := 0; i < len(label); i++ {
		if validDNSLabelByte(label[i], i, len(label)) {
			continue
		}
		return errors.New("DNS label contains invalid characters")
	}
	return nil
}

func validDNSLabelByte(c byte, index, length int) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	default:
		return c == '-' && index > 0 && index < length-1
	}
}
