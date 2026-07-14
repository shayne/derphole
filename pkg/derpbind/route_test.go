// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derpbind

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestParseCustomRoute(t *testing.T) {
	accepted := map[string]Route{
		"https://derp.example.com":           {Host: "derp.example.com", DERPPort: 443, STUNPort: 3478},
		"https://DERP.EXAMPLE.COM./":         {Host: "derp.example.com", DERPPort: 443, STUNPort: 3478},
		"https://derp.example.com/derp":      {Host: "derp.example.com", DERPPort: 443, STUNPort: 3478},
		"https://derp.example.com:8443/derp": {Host: "derp.example.com", DERPPort: 8443, STUNPort: 3478},
		"https://192.0.2.10":                 {Host: "192.0.2.10", DERPPort: 443, STUNPort: 3478},
		"https://[2001:0db8::1]:8443/derp":   {Host: "2001:db8::1", DERPPort: 8443, STUNPort: 3478},
	}
	for raw, want := range accepted {
		t.Run(raw, func(t *testing.T) {
			got, err := ParseCustomRoute(raw)
			if err != nil {
				t.Fatalf("ParseCustomRoute() error = %v", err)
			}
			if got != want {
				t.Fatalf("ParseCustomRoute() = %#v, want %#v", got, want)
			}
		})
	}

	rejected := []string{
		" ",
		"http://derp.example.com",
		"derp.example.com",
		"https://",
		"https://user:pass@derp.example.com",
		"https://derp.example.com?x=1",
		"https://derp.example.com#fragment",
		"https://derp.example.com/other",
		"https://derp.example.com/%64erp",
		"https://derp.example.com:0",
		"https://derp.example.com:65536",
		"https://-bad.example.com",
		"https://bad-.example.com",
		"https://caf\u00e9.example.com",
	}
	for _, raw := range rejected {
		t.Run("reject_"+raw, func(t *testing.T) {
			if got, err := ParseCustomRoute(raw); err == nil {
				t.Fatalf("ParseCustomRoute() = %#v, want error", got)
			}
		})
	}
}

func TestRouteFromEnvironment(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		old, hadOld := os.LookupEnv(CustomDERPServerEnv)
		if err := os.Unsetenv(CustomDERPServerEnv); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if hadOld {
				_ = os.Setenv(CustomDERPServerEnv, old)
			} else {
				_ = os.Unsetenv(CustomDERPServerEnv)
			}
		})

		got, err := RouteFromEnvironment()
		if err != nil {
			t.Fatalf("RouteFromEnvironment() error = %v", err)
		}
		if got != (Route{}) {
			t.Fatalf("RouteFromEnvironment() = %#v, want zero route", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Setenv(CustomDERPServerEnv, "")
		got, err := RouteFromEnvironment()
		if err != nil {
			t.Fatalf("RouteFromEnvironment() error = %v", err)
		}
		if got != (Route{}) {
			t.Fatalf("RouteFromEnvironment() = %#v, want zero route", got)
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Setenv(CustomDERPServerEnv, "https://DERP.EXAMPLE.COM.:8443/derp")
		want := Route{Host: "derp.example.com", DERPPort: 8443, STUNPort: 3478}
		got, err := RouteFromEnvironment()
		if err != nil {
			t.Fatalf("RouteFromEnvironment() error = %v", err)
		}
		if got != want {
			t.Fatalf("RouteFromEnvironment() = %#v, want %#v", got, want)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		const raw = "http://user:secret@derp.example.com"
		t.Setenv(CustomDERPServerEnv, raw)
		_, err := RouteFromEnvironment()
		if err == nil {
			t.Fatal("RouteFromEnvironment() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "invalid "+CustomDERPServerEnv+":") {
			t.Fatalf("RouteFromEnvironment() error = %q, want environment prefix", err)
		}
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("RouteFromEnvironment() error = %q, want raw URL omitted", err)
		}
	})
}

func TestRouteMap(t *testing.T) {
	if got := (Route{}).DERPMap(); got != nil {
		t.Fatalf("Route{}.DERPMap() = %#v, want nil", got)
	}

	route := Route{Host: "derp.example.com", DERPPort: 8443, STUNPort: 3479}
	dm := route.DERPMap()
	if dm == nil {
		t.Fatal("Route.DERPMap() = nil, want custom map")
	}
	if !dm.OmitDefaultRegions {
		t.Fatal("DERPMap.OmitDefaultRegions = false, want true")
	}
	if len(dm.Regions) != 1 {
		t.Fatalf("len(DERPMap.Regions) = %d, want 1", len(dm.Regions))
	}
	region, ok := dm.Regions[CustomDERPRegionID]
	if !ok {
		t.Fatalf("DERPMap.Regions = %#v, want region %d", dm.Regions, CustomDERPRegionID)
	}
	if region.RegionID != CustomDERPRegionID || region.RegionCode != "custom" || region.RegionName != "Custom DERP" {
		t.Fatalf("custom DERP region = %#v", region)
	}
	if len(region.Nodes) != 1 {
		t.Fatalf("len(custom DERP nodes) = %d, want 1", len(region.Nodes))
	}
	node := region.Nodes[0]
	if node.Name != "custom" || node.RegionID != CustomDERPRegionID {
		t.Fatalf("custom DERP node identity = %#v", node)
	}
	if node.HostName != route.Host || node.DERPPort != int(route.DERPPort) || node.STUNPort != int(route.STUNPort) {
		t.Fatalf("custom DERP node route = %#v, want host %q ports %d/%d", node, route.Host, route.DERPPort, route.STUNPort)
	}
	if node.IPv4 != "" || node.IPv6 != "" {
		t.Fatalf("custom DERP node direct IPs = %q/%q, want empty", node.IPv4, node.IPv6)
	}
}

func TestRouteServerURL(t *testing.T) {
	tests := []struct {
		name  string
		route Route
		want  string
	}{
		{name: "public", route: Route{}, want: ""},
		{name: "default", route: Route{Host: "derp.example.com", DERPPort: 443, STUNPort: 3478}, want: "https://derp.example.com/derp"},
		{name: "custom port", route: Route{Host: "derp.example.com", DERPPort: 8443, STUNPort: 3478}, want: "https://derp.example.com:8443/derp"},
		{name: "IPv6", route: Route{Host: "2001:db8::1", DERPPort: 8443, STUNPort: 3478}, want: "https://[2001:db8::1]:8443/derp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.ServerURL(); got != tt.want {
				t.Fatalf("Route.ServerURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWrapCustomDERPConnectErrorRedactsFinalURLsAndPreservesCause(t *testing.T) {
	route := Route{Host: "derp.example.com", DERPPort: 8443, STUNPort: 3478}
	const override = "http://127.0.0.1:54321/derp"
	sentinel := errors.New("dns timeout detail")
	urlErr := &url.Error{Op: "Get", URL: route.ServerURL(), Err: sentinel}
	cause := fmt.Errorf("connect derp client: proxy CONNECT %s failed: %w", override, urlErr)

	got := WrapCustomDERPConnectError(route, override, cause)
	if got == nil {
		t.Fatal("WrapCustomDERPConnectError() = nil, want error")
	}
	for _, want := range []string{
		"connect custom DERP derp.example.com:8443:",
		"proxy CONNECT derp.example.com:8443 failed",
		"Get \"derp.example.com:8443\"",
		"dns timeout detail",
	} {
		if !strings.Contains(got.Error(), want) {
			t.Fatalf("wrapped error = %q, want %q", got, want)
		}
	}
	for _, forbidden := range []string{"https://", "http://", "/derp", "127.0.0.1:54321"} {
		if strings.Contains(got.Error(), forbidden) {
			t.Fatalf("wrapped error = %q, contains final URL detail %q", got, forbidden)
		}
	}
	if !errors.Is(got, sentinel) {
		t.Fatalf("errors.Is(wrapped, sentinel) = false")
	}
	var gotURLError *url.Error
	if !errors.As(got, &gotURLError) || gotURLError != urlErr {
		t.Fatalf("errors.As(wrapped, *url.Error) = %#v, want original %#v", gotURLError, urlErr)
	}
}

func TestWrapCustomDERPConnectErrorLeavesPublicErrorUnchanged(t *testing.T) {
	cause := errors.New("connect derp client: connect to https://public.example.com/derp")
	got := WrapCustomDERPConnectError(Route{}, "https://override.example.com/derp", cause)
	if got != cause {
		t.Fatalf("WrapCustomDERPConnectError(public) = %v, want original error identity", got)
	}
	if got.Error() != cause.Error() {
		t.Fatalf("public error text = %q, want %q", got, cause)
	}
}

func TestRouteJSON(t *testing.T) {
	route := Route{Host: "derp.example.com", DERPPort: 443, STUNPort: 3478}
	got, err := json.Marshal(route)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"host":"derp.example.com","derp_port":443,"stun_port":3478}`
	if string(got) != want {
		t.Fatalf("json.Marshal() = %s, want %s", got, want)
	}
}

func TestRouteWire(t *testing.T) {
	route := Route{Host: "derp.example.com", DERPPort: 443, STUNPort: 3478}
	wire, err := route.AppendWire(nil)
	if err != nil {
		t.Fatalf("Route.AppendWire() error = %v", err)
	}
	want := append([]byte{byte(len(route.Host))}, route.Host...)
	want = append(want, 0x01, 0xbb, 0x0d, 0x96)
	if !bytes.Equal(wire, want) {
		t.Fatalf("Route.AppendWire() = %x, want %x", wire, want)
	}

	withPrefix, err := route.AppendWire([]byte{0xaa, 0xbb})
	if err != nil {
		t.Fatalf("Route.AppendWire(prefix) error = %v", err)
	}
	if !bytes.Equal(withPrefix, append([]byte{0xaa, 0xbb}, want...)) {
		t.Fatalf("Route.AppendWire(prefix) = %x, want prefixed %x", withPrefix, want)
	}

	got, consumed, err := ParseRouteWire(wire)
	if err != nil {
		t.Fatalf("ParseRouteWire() error = %v", err)
	}
	if got != route {
		t.Fatalf("ParseRouteWire() = %#v, want %#v", got, route)
	}
	if consumed != len(wire) {
		t.Fatalf("ParseRouteWire() consumed = %d, want %d", consumed, len(wire))
	}

	trailing := append(append([]byte(nil), wire...), 0xff)
	got, consumed, err = ParseRouteWire(trailing)
	if err != nil {
		t.Fatalf("ParseRouteWire(trailing) error = %v", err)
	}
	if got != route || consumed != len(wire) || consumed == len(trailing) {
		t.Fatalf("ParseRouteWire(trailing) = (%#v, %d), want route and detectable trailing byte", got, consumed)
	}

	maxHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	maxRoute := Route{Host: maxHost, DERPPort: 443, STUNPort: 3478}
	maxWire, err := maxRoute.AppendWire(nil)
	if err != nil {
		t.Fatalf("253-byte host AppendWire() error = %v", err)
	}
	if maxWire[0] != 253 {
		t.Fatalf("253-byte host wire length = %d, want 253", maxWire[0])
	}
	if got, consumed, err := ParseRouteWire(maxWire); err != nil || got != maxRoute || consumed != len(maxWire) {
		t.Fatalf("ParseRouteWire(253-byte host) = (%#v, %d, %v), want (%#v, %d, nil)", got, consumed, err, maxRoute, len(maxWire))
	}

	rejected := map[string][]byte{
		"zero host length":    {0, 0, 1, 0, 1},
		"reserved length 254": {254},
		"reserved length 255": {255},
		"truncated host":      {4, 'h', 'o', 's'},
		"truncated ports":     {1, 'a', 0, 1, 0},
		"zero DERP port":      {1, 'a', 0, 0, 0, 1},
		"zero STUN port":      {1, 'a', 0, 1, 0, 0},
		"non-canonical DNS":   {1, 'A', 0, 1, 0, 1},
		"non-canonical IP":    append(append([]byte{byte(len("2001:0db8::1"))}, "2001:0db8::1"...), 0, 1, 0, 1),
		"invalid UTF-8":       {1, 0xff, 0, 1, 0, 1},
		"non-ASCII":           {2, 0xc3, 0xa9, 0, 1, 0, 1},
	}
	for name, src := range rejected {
		t.Run(name, func(t *testing.T) {
			if got, consumed, err := ParseRouteWire(src); err == nil {
				t.Fatalf("ParseRouteWire() = (%#v, %d, nil), want error", got, consumed)
			}
		})
	}
}
