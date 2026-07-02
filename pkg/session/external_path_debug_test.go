// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "testing"

func TestExternalDirectEndpointClassifiesPublicPrivateAndTailscale(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "public", endpoint: "203.0.113.10:1234", want: "public"},
		{name: "private", endpoint: "192.168.1.10:1234", want: "private"},
		{name: "tailscale-cgnat", endpoint: "100.125.235.82:1234", want: "tailscale"},
		{name: "tailscale-ula", endpoint: "[fd7a:115c:a1e0::1]:1234", want: "tailscale"},
		{name: "invalid", endpoint: "not-an-endpoint", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := externalDirectEndpointClass(tt.endpoint); got != tt.want {
				t.Fatalf("externalDirectEndpointClass(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}
