// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "testing"

func TestExternalTransferProtocolFromEnvDefaultsToV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolV2 {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolV2)
	}
}

func TestExternalTransferProtocolFromEnvAcceptsLegacy(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "legacy")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolLegacy {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolLegacy)
	}
}

func TestExternalTransferProtocolFromEnvAcceptsV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "v2")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolV2 {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolV2)
	}
}

func TestExternalTransferProtocolFromEnvTreatsUnknownAsV2(t *testing.T) {
	t.Setenv("DERPHOLE_TRANSFER_PROTOCOL", "typo")
	if got := externalTransferProtocolFromEnv(); got != externalTransferProtocolV2 {
		t.Fatalf("externalTransferProtocolFromEnv() = %q, want %q", got, externalTransferProtocolV2)
	}
}
