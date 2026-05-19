// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "os"

type externalTransferProtocolKind string

const (
	externalTransferProtocolV2     externalTransferProtocolKind = "v2"
	externalTransferProtocolLegacy externalTransferProtocolKind = "legacy"
)

func externalTransferProtocolFromEnv() externalTransferProtocolKind {
	switch os.Getenv("DERPHOLE_TRANSFER_PROTOCOL") {
	case string(externalTransferProtocolLegacy):
		return externalTransferProtocolLegacy
	case string(externalTransferProtocolV2), "":
		return externalTransferProtocolV2
	default:
		return externalTransferProtocolV2
	}
}
