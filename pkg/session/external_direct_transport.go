// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import "os"

type externalDirectTransportKind string

const (
	externalDirectTransportBlast externalDirectTransportKind = "blast"
	externalDirectTransportQUIC  externalDirectTransportKind = "quic"
	externalDirectTransportAuto  externalDirectTransportKind = "auto"
)

func externalDirectTransportFromEnv() externalDirectTransportKind {
	switch os.Getenv("DERPHOLE_DIRECT_TRANSPORT") {
	case string(externalDirectTransportBlast):
		return externalDirectTransportBlast
	case string(externalDirectTransportQUIC):
		return externalDirectTransportQUIC
	case string(externalDirectTransportAuto):
		return externalDirectTransportAuto
	default:
		return externalDirectTransportBlast
	}
}
