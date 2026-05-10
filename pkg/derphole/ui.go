// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/mdp/qrterminal/v3"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
)

func VerificationString(token string) string {
	sum := sha256.Sum256([]byte("derphole-verify:" + token))
	hexed := strings.ToUpper(hex.EncodeToString(sum[:6]))
	return hexed[:4] + "-" + hexed[4:8] + "-" + hexed[8:12]
}

func WriteSendInstruction(stderr io.Writer, token string) {
	if stderr == nil {
		return
	}
	fmt.Fprintln(stderr, "On the other machine, run:")
	fmt.Fprintf(stderr, "npx -y derphole@latest receive %s\n", token)
}

func WriteSendQRInstruction(stderr io.Writer, token string) {
	if stderr == nil {
		return
	}
	payload, err := qrpayload.EncodeFileToken(token)
	if err != nil {
		fmt.Fprintf(stderr, "Could not render QR payload: %v\n", err)
		return
	}
	fmt.Fprintln(stderr, "Scan this QR code with the Derphole iOS app:")
	qrterminal.GenerateHalfBlock(payload, qrterminal.M, stderr)
}

func WriteReceiveToken(stderr io.Writer, token string) {
	if stderr == nil {
		return
	}
	fmt.Fprintln(stderr, token)
}
