package derphole

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
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

func WriteReceiveToken(stderr io.Writer, token string) {
	if stderr == nil {
		return
	}
	fmt.Fprintln(stderr, token)
}
