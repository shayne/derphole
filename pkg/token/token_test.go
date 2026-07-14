// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/derpbind"
)

const publicV5Golden = "BQECAwQFBgcICQoLDA0ODxAAAAAAZVPxABI0ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gAAAAA3XU8cQ"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     time.Now().Add(5 * time.Minute).Unix(),
		BootstrapRegion: 12,
		DERPPublic:      [32]byte{5, 6, 7, 8},
		BearerSecret:    [32]byte{17, 18, 19, 20},
		Capabilities:    CapabilityStdio | CapabilityShare,
		QUICPublic:      [32]byte{21, 22, 23, 24},
	}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded != tok {
		t.Fatalf("decoded token = %+v, want %+v", decoded, tok)
	}
}

func TestEncodeDefaultsZeroVersion(t *testing.T) {
	tok := Token{ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, time.Now())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Version != SupportedVersion {
		t.Fatalf("Version = %d, want %d", decoded.Version, SupportedVersion)
	}
}

func TestVersionForRoute(t *testing.T) {
	tests := []struct {
		name  string
		route derpbind.Route
		want  uint8
	}{
		{name: "public", want: SupportedVersion},
		{
			name:  "custom",
			route: derpbind.Route{Host: "derp.example.com", DERPPort: derpbind.DefaultDERPPort, STUNPort: derpbind.DefaultSTUNPort},
			want:  CustomDERPVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VersionForRoute(tt.route); got != tt.want {
				t.Fatalf("VersionForRoute(%+v) = %d, want %d", tt.route, got, tt.want)
			}
		})
	}
}

func TestCustomDERPZeroVersionDefaultsForRoute(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tests := []struct {
		name  string
		route derpbind.Route
		want  uint8
	}{
		{name: "public", want: SupportedVersion},
		{
			name:  "custom",
			route: derpbind.Route{Host: "derp.example.com", DERPPort: derpbind.DefaultDERPPort, STUNPort: derpbind.DefaultSTUNPort},
			want:  CustomDERPVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := Encode(Token{ExpiresUnix: now.Add(time.Hour).Unix(), DERPRoute: tt.route})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			decoded, err := Decode(encoded, now)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if decoded.Version != tt.want {
				t.Fatalf("Version = %d, want %d", decoded.Version, tt.want)
			}
		})
	}
}

func TestEncodeRejectsVersionRouteMismatch(t *testing.T) {
	now := time.Unix(1700000000, 0)
	customRoute := derpbind.Route{
		Host:     "derp.example.com",
		DERPPort: derpbind.DefaultDERPPort,
		STUNPort: derpbind.DefaultSTUNPort,
	}
	tests := []struct {
		name  string
		token Token
	}{
		{
			name: "v5 with custom route",
			token: Token{
				Version:     SupportedVersion,
				ExpiresUnix: now.Add(time.Hour).Unix(),
				DERPRoute:   customRoute,
			},
		},
		{
			name: "v6 with public route",
			token: Token{
				Version:     CustomDERPVersion,
				ExpiresUnix: now.Add(time.Hour).Unix(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Encode(tt.token); err != ErrUnsupportedVersion {
				t.Fatalf("Encode() error = %v, want ErrUnsupportedVersion", err)
			}
		})
	}
}

func TestCustomDERPRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tests := []struct {
		name  string
		route derpbind.Route
	}{
		{
			name: "default ports",
			route: derpbind.Route{
				Host:     "derp.example.com",
				DERPPort: derpbind.DefaultDERPPort,
				STUNPort: derpbind.DefaultSTUNPort,
			},
		},
		{
			name: "non-default ports",
			route: derpbind.Route{
				Host:     "2001:db8::1",
				DERPPort: 8443,
				STUNPort: 5349,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := Token{
				Version:      CustomDERPVersion,
				SessionID:    [16]byte{1, 2, 3, 4},
				ExpiresUnix:  now.Add(time.Hour).Unix(),
				BearerSecret: [32]byte{5, 6, 7, 8},
				Capabilities: CapabilityStdio | CapabilityShare,
				DERPRoute:    tt.route,
			}
			encoded, err := Encode(tok)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			decoded, err := Decode(encoded, now)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if decoded != tok {
				t.Fatalf("decoded token = %+v, want %+v", decoded, tok)
			}
		})
	}
}

func TestCustomDERPChecksumCoversRoute(t *testing.T) {
	now := time.Unix(1700000000, 0)
	encoded, err := Encode(Token{
		Version:     CustomDERPVersion,
		ExpiresUnix: now.Add(time.Hour).Unix(),
		DERPRoute: derpbind.Route{
			Host:     "derp.example.com",
			DERPPort: derpbind.DefaultDERPPort,
			STUNPort: derpbind.DefaultSTUNPort,
		},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[fixedPayloadSize+1] ^= 0x01
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, now); err != ErrChecksum {
		t.Fatalf("Decode() error = %v, want ErrChecksum", err)
	}
}

func TestDecodeRejectsCustomDERPMalformedRoute(t *testing.T) {
	now := time.Unix(1700000000, 0)
	encoded, err := Encode(Token{
		Version:     CustomDERPVersion,
		ExpiresUnix: now.Add(time.Hour).Unix(),
		DERPRoute: derpbind.Route{
			Host:     "derp.example.com",
			DERPPort: derpbind.DefaultDERPPort,
			STUNPort: derpbind.DefaultSTUNPort,
		},
	})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	payload := raw[:len(raw)-4]
	hostLen := int(payload[fixedPayloadSize])
	hostStart := fixedPayloadSize + 1
	portsStart := hostStart + hostLen

	zeroHost := append([]byte(nil), payload[:fixedPayloadSize]...)
	zeroHost = append(zeroHost, 0)
	zeroHost = append(zeroHost, payload[portsStart:portsStart+4]...)

	truncatedHost := append([]byte(nil), payload[:portsStart-1]...)
	truncatedHost = append(truncatedHost, payload[portsStart:]...)

	truncatedPorts := append([]byte(nil), payload[:len(payload)-1]...)

	invalidHost := append([]byte(nil), payload...)
	invalidHost[hostStart] = 'D'

	zeroDERPPort := append([]byte(nil), payload...)
	zeroDERPPort[portsStart] = 0
	zeroDERPPort[portsStart+1] = 0

	zeroSTUNPort := append([]byte(nil), payload...)
	zeroSTUNPort[portsStart+2] = 0
	zeroSTUNPort[portsStart+3] = 0

	trailingByte := append(append([]byte(nil), payload...), 0)

	tests := []struct {
		name    string
		encoded string
		wantErr error
	}{
		{name: "zero host length", encoded: encodePayloadWithChecksum(zeroHost)},
		{name: "truncated host", encoded: encodePayloadWithChecksum(truncatedHost), wantErr: ErrInvalidLength},
		{name: "truncated ports", encoded: encodePayloadWithChecksum(truncatedPorts), wantErr: ErrInvalidLength},
		{name: "truncated checksum", encoded: base64.RawURLEncoding.EncodeToString(raw[:len(raw)-1]), wantErr: ErrInvalidLength},
		{name: "invalid host", encoded: encodePayloadWithChecksum(invalidHost)},
		{name: "zero DERP port", encoded: encodePayloadWithChecksum(zeroDERPPort)},
		{name: "zero STUN port", encoded: encodePayloadWithChecksum(zeroSTUNPort)},
		{name: "valid checksum with trailing byte", encoded: encodePayloadWithChecksum(trailingByte), wantErr: ErrInvalidLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.encoded, now)
			if err == nil {
				t.Fatal("Decode() error = nil, want rejection")
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Fatalf("Decode() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestV5RejectsTrailingExtensionAndLeavesRouteZero(t *testing.T) {
	now := time.Unix(1700000000, 0)
	encoded, err := Encode(Token{Version: SupportedVersion, ExpiresUnix: now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}

	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.DERPRoute != (derpbind.Route{}) {
		t.Fatalf("DERPRoute = %+v, want public route", decoded.DERPRoute)
	}

	payloadWithExtension := append(append([]byte(nil), raw[:len(raw)-4]...), 0)
	if _, err := Decode(encodePayloadWithChecksum(payloadWithExtension), now); err != ErrInvalidLength {
		t.Fatalf("Decode(v5 with trailing extension) error = %v, want ErrInvalidLength", err)
	}
}

func encodePayloadWithChecksum(payload []byte) string {
	raw := append([]byte(nil), payload...)
	raw = binary.BigEndian.AppendUint32(raw, crc32.ChecksumIEEE(payload))
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestEncodeRejectsUnsupportedVersion(t *testing.T) {
	_, err := Encode(Token{Version: 7, ExpiresUnix: time.Now().Add(time.Minute).Unix()})
	if err != ErrUnsupportedVersion {
		t.Fatalf("Encode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestEncodeRejectsRetiredV3TokenVersion(t *testing.T) {
	_, err := Encode(Token{Version: 3, ExpiresUnix: time.Now().Add(time.Minute).Unix()})
	if err != ErrUnsupportedVersion {
		t.Fatalf("Encode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[0] = 7
	raw = raw[:len(raw)-1]
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrUnsupportedVersion {
		t.Fatalf("Decode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeRejectsRetiredV3TokenVersion(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[0] = 3
	checksum := crc32.ChecksumIEEE(raw[:len(raw)-4])
	binary.BigEndian.PutUint32(raw[len(raw)-4:], checksum)
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrUnsupportedVersion {
		t.Fatalf("Decode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeRejectsExpiredToken(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(-time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(encoded, time.Now()); err != ErrExpired {
		t.Fatalf("Decode() error = %v, want ErrExpired", err)
	}
}

func TestDecodeRejectsTokenAtExpiryBoundary(t *testing.T) {
	now := time.Now().UTC()
	tok := Token{Version: SupportedVersion, ExpiresUnix: now.Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(encoded, now); err != ErrExpired {
		t.Fatalf("Decode() error = %v, want ErrExpired", err)
	}
}

func TestDecodeRejectsCorruptedChecksum(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrChecksum {
		t.Fatalf("Decode() error = %v, want ErrChecksum", err)
	}
}

func TestEncodeWireFormatContract(t *testing.T) {
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ExpiresUnix:     1700000000,
		BootstrapRegion: 0x1234,
		DERPPublic:      [32]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40},
		BearerSecret:    [32]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60},
		Capabilities:    CapabilityStdio | CapabilityShare,
		QUICPublic:      [32]byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80},
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("encoded token = %q, want raw URL-safe base64 without padding", encoded)
	}
	if encoded != publicV5Golden {
		t.Fatalf("encoded token = %q, want public v5 golden %q", encoded, publicV5Golden)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if got, want := len(raw), fixedPayloadSize+4; got != want {
		t.Fatalf("raw length = %d, want %d", got, want)
	}
	wantRaw, err := base64.RawURLEncoding.DecodeString(publicV5Golden)
	if err != nil {
		t.Fatalf("DecodeString(publicV5Golden) error = %v", err)
	}
	if !bytes.Equal(raw, wantRaw) {
		t.Fatalf("raw token = %x, want public v5 golden %x", raw, wantRaw)
	}
	decoded, err := Decode(encoded, time.Unix(tok.ExpiresUnix-1, 0))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.QUICPublic != tok.QUICPublic {
		t.Fatalf("decoded QUICPublic = %x, want %x", decoded.QUICPublic, tok.QUICPublic)
	}
}

func TestEncodeDecodeRoundTripPublicShareToken(t *testing.T) {
	now := time.Now()
	tok := Token{
		Version:         SupportedVersion,
		SessionID:       [16]byte{1, 2, 3, 4},
		ExpiresUnix:     now.Add(time.Hour).Unix(),
		BootstrapRegion: 7,
		DERPPublic:      [32]byte{9, 9, 9, 9},
		BearerSecret:    [32]byte{8, 8, 8, 8},
		Capabilities:    CapabilityShare,
		QUICPublic:      [32]byte{7, 7, 7, 7},
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.QUICPublic != tok.QUICPublic {
		t.Fatalf("QUICPublic = %x, want %x", decoded.QUICPublic, tok.QUICPublic)
	}
}

func TestEncodeDecodeRoundTripAttachToken(t *testing.T) {
	now := time.Now()
	tok := Token{
		Version:      SupportedVersion,
		SessionID:    [16]byte{9, 8, 7, 6},
		ExpiresUnix:  now.Add(time.Hour).Unix(),
		BearerSecret: [32]byte{6, 7, 8, 9},
		Capabilities: CapabilityStdio | CapabilityShare | CapabilityAttach,
	}

	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded, now)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.Capabilities&CapabilityAttach == 0 {
		t.Fatalf("Capabilities = %08b, want attach bit set", decoded.Capabilities)
	}
	if decoded.Capabilities&CapabilityStdio == 0 || decoded.Capabilities&CapabilityShare == 0 {
		t.Fatalf("Capabilities = %08b, want mixed capability bits preserved", decoded.Capabilities)
	}
}

func TestDecodeRejectsMalformedLength(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw = raw[:len(raw)-1]
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrInvalidLength {
		t.Fatalf("Decode() error = %v, want ErrInvalidLength", err)
	}
}

func TestDecodeRejectsUnsupportedVersionWithWrongLength(t *testing.T) {
	tok := Token{Version: SupportedVersion, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
	encoded, err := Encode(tok)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[0] = 7
	raw = raw[:len(raw)-1]
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(encoded, time.Now()); err != ErrUnsupportedVersion {
		t.Fatalf("Decode() error = %v, want ErrUnsupportedVersion", err)
	}
}

func FuzzDecode(f *testing.F) {
	now := time.Unix(1700000000, 0)
	validV5, err := Encode(Token{
		Version:      SupportedVersion,
		SessionID:    [16]byte{1, 2, 3, 4},
		ExpiresUnix:  now.Add(time.Hour).Unix(),
		BearerSecret: [32]byte{5, 6, 7, 8},
		Capabilities: CapabilityStdio | CapabilityShare,
	})
	if err != nil {
		f.Fatalf("Encode(seed) error = %v", err)
	}
	validV6Default, err := Encode(Token{
		Version:     CustomDERPVersion,
		ExpiresUnix: now.Add(time.Hour).Unix(),
		DERPRoute: derpbind.Route{
			Host:     "derp.example.com",
			DERPPort: derpbind.DefaultDERPPort,
			STUNPort: derpbind.DefaultSTUNPort,
		},
	})
	if err != nil {
		f.Fatalf("Encode(default custom seed) error = %v", err)
	}
	validV6NonDefault, err := Encode(Token{
		Version:     CustomDERPVersion,
		ExpiresUnix: now.Add(time.Hour).Unix(),
		DERPRoute: derpbind.Route{
			Host:     "2001:db8::1",
			DERPPort: 8443,
			STUNPort: 5349,
		},
	})
	if err != nil {
		f.Fatalf("Encode(non-default custom seed) error = %v", err)
	}
	for _, seed := range []string{
		validV5,
		validV6Default,
		validV6NonDefault,
		"",
		"bad",
		"AAAA",
		strings.TrimRight(validV5, "A"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encoded string) {
		decoded, err := Decode(encoded, now)
		if err != nil {
			return
		}
		roundTrip, err := Encode(decoded)
		if err != nil {
			t.Fatalf("Encode(decoded) error = %v", err)
		}
		decodedAgain, err := Decode(roundTrip, now)
		if err != nil {
			t.Fatalf("Decode(re-encoded) error = %v", err)
		}
		if decodedAgain != decoded {
			t.Fatalf("decoded token changed after re-encode: %+v != %+v", decodedAgain, decoded)
		}
	})
}

func FuzzEncodeDecode(f *testing.F) {
	f.Add([]byte("derphole seed"), int64(1), uint32(CapabilityStdio), uint8(0))
	f.Add([]byte(strings.Repeat("x", 128)), int64(3600), uint32(CapabilityShare), uint8(1))
	f.Add([]byte("non-default custom route"), int64(7200), uint32(CapabilityAttach), uint8(2))

	f.Fuzz(func(t *testing.T, seed []byte, expiresDelta int64, capabilities uint32, routeKind uint8) {
		now := time.Unix(1700000000, 0)
		if expiresDelta < 0 {
			expiresDelta = -expiresDelta
		}
		routes := [...]derpbind.Route{
			{},
			{Host: "derp.example.com", DERPPort: derpbind.DefaultDERPPort, STUNPort: derpbind.DefaultSTUNPort},
			{Host: "2001:db8::1", DERPPort: 8443, STUNPort: 5349},
		}
		route := routes[int(routeKind)%len(routes)]
		tok := Token{
			Version:      VersionForRoute(route),
			ExpiresUnix:  now.Unix() + 1 + expiresDelta%86400,
			Capabilities: capabilities,
			DERPRoute:    route,
		}
		copy(tok.SessionID[:], seed)
		copy(tok.DERPPublic[:], seed)
		if len(seed) > 32 {
			copy(tok.QUICPublic[:], seed[32:])
		} else {
			copy(tok.QUICPublic[:], seed)
		}
		if len(seed) > 64 {
			copy(tok.BearerSecret[:], seed[64:])
		} else {
			copy(tok.BearerSecret[:], seed)
		}
		encoded, err := Encode(tok)
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		decoded, err := Decode(encoded, now)
		if err != nil {
			t.Fatalf("Decode(Encode(tok)) error = %v", err)
		}
		if decoded != tok {
			t.Fatalf("Decode(Encode(tok)) = %+v, want %+v", decoded, tok)
		}
	})
}
