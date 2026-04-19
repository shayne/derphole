package qrpayload

import (
	"errors"
	"strings"
	"testing"
)

func TestEncodeFileToken(t *testing.T) {
	got, err := EncodeFileToken("abc-123_DEF")
	if err != nil {
		t.Fatalf("EncodeFileToken() error = %v", err)
	}
	const want = "derphole://file?token=abc-123_DEF&v=1"
	if got != want {
		t.Fatalf("EncodeFileToken() = %q, want %q", got, want)
	}
}

func TestEncodeFileTokenTrimsAndEscapesToken(t *testing.T) {
	got, err := EncodeFileToken(" token with spaces ")
	if err != nil {
		t.Fatalf("EncodeFileToken() error = %v", err)
	}
	const want = "derphole://file?token=token+with+spaces&v=1"
	if got != want {
		t.Fatalf("EncodeFileToken() = %q, want %q", got, want)
	}
}

func TestEncodeFileTokenRejectsEmpty(t *testing.T) {
	_, err := EncodeFileToken(" ")
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("EncodeFileToken() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestParseFilePayload(t *testing.T) {
	got, err := Parse("derphole://file?token=abc-123_DEF&v=1")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Kind != KindFile || got.Token != "abc-123_DEF" {
		t.Fatalf("Parse() = %#v, want file token", got)
	}
}

func TestEncodeAndParseWebPayload(t *testing.T) {
	encoded, err := EncodeWebToken("dtc1_test", "http", "/admin")
	if err != nil {
		t.Fatalf("EncodeWebToken() error = %v", err)
	}
	const want = "derphole://web?path=%2Fadmin&scheme=http&token=dtc1_test&v=1"
	if encoded != want {
		t.Fatalf("EncodeWebToken() = %q, want %q", encoded, want)
	}

	got, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(web) error = %v", err)
	}
	if got.Kind != KindWeb || got.Token != "dtc1_test" || got.Scheme != "http" || got.Path != "/admin" {
		t.Fatalf("Parse(web) = %#v, want web payload", got)
	}
}

func TestEncodeAndParseTCPPayload(t *testing.T) {
	encoded, err := EncodeTCPToken("dtc1_test")
	if err != nil {
		t.Fatalf("EncodeTCPToken() error = %v", err)
	}
	const want = "derphole://tcp?token=dtc1_test&v=1"
	if encoded != want {
		t.Fatalf("EncodeTCPToken() = %q, want %q", encoded, want)
	}

	got, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(tcp) error = %v", err)
	}
	if got.Kind != KindTCP || got.Token != "dtc1_test" {
		t.Fatalf("Parse(tcp) = %#v, want tcp payload", got)
	}
}

func TestParseAcceptsLegacyReceivePayloadAsFile(t *testing.T) {
	got, err := Parse("derphole://receive?v=1&token=legacy-token")
	if err != nil {
		t.Fatalf("Parse(legacy receive) error = %v", err)
	}
	if got.Kind != KindFile || got.Token != "legacy-token" {
		t.Fatalf("Parse(legacy receive) = %#v, want file token", got)
	}
}

func TestParseAcceptsRawTokenAsFile(t *testing.T) {
	got, err := Parse("  raw-token-123  ")
	if err != nil {
		t.Fatalf("Parse(raw token) error = %v", err)
	}
	if got.Kind != KindFile || got.Token != "raw-token-123" {
		t.Fatalf("Parse(raw token) = %#v, want file token", got)
	}
}

func TestParseReceivePayloadReturnsFileToken(t *testing.T) {
	got, err := ParseReceivePayload("derphole://file?token=abc-123_DEF&v=1")
	if err != nil {
		t.Fatalf("ParseReceivePayload() error = %v", err)
	}
	if got != "abc-123_DEF" {
		t.Fatalf("ParseReceivePayload() = %q, want token", got)
	}
}

func TestParseReceivePayloadAcceptsRawToken(t *testing.T) {
	got, err := ParseReceivePayload("  raw-token-123  ")
	if err != nil {
		t.Fatalf("ParseReceivePayload(raw token) error = %v", err)
	}
	if got != "raw-token-123" {
		t.Fatalf("ParseReceivePayload(raw token) = %q, want trimmed token", got)
	}
}

func TestParseReceivePayloadRejectsUnsupportedVersion(t *testing.T) {
	_, err := ParseReceivePayload("derphole://receive?v=2&token=abc")
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ParseReceivePayload() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestParseReceivePayloadRejectsInvalidURLPayloads(t *testing.T) {
	for _, tc := range []struct {
		input   string
		wantErr error
	}{
		{input: "", wantErr: ErrMissingToken},
		{input: "derphole://file?v=1", wantErr: ErrMissingToken},
		{input: "derphole://send?v=1&token=abc", wantErr: ErrUnsupportedPayload},
		{input: "https://example.com/receive?v=1&token=abc", wantErr: ErrUnsupportedPayload},
		{input: "derphole://file?token=abc", wantErr: ErrUnsupportedVersion},
		{input: "derphole://web?token=abc&v=1", wantErr: ErrUnsupportedPayload},
	} {
		t.Run(strings.ReplaceAll(tc.input, "/", "_"), func(t *testing.T) {
			_, err := ParseReceivePayload(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseReceivePayload(%q) error = %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}
