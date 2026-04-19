package qrpayload

import (
	"errors"
	"strings"
	"testing"
)

func TestEncodeReceiveToken(t *testing.T) {
	got, err := EncodeReceiveToken("abc-123_DEF")
	if err != nil {
		t.Fatalf("EncodeReceiveToken() error = %v", err)
	}
	const want = "derphole://receive?v=1&token=abc-123_DEF"
	if got != want {
		t.Fatalf("EncodeReceiveToken() = %q, want %q", got, want)
	}
}

func TestEncodeReceiveTokenTrimsAndEscapesToken(t *testing.T) {
	got, err := EncodeReceiveToken(" token with spaces ")
	if err != nil {
		t.Fatalf("EncodeReceiveToken() error = %v", err)
	}
	const want = "derphole://receive?v=1&token=token+with+spaces"
	if got != want {
		t.Fatalf("EncodeReceiveToken() = %q, want %q", got, want)
	}
}

func TestEncodeReceiveTokenRejectsEmpty(t *testing.T) {
	_, err := EncodeReceiveToken(" ")
	if !errors.Is(err, ErrMissingToken) {
		t.Fatalf("EncodeReceiveToken() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestParseReceivePayload(t *testing.T) {
	got, err := ParseReceivePayload("derphole://receive?v=1&token=abc-123_DEF")
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
		{input: "derphole://receive?v=1", wantErr: ErrMissingToken},
		{input: "derphole://send?v=1&token=abc", wantErr: ErrUnsupportedPayload},
		{input: "https://example.com/receive?v=1&token=abc", wantErr: ErrUnsupportedPayload},
		{input: "derphole://receive?token=abc", wantErr: ErrUnsupportedVersion},
	} {
		t.Run(strings.ReplaceAll(tc.input, "/", "_"), func(t *testing.T) {
			_, err := ParseReceivePayload(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseReceivePayload(%q) error = %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}
