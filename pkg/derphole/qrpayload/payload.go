package qrpayload

import (
	"errors"
	"net/url"
	"strings"
)

const (
	Scheme         = "derphole"
	ReceiveHost    = "receive"
	ReceiveVersion = "1"
)

var (
	ErrMissingToken       = errors.New("missing receive token")
	ErrUnsupportedVersion = errors.New("unsupported derphole QR payload version")
	ErrUnsupportedPayload = errors.New("unsupported derphole QR payload")
)

func EncodeReceiveToken(receiveToken string) (string, error) {
	receiveToken = strings.TrimSpace(receiveToken)
	if receiveToken == "" {
		return "", ErrMissingToken
	}

	query := "v=" + ReceiveVersion + "&token=" + url.QueryEscape(receiveToken)
	return (&url.URL{Scheme: Scheme, Host: ReceiveHost, RawQuery: query}).String(), nil
}

func ParseReceivePayload(payload string) (string, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return "", ErrMissingToken
	}
	if !strings.Contains(payload, "://") {
		return payload, nil
	}

	parsed, err := url.Parse(payload)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != Scheme || parsed.Host != ReceiveHost {
		return "", ErrUnsupportedPayload
	}

	values := parsed.Query()
	if got := values.Get("v"); got != ReceiveVersion {
		return "", ErrUnsupportedVersion
	}
	token := strings.TrimSpace(values.Get("token"))
	if token == "" {
		return "", ErrMissingToken
	}
	return token, nil
}
