package qrpayload

import (
	"errors"
	"net/url"
	"strings"
)

const (
	Scheme  = "derphole"
	Version = "1"

	KindFile Kind = "file"
	KindWeb  Kind = "web"
	KindTCP  Kind = "tcp"

	ReceiveHost    = "receive"
	ReceiveVersion = Version
)

var (
	ErrMissingToken       = errors.New("missing derphole token")
	ErrUnsupportedVersion = errors.New("unsupported derphole QR payload version")
	ErrUnsupportedPayload = errors.New("unsupported derphole QR payload")
)

type Kind string

type Payload struct {
	Kind   Kind
	Token  string
	Scheme string
	Path   string
}

func Encode(payload Payload) (string, error) {
	token := strings.TrimSpace(payload.Token)
	if token == "" {
		return "", ErrMissingToken
	}

	values := url.Values{}
	values.Set("token", token)
	values.Set("v", Version)

	switch payload.Kind {
	case KindFile, KindTCP:
	case KindWeb:
		webScheme := strings.TrimSpace(payload.Scheme)
		if webScheme == "" {
			return "", ErrUnsupportedPayload
		}
		path := strings.TrimSpace(payload.Path)
		if path == "" {
			path = "/"
		}
		values.Set("scheme", webScheme)
		values.Set("path", path)
	default:
		return "", ErrUnsupportedPayload
	}

	return (&url.URL{Scheme: Scheme, Host: string(payload.Kind), RawQuery: values.Encode()}).String(), nil
}

func EncodeFileToken(token string) (string, error) {
	return Encode(Payload{Kind: KindFile, Token: token})
}

func EncodeWebToken(token, scheme, path string) (string, error) {
	return Encode(Payload{Kind: KindWeb, Token: token, Scheme: scheme, Path: path})
}

func EncodeTCPToken(token string) (string, error) {
	return Encode(Payload{Kind: KindTCP, Token: token})
}

func EncodeReceiveToken(receiveToken string) (string, error) {
	return EncodeFileToken(receiveToken)
}

func Parse(raw string) (Payload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Payload{}, ErrMissingToken
	}
	if !strings.Contains(raw, "://") {
		return Payload{Kind: KindFile, Token: raw}, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Payload{}, err
	}
	if parsed.Scheme != Scheme {
		return Payload{}, ErrUnsupportedPayload
	}

	kind := Kind(parsed.Host)
	if kind == Kind(ReceiveHost) {
		kind = KindFile
	}
	if kind != KindFile && kind != KindWeb && kind != KindTCP {
		return Payload{}, ErrUnsupportedPayload
	}

	values := parsed.Query()
	if got := values.Get("v"); got != Version {
		return Payload{}, ErrUnsupportedVersion
	}
	token := strings.TrimSpace(values.Get("token"))
	if token == "" {
		return Payload{}, ErrMissingToken
	}

	payload := Payload{Kind: kind, Token: token}
	if kind == KindWeb {
		payload.Scheme = strings.TrimSpace(values.Get("scheme"))
		if payload.Scheme == "" {
			return Payload{}, ErrUnsupportedPayload
		}
		payload.Path = strings.TrimSpace(values.Get("path"))
		if payload.Path == "" {
			payload.Path = "/"
		}
	}
	return payload, nil
}

func ParseReceivePayload(payload string) (string, error) {
	parsed, err := Parse(payload)
	if err != nil {
		return "", err
	}
	if parsed.Kind != KindFile {
		return "", ErrUnsupportedPayload
	}
	return parsed.Token, nil
}
