// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

	parsed, err := parsePayloadURL(raw)
	if err != nil {
		return Payload{}, err
	}
	kind, err := parsePayloadKind(parsed.Host)
	if err != nil {
		return Payload{}, err
	}
	payload, err := parsePayloadValues(kind, parsed.Query())
	if err != nil {
		return Payload{}, err
	}
	return payload, nil
}

func parsePayloadURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != Scheme {
		return nil, ErrUnsupportedPayload
	}
	return parsed, nil
}

func parsePayloadKind(host string) (Kind, error) {
	kind := Kind(host)
	if kind == Kind(ReceiveHost) {
		return KindFile, nil
	}
	if kind == KindFile || kind == KindWeb || kind == KindTCP {
		return kind, nil
	}
	return "", ErrUnsupportedPayload
}

func parsePayloadValues(kind Kind, values url.Values) (Payload, error) {
	if got := values.Get("v"); got != Version {
		return Payload{}, ErrUnsupportedVersion
	}
	token := strings.TrimSpace(values.Get("token"))
	if token == "" {
		return Payload{}, ErrMissingToken
	}
	payload := Payload{Kind: kind, Token: token}
	if kind != KindWeb {
		return payload, nil
	}
	return parseWebPayload(payload, values)
}

func parseWebPayload(payload Payload, values url.Values) (Payload, error) {
	payload.Scheme = strings.TrimSpace(values.Get("scheme"))
	if payload.Scheme == "" {
		return Payload{}, ErrUnsupportedPayload
	}
	payload.Path = strings.TrimSpace(values.Get("path"))
	if payload.Path == "" {
		payload.Path = "/"
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
