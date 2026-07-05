// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package endpointlookup

import (
	"context"
	"errors"
	"strings"
	"time"
)

const recordVersion = 1

type Kind string

const (
	KindDerptunClientToken Kind = "derptun-client-token"
	KindDerpsshInvite      Kind = "derpssh-invite"
)

var (
	ErrNotFound    = errors.New("endpoint lookup record not found")
	ErrInvalidName = errors.New("invalid endpoint lookup name")
	ErrInvalidKind = errors.New("invalid endpoint lookup kind")
	ErrExpired     = errors.New("endpoint lookup record expired")
)

type Record struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	Value       string `json:"value"`
	CreatedUnix int64  `json:"created_unix"`
	ExpiresUnix int64  `json:"expires_unix"`
}

type RecordSummary struct {
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	CreatedUnix int64  `json:"created_unix"`
	ExpiresUnix int64  `json:"expires_unix"`
	Display     string `json:"display"`
}

type Resolver interface {
	Resolve(context.Context, string, Kind) (Record, error)
}

type Publisher interface {
	Publish(context.Context, Record) error
	Remove(context.Context, string) error
	List(context.Context) ([]RecordSummary, error)
}

func ValidateName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || len(name) > 128 {
		return ErrInvalidName
	}
	if invalidNameShape(name) {
		return ErrInvalidName
	}
	for _, r := range name {
		if !validNameRune(r) {
			return ErrInvalidName
		}
	}
	return nil
}

func invalidNameShape(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") || strings.Contains(name, "..")
}

func validNameRune(r rune) bool {
	return asciiLetter(r) || asciiDigit(r) || r == '-' || r == '_' || r == '.'
}

func asciiLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func asciiDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func ValidateKind(kind Kind) error {
	switch kind {
	case KindDerptunClientToken, KindDerpsshInvite:
		return nil
	default:
		return ErrInvalidKind
	}
}

func NewRecord(name string, kind Kind, value string, created, expires time.Time) (Record, error) {
	value = strings.TrimSpace(value)
	if err := ValidateName(name); err != nil {
		return Record{}, err
	}
	if err := ValidateKind(kind); err != nil {
		return Record{}, err
	}
	if value == "" {
		return Record{}, ErrNotFound
	}
	return Record{
		Version:     recordVersion,
		Name:        name,
		Kind:        kind,
		Value:       value,
		CreatedUnix: created.Unix(),
		ExpiresUnix: expires.Unix(),
	}, nil
}

func (r Record) Expired(now time.Time) bool {
	return r.ExpiresUnix > 0 && !now.Before(time.Unix(r.ExpiresUnix, 0))
}

func (r Record) RedactedSummary() RecordSummary {
	return RecordSummary{
		Name:        r.Name,
		Kind:        r.Kind,
		CreatedUnix: r.CreatedUnix,
		ExpiresUnix: r.ExpiresUnix,
		Display:     "value redacted",
	}
}
