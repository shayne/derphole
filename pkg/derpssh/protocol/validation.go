// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxDisplayNameRunes = 24

var ErrEmptyDisplayName = errors.New("display name is empty")

func NormalizeDisplayName(value string) (string, error) {
	value = strings.TrimSpace(stripControlNoise(value))
	if value == "" {
		return "", ErrEmptyDisplayName
	}
	runes := []rune(value)
	if len(runes) > MaxDisplayNameRunes {
		value = string(runes[:MaxDisplayNameRunes])
	}
	return value, nil
}

func stripControlNoise(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == '\x1b' {
			i += size
			i = skipANSIEscape(value, i)
			continue
		}
		if !unicode.IsControl(r) {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func skipANSIEscape(value string, i int) int {
	if i >= len(value) {
		return i
	}
	switch value[i] {
	case '[':
		return skipCSI(value, i+1)
	case ']':
		return skipOSC(value, i+1)
	default:
		return i + 1
	}
}

func skipCSI(value string, i int) int {
	for i < len(value) {
		c := value[i]
		i++
		if c >= 0x40 && c <= 0x7e {
			return i
		}
	}
	return i
}

func skipOSC(value string, i int) int {
	rest := value[i:]
	bel := strings.IndexByte(rest, '\a')
	st := strings.Index(rest, "\x1b\\")
	if bel < 0 && st < 0 {
		return len(value)
	}
	if bel >= 0 && (st < 0 || bel < st) {
		return i + bel + 1
	}
	return i + st + 2
}
