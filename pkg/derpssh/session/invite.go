// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/shayne/derphole/pkg/derptun"
)

const InvitePrefix = "DSH1"

var ErrInvalidInvite = errors.New("invalid derpssh invite")

type Invite struct {
	ClientToken string `json:"client_token"`
}

func EncodeInvite(inv Invite) (string, error) {
	if strings.TrimSpace(inv.ClientToken) == "" {
		return "", ErrInvalidInvite
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	return InvitePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeInvite(raw string) (Invite, error) {
	if len(raw) <= len(InvitePrefix) || raw[:len(InvitePrefix)] != InvitePrefix {
		return Invite{}, ErrInvalidInvite
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw[len(InvitePrefix):])
	if err != nil {
		return Invite{}, ErrInvalidInvite
	}
	var inv Invite
	if err := json.Unmarshal(payload, &inv); err != nil {
		return Invite{}, ErrInvalidInvite
	}
	if !validInviteClientToken(inv.ClientToken) {
		return Invite{}, ErrInvalidInvite
	}
	return inv, nil
}

func validInviteClientToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	_, err := derptun.DecodeClientToken(token, time.Now())
	return err == nil
}
