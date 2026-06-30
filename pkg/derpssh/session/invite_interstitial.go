// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"io"
	"strings"

	"github.com/shayne/derphole/pkg/derpssh/brand"
)

const hostQuitBeforeApprovalReason = "host_quit_before_approval"

type InviteOptions struct {
	Output  io.Writer
	Command string
}

type InviteInterstitial struct {
	output  io.Writer
	command string
}

func NewInviteInterstitial(opts InviteOptions) *InviteInterstitial {
	return &InviteInterstitial{
		output:  opts.Output,
		command: strings.TrimSpace(opts.Command),
	}
}

func (i *InviteInterstitial) Print() error {
	if i == nil || i.output == nil {
		return nil
	}
	_, err := io.WriteString(i.output, i.Text())
	return err
}

func (i *InviteInterstitial) Text() string {
	if i == nil {
		return invitePreflightScreen("")
	}
	return invitePreflightScreen(i.command)
}

func (i *InviteInterstitial) TextWithLineEnding(lineEnding string) string {
	text := i.Text()
	if lineEnding == "" || lineEnding == "\n" {
		return text
	}
	return strings.ReplaceAll(text, "\n", lineEnding)
}

func inviteInterstitialQuitReason(guestPending bool) CloseReason {
	if guestPending {
		return CloseReason{
			Code:    hostQuitBeforeApprovalReason,
			Message: "host quit before approval",
		}
	}
	return CloseReason{Code: "host_quit", Message: hostQuitReason}
}

func invitePreflightScreen(command string) string {
	lines := append(brand.WordmarkLines(),
		"",
		"Copy this command and send it to the other person:",
		"",
		strings.TrimSpace(command),
		"",
		"Press Enter to start sharing. Press q to quit.",
		"",
	)
	return strings.Join(lines, "\n")
}
