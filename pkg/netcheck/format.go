// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netcheck

import (
	"fmt"
	"strings"
)

func FormatHuman(report Report) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "Network check: %s\n\n", valueOrUnknown(report.Verdict))
	_, _ = fmt.Fprintf(&b, "UDP:\n")
	_, _ = fmt.Fprintf(&b, "  Outbound UDP: %s\n", yesNo(report.UDP.Outbound))
	_, _ = fmt.Fprintf(&b, "  STUN: %s\n", yesNo(report.UDP.STUN))
	_, _ = fmt.Fprintf(&b, "  Public endpoint: %s\n", joinOrUnavailable(report.UDP.PublicEndpoints))
	_, _ = fmt.Fprintf(&b, "  Mapping: %s\n", mappingText(report))
	_, _ = fmt.Fprintf(&b, "  Port preservation: %s\n\n", yesNo(report.UDP.PortPreserving))
	_, _ = fmt.Fprintf(&b, "Candidates:\n")
	_, _ = fmt.Fprintf(&b, "  LAN: %s\n", joinOrNone(report.Candidates.LAN))
	_, _ = fmt.Fprintf(&b, "  Overlay: %s\n", joinOrNone(report.Candidates.Overlay))
	_, _ = fmt.Fprintf(&b, "  Public: %s\n\n", joinOrNone(report.Candidates.Public))
	_, _ = fmt.Fprintf(&b, "Direct-connect readiness:\n")
	_, _ = fmt.Fprintf(&b, "  %s\n", valueOrUnknown(report.Recommendation))
	return b.String()
}

func mappingText(report Report) string {
	if !report.UDP.STUN || len(report.UDP.PublicEndpoints) == 0 {
		return "unavailable"
	}
	if report.UDP.MappingStable {
		return "stable across STUN servers"
	}
	return "changes by STUN destination"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func joinOrUnavailable(values []string) string {
	if len(values) == 0 {
		return "unavailable"
	}
	return strings.Join(values, ", ")
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
