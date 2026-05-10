// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package quicpath

import (
	"testing"

	"github.com/quic-go/quic-go/qlog"
)

func TestQUICMetricsTraceCountsCongestionStateTransitions(t *testing.T) {
	trace := &quicMetricsTrace{}

	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateApplicationLimited})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateApplicationLimited})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateCongestionAvoidance})
	trace.recordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateRecovery})

	if trace.summary.SlowStartEvents != 1 {
		t.Fatalf("SlowStartEvents = %d, want 1", trace.summary.SlowStartEvents)
	}
	if trace.summary.ApplicationLimitedEvents != 2 {
		t.Fatalf("ApplicationLimitedEvents = %d, want 2", trace.summary.ApplicationLimitedEvents)
	}
	if trace.summary.CongestionAvoidanceEvents != 1 {
		t.Fatalf("CongestionAvoidanceEvents = %d, want 1", trace.summary.CongestionAvoidanceEvents)
	}
	if trace.summary.RecoveryEvents != 1 {
		t.Fatalf("RecoveryEvents = %d, want 1", trace.summary.RecoveryEvents)
	}
}
