// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import "testing"

func TestParseIperf3ResultPrefersReceivedTotals(t *testing.T) {
	report, err := parseIperf3Result([]byte(`{
  "end": {
    "sum_sent": {
      "seconds": 1.5,
      "bytes": 1048576,
      "bits_per_second": 5592405.3
    },
    "sum_received": {
      "seconds": 1.4,
      "bytes": 2097152,
      "bits_per_second": 11983725.7
    }
  }
}`))
	if err != nil {
		t.Fatalf("parseIperf3Result() error = %v", err)
	}
	if report.Bytes != 2097152 {
		t.Fatalf("report.Bytes = %d, want 2097152", report.Bytes)
	}
	if report.DurationMS != 1400 {
		t.Fatalf("report.DurationMS = %d, want 1400", report.DurationMS)
	}
	if report.BitsPerSecond != 11983725.7 {
		t.Fatalf("report.BitsPerSecond = %f, want 11983725.7", report.BitsPerSecond)
	}
}

func TestParseIperf3ResultFallsBackToSentTotals(t *testing.T) {
	report, err := parseIperf3Result([]byte(`{
  "end": {
    "sum_sent": {
      "seconds": 2.0,
      "bytes": 5242880,
      "bits_per_second": 20971520.0
    }
  }
}`))
	if err != nil {
		t.Fatalf("parseIperf3Result() error = %v", err)
	}
	if report.Bytes != 5242880 {
		t.Fatalf("report.Bytes = %d, want 5242880", report.Bytes)
	}
	if report.DurationMS != 2000 {
		t.Fatalf("report.DurationMS = %d, want 2000", report.DurationMS)
	}
	if report.BitsPerSecond != 20971520.0 {
		t.Fatalf("report.BitsPerSecond = %f, want 20971520.0", report.BitsPerSecond)
	}
}
