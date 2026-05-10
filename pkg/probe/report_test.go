// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"encoding/json"
	"testing"
)

func TestMarkdownReportIncludesCoreMetrics(t *testing.T) {
	report := RunReport{
		Host:          "ktzlxc",
		Mode:          "raw",
		Transport:     "batched",
		Direction:     "forward",
		SizeBytes:     1 << 20,
		BytesReceived: 1 << 20,
		DurationMS:    1250,
		GoodputMbps:   670.5,
		Direct:        true,
		FirstByteMS:   18,
		LossRate:      0.125,
		Retransmits:   4,
		Local: TransportCaps{
			Kind:             "legacy",
			RequestedKind:    "batched",
			RequestedSockBuf: 8 << 20,
			ReadBufferBytes:  425984,
			WriteBufferBytes: 425984,
		},
		Remote: TransportCaps{
			Kind:          "batched",
			RequestedKind: "batched",
			BatchSize:     128,
			RXOffload:     true,
			TXOffload:     true,
		},
	}

	md := report.Markdown()
	want := "- host=ktzlxc mode=raw transport=batched direction=forward size=1048576 bytes_received=1048576 duration_ms=1250 goodput_mbps=670.5 direct=true first_byte_ms=18 loss_rate=0.1250 retransmits=4 local=legacy(req=batched batch=0 read_buf=425984 write_buf=425984 tx_offload=false rx_offload=false rxq_overflow=false connected=false) remote=batched(req=batched batch=128 read_buf=0 write_buf=0 tx_offload=true rx_offload=true rxq_overflow=false connected=false)"
	if md != want {
		t.Fatalf("Markdown() = %q, want %q", md, want)
	}
}

func TestRunReportJSONEncodesCoreMetrics(t *testing.T) {
	report := RunReport{
		Host:              "ktzlxc",
		Mode:              "raw",
		Transport:         "batched",
		Direction:         "forward",
		SizeBytes:         1024,
		BytesReceived:     1000,
		DurationMS:        10,
		GoodputMbps:       8.5,
		PeakGoodputMbps:   8.5,
		Direct:            true,
		FirstByteMS:       3,
		FirstByteMeasured: boolPtr(true),
		LossRate:          0.02,
		Retransmits:       1,
		Success:           boolPtr(true),
		Local:             TransportCaps{Kind: "legacy", RequestedKind: "batched"},
		Remote:            TransportCaps{Kind: "batched", RequestedKind: "batched", BatchSize: 128, TXOffload: true},
	}

	got, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	for _, forbidden := range []string{"user", "remote_path", "listen_addr", "server_command", "client_command"} {
		if _, ok := decoded[forbidden]; ok {
			t.Fatalf("JSON unexpectedly included %q: %#v", forbidden, decoded)
		}
	}
	if decoded["host"] != "ktzlxc" || decoded["mode"] != "raw" || decoded["transport"] != "batched" || decoded["direct"] != true || decoded["first_byte_ms"] != float64(3) || decoded["first_byte_measured"] != true || decoded["loss_rate"] != float64(0.02) || decoded["retransmits"] != float64(1) || decoded["bytes_received"] != float64(1000) || decoded["success"] != true || decoded["peak_goodput_mbps"] != float64(8.5) {
		t.Fatalf("decoded report = %#v", decoded)
	}
	local, ok := decoded["local"].(map[string]any)
	if !ok || local["kind"] != "legacy" || local["requested_kind"] != "batched" {
		t.Fatalf("decoded local transport = %#v", decoded["local"])
	}
	remote, ok := decoded["remote"].(map[string]any)
	if !ok || remote["kind"] != "batched" || remote["batch_size"] != float64(128) || remote["tx_offload"] != true {
		t.Fatalf("decoded remote transport = %#v", decoded["remote"])
	}
}

func TestRunReportJSONRoundTripsExplicitFalseSuccess(t *testing.T) {
	report := RunReport{
		Host:        "ktzlxc",
		Mode:        "raw",
		Direction:   "forward",
		DurationMS:  1,
		GoodputMbps: 1,
		Success:     boolPtr(false),
	}

	got, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(map) error = %v", err)
	}
	if decoded["success"] != false {
		t.Fatalf("decoded success = %#v, want false", decoded["success"])
	}

	var roundTripped RunReport
	if err := json.Unmarshal(got, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal(RunReport) error = %v", err)
	}
	if roundTripped.Success == nil || *roundTripped.Success {
		t.Fatalf("roundTripped.Success = %#v, want false", roundTripped.Success)
	}
}

func TestRunReportJSONLegacyOmittedSuccessPreservesLegacyBehavior(t *testing.T) {
	report := RunReport{
		Host:        "ktzlxc",
		Mode:        "raw",
		Direction:   "forward",
		DurationMS:  1,
		GoodputMbps: 1,
	}

	got, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(map) error = %v", err)
	}
	if _, ok := decoded["success"]; ok {
		t.Fatalf("decoded unexpectedly included success: %#v", decoded)
	}

	var roundTripped RunReport
	if err := json.Unmarshal(got, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal(RunReport) error = %v", err)
	}
	if roundTripped.Success != nil {
		t.Fatalf("roundTripped.Success = %#v, want nil", roundTripped.Success)
	}
	if got := SummarizeRuns([]RunReport{roundTripped}); got.SuccessCount != 1 {
		t.Fatalf("legacy round-tripped report did not count as successful")
	}
}

func TestRunReportJSONOmitsEmptyTransportCaps(t *testing.T) {
	report := RunReport{
		Host:        "ktzlxc",
		Mode:        "raw",
		Direction:   "forward",
		DurationMS:  1,
		GoodputMbps: 1,
	}

	got, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if _, ok := decoded["local"]; ok {
		t.Fatalf("decoded unexpectedly included local: %#v", decoded)
	}
	if _, ok := decoded["remote"]; ok {
		t.Fatalf("decoded unexpectedly included remote: %#v", decoded)
	}
	if _, ok := decoded["first_byte_measured"]; ok {
		t.Fatalf("decoded unexpectedly included first_byte_measured: %#v", decoded)
	}
}
