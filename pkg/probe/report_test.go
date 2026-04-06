package probe

import (
	"encoding/json"
	"testing"
)

func TestMarkdownReportIncludesCoreMetrics(t *testing.T) {
	report := RunReport{
		Host:        "ktzlxc",
		Mode:        "raw",
		Direction:   "forward",
		SizeBytes:   1 << 20,
		DurationMS:  1250,
		GoodputMbps: 670.5,
		Direct:      true,
		FirstByteMS: 18,
		LossRate:    0.125,
		Retransmits: 4,
	}

	md := report.Markdown()
	want := "- host=ktzlxc mode=raw direction=forward size=1048576 duration_ms=1250 goodput_mbps=670.5 direct=true first_byte_ms=18 loss_rate=0.1250 retransmits=4"
	if md != want {
		t.Fatalf("Markdown() = %q, want %q", md, want)
	}
}

func TestRunReportJSONEncodesCoreMetrics(t *testing.T) {
	report := RunReport{
		Host:        "ktzlxc",
		Mode:        "raw",
		Direction:   "forward",
		SizeBytes:   1024,
		DurationMS:  10,
		GoodputMbps: 8.5,
		Direct:      true,
		FirstByteMS: 3,
		LossRate:    0.02,
		Retransmits: 1,
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
	if decoded["host"] != "ktzlxc" || decoded["mode"] != "raw" || decoded["direct"] != true || decoded["first_byte_ms"] != float64(3) || decoded["loss_rate"] != float64(0.02) || decoded["retransmits"] != float64(1) {
		t.Fatalf("decoded report = %#v", decoded)
	}
}
