package probe

import (
	"encoding/json"
	"strings"
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
	}

	md := report.Markdown()
	for _, want := range []string{"ktzlxc", "raw", "670.5", "direct=true"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q: %s", want, md)
		}
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
	}

	got, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded["host"] != "ktzlxc" || decoded["mode"] != "raw" || decoded["direct"] != true {
		t.Fatalf("decoded report = %#v", decoded)
	}
}
