package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shayne/derphole/pkg/netcheck"
)

func TestRunNetcheckPrintsHumanReport(t *testing.T) {
	oldRunNetcheck := runNetcheck
	defer func() { runNetcheck = oldRunNetcheck }()
	runNetcheck = func(ctx context.Context, cfg netcheck.Config) (netcheck.Report, error) {
		if cfg.Timeout != 5*time.Second {
			t.Fatalf("Timeout = %v, want 5s", cfg.Timeout)
		}
		return netcheck.Report{
			Verdict: netcheck.VerdictDirectFriendly,
			UDP: netcheck.UDPReport{
				Outbound:        true,
				STUN:            true,
				PublicEndpoints: []string{"203.0.113.10:57179"},
				MappingStable:   true,
				PortPreserving:  true,
			},
			Recommendation: netcheck.Recommendation(netcheck.VerdictDirectFriendly),
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"netcheck"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Network check: direct-friendly") {
		t.Fatalf("stderr = %q, want human report", stderr.String())
	}
}

func TestRunNetcheckPrintsJSONReport(t *testing.T) {
	oldRunNetcheck := runNetcheck
	defer func() { runNetcheck = oldRunNetcheck }()
	runNetcheck = func(ctx context.Context, cfg netcheck.Config) (netcheck.Report, error) {
		return netcheck.Report{
			Verdict: netcheck.VerdictDirectLimited,
			UDP: netcheck.UDPReport{
				Outbound:        true,
				STUN:            true,
				PublicEndpoints: []string{"198.51.100.20:51433"},
			},
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"netcheck", "--json", "--timeout", "2s"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verdict": "direct-limited"`) {
		t.Fatalf("stdout = %q, want JSON report", stdout.String())
	}
}

func TestRunNetcheckRejectsInvalidTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"netcheck", "--timeout", "nope"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "timeout must be a positive duration") {
		t.Fatalf("stderr = %q, want timeout validation", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}
