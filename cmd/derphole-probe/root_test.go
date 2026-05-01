package main

import (
	"bytes"
	"testing"
)

func TestRunShowsHelpForNoArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}

func TestRunShowsHelpForHelpFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}

func TestRunHelpCommandShowsSubcommandHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "server"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if got, want := stderr.String(), "usage: derphole-probe server\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunHelpCommandShowsTopologySubcommandHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "topology"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if got, want := stderr.String(), "usage: derphole-probe topology\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunHelpCommandRejectsExtraArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "server", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}

func TestRunHelpCommandRejectsUnknownSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "bogus", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if got, want := stderr.String(), "unknown command: bogus\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}

func TestRunServerRejectsPositionalArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if got := runServer([]string{"unexpected"}, &stdout, &stderr); got != 2 {
		t.Fatalf("runServer() = %d, want 2", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}

func TestRunClientRejectsPositionalArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if got := runClient([]string{"unexpected"}, &stdout, &stderr); got != 2 {
		t.Fatalf("runClient() = %d, want 2", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}

func TestRunOrchestrateRejectsPositionalArgs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if got := runOrchestrate([]string{"unexpected"}, &stdout, &stderr); got != 2 {
		t.Fatalf("runOrchestrate() = %d, want 2", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr error text is empty")
	}
}

func TestRunServerShowsHelpForHelpFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if got := runServer([]string{"--help"}, &stdout, &stderr); got != 0 {
		t.Fatalf("runServer() = %d, want 0", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}
