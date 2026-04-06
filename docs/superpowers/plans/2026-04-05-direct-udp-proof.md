# Direct UDP Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, with repeatable benchmarks, whether a standalone direct UDP probe can materially outperform current no-Tailscale derpcat on `ktzlxc`, `canlxc`, `uklxc`, and `orange-india.exe.xyz`, while staying isolated from derpcat's production transport.

**Architecture:** Build a separate `derpcat-probe` binary plus a focused `pkg/probe` package. The probe uses SSH for orchestration, `pkg/traversal` for public endpoint discovery, a minimal fixed-header UDP transport with ACK/SACK-based recovery, and optional AEAD mode only after the raw-mode benchmark gate passes on `ktzlxc`.

**Tech Stack:** Go, `github.com/shayne/yargs`, standard `net` UDP sockets, `os/exec` for `ssh`/`scp`, existing `pkg/traversal` STUN helpers, existing benchmark shell harnesses, markdown + JSON result logs.

---

## File Structure

**Create:**

- `cmd/derpcat-probe/main.go` — entrypoint for the experimental probe binary.
- `cmd/derpcat-probe/root.go` — CLI registry and subcommand dispatch.
- `cmd/derpcat-probe/server.go` — `server` subcommand wiring.
- `cmd/derpcat-probe/client.go` — `client` subcommand wiring.
- `cmd/derpcat-probe/orchestrate.go` — `orchestrate` subcommand wiring.
- `cmd/derpcat-probe/root_test.go` — CLI routing and help coverage.
- `pkg/probe/protocol.go` — packet types, header encode/decode, shared constants.
- `pkg/probe/protocol_test.go` — protocol round-trip and validation tests.
- `pkg/probe/session.go` — sender/receiver session loop, ACK handling, retransmit window.
- `pkg/probe/session_test.go` — packet loss/reorder tests and end-to-end loopback tests.
- `pkg/probe/discovery.go` — public endpoint discovery and simultaneous punch helpers.
- `pkg/probe/discovery_test.go` — direct punch behavior tests.
- `pkg/probe/report.go` — JSON result structs and markdown formatting helpers.
- `pkg/probe/report_test.go` — stable report formatting tests.
- `pkg/probe/orchestrator.go` — remote command runner, deploy logic, benchmark flow.
- `pkg/probe/orchestrator_test.go` — command construction and result aggregation tests.
- `scripts/probe-benchmark.sh` — forward benchmark harness for the probe.
- `scripts/probe-benchmark-reverse.sh` — reverse benchmark harness for the probe.
- `scripts/probe-matrix.sh` — matrix runner for `ktzlxc`, `canlxc`, `uklxc`, and `orange-india.exe.xyz`.

**Modify:**

- `docs/benchmarks.md` — add the probe harnesses and proof workflow.

**Reuse without modification where possible:**

- `pkg/traversal/candidates.go`
- `pkg/traversal/prober.go`
- `scripts/promotion-test.sh`
- `scripts/promotion-test-reverse.sh`

## Scope Note

This plan covers **phase 1 only**. It intentionally stops at the proof gate. If the raw or encrypted probe does not beat current derpcat on `ktzlxc`, do not start a production refactor. Write down the benchmark evidence and stop.

### Task 1: Scaffold the probe protocol and CLI shell

**Files:**
- Create: `pkg/probe/protocol.go`
- Create: `pkg/probe/protocol_test.go`
- Create: `cmd/derpcat-probe/main.go`
- Create: `cmd/derpcat-probe/root.go`
- Create: `cmd/derpcat-probe/server.go`
- Create: `cmd/derpcat-probe/client.go`
- Create: `cmd/derpcat-probe/orchestrate.go`
- Create: `cmd/derpcat-probe/root_test.go`

- [ ] **Step 1: Write the failing protocol and CLI tests**

```go
// pkg/probe/protocol_test.go
package probe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	p := Packet{
		Version:  ProtocolVersion,
		Type:     PacketTypeData,
		RunID:    [16]byte{1, 2, 3, 4},
		Seq:      42,
		Offset:   8192,
		AckFloor: 4096,
		Payload:  []byte("hello"),
	}

	buf, err := MarshalPacket(p, nil)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}

	got, err := UnmarshalPacket(buf, nil)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}

	if got.Version != p.Version || got.Type != p.Type || got.RunID != p.RunID || got.Seq != p.Seq || got.Offset != p.Offset || got.AckFloor != p.AckFloor || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("round trip mismatch: got %#v want %#v", got, p)
	}
}

func TestUnmarshalPacketRejectsShortHeader(t *testing.T) {
	if _, err := UnmarshalPacket([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("UnmarshalPacket() error = nil, want short header error")
	}
}

func TestPacketRejectsAEAD(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	if _, err := MarshalPacket(Packet{}, aead); err == nil {
		t.Fatal("MarshalPacket() error = nil, want encrypted mode error")
	}
	if _, err := UnmarshalPacket(make([]byte, headerLen), aead); err == nil {
		t.Fatal("UnmarshalPacket() error = nil, want encrypted mode error")
	}
}
```

```go
// cmd/derpcat-probe/root_test.go
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
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
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
		t.Fatal("stderr help text is empty")
	}
}

func TestRunHelpCommandRejectsUnknownSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help", "bogus", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stderr.String() != "unknown command: bogus\n" {
		t.Fatalf("stderr = %q, want unknown command output", stderr.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
}

func TestRunServerRejectsPositionalArgs(t *testing.T) {
	var stderr bytes.Buffer
	if got := runServer([]string{"unexpected"}, nil, &stderr); got != 2 {
		t.Fatalf("runServer() = %d, want 2", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}

func TestRunClientRejectsPositionalArgs(t *testing.T) {
	var stderr bytes.Buffer
	if got := runClient([]string{"unexpected"}, nil, &stderr); got != 2 {
		t.Fatalf("runClient() = %d, want 2", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}

func TestRunOrchestrateRejectsPositionalArgs(t *testing.T) {
	var stderr bytes.Buffer
	if got := runOrchestrate([]string{"unexpected"}, nil, &stderr); got != 2 {
		t.Fatalf("runOrchestrate() = %d, want 2", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}

func TestRunServerShowsHelpForHelpFlag(t *testing.T) {
	var stderr bytes.Buffer
	if got := runServer([]string{"--help"}, nil, &stderr); got != 0 {
		t.Fatalf("runServer() = %d, want 0", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr help text is empty")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/probe -run 'TestPacketRoundTrip|TestUnmarshalPacketRejectsShortHeader|TestPacketRejectsAEAD' -count=1
go test ./cmd/derpcat-probe -run 'TestRunShowsHelpForNoArgs|TestRunShowsHelpForHelpFlag|TestRunHelpCommandShowsSubcommandHelp|TestRunHelpCommandRejectsExtraArgs|TestRunHelpCommandRejectsUnknownSubcommand|TestRunRejectsUnknownCommand|TestRunServerRejectsPositionalArgs|TestRunClientRejectsPositionalArgs|TestRunOrchestrateRejectsPositionalArgs|TestRunServerShowsHelpForHelpFlag' -count=1
```

Expected:

- first command fails because `pkg/probe` does not exist
- second command fails because `cmd/derpcat-probe` does not exist

- [ ] **Step 3: Write the minimal protocol and CLI shell**

```go
// pkg/probe/protocol.go
package probe

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	ProtocolVersion = 1
	headerLen       = 44
)

type PacketType uint8

const (
	PacketTypeHello PacketType = iota + 1
	PacketTypeHelloAck
	PacketTypeData
	PacketTypeAck
	PacketTypeDone
	PacketTypeStats
)

type Packet struct {
	Version  uint8
	Type     PacketType
	RunID    [16]byte
	Seq      uint64
	Offset   uint64
	AckFloor uint64
	Payload  []byte
}

func MarshalPacket(p Packet, aead cipher.AEAD) ([]byte, error) {
	buf := make([]byte, headerLen+len(p.Payload))
	buf[0] = p.Version
	buf[1] = byte(p.Type)
	copy(buf[4:20], p.RunID[:])
	binary.BigEndian.PutUint64(buf[20:28], p.Seq)
	binary.BigEndian.PutUint64(buf[28:36], p.Offset)
	binary.BigEndian.PutUint64(buf[36:44], p.AckFloor)
	copy(buf[44:], p.Payload)
	if aead != nil {
		return nil, errors.New("encrypted mode not implemented")
	}
	return buf, nil
}

func UnmarshalPacket(buf []byte, aead cipher.AEAD) (Packet, error) {
	if len(buf) < headerLen {
		return Packet{}, errors.New("short packet")
	}
	if aead != nil {
		return Packet{}, errors.New("encrypted mode not implemented")
	}
	var p Packet
	p.Version = buf[0]
	p.Type = PacketType(buf[1])
	copy(p.RunID[:], buf[4:20])
	p.Seq = binary.BigEndian.Uint64(buf[20:28])
	p.Offset = binary.BigEndian.Uint64(buf[28:36])
	p.AckFloor = binary.BigEndian.Uint64(buf[36:44])
	p.Payload = append([]byte(nil), buf[44:]...)
	return p, nil
}
```

```go
// cmd/derpcat-probe/main.go
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
```

```go
// cmd/derpcat-probe/root.go
package main

import (
	"fmt"
	"io"

	"github.com/shayne/yargs"
)

var registry = yargs.Registry{
	Command: yargs.CommandInfo{
		Name:        "derpcat-probe",
		Description: "Experimental direct UDP benchmark probe.",
	},
	SubCommands: map[string]yargs.CommandSpec{
		"server":      {Info: yargs.SubCommandInfo{Name: "server", Description: "Run remote server mode."}},
		"client":      {Info: yargs.SubCommandInfo{Name: "client", Description: "Run local client mode."}},
		"orchestrate": {Info: yargs.SubCommandInfo{Name: "orchestrate", Description: "Run end-to-end proof benchmark."}},
	},
}

var helpConfig = registry.HelpConfig()

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isRootHelpRequest(args) {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(helpConfig, struct{}{}))
		return 0
	}
	if args[0] == "help" {
		return runHelp(args[1:], stderr)
	}
	switch args[0] {
	case "server":
		return runServer(args[1:], stdout, stderr)
	case "client":
		return runClient(args[1:], stdout, stderr)
	case "orchestrate":
		return runOrchestrate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}

func isRootHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help")
}

func runHelp(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, yargs.GenerateGlobalHelp(helpConfig, struct{}{}))
		return 0
	}
	switch args[0] {
	case "server":
		if len(args) != 1 {
			fmt.Fprint(stderr, subcommandUsageLine("server"))
			return 2
		}
		fmt.Fprint(stderr, "usage: derpcat-probe server\n")
		return 0
	case "client":
		if len(args) != 1 {
			fmt.Fprint(stderr, subcommandUsageLine("client"))
			return 2
		}
		fmt.Fprint(stderr, "usage: derpcat-probe client\n")
		return 0
	case "orchestrate":
		if len(args) != 1 {
			fmt.Fprint(stderr, subcommandUsageLine("orchestrate"))
			return 2
		}
		fmt.Fprint(stderr, "usage: derpcat-probe orchestrate\n")
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}
```

```go
// cmd/derpcat-probe/server.go
package main

import (
	"fmt"
	"io"
)

func runServer(args []string, stdout, stderr io.Writer) int {
	if isRootHelpRequest(args) {
		fmt.Fprint(stderr, "usage: derpcat-probe server\n")
		return 0
	}
	if len(args) != 0 {
		fmt.Fprint(stderr, "usage: derpcat-probe server\n")
		return 2
	}
	return 0
}
```

```go
// cmd/derpcat-probe/client.go
package main

import (
	"fmt"
	"io"
)

func runClient(args []string, stdout, stderr io.Writer) int {
	if isRootHelpRequest(args) {
		fmt.Fprint(stderr, "usage: derpcat-probe client\n")
		return 0
	}
	if len(args) != 0 {
		fmt.Fprint(stderr, "usage: derpcat-probe client\n")
		return 2
	}
	return 0
}
```

```go
// cmd/derpcat-probe/orchestrate.go
package main

import (
	"fmt"
	"io"
)

func runOrchestrate(args []string, stdout, stderr io.Writer) int {
	if isRootHelpRequest(args) {
		fmt.Fprint(stderr, "usage: derpcat-probe orchestrate\n")
		return 0
	}
	if len(args) != 0 {
		fmt.Fprint(stderr, "usage: derpcat-probe orchestrate\n")
		return 2
	}
	return 0
}
```

- [ ] **Step 4: Run tests to verify the shell passes**

Run:

```bash
go test ./pkg/probe -run 'TestPacketRoundTrip|TestUnmarshalPacketRejectsShortHeader|TestPacketRejectsAEAD' -count=1
go test ./cmd/derpcat-probe -run 'TestRunShowsHelpForNoArgs|TestRunShowsHelpForHelpFlag|TestRunHelpCommandShowsSubcommandHelp|TestRunHelpCommandRejectsExtraArgs|TestRunHelpCommandRejectsUnknownSubcommand|TestRunRejectsUnknownCommand|TestRunServerRejectsPositionalArgs|TestRunClientRejectsPositionalArgs|TestRunOrchestrateRejectsPositionalArgs|TestRunServerShowsHelpForHelpFlag' -count=1
```

Expected:

- both commands PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/probe/protocol.go pkg/probe/protocol_test.go cmd/derpcat-probe/main.go cmd/derpcat-probe/root.go cmd/derpcat-probe/server.go cmd/derpcat-probe/client.go cmd/derpcat-probe/orchestrate.go cmd/derpcat-probe/root_test.go
git commit -m "probe: scaffold udp proof cli"
```

### Task 2: Implement raw UDP discovery, punch, and transfer

**Files:**
- Create: `pkg/probe/discovery.go`
- Create: `pkg/probe/discovery_test.go`
- Create: `pkg/probe/session.go`
- Create: `pkg/probe/session_test.go`
- Modify: `pkg/probe/protocol.go`

- [ ] **Step 1: Write the failing discovery and transfer tests**

```go
// pkg/probe/discovery_test.go
package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPunchDirectLoopback(t *testing.T) {
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := PunchDirect(ctx, a, b.LocalAddr().String(), b, a.LocalAddr().String())
	if err != nil {
		t.Fatalf("PunchDirect() error = %v", err)
	}
	if !got.Direct {
		t.Fatal("PunchDirect() direct = false, want true")
	}
}
```

```go
// pkg/probe/session_test.go
package probe

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestTransferCompletesAcrossLoopback(t *testing.T) {
	src := bytes.Repeat([]byte("derpcat"), 1<<17)
	a, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	b, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := Receive(ctx, b, a.LocalAddr().String(), ReceiveConfig{Raw: true})
		done <- err
	}()

	stats, err := Send(ctx, a, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if stats.BytesSent != int64(len(src)) {
		t.Fatalf("BytesSent = %d, want %d", stats.BytesSent, len(src))
	}
	if err := <-done; err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/probe -run 'TestPunchDirectLoopback|TestTransferCompletesAcrossLoopback' -count=1
```

Expected:

- FAIL with undefined `PunchDirect`, `Send`, `Receive`, `ReceiveConfig`, or `SendConfig`

- [ ] **Step 3: Implement raw UDP discovery and bounded reliability**

```go
// pkg/probe/discovery.go
package probe

import (
	"context"
	"net"

	"github.com/shayne/derpcat/pkg/traversal"
)

type DirectResult struct {
	Direct bool
}

func PunchDirect(ctx context.Context, local net.PacketConn, remoteAddr string, remote net.PacketConn, localAddr string) (DirectResult, error) {
	result, err := traversal.ProbeDirect(ctx, local, remoteAddr, remote, localAddr)
	if err != nil {
		return DirectResult{}, err
	}
	return DirectResult{Direct: result.Direct}, nil
}
```

```go
// pkg/probe/session.go
package probe

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type SendConfig struct {
	Raw        bool
	ChunkSize  int
	WindowSize int
}

type ReceiveConfig struct {
	Raw bool
}

type TransferStats struct {
	BytesSent     int64
	BytesReceived int64
	PacketsSent   int64
	PacketsAcked  int64
	StartedAt     time.Time
	CompletedAt   time.Time
}

func Send(ctx context.Context, conn net.PacketConn, remoteAddr string, src io.Reader, cfg SendConfig) (TransferStats, error) {
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = 1200
	}
	peer, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return TransferStats{}, err
	}
	stats := TransferStats{StartedAt: time.Now()}
	buf := make([]byte, cfg.ChunkSize)
	var seq uint64
	var offset uint64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			pkt, err := MarshalPacket(Packet{
				Version: ProtocolVersion,
				Type:    PacketTypeData,
				Seq:     seq,
				Offset:  offset,
				Payload: append([]byte(nil), buf[:n]...),
			}, nil)
			if err != nil {
				return TransferStats{}, err
			}
			if _, err := conn.WriteTo(pkt, peer); err != nil {
				return TransferStats{}, err
			}
			atomic.AddInt64(&stats.BytesSent, int64(n))
			atomic.AddInt64(&stats.PacketsSent, 1)
			seq++
			offset += uint64(n)
		}
		if readErr == io.EOF {
			donePkt, err := MarshalPacket(Packet{Version: ProtocolVersion, Type: PacketTypeDone, Seq: seq, Offset: offset}, nil)
			if err != nil {
				return TransferStats{}, err
			}
			_, err = conn.WriteTo(donePkt, peer)
			stats.CompletedAt = time.Now()
			return stats, err
		}
		if readErr != nil {
			return TransferStats{}, readErr
		}
	}
}

func Receive(ctx context.Context, conn net.PacketConn, remoteAddr string, cfg ReceiveConfig) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 64<<10)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return nil, err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if remoteAddr != "" && addr.String() != remoteAddr {
			continue
		}
		pkt, err := UnmarshalPacket(buf[:n], nil)
		if err != nil {
			return nil, err
		}
		switch pkt.Type {
		case PacketTypeData:
			if _, err := out.Write(pkt.Payload); err != nil {
				return nil, err
			}
		case PacketTypeDone:
			return out.Bytes(), nil
		}
	}
}
```

- [ ] **Step 4: Add loss/reorder coverage before moving on**

```go
// pkg/probe/session_test.go
func TestTransferSurvivesDroppedPackets(t *testing.T) {
	t.Skip("replace with lossy packet conn wrapper before production benchmarking")
}
```

Run:

```bash
go test ./pkg/probe -run 'TestPunchDirectLoopback|TestTransferCompletesAcrossLoopback' -count=1
```

Expected:

- PASS

- [ ] **Step 5: Replace the skip with a real lossy wrapper test**

```go
// pkg/probe/session_test.go
type lossyPacketConn struct {
	net.PacketConn
	dropEvery int
	writes    int
}

func (l *lossyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	l.writes++
	if l.dropEvery > 0 && l.writes%l.dropEvery == 0 {
		return len(p), nil
	}
	return l.PacketConn.WriteTo(p, addr)
}

func TestTransferSurvivesDroppedPackets(t *testing.T) {
	src := bytes.Repeat([]byte("udp-proof"), 1<<16)
	a, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer a.Close()
	b, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer b.Close()

	lossy := &lossyPacketConn{PacketConn: a, dropEvery: 7}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan []byte, 1)
	go func() {
		got, err := Receive(ctx, b, "", ReceiveConfig{Raw: true})
		if err != nil {
			t.Errorf("Receive() error = %v", err)
			return
		}
		done <- got
	}()

	if _, err := Send(ctx, lossy, b.LocalAddr().String(), bytes.NewReader(src), SendConfig{Raw: true, ChunkSize: 1200}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	got := <-done
	if !bytes.Equal(got, src) {
		t.Fatal("received payload mismatch")
	}
}
```

Run:

```bash
go test ./pkg/probe -count=1
```

Expected:

- PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/probe/discovery.go pkg/probe/discovery_test.go pkg/probe/session.go pkg/probe/session_test.go pkg/probe/protocol.go
git commit -m "probe: add raw udp transfer path"
```

### Task 3: Implement reporting and SSH orchestration

**Files:**
- Create: `pkg/probe/report.go`
- Create: `pkg/probe/report_test.go`
- Create: `pkg/probe/orchestrator.go`
- Create: `pkg/probe/orchestrator_test.go`
- Modify: `cmd/derpcat-probe/server.go`
- Modify: `cmd/derpcat-probe/client.go`
- Modify: `cmd/derpcat-probe/orchestrate.go`

- [ ] **Step 1: Write the failing orchestration and report tests**

```go
// pkg/probe/report_test.go
package probe

import (
	"strings"
	"testing"
)

func TestMarkdownReportIncludesCoreMetrics(t *testing.T) {
	report := RunReport{
		Host:       "ktzlxc",
		Mode:       "raw",
		Direction:  "forward",
		SizeBytes:  1 << 20,
		DurationMS: 1250,
		GoodputMbps: 670.5,
		Direct:     true,
	}

	md := report.Markdown()
	for _, want := range []string{"ktzlxc", "raw", "670.5", "direct=true"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q: %s", want, md)
		}
	}
}
```

```go
// pkg/probe/orchestrator_test.go
package probe

import (
	"context"
	"testing"
)

func TestRemoteCommandIncludesProbeBinaryAndServerMode(t *testing.T) {
	runner := SSHRunner{User: "root", Host: "ktzlxc", RemotePath: "/tmp/derpcat-probe"}
	cmd := runner.ServerCommand(ServerConfig{ListenAddr: ":0", Raw: true})
	if got, want := cmd[0], "ssh"; got != want {
		t.Fatalf("cmd[0] = %q, want %q", got, want)
	}
	found := false
	for _, part := range cmd {
		if part == "/tmp/derpcat-probe server --listen :0 --mode raw" {
			found = true
		}
	}
	if !found {
		t.Fatalf("server command missing expected remote invocation: %#v", cmd)
	}
}

func TestOrchestratorRejectsMissingHost(t *testing.T) {
	_, err := RunOrchestrate(context.Background(), OrchestrateConfig{})
	if err == nil {
		t.Fatal("RunOrchestrate() error = nil, want validation error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/probe -run 'TestMarkdownReportIncludesCoreMetrics|TestRemoteCommandIncludesProbeBinaryAndServerMode|TestOrchestratorRejectsMissingHost' -count=1
```

Expected:

- FAIL with undefined `RunReport`, `SSHRunner`, or `RunOrchestrate`

- [ ] **Step 3: Implement JSON and markdown reporting**

```go
// pkg/probe/report.go
package probe

import (
	"encoding/json"
	"fmt"
)

type RunReport struct {
	Host         string  `json:"host"`
	Mode         string  `json:"mode"`
	Direction    string  `json:"direction"`
	SizeBytes    int64   `json:"size_bytes"`
	DurationMS   int64   `json:"duration_ms"`
	GoodputMbps  float64 `json:"goodput_mbps"`
	Direct       bool    `json:"direct"`
	FirstByteMS  int64   `json:"first_byte_ms"`
	LossRate     float64 `json:"loss_rate"`
	Retransmits  int64   `json:"retransmits"`
}

func (r RunReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r RunReport) Markdown() string {
	return fmt.Sprintf("- host=%s mode=%s direction=%s size=%d duration_ms=%d goodput_mbps=%.1f direct=%t first_byte_ms=%d loss_rate=%.4f retransmits=%d",
		r.Host, r.Mode, r.Direction, r.SizeBytes, r.DurationMS, r.GoodputMbps, r.Direct, r.FirstByteMS, r.LossRate, r.Retransmits)
}
```

- [ ] **Step 4: Implement orchestration and wire the CLI**

```go
// pkg/probe/orchestrator.go
package probe

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type OrchestrateConfig struct {
	Host       string
	User       string
	RemotePath string
	SizeBytes  int64
	Mode       string
	Direction  string
}

type SSHRunner struct {
	User       string
	Host       string
	RemotePath string
}

func (r SSHRunner) target() string {
	if r.User == "" {
		return r.Host
	}
	return r.User + "@" + r.Host
}

func (r SSHRunner) ServerCommand(cfg ServerConfig) []string {
	return []string{
		"ssh",
		r.target(),
		fmt.Sprintf("%s server --listen %s --mode %s", r.RemotePath, cfg.ListenAddr, cfg.Mode),
	}
}

func RunOrchestrate(ctx context.Context, cfg OrchestrateConfig) (RunReport, error) {
	if cfg.Host == "" {
		return RunReport{}, errors.New("host is required")
	}
	if cfg.RemotePath == "" {
		cfg.RemotePath = "/tmp/derpcat-probe"
	}
	if cfg.Mode == "" {
		cfg.Mode = "raw"
	}
	if cfg.Direction == "" {
		cfg.Direction = "forward"
	}
	return RunReport{
		Host:      cfg.Host,
		Mode:      cfg.Mode,
		Direction: cfg.Direction,
		// Task 3 only verifies SSH/binary reachability. It does not prove a
		// direct UDP path yet, so the scaffold report must stay false here.
		Direct:    false,
	}, nil
}

func runCommand(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return out, nil
}
```

```go
// cmd/derpcat-probe/orchestrate.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/shayne/derpcat/pkg/probe"
	"github.com/shayne/yargs"
)

type orchestrateFlags struct {
	Host      string `flag:"host" help:"Remote host to benchmark"`
	User      string `flag:"user" help:"SSH user" default:"root"`
	SizeBytes int64  `flag:"size-bytes" help:"Payload size in bytes" default:"1048576"`
	Mode      string `flag:"mode" help:"raw only in Task 3; AEAD lands in Task 5" default:"raw"`
}

func runOrchestrate(args []string, stdout, stderr io.Writer) int {
	parsed, err := yargs.ParseKnownFlags[orchestrateFlags](args, yargs.KnownFlagsOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report, err := probe.RunOrchestrate(ctx, probe.OrchestrateConfig{
		Host:      parsed.Flags.Host,
		User:      parsed.Flags.User,
		SizeBytes: parsed.Flags.SizeBytes,
		Mode:      parsed.Flags.Mode,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
	return 0
}
```

- [ ] **Step 5: Run tests to verify orchestration scaffolding passes**

Run:

```bash
go test ./pkg/probe -run 'TestMarkdownReportIncludesCoreMetrics|TestRemoteCommandIncludesProbeBinaryAndServerMode|TestOrchestratorRejectsMissingHost' -count=1
go test ./cmd/derpcat-probe -count=1
```

Expected:

- both commands PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/probe/report.go pkg/probe/report_test.go pkg/probe/orchestrator.go pkg/probe/orchestrator_test.go cmd/derpcat-probe/server.go cmd/derpcat-probe/client.go cmd/derpcat-probe/orchestrate.go
git commit -m "probe: add orchestration and reporting"
```

### Task 4: Add benchmark harnesses and run the raw-mode proof gate on `ktzlxc`

**Files:**
- Create: `scripts/probe-benchmark.sh`
- Create: `scripts/probe-benchmark-reverse.sh`
- Create: `scripts/probe-matrix.sh`
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Write the failing harness smoke test**

```bash
test -x scripts/probe-benchmark.sh
test -x scripts/probe-benchmark-reverse.sh
test -x scripts/probe-matrix.sh
```

Expected:

- FAIL because the scripts do not exist

- [ ] **Step 2: Implement the probe harnesses**

```bash
#!/usr/bin/env bash
# scripts/probe-benchmark.sh
set -euo pipefail

target="${1:?usage: $0 <target> [size-bytes]}"
size_bytes="${2:-1073741824}"
remote_user="${DERPCAT_REMOTE_USER:-root}"

mise run build
GOOS=linux GOARCH=amd64 go build -o dist/derpcat-probe-linux-amd64 ./cmd/derpcat-probe
scp dist/derpcat-probe-linux-amd64 "${remote_user}@${target}:/tmp/derpcat-probe" >/dev/null
ssh "${remote_user}@${target}" "chmod +x /tmp/derpcat-probe"

./dist/derpcat-probe orchestrate --host "${target}" --user "${remote_user}" --size-bytes "${size_bytes}" --mode raw
```

```bash
#!/usr/bin/env bash
# scripts/probe-benchmark-reverse.sh
set -euo pipefail

target="${1:?usage: $0 <target> [size-bytes]}"
size_bytes="${2:-1073741824}"
remote_user="${DERPCAT_REMOTE_USER:-root}"

mise run build
GOOS=linux GOARCH=amd64 go build -o dist/derpcat-probe-linux-amd64 ./cmd/derpcat-probe
scp dist/derpcat-probe-linux-amd64 "${remote_user}@${target}:/tmp/derpcat-probe" >/dev/null
ssh "${remote_user}@${target}" "chmod +x /tmp/derpcat-probe"

ssh "${remote_user}@${target}" "/tmp/derpcat-probe orchestrate --host '$(hostname -s)' --user '${USER}' --size-bytes '${size_bytes}' --mode raw"
```

```bash
#!/usr/bin/env bash
# scripts/probe-matrix.sh
set -euo pipefail

for host in ktzlxc canlxc uklxc orange-india.exe.xyz; do
  ./scripts/probe-benchmark.sh "${host}" 10240
  ./scripts/probe-benchmark.sh "${host}" 1048576
  ./scripts/probe-benchmark.sh "${host}" 10485760
  ./scripts/probe-benchmark.sh "${host}" 52428800
  ./scripts/probe-benchmark.sh "${host}" 134217728
  ./scripts/probe-benchmark.sh "${host}" 1073741824
done
```

```markdown
<!-- docs/benchmarks.md -->
- `./scripts/probe-benchmark.sh my-server.example.com 1073741824`
- `./scripts/probe-benchmark-reverse.sh my-server.example.com 1073741824`
- `./scripts/probe-matrix.sh`
```

- [ ] **Step 3: Run the raw proof gate on `ktzlxc`**

Run:

```bash
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024 | tee /tmp/derpcat-ktzlxc-current.log
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh ktzlxc 1024 | tee /tmp/derpcat-ktzlxc-auto.log
./scripts/probe-benchmark.sh ktzlxc 1073741824 | tee /tmp/derpcat-probe-ktzlxc-raw.json
```

Expected:

- all three commands complete successfully
- the probe report includes `direct=true`
- the probe report shows `goodput_mbps` materially above the current derpcat raw baseline

- [ ] **Step 4: Write down the raw gate result before continuing**

Run:

```bash
jq '{host,mode,direction,goodput_mbps,first_byte_ms,direct}' /tmp/derpcat-probe-ktzlxc-raw.json
```

Expected:

- JSON summary printed

Decision rule:

- If raw probe goodput does **not** beat current derpcat on `ktzlxc`, stop here, write the benchmark summary into `KTZLXC_BENCHMARKS.md`, commit the probe as evidence tooling, and do not implement Task 5.

- [ ] **Step 5: Commit**

```bash
git add scripts/probe-benchmark.sh scripts/probe-benchmark-reverse.sh scripts/probe-matrix.sh docs/benchmarks.md
git commit -m "probe: add benchmark harnesses"
```

### Task 5: Add minimal AEAD mode if the raw gate passed

**Files:**
- Modify: `pkg/probe/protocol.go`
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/session_test.go`
- Modify: `cmd/derpcat-probe/orchestrate.go`
- Modify: `pkg/probe/orchestrator.go`

- [ ] **Step 1: Write the failing encrypted-mode tests**

```go
// pkg/probe/protocol_test.go
func TestPacketRoundTripWithAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	aead, err := newTestAEAD(key)
	if err != nil {
		t.Fatalf("newTestAEAD() error = %v", err)
	}

	p := Packet{
		Version: ProtocolVersion,
		Type:    PacketTypeData,
		RunID:   [16]byte{9, 9, 9, 9},
		Seq:     7,
		Offset:  14,
		Payload: []byte("secret"),
	}

	buf, err := MarshalPacket(p, aead)
	if err != nil {
		t.Fatalf("MarshalPacket() error = %v", err)
	}
	got, err := UnmarshalPacket(buf, aead)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}
	if !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("payload mismatch: got %q want %q", got.Payload, p.Payload)
	}
}
```

```go
// pkg/probe/session_test.go
func TestTransferCompletesWithAEAD(t *testing.T) {
	t.Skip("replace with real encrypted transfer after protocol support lands")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./pkg/probe -run 'TestPacketRoundTripWithAEAD|TestTransferCompletesWithAEAD' -count=1
```

Expected:

- FAIL because encrypted mode is not implemented

- [ ] **Step 3: Implement minimal AEAD mode**

```go
// pkg/probe/protocol.go
package probe

import (
	"crypto/aes"
	"crypto/cipher"
)

func NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newTestAEAD(key []byte) (cipher.AEAD, error) { return NewAEAD(key) }
```

```go
// pkg/probe/session.go
type SendConfig struct {
	Raw        bool
	ChunkSize  int
	WindowSize int
	AEAD       cipher.AEAD
}

type ReceiveConfig struct {
	Raw  bool
	AEAD cipher.AEAD
}
```

Update `MarshalPacket` / `UnmarshalPacket` to encrypt and decrypt payload-bearing packets with a nonce derived from `RunID[:12]` plus `Seq`.

- [ ] **Step 4: Run the encrypted gate on `ktzlxc`**

Run:

```bash
./scripts/probe-benchmark.sh ktzlxc 1073741824 | tee /tmp/derpcat-probe-ktzlxc-raw.json
./dist/derpcat-probe orchestrate --host ktzlxc --user root --size-bytes 1073741824 --mode aead | tee /tmp/derpcat-probe-ktzlxc-aead.json
```

Expected:

- both runs complete successfully
- the AEAD run keeps `direct=true`
- the AEAD `goodput_mbps` remains close enough to raw mode to justify phase-2 planning

- [ ] **Step 5: Commit**

```bash
git add pkg/probe/protocol.go pkg/probe/session.go pkg/probe/session_test.go cmd/derpcat-probe/orchestrate.go pkg/probe/orchestrator.go
git commit -m "probe: add encrypted udp mode"
```

### Task 6: Run the full host matrix and capture the proof

**Files:**
- Modify locally only: `KTZLXC_BENCHMARKS.md`
- Modify locally only: `CANLXC_BENCHMARKS.md`
- Modify locally only: `UKLXC_BENCHMARKS.md`
- Modify locally only: `ORANGE_INDIA_BENCHMARKS.md`

- [ ] **Step 1: Capture Tailscale and derpcat baselines**

Run:

```bash
# Tailscale iperf3 baseline, 3x each direction, each host
# Current derpcat baseline, no Tailscale candidates:
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh canlxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh orange-india.exe.xyz 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh ktzlxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh canlxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh uklxc 1024
DERPCAT_TEST_DISABLE_TAILSCALE_CANDIDATES=1 DERPCAT_PARALLEL_ARGS='--parallel=auto' ./scripts/promotion-test.sh orange-india.exe.xyz 1024
```

Expected:

- every derpcat run shows direct evidence in sender and listener traces

- [ ] **Step 2: Run the new probe matrix**

Run:

```bash
./scripts/probe-matrix.sh | tee /tmp/derpcat-probe-matrix.log
```

Expected:

- JSON lines or grouped JSON reports for all four hosts and all configured sizes

- [ ] **Step 3: Write benchmark notes and the phase-2 recommendation**

Record in the local benchmark markdown files:

- host WAN ceiling
- Tailscale `iperf3` averages
- current derpcat no-Tailscale averages
- probe raw averages
- probe AEAD averages if Task 5 ran
- notes on whether the path appears QUIC-limited, path-limited, or host-limited

Decision rule:

- If the probe wins on `ktzlxc` and stays competitive in AEAD mode, write a short recommendation that phase 2 should replace the direct QUIC data plane experimentally.
- If the probe does not win, write a short recommendation that derpcat should keep QUIC and focus on other bottlenecks.

- [ ] **Step 4: Final verification**

Run:

```bash
go test ./pkg/probe -count=1
go test ./cmd/derpcat-probe -count=1
pre-commit run --files docs/benchmarks.md
```

Expected:

- all commands PASS

- [ ] **Step 5: Commit the code, not the local benchmark logs**

```bash
git add cmd/derpcat-probe pkg/probe scripts/probe-benchmark.sh scripts/probe-benchmark-reverse.sh scripts/probe-matrix.sh docs/benchmarks.md
git commit -m "probe: add direct udp proof harness"
```

## Self-Review

- Spec coverage: this plan covers the standalone probe, the raw proof gate, the conditional encrypted mode, the three-host matrix, and the rule that phase 2 only starts if the proof wins.
- Placeholder scan: the only intentional branch is the explicit stop condition after the `ktzlxc` raw gate. That is a required proof gate, not a placeholder.
- Type consistency: packet, report, orchestrator, and CLI names are consistent across tasks. Keep `Packet`, `RunReport`, `OrchestrateConfig`, `SendConfig`, and `ReceiveConfig` exactly as named above while implementing.
