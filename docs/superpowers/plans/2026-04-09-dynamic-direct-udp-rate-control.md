# Dynamic Direct UDP Rate Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DERP-coordinated direct UDP stream transfers dynamically scale from sub-1 MB/s WAN links to a guarded 10 Gbps ceiling while preserving relay-first streaming and bounded memory.

**Architecture:** Keep the existing relay-prefix stream handoff, but keep DERP active while direct UDP runs synthetic capacity probes. Select the initial direct stream rate from measured delivery, then let the blast rate controller adapt using receiver stats and replay pressure. Replay memory remains a hard bounded budget; slow paths backpressure stdin rather than buffering unbounded data.

**Tech Stack:** Go, existing `pkg/session` DERP/direct-UDP handshake code, existing `pkg/probe` blast sender/receiver, existing `telemetry.Emitter`, `mise` verification commands, live SSH promotion scripts.

---

## File Structure

- Modify `pkg/session/external_direct_udp.go`: guarded ceiling, slow-to-fast probe tiers, synthetic probe sender, direct UDP rate-probe envelope subscription, stream handoff wiring, verbose output.
- Modify `pkg/session/external_direct_udp_test.go`: unit tests for ceiling, probe tier selection, synthetic probe payloads, and stream start rate selection.
- Modify `pkg/probe/session.go`: replay-pressure stats, replay-window-full backpressure accounting, call into rate controller on replay pressure.
- Modify `pkg/probe/blast_rate.go`: rate controller pressure signal, socket pacing ceiling helper, and minimum-rate behavior below 1 MB/s.
- Modify `pkg/probe/session_test.go`: tests for replay full backpressure, stats, and rate decrease on replay pressure.

### Task 1: Guarded Ceiling and Probe Tier Policy

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Test: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing tests for 10 Gbps ceiling and slow-to-fast tiers**

Add or update these tests in `pkg/session/external_direct_udp_test.go` near the existing rate-probe tests:

```go
func TestExternalDirectUDPDefaultUsesGuardedTenGigabitCeiling(t *testing.T) {
	if got, want := externalDirectUDPMaxRateMbps, 10_000; got != want {
		t.Fatalf("externalDirectUDPMaxRateMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPInitialProbeFallbackMbps, 150; got != want {
		t.Fatalf("externalDirectUDPInitialProbeFallbackMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPRateProbeMinMbps, 1; got != want {
		t.Fatalf("externalDirectUDPRateProbeMinMbps = %d, want %d", got, want)
	}
	if got, want := externalDirectUDPTransportLabel, "batched"; got != want {
		t.Fatalf("externalDirectUDPTransportLabel = %q, want %q", got, want)
	}
}

func TestExternalDirectUDPRateProbeRatesCoverSlowAndTenGigabitUnknownStreams(t *testing.T) {
	got := externalDirectUDPRateProbeRates(10_000, -1)
	want := []int{8, 25, 75, 150, 350, 700, 1200, 2250, 5000, 10000}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("externalDirectUDPRateProbeRates(unknown) = %v, want %v", got, want)
	}
}

func TestExternalDirectUDPRateProbeRatesStillSkipSmallKnownTransfers(t *testing.T) {
	if got := externalDirectUDPRateProbeRates(10_000, 64<<20); len(got) != 0 {
		t.Fatalf("externalDirectUDPRateProbeRates(small known transfer) = %v, want none", got)
	}
}
```

Update the existing `TestExternalDirectUDPDefaultUsesEightSectionedLanesWithFEC` so it no longer expects `externalDirectUDPRateMbps == 2250`. It should check `externalDirectUDPMaxRateMbps == 10_000`.

- [ ] **Step 2: Run tests and verify the failure**

Run:

```sh
go test ./pkg/session -run 'TestExternalDirectUDP(DefaultUses|RateProbeRates)' -count=1
```

Expected: fail because `externalDirectUDPMaxRateMbps` and `externalDirectUDPInitialProbeFallbackMbps` do not exist, and because the existing helper returns the old tier table.

- [ ] **Step 3: Implement the constants and tier helper**

In `pkg/session/external_direct_udp.go`, update the existing top-level constant block so the relevant direct UDP rate constants are:

```go
const (
	externalDirectUDPTransportLabel          = "batched"
	externalDirectUDPParallelism             = 8
	externalDirectUDPChunkSize               = 1384 // 52-byte probe header + 16-byte GCM tag keeps UDP payload at 1452 bytes.
	externalDirectUDPMaxRateMbps             = 10_000
	externalDirectUDPInitialProbeFallbackMbps = 150
	externalDirectUDPRateProbeMinMbps        = 1
)
```

Remove `externalDirectUDPRateMbps`; do not leave both the old fixed-rate constant and the new guarded ceiling.

Then update `externalDirectUDPRateProbeRates`:

```go
func externalDirectUDPRateProbeRates(maxRateMbps int, totalBytes int64) []int {
	if maxRateMbps <= 0 {
		return nil
	}
	if totalBytes >= 0 && totalBytes < externalDirectUDPRateProbeMinBytes {
		return nil
	}
	bases := []int{8, 25, 75, 150, 350, 700, 1200, 2250, 5000, maxRateMbps}
	out := make([]int, 0, len(bases))
	seen := make(map[int]bool)
	for _, rate := range bases {
		if rate < externalDirectUDPRateProbeMinMbps || rate > maxRateMbps || seen[rate] {
			continue
		}
		out = append(out, rate)
		seen[rate] = true
	}
	if len(out) == 0 {
		out = append(out, maxRateMbps)
	}
	return out
}
```

Also change all direct stream references from `externalDirectUDPRateMbps` to `externalDirectUDPMaxRateMbps`.

- [ ] **Step 4: Run tests and verify the task passes**

Run:

```sh
go test ./pkg/session -run 'TestExternalDirectUDP(DefaultUses|RateProbeRates)' -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "transport: add guarded direct udp rate ceiling"
```

### Task 2: Synthetic Direct UDP Probe Sender

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Test: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing tests for probe payload encoding and send accounting**

Add tests near `TestExternalDirectUDPReceiveRateProbes` or the rate-probe tests:

```go
func TestExternalDirectUDPRateProbePayloadEncodesIndex(t *testing.T) {
	payload, err := externalDirectUDPRateProbePayload(3, 128)
	if err != nil {
		t.Fatalf("externalDirectUDPRateProbePayload() error = %v", err)
	}
	if len(payload) != 128 {
		t.Fatalf("payload len = %d, want 128", len(payload))
	}
	index, ok := externalDirectUDPRateProbeIndex(payload, 10)
	if !ok {
		t.Fatal("externalDirectUDPRateProbeIndex() did not recognize payload")
	}
	if index != 3 {
		t.Fatalf("probe index = %d, want 3", index)
	}
}

func TestExternalDirectUDPSendRateProbesWritesSyntheticPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	rates := []int{8, 25}
	readCh := make(chan int, 16)
	go func() {
		buf := make([]byte, 2048)
		deadline := time.Now().Add(1200 * time.Millisecond)
		_ = server.SetReadDeadline(deadline)
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				close(readCh)
				return
			}
			index, ok := externalDirectUDPRateProbeIndex(buf[:n], len(rates))
			if ok {
				readCh <- index
			}
		}
	}()

	sent, err := externalDirectUDPSendRateProbes(ctx, client, server.LocalAddr().String(), rates)
	if err != nil {
		t.Fatalf("externalDirectUDPSendRateProbes() error = %v", err)
	}
	if len(sent) != len(rates) {
		t.Fatalf("sent samples len = %d, want %d", len(sent), len(rates))
	}
	for i, sample := range sent {
		if sample.RateMbps != rates[i] {
			t.Fatalf("sent[%d].RateMbps = %d, want %d", i, sample.RateMbps, rates[i])
		}
		if sample.BytesSent <= 0 {
			t.Fatalf("sent[%d].BytesSent = %d, want > 0", i, sample.BytesSent)
		}
	}
	seen := map[int]bool{}
	for index := range readCh {
		seen[index] = true
		if len(seen) == len(rates) {
			break
		}
	}
	for i := range rates {
		if !seen[i] {
			t.Fatalf("probe index %d was not observed; seen=%v", i, seen)
		}
	}
}
```

- [ ] **Step 2: Run tests and verify the failure**

Run:

```sh
go test ./pkg/session -run 'TestExternalDirectUDP.*RateProbe.*(Payload|Writes)' -count=1
```

Expected: fail because `externalDirectUDPRateProbePayload` and `externalDirectUDPSendRateProbes` do not exist.

- [ ] **Step 3: Implement synthetic probe helpers**

Add these helpers near `externalDirectUDPReceiveRateProbes`:

```go
func externalDirectUDPRateProbePayload(index int, size int) ([]byte, error) {
	if index < 0 {
		return nil, fmt.Errorf("negative rate probe index %d", index)
	}
	if size < 20 {
		size = 20
	}
	payload := make([]byte, size)
	copy(payload[:16], externalDirectUDPRateProbeMagic[:])
	binary.BigEndian.PutUint32(payload[16:20], uint32(index))
	return payload, nil
}

func externalDirectUDPSendRateProbes(ctx context.Context, conn net.PacketConn, remoteAddr string, rates []int) ([]directUDPRateProbeSample, error) {
	if len(rates) == 0 {
		return nil, nil
	}
	if conn == nil {
		return nil, errors.New("nil rate probe conn")
	}
	if remoteAddr == "" {
		return nil, errors.New("empty rate probe remote addr")
	}
	remote, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, err
	}
	samples := make([]directUDPRateProbeSample, len(rates))
	payload, err := externalDirectUDPRateProbePayload(0, externalDirectUDPChunkSize)
	if err != nil {
		return nil, err
	}
	for i, rate := range rates {
		if rate <= 0 {
			return nil, fmt.Errorf("invalid rate probe rate %d", rate)
		}
		samples[i].RateMbps = rate
		samples[i].DurationMillis = externalDirectUDPRateProbeDuration.Milliseconds()
		tierStart := time.Now()
		deadline := tierStart.Add(externalDirectUDPRateProbeDuration)
		binary.BigEndian.PutUint32(payload[16:20], uint32(i))
		var sent int64
		for time.Now().Before(deadline) {
			if err := ctx.Err(); err != nil {
				return samples, err
			}
			n, err := conn.WriteTo(payload, remote)
			if err != nil {
				return samples, err
			}
			sent += int64(n)
			elapsed := time.Since(tierStart)
			target := int64(float64(rate*1000*1000)/8.0*elapsed.Seconds() + 0.5)
			if sent > target {
				sleepFor := time.Duration(float64(sent-target)*8.0/float64(rate*1000*1000)*float64(time.Second))
				if sleepFor > 0 {
					if err := sleepWithContext(ctx, sleepFor); err != nil {
						return samples, err
					}
				}
			}
		}
		samples[i].BytesSent = sent
	}
	return samples, nil
}
```

- [ ] **Step 4: Run tests and verify the task passes**

Run:

```sh
go test ./pkg/session -run 'TestExternalDirectUDP.*RateProbe.*(Payload|Writes)' -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "transport: add direct udp rate probes"
```

### Task 3: Wire Probe Results Into Stream Handoff

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Test: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing tests for probe response payload detection and selected rate**

Add tests:

```go
func TestIsDirectUDPRateProbePayloadAcceptsRateProbeEnvelope(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type: envelopeDirectUDPRateProbe,
		DirectUDPRateProbe: &directUDPRateProbeResult{
			Samples: []directUDPRateProbeSample{{RateMbps: 150, BytesReceived: 1, DurationMillis: 200}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !isDirectUDPRateProbePayload(payload) {
		t.Fatal("isDirectUDPRateProbePayload() = false, want true")
	}
}

func TestWaitForDirectUDPRateProbeReturnsSamples(t *testing.T) {
	payload, err := json.Marshal(envelope{
		Type: envelopeDirectUDPRateProbe,
		DirectUDPRateProbe: &directUDPRateProbeResult{
			Samples: []directUDPRateProbeSample{{RateMbps: 350, BytesReceived: 8_000_000, DurationMillis: 200}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan derpbind.Packet, 1)
	ch <- derpbind.Packet{Payload: payload}

	got, err := waitForDirectUDPRateProbe(context.Background(), ch)
	if err != nil {
		t.Fatalf("waitForDirectUDPRateProbe() error = %v", err)
	}
	if len(got.Samples) != 1 || got.Samples[0].RateMbps != 350 {
		t.Fatalf("waitForDirectUDPRateProbe() = %#v, want 350 Mbps sample", got)
	}
}

func TestExternalDirectUDPSelectInitialRateUsesProbeSamples(t *testing.T) {
	sent := []directUDPRateProbeSample{
		{RateMbps: 8, BytesSent: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesSent: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesSent: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesSent: 3_750_000, DurationMillis: 200},
		{RateMbps: 350, BytesSent: 8_750_000, DurationMillis: 200},
	}
	received := []directUDPRateProbeSample{
		{RateMbps: 8, BytesReceived: 200_000, DurationMillis: 200},
		{RateMbps: 25, BytesReceived: 625_000, DurationMillis: 200},
		{RateMbps: 75, BytesReceived: 1_875_000, DurationMillis: 200},
		{RateMbps: 150, BytesReceived: 3_700_000, DurationMillis: 200},
		{RateMbps: 350, BytesReceived: 1_000_000, DurationMillis: 200},
	}
	got := externalDirectUDPSelectInitialRateMbps(10_000, sent, received)
	if got <= 0 || got > 150 {
		t.Fatalf("externalDirectUDPSelectInitialRateMbps() = %d, want safe rate <= 150", got)
	}
}
```

- [ ] **Step 2: Run tests and verify the failure**

Run:

```sh
go test ./pkg/session -run 'Test(IsDirectUDPRateProbePayload|WaitForDirectUDPRateProbe|ExternalDirectUDPSelectInitialRate)' -count=1
```

Expected: fail because the helper functions do not exist.

- [ ] **Step 3: Implement rate-probe envelope helpers**

Add helpers near the other direct UDP wait helpers:

```go
func waitForDirectUDPRateProbe(ctx context.Context, rateProbeCh <-chan derpbind.Packet) (directUDPRateProbeResult, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalDirectUDPStartWait)
	defer cancel()
	pkt, err := receiveSubscribedPacket(waitCtx, rateProbeCh)
	if err != nil {
		return directUDPRateProbeResult{}, err
	}
	env, err := decodeEnvelope(pkt.Payload)
	if err != nil || env.Type != envelopeDirectUDPRateProbe {
		return directUDPRateProbeResult{}, errors.New("unexpected direct UDP rate probe response")
	}
	if env.DirectUDPRateProbe == nil {
		return directUDPRateProbeResult{}, errors.New("direct UDP rate probe response missing samples")
	}
	return *env.DirectUDPRateProbe, nil
}

func isDirectUDPRateProbePayload(payload []byte) bool {
	env, err := decodeEnvelope(payload)
	return err == nil && env.Type == envelopeDirectUDPRateProbe
}

func externalDirectUDPSelectInitialRateMbps(maxRateMbps int, sent []directUDPRateProbeSample, received []directUDPRateProbeSample) int {
	selected := externalDirectUDPSelectRateFromProbeSamples(maxRateMbps, sent, received)
	if selected <= 0 || selected > maxRateMbps {
		selected = externalDirectUDPInitialProbeFallbackMbps
	}
	return selected
}
```

- [ ] **Step 4: Wire the sender subscription and selected rate**

In `sendExternalViaDirectUDP`, add:

```go
rateProbeCh, unsubscribeRateProbe := derpClient.SubscribeLossless(func(pkt derpbind.Packet) bool {
	return pkt.From == listenerDERP && isDirectUDPRateProbePayload(pkt.Payload)
})
defer unsubscribeRateProbe()
```

Add `rateProbeCh <-chan derpbind.Packet` to `sendExternalViaDirectUDPOnly` and `externalRelayPrefixSendConfig`, and pass it from both call sites.

In `sendExternalViaDirectUDPOnly`, replace the fixed-rate setup with:

```go
maxRateMbps := externalDirectUDPMaxRateMbps
probeRates := externalDirectUDPRateProbeRates(maxRateMbps, -1)
activeRateMbps := externalDirectUDPInitialProbeFallbackMbps
```

When sending `envelopeDirectUDPStart`, include:

```go
DirectUDPStart: &directUDPStart{
	Stream:     true,
	ProbeRates: probeRates,
},
```

After `waitForDirectUDPStartAck` and before `probe.Send`, add:

```go
var sentProbeSamples []directUDPRateProbeSample
var probeResult directUDPRateProbeResult
if len(probeRates) > 0 {
	var probeErr error
	sentProbeSamples, probeErr = externalDirectUDPSendRateProbes(ctx, streamProbeConn, streamRemoteAddr, probeRates)
	if probeErr != nil {
		return probeErr
	}
	probeResult, probeErr = waitForDirectUDPRateProbe(ctx, rateProbeCh)
	if probeErr != nil {
		return probeErr
	}
	activeRateMbps = externalDirectUDPSelectInitialRateMbps(maxRateMbps, sentProbeSamples, probeResult.Samples)
}
sendCfg.RateMbps = activeRateMbps
sendCfg.RateCeilingMbps = maxRateMbps
```

Set `streamRemoteAddr` to the selected peer address string already available after direct candidate selection.

Emit:

```go
cfg.Emitter.Debug("udp-rate-ceiling-mbps=" + strconv.Itoa(maxRateMbps))
cfg.Emitter.Debug("udp-rate-probe-rates=" + strings.Trim(strings.Join(strings.Fields(fmt.Sprint(probeRates)), ","), "[]"))
cfg.Emitter.Debug("udp-rate-probe-samples=" + externalDirectUDPFormatRateProbeSamples(sentProbeSamples, probeResult.Samples))
cfg.Emitter.Debug("udp-rate-selected-mbps=" + strconv.Itoa(activeRateMbps))
```

- [ ] **Step 5: Run tests and verify the task passes**

Run:

```sh
go test ./pkg/session -run 'Test(IsDirectUDPRateProbePayload|WaitForDirectUDPRateProbe|ExternalDirectUDPSelectInitialRate|ExternalDirectUDP.*RateProbe)' -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

Run:

```sh
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "transport: select direct udp stream rate from probes"
```

### Task 4: Replay Pressure Stats and Backpressure Signal

**Files:**
- Modify: `pkg/probe/session.go`
- Modify: `pkg/probe/blast_rate.go`
- Test: `pkg/probe/session_test.go`

- [ ] **Step 1: Write failing tests for stats and pressure-driven decrease**

Add tests to `pkg/probe/session_test.go` near existing stream replay tests:

```go
func TestBlastSendControlDecreasesOnReplayPressure(t *testing.T) {
	now := time.Unix(0, 0)
	control := newBlastSendControl(1200, 10_000, now)
	control.ObserveReplayPressure(now.Add(100*time.Millisecond), 200<<20, 256<<20)
	if got := control.RateMbps(); got >= 1200 {
		t.Fatalf("RateMbps() = %d, want decrease below 1200 after replay pressure", got)
	}
}

func TestBlastSendControlCanDecreaseBelowOneMegabytePerSecond(t *testing.T) {
	now := time.Unix(0, 0)
	control := newBlastSendControl(8, 10_000, now)
	for i := 0; i < 10; i++ {
		control.ObserveReplayPressure(now.Add(time.Duration(i+1)*time.Second), 8<<20, 8<<20)
	}
	if got := control.RateMbps(); got >= 8 {
		t.Fatalf("RateMbps() = %d, want below 8 Mbps after repeated pressure", got)
	}
	if got, want := control.RateMbps(), blastRateMinMbps; got != want {
		t.Fatalf("RateMbps() = %d, want floor %d", got, want)
	}
}

func TestRecordReplayWindowFullWaitUpdatesStats(t *testing.T) {
	var stats TransferStats
	recordReplayWindowFullWait(&stats, 64<<10, 25*time.Millisecond)
	if got, want := stats.ReplayWindowFullWaits, int64(1); got != want {
		t.Fatalf("ReplayWindowFullWaits = %d, want %d", got, want)
	}
	if got, want := stats.ReplayWindowFullWaitDuration, 25*time.Millisecond; got != want {
		t.Fatalf("ReplayWindowFullWaitDuration = %s, want %s", got, want)
	}
	if got, want := stats.MaxReplayBytes, uint64(64<<10); got != want {
		t.Fatalf("MaxReplayBytes = %d, want %d", got, want)
	}
}

func TestBlastSocketPacingUsesCeilingForAdaptiveRamp(t *testing.T) {
	if got, want := blastSocketPacingRateMbps(150, 10_000), 10_000; got != want {
		t.Fatalf("blastSocketPacingRateMbps(150, 10000) = %d, want %d", got, want)
	}
	if got, want := blastSocketPacingRateMbps(150, 0), 150; got != want {
		t.Fatalf("blastSocketPacingRateMbps(150, 0) = %d, want %d", got, want)
	}
	if got, want := blastSocketPacingRateMbps(1200, 700), 1200; got != want {
		t.Fatalf("blastSocketPacingRateMbps(1200, 700) = %d, want %d", got, want)
	}
}
```

- [ ] **Step 2: Run tests and verify the failure**

Run:

```sh
go test ./pkg/probe -run 'Test(BlastSendControlDecreasesOnReplayPressure|BlastSendControlCanDecreaseBelowOneMegabytePerSecond|RecordReplayWindowFullWaitUpdatesStats|BlastSocketPacingUsesCeilingForAdaptiveRamp)' -count=1
```

Expected: fail because `ObserveReplayPressure`, `ReplayWindowFullWaits`, `ReplayWindowFullWaitDuration`, `recordReplayWindowFullWait`, `blastSocketPacingRateMbps`, and the lower minimum rate behavior do not exist.

- [ ] **Step 3: Add replay pressure fields and controller method**

In `pkg/probe/session.go`, extend `TransferStats`:

```go
type TransferStats struct {
	BytesSent                    int64
	BytesReceived                int64
	PacketsSent                  int64
	PacketsAcked                 int64
	Retransmits                  int64
	Lanes                        int
	StartedAt                    time.Time
	CompletedAt                  time.Time
	FirstByteAt                  time.Time
	Transport                    TransportCaps
	MaxReplayBytes               uint64
	ReplayWindowFullWaits        int64
	ReplayWindowFullWaitDuration time.Duration
}
```

In `pkg/probe/blast_rate.go`, update the existing constant block so `blastRateMinMbps` is `1` and add `blastReplayPressureThreshold`:

```go
const (
	blastRateMinMbps              = 1
	blastReplayPressureThreshold  = 0.80
)

func (c *blastSendControl) ObserveReplayPressure(now time.Time, retainedBytes uint64, maxBytes uint64) {
	if c == nil || c.controller == nil || maxBytes == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	if float64(retainedBytes)/float64(maxBytes) < blastReplayPressureThreshold {
		return
	}
	c.controller.decrease(now)
}
```

In `pkg/probe/session.go`, add:

```go
func recordReplayWindowFullWait(stats *TransferStats, retainedBytes uint64, waited time.Duration) {
	if stats == nil {
		return
	}
	stats.ReplayWindowFullWaits++
	stats.ReplayWindowFullWaitDuration += waited
	stats.MaxReplayBytes = max(stats.MaxReplayBytes, retainedBytes)
}
```

In `pkg/probe/blast_rate.go`, add:

```go
func blastSocketPacingRateMbps(initialRateMbps int, ceilingMbps int) int {
	if ceilingMbps > initialRateMbps {
		return ceilingMbps
	}
	return initialRateMbps
}
```

- [ ] **Step 4: Account replay pressure and keep socket pacing from capping adaptive ramp**

In `sendBlast`, replace:

```go
_ = setSocketPacing(conn, rateMbps)
```

with:

```go
_ = setSocketPacing(conn, blastSocketPacingRateMbps(rateMbps, rateCeilingMbps))
```

Then, in the `addReplayPacket` loop in `sendBlast`, after `errStreamReplayWindowFull` is detected and after control events are drained, add:

```go
waitStart := time.Now()
if control.Adaptive() && history.streamReplay != nil {
	control.ObserveReplayPressure(waitStart, history.streamReplay.RetainedBytes(), history.streamReplay.MaxBytes())
}
if err := sleepWithContext(ctx, blastRepairInterval); err != nil {
	return nil, err
}
if history.streamReplay != nil {
	recordReplayWindowFullWait(stats, history.streamReplay.RetainedBytes(), time.Since(waitStart))
}
```

Keep `stats.MaxReplayBytes = max(stats.MaxReplayBytes, history.MaxReplayBytes())` after ack-floor updates. Do not read more from `src` while the replay window is full.

- [ ] **Step 5: Run tests and verify the task passes**

Run:

```sh
go test ./pkg/probe -run 'Test(BlastSendControlDecreasesOnReplayPressure|BlastSendControlCanDecreaseBelowOneMegabytePerSecond|RecordReplayWindowFullWaitUpdatesStats|BlastSocketPacingUsesCeilingForAdaptiveRamp|StreamReplay)' -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

Run:

```sh
git add pkg/probe/session.go pkg/probe/blast_rate.go pkg/probe/session_test.go
git commit -m "transport: reduce direct udp rate on replay pressure"
```

### Task 5: Verbose Observability for Dynamic Rate and Replay Pressure

**Files:**
- Modify: `pkg/session/external_direct_udp.go`
- Test: `pkg/session/external_direct_udp_test.go`

- [ ] **Step 1: Write failing test for verbose stats fields**

Add a focused test near `TestEmitExternalDirectUDPStatsIncludesDataGoodputFromFirstByte`:

```go
func TestEmitExternalDirectUDPSendStatsIncludesReplayPressure(t *testing.T) {
	var buf bytes.Buffer
	emitter := telemetry.New(&buf, telemetry.LevelVerbose)
	stats := probe.TransferStats{
		MaxReplayBytes:               64 << 20,
		ReplayWindowFullWaits:        7,
		ReplayWindowFullWaitDuration: 250 * time.Millisecond,
	}

	emitExternalDirectUDPSendReplayStats(emitter, stats)

	got := buf.String()
	for _, want := range []string{
		"udp-send-max-replay-bytes=67108864\n",
		"udp-send-replay-window-full-waits=7\n",
		"udp-send-replay-window-full-wait-ms=250\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("emitted stats = %q, want %q", got, want)
		}
	}
}
```

- [ ] **Step 2: Run test and verify the failure**

Run:

```sh
go test ./pkg/session -run TestEmitExternalDirectUDPSendStatsIncludesReplayPressure -count=1
```

Expected: fail because `emitExternalDirectUDPSendReplayStats` does not exist.

- [ ] **Step 3: Implement the emitter helper and use it**

Add near the existing direct UDP stat emitters:

```go
func emitExternalDirectUDPSendReplayStats(emitter *telemetry.Emitter, stats probe.TransferStats) {
	if emitter == nil {
		return
	}
	emitter.Debug("udp-send-max-replay-bytes=" + strconv.FormatUint(stats.MaxReplayBytes, 10))
	emitter.Debug("udp-send-replay-window-full-waits=" + strconv.FormatInt(stats.ReplayWindowFullWaits, 10))
	emitter.Debug("udp-send-replay-window-full-wait-ms=" + strconv.FormatInt(stats.ReplayWindowFullWaitDuration.Milliseconds(), 10))
}
```

Replace the direct debug line:

```go
cfg.Emitter.Debug("udp-send-max-replay-bytes=" + strconv.FormatUint(stats.MaxReplayBytes, 10))
```

with:

```go
emitExternalDirectUDPSendReplayStats(cfg.Emitter, stats)
```

- [ ] **Step 4: Run tests and verify the task passes**

Run:

```sh
go test ./pkg/session -run 'TestEmitExternalDirectUDP.*Stats' -count=1
```

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add pkg/session/external_direct_udp.go pkg/session/external_direct_udp_test.go
git commit -m "transport: report direct udp replay pressure"
```

### Task 6: Package Tests and Static Verification

**Files:**
- No new source files expected.

- [ ] **Step 1: Run focused package tests**

Run:

```sh
go test ./pkg/session ./pkg/probe -count=1
```

Expected: pass.

- [ ] **Step 2: Run full Go tests**

Run:

```sh
mise run test
```

Expected: pass.

- [ ] **Step 3: Run full repository check**

Run:

```sh
mise run check
```

Expected: pass.

### Task 7: Live WAN Validation

**Files:**
- No tracked source files.
- Logs should go under ignored `notes/`.

- [ ] **Step 1: Build current derphole**

Run:

```sh
mise run build
```

Expected: pass and produce `dist/derphole`.

- [ ] **Step 2: Measure WAN ceiling with iperf3 using nix**

Use the existing forwarded test port only as baseline validation, not as derphole transport design input.

Example Mac-side command shape:

```sh
nix run nixpkgs#iperf3 -- -c <public-or-forwarded-host> -p 8321 -t 10
nix run nixpkgs#iperf3 -- -c <public-or-forwarded-host> -p 8321 -t 10 -R
```

Record the exact host and results in `notes/YYYY-MM-DD-dynamic-rate-validation.md`. Omit any sensitive tokens.

- [ ] **Step 3: Run single-shot uklxc reverse**

Run:

```sh
DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh uklxc 1024 2>&1 | tee notes/$(date +%Y-%m-%d)-uklxc-reverse-dynamic-single.log
```

Expected: completes without exit 137, timeout, or leaked remote derphole UDP sockets. Verbose output should include `udp-rate-ceiling-mbps=10000`, probe rates, probe samples, selected rate, replay pressure stats, and `stream-complete`.

- [ ] **Step 4: Run 10x uklxc reverse**

Run:

```sh
for i in $(seq -w 1 10); do
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh uklxc 1024 2>&1 | tee "notes/$(date +%Y-%m-%d)-uklxc-reverse-dynamic-${i}.log"
done
```

Expected: 10/10 complete, no OOM kill increment on `uklxc`, no leaked remote derphole UDP sockets, no replay window pegged at the hard budget across the run set.

- [ ] **Step 5: Run 10x uklxc forward**

Run:

```sh
for i in $(seq -w 1 10); do
  DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh uklxc 1024 2>&1 | tee "notes/$(date +%Y-%m-%d)-uklxc-forward-dynamic-${i}.log"
done
```

Expected: 10/10 complete, throughput near current `uklxc` WAN ceiling, retransmits and max replay materially below the prior bad baseline when the WAN ceiling is similar.

- [ ] **Step 6: Run ktzlxc regression matrix**

Run:

```sh
for dir in forward reverse; do
  for i in $(seq -w 1 10); do
    if [ "$dir" = forward ]; then
      DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test.sh ktzlxc 1024 2>&1 | tee "notes/$(date +%Y-%m-%d)-ktzlxc-forward-dynamic-${i}.log"
    else
      DERPHOLE_TEST_DISABLE_TAILSCALE_CANDIDATES=1 ./scripts/promotion-test-reverse.sh ktzlxc 1024 2>&1 | tee "notes/$(date +%Y-%m-%d)-ktzlxc-reverse-dynamic-${i}.log"
    fi
  done
done
```

Expected: 10/10 each direction complete. Reverse should still approach the measured WAN ceiling within a few seconds; if WAN conditions match the prior run, expect p50 around 1.5 Gbps+ and max near 1.9 Gbps.

- [ ] **Step 7: Summarize validation evidence**

Write a local ignored note:

```sh
$EDITOR notes/$(date +%Y-%m-%d)-dynamic-rate-validation.md
```

Include:

```md
# Dynamic rate validation

## Baseline

- iperf3 forward:
- iperf3 reverse:

## derphole

- uklxc reverse 10x:
- uklxc forward 10x:
- ktzlxc reverse 10x:
- ktzlxc forward 10x:

## Observed controller behavior

- selected initial rates:
- rate update pattern:
- max replay bytes:
- retransmits:
- failures:
```

Do not commit `notes/`.
