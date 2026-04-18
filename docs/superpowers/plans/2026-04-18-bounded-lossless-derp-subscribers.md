# Bounded Lossless DERP Subscribers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound `SubscribeLossless` memory while preserving ordered, non-dropping delivery for control frames.

**Architecture:** Keep the public API unchanged: `SubscribeLossless(func(Packet) bool) (<-chan Packet, func())`. Lossless subscribers get a hard backlog cap and apply backpressure when full; they never drop matching packets. Lossy `Subscribe` keeps drop-oldest behavior.

**Tech Stack:** Go, `pkg/derpbind`, existing session and webrelay tests, `mise`.

---

## File Structure

- Modify: `pkg/derpbind/client.go`
  - Add a bounded slot semaphore to `packetSubscriber`.
  - Initialize it for `subscriberLossless`.
  - Make `enqueue` block at `losslessSubscriberQueueSize`.
  - Release a slot after the subscriber runner hands the packet to the returned channel, or when delivery is abandoned during shutdown.
- Modify: `pkg/derpbind/derpbind_test.go`
  - Add blocking and unsubscribe regression tests.
  - Update the current backed-up subscriber test so it asserts nonblocking behavior before the hard limit, not beyond it.
- Read-only regression surface:
  - `pkg/session/external.go`
  - `pkg/session/external_direct_udp.go`
  - `pkg/session/external_wg.go`
  - `pkg/session/external_offer.go`
  - `pkg/session/external_share.go`
  - `pkg/session/external_parallel.go`
  - `pkg/derphole/webrelay/relay.go`

## Proposed Behavior

`SubscribeLossless` remains lossless and ordered. When a matching subscriber has `losslessSubscriberQueueSize` queued packets that have not been delivered into its returned channel, DERP dispatch blocks until the consumer drains, the subscriber unsubscribes, or the client closes. This bounds memory and pushes pressure back to DERP/TCP instead of dropping control messages.

Effective per-subscriber retention is bounded by `losslessSubscriberQueueSize + cap(returned channel)`. That returned channel is currently created with capacity `16` in `subscribe`.

## Compatibility Risks

- A stalled lossless subscriber can now stall DERP packet dispatch. This is intentional for bounded memory and control-message correctness.
- Broad filters such as webrelay frames, relay-prefix frames, and transport data subscribers can exert backpressure under slow consumers.
- Do not switch lossless overflow to drop-oldest or drop-newest; that can lose ACK, abort, heartbeat, claim, decision, handoff, or path-switch frames.

---

### Task 1: Add Red Tests For Bounded Backpressure

**Files:**
- Modify: `pkg/derpbind/derpbind_test.go`

- [ ] **Step 1: Add `TestClientSubscribeLosslessBlocksWhenQueueFull`**

Append this test near the existing lossless subscriber tests:

```go
func TestClientSubscribeLosslessBlocksWhenQueueFull(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	defer unsubscribe()

	for i := 0; i < cap(controlCh); i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
			t.Fatalf("dispatchSubscriber(channel-fill %d) = false, want true", i)
		}
	}
	for i := 0; i < losslessSubscriberQueueSize; i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i + cap(controlCh))}}) {
			t.Fatalf("dispatchSubscriber(queue-fill %d) = false, want true", i)
		}
	}

	done := make(chan bool, 1)
	go func() {
		done <- c.dispatchSubscriber(Packet{Payload: []byte("blocked")})
	}()

	select {
	case handled := <-done:
		t.Fatalf("dispatchSubscriber past hard limit returned %v, want blocked", handled)
	case <-time.After(50 * time.Millisecond):
	}

	<-controlCh

	select {
	case handled := <-done:
		if !handled {
			t.Fatal("dispatchSubscriber after drain = false, want true")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dispatchSubscriber did not unblock after drain")
	}
}
```

- [ ] **Step 2: Add `TestClientSubscribeLosslessUnsubscribeReleasesBlockedDispatch`**

Append this test:

```go
func TestClientSubscribeLosslessUnsubscribeReleasesBlockedDispatch(t *testing.T) {
	c := &Client{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*packetSubscriber),
	}

	controlCh, unsubscribe := c.SubscribeLossless(func(Packet) bool { return true })
	for i := 0; i < cap(controlCh); i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i)}}) {
			t.Fatalf("dispatchSubscriber(channel-fill %d) = false, want true", i)
		}
	}
	for i := 0; i < losslessSubscriberQueueSize; i++ {
		if !c.dispatchSubscriber(Packet{Payload: []byte{byte(i + cap(controlCh))}}) {
			t.Fatalf("dispatchSubscriber(queue-fill %d) = false, want true", i)
		}
	}

	done := make(chan bool, 1)
	go func() {
		done <- c.dispatchSubscriber(Packet{Payload: []byte("blocked")})
	}()

	select {
	case handled := <-done:
		t.Fatalf("dispatchSubscriber past hard limit returned %v, want blocked", handled)
	case <-time.After(50 * time.Millisecond):
	}

	unsubscribe()

	select {
	case handled := <-done:
		if handled {
			t.Fatal("dispatchSubscriber after unsubscribe = true, want false")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dispatchSubscriber did not unblock after unsubscribe")
	}
}
```

- [ ] **Step 3: Replace the current backed-up subscriber test**

Rename `TestClientSubscribeLosslessDoesNotBlockDispatchWhenConsumerBacksUp` to `TestClientSubscribeLosslessDoesNotBlockBeforeHardLimit` and change its `total` to:

```go
const total = losslessSubscriberQueueSize
```

Keep its assertion that dispatch completes quickly and packets drain in order.

- [ ] **Step 4: Run red tests**

Run:

```bash
go test ./pkg/derpbind -run 'TestClientSubscribeLossless(BlocksWhenQueueFull|UnsubscribeReleasesBlockedDispatch|DoesNotBlockBeforeHardLimit|RetainsAllBackedUpPackets)' -count=1
```

Expected: FAIL. `TestClientSubscribeLosslessBlocksWhenQueueFull` should report that dispatch returned instead of blocking.

### Task 2: Bound The Lossless Queue

**Files:**
- Modify: `pkg/derpbind/client.go`

- [ ] **Step 1: Add a slot semaphore field**

Update `packetSubscriber`:

```go
type packetSubscriber struct {
	filter func(Packet) bool
	ch     chan Packet
	mode   subscriberMode
	done   chan struct{}
	once   sync.Once

	queueMu    sync.Mutex
	queue      []Packet
	queueReady chan struct{}
	queueSlots chan struct{}

	deliverMu sync.Mutex
	closed    bool
}
```

- [ ] **Step 2: Initialize the semaphore**

Inside `subscribe`, in the `subscriberLossless` branch:

```go
if mode == subscriberLossless {
	sub.done = make(chan struct{})
	sub.queueReady = make(chan struct{}, 1)
	sub.queueSlots = make(chan struct{}, losslessSubscriberQueueSize)
	go sub.run(c.stopCh)
}
```

- [ ] **Step 3: Acquire a slot before append**

Replace `packetSubscriber.enqueue` with:

```go
func (s *packetSubscriber) enqueue(stopCh <-chan struct{}, pkt Packet) bool {
	select {
	case <-s.done:
		return false
	case <-stopCh:
		return false
	default:
	}

	select {
	case s.queueSlots <- struct{}{}:
	case <-s.done:
		return false
	case <-stopCh:
		return false
	}

	s.queueMu.Lock()
	if s.closed {
		s.queueMu.Unlock()
		<-s.queueSlots
		return false
	}
	s.queue = append(s.queue, pkt)
	s.queueMu.Unlock()

	select {
	case s.queueReady <- struct{}{}:
	default:
	}
	return true
}
```

- [ ] **Step 4: Clear shifted packet references**

In `nextQueuedPacket`, replace the pop block with:

```go
if len(s.queue) > 0 {
	pkt := s.queue[0]
	var zero Packet
	s.queue[0] = zero
	s.queue = s.queue[1:]
	s.queueMu.Unlock()
	return pkt, true
}
```

- [ ] **Step 5: Release slots in the runner**

Replace `packetSubscriber.run` with:

```go
func (s *packetSubscriber) run(stopCh <-chan struct{}) {
	defer s.once.Do(func() {
		close(s.ch)
	})
	for {
		pkt, ok := s.nextQueuedPacket(stopCh)
		if !ok {
			return
		}
		delivered := false
		select {
		case s.ch <- pkt:
			delivered = true
		case <-s.done:
		case <-stopCh:
		}
		if s.queueSlots != nil {
			<-s.queueSlots
		}
		if !delivered {
			return
		}
	}
}
```

- [ ] **Step 6: Run green tests**

Run:

```bash
go test ./pkg/derpbind -run 'TestClientSubscribeLossless(BlocksWhenQueueFull|UnsubscribeReleasesBlockedDispatch|DoesNotBlockBeforeHardLimit|RetainsAllBackedUpPackets)' -count=1
```

Expected: PASS.

### Task 3: Validate Subscriber Regression Surface

**Files:**
- Test: `pkg/derpbind/derpbind_test.go`
- Test: `pkg/session/...`
- Test: `pkg/derphole/webrelay/...`

- [ ] **Step 1: Run DERP package tests**

Run:

```bash
go test ./pkg/derpbind -count=1
```

Expected: PASS.

- [ ] **Step 2: Run key lossless call-site tests**

Run:

```bash
go test ./pkg/session ./pkg/derphole/webrelay -count=1
```

Expected: PASS.

- [ ] **Step 3: Run full suite**

Run:

```bash
mise run test
```

Expected: PASS.

If relay or transport tests expose throughput stalls, keep the lossless cap behavior and fix the specific consumer by narrowing its filter or draining faster. Do not reintroduce unbounded queues.

### Task 4: Final Verification And Commit

**Files:**
- Modify: `pkg/derpbind/client.go`
- Modify: `pkg/derpbind/derpbind_test.go`

- [ ] **Step 1: Run vet**

Run:

```bash
mise run vet
```

Expected: PASS.

- [ ] **Step 2: Run local smoke**

Run:

```bash
mise run smoke-local
```

Expected: PASS.

- [ ] **Step 3: Commit**

Run:

```bash
git add pkg/derpbind/client.go pkg/derpbind/derpbind_test.go
git commit -m "derpbind: bound lossless subscriber queues"
```

Expected: commit succeeds after hooks pass.
