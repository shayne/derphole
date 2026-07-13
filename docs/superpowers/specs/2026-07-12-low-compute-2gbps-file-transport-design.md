# Low-Compute 2 Gbps File Transport Design

Date: 2026-07-12

Status: TLS feasibility winner integrated; final six-run product acceptance is in progress.

## Summary

Make normal file `send` and `receive` exceed 2.0 Gbps of verified file goodput in both directions between this Mac and the exact two-vCPU Hetzner VM. Do not get there by measuring an in-memory pipe, skipping encryption, relying on Tailscale, or testing a larger VM. The file, route, CPU limit, integrity check, and command wall clock all count.

The investigation found two different limits. Current multi-connection QUIC reaches roughly 1.19 Gbps Mac-to-Hetz and 1.24 to 1.34 Gbps Hetz-to-Mac. Changing QUIC from one to eight independent connections moves the Mac-to-Hetz result, but it never approaches 2 Gbps; the reverse result barely moves. Current custom bulk is competitive on lossy residential cable but slower on Hetz. Most importantly, ordinary 1,400-byte UDP sends from Hetz consume almost both vCPUs and settle around 1.33 to 1.44 Gbps at the receiver. The same VM repeatedly moves 2.07 Gbps with eight TCP flows while using about 6 percent sender CPU. The bottleneck is therefore not merely QUIC's congestion controller. On Hetz-to-Mac, it is the cost of emitting hundreds of thousands of small userspace UDP packets per second.

The design starts with a short feasibility gate instead of immediately adding another transport and hoping it is fast. Two encrypted prototypes compete on the real path:

1. a wire-compatible bulk UDP engine using slab reuse, CPU-sized crypto workers, Linux `recvmmsg`, and UDP GSO or `sendmmsg`; and
2. an eight-connection TLS stream engine that lets the kernel use its existing TCP segmentation and buffering machinery.

Only an engine that clears the full two-way file gate on the exact machines can enter the product. If batched UDP clears it, improve `bulk-packets-v1` without changing its wire format. If it does not and the TLS stream engine does, add a negotiated direct-TCP fast path for peers that can establish it. Keep QUIC and bulk UDP as fallbacks. Eric's cable path is evidence for keeping selective-repair bulk, not evidence that every network should pay its packet-rate bill.

The feasibility work selected the TLS stream engine. The integrated production path has measured 2.28 to 2.33 Gbps Mac-to-Hetz and 2.08 Gbps Hetz-to-Mac on valid public-path samples. Those measurements established feasibility but do not close the outcome: the exact current revision still needs three valid 3 GiB normal-file runs in each direction.

## Required Outcome

The accepted implementation must complete three 3 GiB normal file transfers in each direction between this Mac and the exact two-vCPU Hetzner VM. Every valid run must satisfy all of these:

- receiver-anchored canonical goodput greater than 2.0 Gbps
- exact byte count and SHA-256 match
- public-internet selected addresses, with Tailscale candidates disabled for the benchmark
- paired same-direction eight-flow TCP iperf capacity of at least 2.05 Gbps
- no payload flatline of one second or longer
- no socket-buffer failure, stuck process, leaked listener, or incomplete trace
- sender and receiver CPU, RSS, packet, retransmit, repair, and wall-time measurements present

The paired iperf floor separates a product failure from a WAN-capacity dip. A run below that floor is invalid and rerun; it is not silently counted as a pass or failure. There is no analogous waiver when derphole fails integrity, routing, cleanup, or throughput while the paired capacity is present.

The exact two-vCPU VM is part of the contract. Adding vCPUs may be useful for diagnosis, but it cannot satisfy the gate.

## Evidence

### Current transports

Fresh 1 GiB public-path measurements produced these representative results:

| Direction | Transport | Canonical goodput | Paired TCP capacity |
| --- | --- | ---: | ---: |
| Mac to Hetz | QUIC, 8 connections | 1.186 Gbps | 2.340 Gbps |
| Mac to Hetz | bulk UDP, 8 lanes | 1.144 Gbps | 2.340 Gbps |
| Hetz to Mac | QUIC, 8 connections | 1.240 Gbps | 2.000 Gbps |
| Hetz to Mac | bulk UDP, 8 lanes | 0.585 to 0.614 Gbps | 1.643 to 1.956 Gbps |

The QUIC connection-count matrix ruled out a simple fanout fix. Mac-to-Hetz rose from 0.441 Gbps with one connection to 1.015 Gbps with four and 1.186 Gbps with eight. Hetz-to-Mac stayed around 1.24 to 1.34 Gbps across one, two, four, and eight connections. Sixteen lanes made direct setup less reliable and did not produce a successful sample.

### The packet-rate ceiling

Four-flow UDP iperf with 1,400-byte datagrams exposed the limiting mechanism on the constrained VM:

- Mac-to-Hetz at a 2.3 Gbps offered rate delivered 2.197 Gbps with 4.46 percent loss.
- Hetz-to-Mac at the same offered rate delivered 1.330 Gbps with 41.58 percent loss while the Hetz sender consumed 189.61 percent CPU.
- Hetz-to-Mac delivered 1.197 Gbps with negligible loss at a 1.2 Gbps offer and 1.438 Gbps with 2.97 percent loss at a 1.5 Gbps offer. Higher offers produced more loss, not more useful traffic.

At 2 Gbps, a 1,358-byte bulk payload requires roughly 184,000 encrypted datagrams per second. The current sender allocates and reads one payload, seals one packet, waits on the pacer, and calls `WriteTo` once for every datagram. The receiver performs one `ReadFrom`, one open, and one channel handoff per datagram. That shape works until syscall, scheduler, allocation, and crypto overhead fill two cores. Then the queue grows, packets drop, repair grows, and the throughput graph settles lower. This is not mysterious congestion. It is a very small packet factory running out of workers.

The Hetz interface reports generic segmentation and receive offload enabled, but `tx-udp-segmentation` is fixed off. Linux software UDP GSO may still work, but the product must prove that on this VM rather than infer it from a feature name. `sendmmsg` reduces syscall count but does not remove per-datagram kernel work. That distinction is the reason for the feasibility gate.

### TCP and crypto headroom

A repeated feasibility refresh separated the TCP connection-count problem from the VM CPU problem. Four Hetz-to-Mac TCP flows delivered 1.887, 1.997, and 2.057 Gbps over 10-second samples, then averaged 1.86 Gbps over a 30-second sample. The VM was not busy: the Hetz sender used roughly 5.5 to 6.0 percent CPU. The four flows were uneven and left path capacity unused.

Eight flows changed the result. Three 20-second Hetz-to-Mac samples delivered 2.070, 2.071, and 2.073 Gbps. Hetz sender CPU remained between 5.89 and 6.10 percent. In the other direction, four-flow Mac-to-Hetz samples delivered 2.290, 2.330, and 2.330 Gbps while the Hetz receiver used roughly 37 to 39 percent CPU. The kernel stream path therefore has enough network and CPU headroom in both directions, but the constrained direction needs eight independent congestion windows on this route.

Encryption also has headroom. One Hetz vCPU processed 16 KiB AES-128-GCM blocks at 3.958 GB/s, or roughly 31.7 Gbps, with the host's AES instructions active. That does not prove an integrated Go TLS file engine will pass. It does rule out bulk symmetric encryption as the reason a correctly buffered TLS stream would stop near 1.3 Gbps.

### Why Eric is different

On the New York-to-California cable path, custom bulk has sustained roughly 0.8 to 0.88 Gbps while QUIC historical samples were roughly 0.27 to 0.43 Gbps. Selective repair lets independent lanes keep delivering when a few packets are lost; QUIC's congestion response reduces a connection's sending rate. Eric therefore remains a valid bulk-UDP use case. A clean, nearby, high-capacity path has a different bottleneck and should be allowed to select a different engine.

## Considered Approaches

### Prove batching, then integrate the winner -- selected

Build two minimal encrypted file-path prototypes, measure them on the exact machines, and integrate only the one that passes. This spends a small amount of work to answer the uncertain question before spending a large amount of work around an assumption.

The UDP prototype tests whether software GSO or end-to-end batching can escape the observed packet-rate ceiling. The TLS stream prototype tests the known lower-packet-rate path while including encryption and file I/O. The comparison uses the same files, hashes, directions, traces, and CPU accounting.

This is the selected approach because the evidence supports both a promising UDP optimization and a serious reason it may fail on this vNIC. The prototype turns that uncertainty into a number.

### Optimize QUIC further -- rejected as the primary route

Current raw-direct QUIC already uses independent endpoints and connections per stripe. Quic-go already uses Linux receive batching and GSO when the socket and kernel support them. Connection-count tests did not move the reverse plateau. There may still be worthwhile QUIC improvements, but none currently explain a path from 1.3 to greater than 2.0 Gbps on two saturated vCPUs.

### Replace everything with direct TCP -- rejected

Eight-flow TCP exceeds the required rate because the kernel aggregates work well. But direct TCP is not universally reachable through NAT, and Eric demonstrates that selective repair can outperform a congestion-controlled stream on a lossy asymmetric path. Making TCP the only data plane would trade one benchmark win for a product regression. The direct stream engine is a capability, not a new universal default.

## Phase Zero: Feasibility Harness

Phase zero adds an internal benchmark command or test binary, not a user-facing transport. It reuses the production file reader, file writer, hashing, key derivation, tracing schema, and cleanup rules so the prototype cannot win by omitting expensive work that production must perform.

The harness accepts a role, direction, file path, peer address, engine, connection or lane count, and trace path. It emits one summary JSON object plus the standard time-series CSV. Test-only knobs remain internal and cannot affect normal negotiation.

### Batched UDP candidate

The UDP candidate preserves the `bulk-packets-v1` packet size and authenticated packet format. It changes how work reaches the socket:

- read the source into reusable large slabs rather than allocating and calling `ReadAt` for every packet
- divide slabs among no more encryption workers than the constrained endpoint has CPUs
- seal directly into reusable packet storage
- pace batches while retaining per-packet sequence numbers and repair semantics
- on Linux transmit, attempt UDP GSO and report whether it was actually accepted
- fall back to `sendmmsg` when GSO is unavailable or rejected
- on Linux receive, use cancellable `recvmmsg` batches without enabling UDP GRO initially
- decrypt with a bounded CPU-sized worker pool and deliver completed extents in batches
- coalesce file writes behind a bounded asynchronous writer
- keep repair on an independent 100 ms clock so a busy packet loop cannot starve it

The existing GRO experiment is not repeated as a default. It increased repair and reduced WAN throughput. GRO can return only as a separately measured experiment with packet-boundary and truncation tests.

The UDP prototype records GSO attempted, GSO active, segment count, `sendmmsg` batch size, receive batch size, datagrams per syscall, encryption queue depth, writer queue depth, drops, repair ratio, and CPU seconds per GiB. A platform fallback that sends one datagram at a time remains correct, but it cannot be mistaken for a successful batched run.

### TLS stream candidate

The stream candidate opens eight independent TCP connections to one authenticated listener. Four-flow samples left the constrained direction between 1.86 and 2.06 Gbps. Three eight-flow samples held 2.070 to 2.073 Gbps with no material Hetz CPU increase, so eight is the smallest measured count that repeatedly clears the raw-path target. More connections add scheduling and failure surface without evidence of benefit.

Each connection uses TLS 1.3. The receiver creates an ephemeral certificate for the transfer. Its public-key fingerprint is carried over the existing authenticated session control plane, and the sender pins that fingerprint instead of trusting the public CA set. The TLS handshake therefore authenticates the data connection to the already authenticated transfer without introducing durable certificates.

After TLS setup, each lane authenticates its protocol version, transfer identifier, lane index, and lane count. A shared scheduler hands out aligned 1 MiB chunks to whichever lane is ready next, avoiding a slow final lane while preserving exact non-overlapping coverage. The receiver rejects duplicate chunks, out-of-range or misaligned extents, wrong transfer identifiers, invalid lane identities, and unexpected versions before writing payload. Each lane reuses one bounded buffer and writes into the existing random-access sink. The authenticated control plane carries final committed byte counts; the acceptance harness independently verifies the whole-file SHA-256 and size.

This prototype measures TLS cipher, connection count, bytes per read and write syscall, retransmits from TCP info where available, per-lane progress, CPU seconds per GiB, and disk queue depth. It must include hashing and real file I/O. A loop that encrypts zeros into `/dev/null` would be fast and useless, which is an impressively common benchmark genre.

### Phase-zero decision rule

Run three 3 GiB transfers per direction for each candidate. A candidate advances only if all six runs meet the required outcome. If both pass, select the candidate with lower maximum endpoint CPU seconds per GiB; use wall goodput and peak RSS as tie breakers.

If UDP fails only because GSO is unavailable and the stream engine passes, select the stream engine. If UDP passes and stream does not, integrate UDP batching. If both pass, prefer UDP batching because it improves the existing generally reachable transport without adding candidate discovery. If neither passes, stop product integration and return to root-cause work with profiles from the failed candidates. Do not combine two losing prototypes and call the average a win.

## Product Architecture

### Common engine boundary

Introduce a small file data-plane interface around responsibilities already shared by QUIC and bulk:

```text
prepare -> establish authenticated lanes -> transfer ranges -> verify -> close
```

The interface receives an immutable transfer descriptor, source or sink, session-derived authentication material, trace sink, and cancellation context. Engines own sockets, lane scheduling, transport-specific recovery, and transport-specific telemetry. The session owns negotiation, selected-engine reporting, whole-file integrity, user-visible progress, and fallback policy.

This boundary is deliberately file-specific. Pipe behavior stays supported by its existing path, but it does not drive this optimization.

### If batched UDP wins

Replace the current per-packet bulk hot path behind the existing `bulk-packets-v1` capability. Keep packet and repair frames wire-compatible so mixed-version peers continue to transfer. Use optimized Linux send and receive implementations selected by build tags or runtime socket capability, with the portable one-packet fallback preserved.

Batching is bounded at every stage. Slab pools, sealed-packet queues, decrypt queues, and writer queues have explicit byte ceilings. When a downstream queue fills, pacing stops reading more source data. The system applies backpressure instead of converting RAM into a very temporary network.

### If the TLS stream engine wins

Add a versioned `direct-tcp-files-v1` capability. Either file endpoint may own the TCP listener, which lets a forwarded Mac receive from Hetz or send to Hetz without requiring a second public listener. A peer advertises a listener only when it has an explicit same-port TCP forward or a directly routed address. Keep TCP advertisements separate from the existing UDP data-plane negotiation. A UDP port mapping proves nothing about TCP reachability, even when both protocols happen to use the same number.

The current Tailscale portmapper dependency is explicitly UDP-only. Its public interface, NAT-PMP requests, PCP requests, and UPnP requests all create UDP mappings. Version one therefore accepts two honest TCP candidate sources:

- a directly routed interface address using the listener's bound port
- an existing same-port TCP forward selected with `--direct-tcp-port`

For the forwarded case, the endpoint binds that local port and combines it with public addresses already learned through STUN. The peer still proves reachability before payload starts. External-to-internal port translation is out of scope for version one; the configured external and local ports must match. This supports an existing public TCP forward without hard-coding a port or address into the product. The option controls reachability, not connection count, buffers, pacing, or another performance knob.

Automatic TCP mappings through PCP, NAT-PMP, and UPnP are a separate follow-up. They require a TCP-capable mapping implementation rather than an extension flag on the current dependency. Do not fork or partially copy that machinery until the encrypted stream engine passes phase zero and the normal-file Hetz gate.

Add optional `direct_tcp_file_capable` and `direct_tcp_file` fields to both authenticated claim and accept messages. The nested advertisement contains at most eight canonical address-port candidates, the SHA-256 fingerprint of an ephemeral TLS public key, and a random transfer identifier. Both peers set the capability field; whichever endpoint has configured reachability may supply the advertisement. Keeping the fields on both messages supports both token topologies and either listener role without changing the token format. Old peers ignore the optional JSON fields and continue with QUIC or bulk.

The existing authenticated control plane protects the capability, candidates, certificate fingerprint, and readiness result. Candidate validation rejects invalid addresses, unspecified addresses, zero ports, duplicate endpoints, and more than eight entries before dialing. TLS 1.3 pins the advertised key, and every lane must also present an HMAC proof derived from the session secret and transfer identifier. Negotiation selects the stream engine only after all eight lanes authenticate and both peers exchange a ready result. If establishment fails before payload starts, the session continues with QUIC without restarting the claim.

The stream engine is intended for high-capacity, low-loss paths where kernel segmentation is the efficient answer. It does not replace bulk on Eric-like paths and does not replace QUIC where TCP reachability is absent.

### Selection policy

Selection uses negotiated capabilities and the existing receiver-owned block policy, not hostname rules:

1. Attempt authenticated direct candidates as today.
2. Let the receiver compute `blocks-v1` or `bulk-packets-v1` from the same candidate policy it uses today.
3. If the receiver selects `blocks-v1`, the file is at least 64 MiB, `direct-tcp-files-v1` is mutually supported, and its TCP reachability probe succeeds, select direct TCP.
4. If the receiver selects `bulk-packets-v1`, use bulk UDP even when a TCP candidate is reachable.
5. Otherwise use multi-connection QUIC as the generally reachable direct path.
6. Retain DERP relay fallback when no direct data plane succeeds.

The 64 MiB threshold keeps an extra probe and eight TLS handshakes off small transfers where setup time matters more than line rate. It is a protocol constant in version one, covered by boundary tests, rather than a user-facing tuning flag. The selector must log file size, receiver policy result, mutual capabilities, candidate source, probe result, selected engine, and final reason. A selector that says only `quick` or `bulk` after the fact is not enough to debug a wrong choice.

Fallback is allowed during establishment, before file payload is committed. Mid-transfer migration is out of scope for this cycle. A transport failure after payload starts fails the attempt cleanly; automatic retry may begin a new attempt with the next engine only after the sink is reset or replaced atomically.

## Failure Handling

- Every listener and lane is owned by the transfer context and closes on cancellation, timeout, integrity failure, or peer failure.
- Establishment has a bounded timeout per candidate and a bounded total direct-upgrade timeout.
- UDP GSO failure disables GSO for that socket and records the kernel error; it falls back to `sendmmsg` without losing packet sequence state.
- Short batched sends retry only unsent messages. Already accepted datagrams are never duplicated by resending the whole batch.
- Receive batches validate message length and truncation flags before decryption.
- Crypto and writer queues stop accepting work after the first fatal error and drain no more data than their documented bounds.
- TLS lane failure cancels sibling lanes. Partial output is never reported as a successful file.
- Whole-file size and SHA-256 remain authoritative even when the transport has its own integrity protection.
- A failed direct-TCP probe does not poison the authenticated QUIC or bulk candidates.
- UDP candidates and UDP mappings are never copied into the TCP candidate field. A configured forwarded port supplies an explicit TCP reachability claim, and the probe supplies the proof.
- Test harness traps remove only the exact processes and temporary files it created. No broad process killing is permitted on Eric or any shared host.

## Telemetry

Every engine emits the same common measurements:

- canonical receiver-anchored goodput and command-wall goodput
- per-second payload bytes, wire bytes, and current rate
- sender and receiver user CPU, system CPU, CPU seconds per GiB, and peak RSS
- bytes read from source and committed to sink
- hash and size verification state
- selected public addresses and Tailscale-candidate count
- establishment time, first-byte time, completion time, and close reason
- per-lane payload and stall duration

Transport-specific fields remain namespaced. UDP adds syscall batching, GSO, loss, repair, and queue data. TCP adds cipher, retransmits, congestion window where available, and socket read/write sizes. QUIC retains congestion, RTT, loss, stream, and GSO diagnostics.

The CSV sampler runs at 100 ms for short high-speed transfers and emits a final sample on completion. Summary calculations use monotonic counters rather than adding rounded rates. Healthy zeroes are values. Missing measurements are errors, not zeroes.

## Test Strategy

Implementation follows red/green TDD after the feasibility engine is chosen.

### Common tests

- exact 0-byte, one-byte, boundary-size, 3 GiB sparse, and ordinary 3 GiB files
- short reads, short writes, cancellation, peer disappearance, and disk failure
- whole-file hash mismatch never reports success
- progress counters remain monotonic and never exceed file size
- queue memory stays within configured bounds under a stalled sink
- all goroutines, sockets, listeners, temporary files, and samplers exit

### UDP tests

- GSO capability detection distinguishes attempted, active, rejected, and unavailable
- a GSO batch produces the same authenticated datagrams as individual sends
- partial `sendmmsg` writes resume at the first unsent message
- cancellable `recvmmsg` exits promptly without breaking deterministic loss-and-repair tests
- reordering and loss preserve the independent 100 ms repair cadence
- batching does not increase repair ratio or create truncated packets
- old and new peers interoperate with unchanged `bulk-packets-v1` frames

### TLS stream tests

- certificate fingerprint pinning accepts only the transfer certificate
- wrong transfer ID, duplicate lane, overlap, range overflow, and version mismatch fail before payload write
- a failed lane cancels all siblings and leaves no successful partial output
- eight lanes cover every byte exactly once
- direct-TCP probe failure falls back without delaying existing direct setup beyond its budget
- claim and accept messages negotiate TCP capability in either receiver topology without changing the token wire format
- invalid, duplicate, unspecified, zero-port, and oversized TCP candidate lists are rejected before dialing
- UDP mappings never become TCP candidates implicitly
- old peers ignore the new capability and continue with QUIC or bulk

### Selection tests

- high-capacity reachable TCP candidate selects the stream engine when it is the accepted winner
- lossy asymmetric policy selects bulk
- unavailable TCP and unavailable bulk select QUIC
- no direct path selects relay
- every selection includes a machine-readable reason and all policy inputs

## Live Gates

### Hetz performance gate

Run the six required 3 GiB transfers on the exact two-vCPU VM. Interleave directions and controls to reduce time-of-day bias. Record paired eight-flow TCP and 1,400-byte UDP baselines. The Mac receiver uses its existing same-port TCP 8123 forward through `--direct-tcp-port 8123`; the Hetz receiver advertises its directly routed listener. The final measurements use normal `send` and `receive`, not the feasibility binary, and must pass every required-outcome condition.

Then repeat the six-run gate once after a clean rebuild and process cleanup. The second pass catches accidental warm-cache, leaked-listener, and one-lucky-route results.

### Eric stability gate

Run three unoverridden 3 GiB Mac-to-Eric file transfers and three Eric-to-Mac transfers using public candidates with Tailscale disabled for the benchmark. Preserve exact integrity and cleanup. The accepted implementation may select bulk or another mutually supported engine, but it may not regress the fresh control median canonical or wall goodput by more than 3 percent, increase repair ratio, or reproduce the VM-disrupting resource behavior seen during earlier stress work.

Eric tests are sequential. Record VM memory, load, kernel OOM messages, interface drops, and process state before and after each run. Stop after the first host-health failure; do not turn a stability test into a denial-of-service loop.

### Reachable fleet gate

Run three 1 GiB normal file transfers in both directions for every reachable canonical test machine. Use each machine's negotiated production mode, except that public benchmarking disables Tailscale candidates. Require integrity, trace completeness, bounded resources, cleanup, no one-second flatline, and no more than 3 percent median regression against a fresh control.

### Project gates

Run focused package tests, the full suite, vet, hook checks, local smoke, remote smoke, and the normal release dry run if packaging or capability metadata changes. Independent review must find no unresolved Important issue before landing.

## Scope Boundaries

- Optimize normal file `send` and `receive`; do not substitute `pipe` results.
- Do not add FEC in this cycle.
- Do not enable UDP GRO by default without new evidence that reverses the earlier result.
- Do not change the bulk wire format unless the feasibility result proves compatibility cannot meet the goal.
- Do not require more than two vCPUs on Hetz.
- Do not hard-code hostnames, local paths, public addresses, or developer-specific defaults.
- Do not treat the UDP-only portmapper as a TCP mapping implementation. Automatic TCP mapping is a later, separately tested subsystem.
- Do not remove QUIC, bulk, or relay until fleet evidence proves an engine has no remaining network class to serve.
- Do not expose experimental tuning flags as user-facing product configuration.
- Do not publish or release from a prototype result. Product and fleet gates come first.

## Completion

This work is complete only when normal encrypted file transfers exceed 2.0 Gbps in all three valid 3 GiB samples in both directions on the exact two-vCPU Hetzner VM, the repeated clean-build gate also passes, Eric and the reachable fleet remain stable, independent review is clean, all project gates pass, and the final work is landed on local and remote `main` with the development package resolving to that commit.

If neither feasibility candidate clears the exact two-way gate, the honest result is that this VM, route, and current reachability constraints need a different kernel or NIC primitive. That is not permission to lower the target or report iperf as file throughput. It is a new root-cause result, and the next design starts there.
