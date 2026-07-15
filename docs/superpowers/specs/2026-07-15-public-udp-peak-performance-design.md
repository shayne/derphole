# Public UDP Peak Performance and Hard-Ceiling Design

## Objective

Prove one of two outcomes on the exact two-vCPU Hetzner VM without changing
the host:

1. derphole completes exactly three 3 GiB normal-file transfers in each
   direction over the public Internet, every run exceeds 2.0 Gbps
   receiver-anchored goodput, and the trace proves QUIC or custom bulk carried
   every file payload byte over UDP; or
2. repeatable evidence establishes the public-UDP packet-processing ceiling,
   identifies its mechanism, and proves the retained implementation is the
   fastest stable member of a predeclared candidate space on this VM and path.

TCP port 8123 remains an independent capacity control. TCP, TLS, relay payload,
Tailscale-selected addresses, pipe workloads, and host tuning cannot satisfy
the result.

The first outcome is the acceptance target. The second is a hard-ceiling
conclusion, not a redefinition of acceptance. If the hard ceiling is below
2.0 Gbps, the 3 GiB gate remains failed and is not run.

## Constraints

- Use ordinary files through `send FILE` and `receive TOKEN`.
- Use the exact Hetzner VM with exactly two online CPUs.
- Make no kernel, sysctl, NIC, qdisc, service, package, CPU, memory, swap, or
  other host changes.
- Use public non-Tailscale addresses for payload lanes.
- Preserve DERP rendezvous, NAT traversal, and hole punching.
- Leave production Tailscale candidate discovery enabled outside benchmarks.
- Keep transport queues bounded and clean up only harness-owned files,
  processes, sockets, and directories.
- Do not attempt a 3 GiB transfer until the exact candidate has completed a
  capacity-valid 1 GiB normal-file transfer above 2.0 Gbps in both directions.
- Be conservative with Hetzner disk use and with Eric's VM and host health.

## Current Evidence

The path itself is not the principal limit. Eight-flow TCP controls have
delivered roughly 2.08 to 2.15 Gbps from Hetzner to the Mac with low Hetzner
sender CPU. In contrast, 1,400-byte UDP offered near 2.2 Gbps delivered only
about 1.36 to 1.42 Gbps while consuming about 190 percent Hetzner CPU and
losing roughly 35 to 38 percent of packets.

The transport evidence follows the same shape:

- raw-direct QUIC remained near 1.24 to 1.34 Gbps across one, two, four, and
  eight connections;
- synchronous custom bulk with GSO3 reached about 1.29 Gbps;
- a frozen synchronous sender profile attributed about 61.9 percent of flat
  samples to Linux syscall work, with about 19.3 percent cumulative in source
  reads and about 10 percent flat in grouped AES-GCM;
- fixed GSO12 reduced sender CPU but increased repair and lowered goodput
  relative to GSO3;
- one-owner and two-owner io_uring designs increased CPU without materially
  escaping the same throughput plateau; and
- extra lanes, Linux GRO, larger receive writes, and plain sendmmsg-only
  variants have already produced rejected evidence.

This makes custom bulk the appropriate final optimization surface. QUIC
cleanup may still be useful product work, but the existing QUIC packet-rate
shape is not the recommended route to the two-vCPU acceptance target.

## Approaches

### Optimize custom bulk incrementally

Collapse source reads and remove Linux connected-send administration while
retaining the current Internet-safe wire format. Then search a bounded GSO
space under exact capacity, integrity, repair, CPU, and stability gates.

This is the recommended approach. It directly attacks measured costs, keeps
fallbacks, and produces falsifiable evidence even if it cannot overcome the
kernel packet-rate ceiling.

### Fork or deeply modify quic-go

Larger quic-go receive batches, larger GSO aggregation, and better internal
telemetry could reduce administration. However, quic-go already uses Linux
GSO and recvmmsg, additional connections did not move the plateau, and every
MTU-sized QUIC packet still carries encryption, header protection, parsing,
ACK, and recovery work. This option has higher maintenance risk and weaker
evidence of a path to 2.0 Gbps.

It remains a measured control, not the primary implementation path.

### Use larger on-wire UDP datagrams

IP fragmentation or jumbo datagrams could reduce application-visible packet
rate, but they are not a defensible public-Internet default across NATs and
varied networks. FEC could reduce repair but would not remove the base packet
rate. This approach is rejected.

## Sender Architecture

### Coalesced grouped source reads

The grouped sender prepares sixteen consecutive authenticated groups per slab.
It currently issues one `ReadAt` for each roughly 61 KiB group even though the
file ranges are contiguous. Sixteen full groups contain 989,024 plaintext
bytes and fit the existing 1,042,944-byte slab input.

The optimized path calculates the complete plaintext range for the preparation
job, performs one `ReadAt` into the slab, then seals each group from a slice of
that buffer. A partial final slab reads only its exact remaining range. Short
reads, EOF, cancellation, offsets, payload accounting, and ciphertext output
retain current semantics.

### Connected native Linux transmission

After authenticated probing selects the raw data lanes, each dedicated Linux
data socket may enter fixed-peer mode only when more sockets exist than active
data lanes. This preserves at least one unconnected socket for control hello,
ACK, repair, completion, and other fan-out traffic.

Fixed-peer enablement receives the expected lane peer. It connects the socket
and verifies `getpeername` against the expected binary IP address, port, and
IPv6 zone. String comparison is not sufficient. A mismatch rejects the fast
path before payload.

The raw connected writer uses `RawConn.Write` and Linux `sendmsg` or
`sendmmsg` with `msg_name=nil`. It reuses bounded message, iovec, control, and
logical-completion scratch. `RawConn.Write` returns false only for `EAGAIN` or
`EWOULDBLOCK`, allowing the Go netpoller and socket deadline to remain the
blocking authority. The writer preserves partial logical counts, `ENOBUFS`,
zero-progress, cancellation, and buffer lifetime semantics.

The fallback state is explicit:

1. Failure before connecting keeps the existing addressed backend available.
2. GSO rejection after connecting falls back to raw connected non-GSO
   `sendmmsg`.
3. A fatal raw failure after connecting may use an addressed backend only
   after an explicit disconnect; otherwise the lane fails cleanly.

The fast path removes per-batch address stringification, sockaddr packing,
`x/net` message conversion, and addressed message validation. macOS and
portable backends are unchanged.

### GSO candidate space

The production default begins as GSO3. The benchmark search covers logical
segment counts `1, 2, 3, 4, 6, 8, 12`; `1` means raw non-GSO sendmmsg rather
than a one-segment `UDP_SEGMENT` control message.

Candidate-specific scratch is sized for the smallest segment grouping. The
search uses benchmark-only configuration and records the selected grouping in
the binary manifest and trace. The final code retains one proven production
default and the safe runtime fallback; it does not expose a user tuning knob.

Larger fixed groups are not presumed faster. GSO12 already demonstrated the
CPU-versus-drop tradeoff, and a full 45-fragment GSO skb would enlarge qdisc
drop amplification further.

### Conditional synchronous zero-copy

Plain synchronous `MSG_ZEROCOPY` is eligible only when a fresh optimized
profile still attributes at least 10 percent of sender CPU to copy or buffer
movement. Existing profiles are below that threshold, so the expected outcome
is to skip this experiment. io_uring is not revisited.

## Telemetry

The implementation and harness record enough evidence to bind the mechanism
to every result. Both engines require:

- actual transmit attempts and native-backend syscall telemetry at the
  selected engine's available instrumentation boundary;
- source read calls and bytes;
- native send and receive backend;
- sender and receiver user/system CPU seconds and CPU seconds per GiB;
- queue peaks and flatlines;
- exact selected public lane addresses;
- exact payload engine and carrier-specific committed file bytes; and
- host CPU, OOM, memory, disk, kernel, interface, softnet, UDP, and process
  deltas.

Custom bulk additionally requires transmit syscall attempts from inside the
raw callback, GSO messages, logical datagrams, segments per message, accepted
payload bytes per syscall, probe state, batch counters, `ENOBUFS` telemetry,
repair bytes and ratio, retransmits, and missing-scan work.

QUIC instead requires raw-direct socket identity, connection and stream count,
handshake and first-byte time, smoothed RTT, packets sent and lost,
retransmitted wire bytes, stream bytes sent and received, close reason, and
native GSO/receive-batch identity when the platform exposes it. QUIC recovery
ratio is retransmitted wire bytes divided by initially sent wire bytes.

Missing telemetry required for the selected engine is invalid evidence, not a
healthy zero. Bulk-only fields may be absent for QUIC and QUIC-only fields may
be absent for bulk.

## Harness Hardening

Live performance work must not begin until the checked-in harness mechanically
enforces the proof contract.

### Payload, carrier, and route proof

- Add an exact expected-file-payload operand to `transfertracecheck` so framed
  application bytes and committed file bytes are verified independently.
- Add `file_payload_engine` to sender and receiver traces. Add receiver-owned
  fields `file_payload_bytes_committed`, `file_payload_bytes_bulk`, and
  `file_payload_bytes_quic`. The bulk receive engine increments only the bulk
  counter after authenticated payload commits. The QUIC block receiver
  increments only the QUIC counter after authenticated block plaintext commits
  to the file sink, excluding frame headers and session control bytes. Exactly
  one receiver engine counter must equal the expected file size, the other must
  be zero, and their sum must equal `file_payload_bytes_committed`.
- Require a present, unique reported SHA-256 and exact sink size and hash. Do
  not substitute the expected hash when a footer is missing.
- Require `file_payload_engine` to be `bulk-packets-v1` or `quic-blocks-v1` and
  require the sender and receiver traces to agree on the authenticated
  negotiated engine. Sender traces do not synthesize receiver-owned committed
  counters from generic progress acknowledgements.
- Require UDP as the direct payload transport and forbid TCP, TLS, and relay
  payload.
- Parse actual selected payload-lane addresses. Every lane must use the
  expected literal public IPv4; private, link-local, CGNAT/Tailscale, ULA,
  multicast, or unexpected addresses reject the sample.
- Require native backend, queue, and resource fields plus the selected
  engine's telemetry set to be present and internally consistent.

### Mechanical size prerequisite

The final harness consumes a signed or hash-bound decision artifact from the
1 GiB prerequisite. The artifact names the exact candidate binary hashes and
proves at least one capacity-valid, fully healthy, greater-than-2.0-Gbps
normal-file sample in each direction. A different binary or missing proof
cannot start a 3 GiB run.

### Health and cleanup

- Record boot ID, uptime, global and cgroup OOM counters, available memory,
  swap, disk, kernel error tail, interface counters, UDP counters, softnet
  counters, and process state before and after every sample.
- Recheck disk space before staging and before every run.
- Treat reboot, OOM increment, severe memory pressure, new kernel error,
  cleanup failure, unexpected process/socket, or harness-owned disk leak as a
  hard failure.
- Track exact wrapper and child PIDs. Use bounded TERM then KILL only for
  recorded PIDs; never use broad process killing.
- Make failure to remove the exact scoped remote directory fail the decision.
- Rehash and remove harness-owned source and receive payloads after preserving
  their size, SHA-256, and evidence. Do not retain multi-gigabyte payloads in
  artifact directories.
- Install no package or dependency on any host. Missing prerequisites fail or
  skip the cell.
- Start benchmark processes with an explicit environment allowlist so TCP or
  experimental overrides cannot leak between cells.

## Candidate Search

### Immutable manifest

Before testing, write one manifest containing:

- control and candidate commits, binary SHA-256 values, and configuration;
- Mac and Hetzner public addresses;
- Hetzner kernel, architecture, boot ID, and exactly two online CPUs;
- source size and SHA-256;
- the predeclared candidate set, schedules, thresholds, and elimination rules;
- production-confirmation environment with no benchmark transport override;
  and
- baseline health and packet-processing counters.

TCP port 8123 appears only as the independent capacity-control port.

### Screening

Use one reusable 1 GiB ordinary file per endpoint and delete every verified
receive output. Screen first in the Hetzner-to-Mac direction, where Linux
transmit is the known limiter.

Each candidate receives one capacity-valid 1 GiB sample bracketed by the
frozen synchronous GSO3 control. Integrity, public route, UDP carrier, trace,
CPU-limit, selected-engine recovery, or flatline failure rejects the candidate
immediately. A one-run performance result eliminates a candidate only when
both bracketing controls are within 3 percent of each other and another
candidate dominates it by at least 10 percent in raw goodput, normalized
goodput, and goodput per CPU second. Otherwise it advances.

Reboot, OOM, severe memory pressure, new kernel error, or cleanup failure does
not become a performance loss for the active candidate. It invalidates and
postpones the entire host block, stops further use of that host for the
session, and remains in the evidence record.

The screened set includes:

- frozen synchronous GSO3 control;
- coalesced reads only;
- connected native Linux send only;
- the combined implementation;
- the combined implementation at GSO `1, 2, 3, 4, 6, 8, 12`;
- a fresh QUIC control; and
- synchronous zero-copy only when its profile gate opens.

The recent exact one-owner and two-owner io_uring artifacts remain indexed as
rejected evidence. Historical lane, GRO, and other results may support the
record only when their artifact identity and conditions are sufficiently
comparable; otherwise they receive one bounded fresh diagnostic rather than
being silently treated as current evidence.

### Balanced finalist comparison

Every candidate that survives reverse-direction screening receives three
capacity-valid preliminary 1 GiB samples in each direction. The reverse block
runs first. The manifest fixes a three-block rotation of candidate order before
execution so each candidate runs once early, once in the middle, and once late
in each direction. This rule applies to QUIC as well as bulk and supplies
QUIC's three-run preliminary medians.

The frozen control and every candidate whose preliminary raw or normalized
median is within 5 percent of the leader in either direction advance. The same
is true when its minimum-direction median is within 5 percent of the strongest
minimum-direction result. At least the two strongest healthy candidates
advance even when those rules would select only one. With exactly three
finalists, `A`, `B`, and `C` run in each direction using:

```text
A B C
C B A
B C A
```

This adds three samples to the three preliminary samples, yielding six per
configuration while balancing early, middle, and late path conditions. With
more than three finalists, the manifest uses a deterministic balanced Latin
rotation of three additional samples per configuration and still gives every
configuration six total samples with balanced position counts.

A screened candidate outside the finalist set is a closed non-peak result only
when both its raw and normalized preliminary medians are more than 5 percent
below the leader. Otherwise it joins the finalists. The peak decision therefore
has replicated evidence for every candidate not already eliminated by the
strict 10 percent bracketed-screen rule.

Before every file transfer, run a 20-second, eight-flow same-direction TCP
control. Capacity at or above 2.05 Gbps authorizes the file transfer. Capacity
below 2.05 Gbps does not start a transfer and may be retried at most three
times. Three failed controls postpone the whole block.

Once a capacity-valid transfer starts, its result remains in the record. No
throughput outlier, failed transfer, or inconvenient sample is replaced.
Integrity, route, transport, trace, resource-evidence, CPU-limit, and
engine-specific recovery failures are candidate failures rather than noise.
Reboot, OOM, host pressure, kernel error, or cleanup failure invalidates and
postpones the host block, stops further testing on that host for the session,
and never ranks the active candidate.

Report raw goodput and goodput divided by same-run TCP capacity, including
mean, median, minimum, maximum, population standard deviation, coefficient of
variation, nearest-time comparisons, and bootstrap confidence intervals. A
finalist requires coefficient of variation at or below 0.10 for raw and
normalized goodput.

If capacity CV exceeds 0.10, one complete balanced schedule may run again
after full cleanup. Preserve both schedules and require the pooled evidence to
retain the same selection.

## Operational Definition of Peak

A candidate's bottleneck score is the lower of its two direction medians.
Pairwise samples are matched independently per direction within the same
balanced schedule block by minimum timestamp distance without reuse; a tie in
distance chooses the earlier sample. A paired win requires both raw and
capacity-normalized goodput to exceed the opponent for that match.

Candidate `X` materially beats candidate `Y` when:

- its raw and capacity-normalized bottleneck scores both improve by more than
  3 percent over `Y`;
- neither direction's raw nor normalized median regresses by more than 3
  percent;
- it wins at least four of six nearest-time comparisons in each direction;
  and
- every correctness, route, transport, selected-engine recovery, CPU, health,
  and cleanup gate passes.

For more than two finalists, build the complete directed pairwise result graph,
with an edge from `X` to `Y` when `X` materially beats `Y`. Collapse strongly
connected components, then define the peak-equivalent frontier as every member
of every component with no incoming edge in the resulting acyclic graph. An
unbeaten candidate is therefore a one-member frontier component, while a
non-transitive cycle remains a nonempty frontier component instead of erasing
all candidates. Retain the frontier member with the highest raw bottleneck
score, then highest normalized bottleneck score, then lowest maximum
Hetzner-role CPU seconds per GiB, then lower engine-specific recovery ratio,
then higher wall goodput. The manifest computes this rule mechanically.

This proves the fastest stable bidirectional configuration in the predeclared
candidate space on this exact VM and path. It does not claim that no imaginable
future algorithm could improve it.

## Fresh 1 GiB Production Gate

Build the selected winner cleanly with the production default and no
experimental transport override. Run three fresh capacity-valid 1 GiB normal
files in each direction. Every sample must:

- exceed 2.0 Gbps receiver-anchored verified-file goodput;
- use public UDP and account every committed payload byte to QUIC or custom
  bulk;
- have exact size and SHA-256;
- contain zero TCP, TLS, or relay payload;
- keep payload flatline below one second;
- for bulk, keep repair below 2 percent and scan work below 2.0 checks per
  packet, with valid probe, batch, and GSO evidence;
- for QUIC, keep recovery ratio below 2 percent, report valid handshake, RTT,
  loss, stream, backend, and close evidence, and have no non-normal close;
- keep the Hetzner-role CPU below 8.0 seconds per GiB;
- keep direction CV at or below 0.10;
- preserve exactly two Hetzner CPUs and unchanged OOM state; and
- provide complete traces, resources, health evidence, and zero leaks.

No 3 GiB transfer starts unless all six fresh samples pass.

If Hetzner-to-Mac crosses 2.0 Gbps but Mac-to-Hetzner does not, the work does
not declare the overall limit. It captures a fresh Linux receiver profile and
begins a separately reviewed bounded receive-side optimization design.

## Reachable Fleet Guard

Before the campaign, bind the canonical test-host inventory into the immutable
manifest from the checked-in inventory plus the explicitly supplied benchmark
host list. Probe every member without installing or changing anything. A host
that fails SSH or prerequisites at the initial probe and one bounded recheck is
recorded as unavailable; it cannot be silently omitted or later counted as a
tested host. Every host available at either probe is mandatory for the guard.

After the selected winner completes the fresh Hetzner 1 GiB health gates, run
three unoverridden 1 GiB normal files in both directions on every mandatory
host. A mandatory host that becomes unavailable postpones the guard rather
than being skipped. The acceptance path requires all six Hetzner samples to
exceed 2.0 Gbps before this guard; a hard-ceiling path may run the fleet guard
after peak selection, but still cannot start a 3 GiB transfer.

Lower-capacity hosts are judged against same-run capacity and their stable
behavior, not the Hetzner 2.0-Gbps threshold. Every cell still requires exact
integrity, intended UDP or compatible fallback mode, bounded selected-engine
recovery and CPU, no flatline, complete trace/resource evidence, and no leak or
host failure.

Eric runs last, one sample at a time. Record boot ID, uptime, OOM counters,
memory, swap, disk, interface drops, kernel deltas, and processes before,
during, and after each sample. SSH disappearance, reboot, OOM, severe memory
pressure, kernel error, or cleanup failure stops Eric for the session and is
not retried after a restart.

## Final 3 GiB Acceptance

After the reachable fleet guard passes, run exactly three normal-file
transfers in each direction. Every transfer gets its own qualifying
same-direction TCP capacity control, but TCP never counts toward payload
performance.

Every one of the six UDP file samples must satisfy the fresh 1 GiB production
gates and exceed 2.0 Gbps. A capacity-valid failed sample fails acceptance and
is not replaced. Direction CV must remain at or below 0.10.

### Disk-safe ordering

The current harness can require roughly 6.5 GiB remotely, while recent evidence
recorded only about 5.76 GB free. The final sequence therefore avoids staging a
separate remote source:

1. Run the three Mac-to-Hetzner transfers. Remove verified remote outputs from
   runs one and two.
2. Retain run three's verified remote output as the Hetzner-to-Mac source.
3. Run three Hetzner-to-Mac transfers from that source, removing each verified
   local receive output after its evidence is recorded.
4. Cleanup removes only the exact harness-owned remote source and scoped
   directory.

Remote peak data stays near one 3 GiB file plus binaries, logs, and margin.

## Hard-Ceiling Decision

If the selected candidate cannot satisfy the fresh 1 GiB greater-than-2.0-Gbps
gate, do not run 3 GiB acceptance. Retain every capacity-valid sample from the
three-run production gate even though it missed the throughput threshold.
Together with the six finalist samples, this produces nine capacity-valid
1 GiB winner samples per direction.

Run a diagnostic public-UDP iperf sweep with 1,400-byte datagrams at 1.2, 1.5,
1.8, 2.1, and 2.4 Gbps once ascending and once descending. Qualifying TCP
controls bracket the sweep. UDP iperf remains diagnostic and never satisfies
file acceptance.

A hard-ceiling conclusion requires all of the following:

- TCP independently demonstrates at least 2.05 Gbps in both directions.
- Across both sweeps, at least 20 percent more offered UDP load produces no
  more than 3 percent additional delivered goodput while loss or queue pressure
  rises.
- Hetzner-role CPU or kernel packet-processing evidence saturates at the
  plateau.
- Repeated profiles and transport counters identify the same limiting
  mechanism.
- Every predeclared candidate has exact passed or rejected evidence.
- No candidate beats the retained winner outside the 3 percent
  peak-equivalent frontier.
- The retained configuration has nine stable, capacity-valid, integrity- and
  route-verified 1 GiB samples per direction with CV at or below 0.10 and no
  host instability.

The conclusion reports the measured ceiling band and mechanism. It explicitly
states that the six-run 3 GiB acceptance target was not achieved.

## Artifact Contract

The final artifact root contains:

- `manifest.json` with immutable experiment identity and rules;
- a candidate registry with commit, binary hash, configuration, and outcome;
- every raw capacity and file result, including failed controls and failed
  candidates;
- normalized `results.csv` with raw and capacity-normalized rates;
- sender and receiver profiles and resource JSON;
- trace, log, route, selected-engine transport and recovery, health, and
  cleanup evidence;
- no retained multi-gigabyte payload; and
- atomically written `decision.json` stating either exact six-run acceptance or
  the measured hard ceiling, peak-equivalent frontier, limiting mechanism, and
  failed acceptance requirement.

## Test Strategy

Implementation follows red-green-refactor with focused tests before production
changes.

### Coalesced reads

- A full sixteen-group slab performs exactly one source read.
- Partial final slabs and nonzero group starts use exact ranges.
- Short reads, EOF, read failures, and pre-read cancellation propagate.
- Wire output and payload accounting match the current implementation.

### Connected Linux writer

- IPv4 and IPv6 connect and binary `getpeername` validation.
- Invalid or mismatched peers reject fixed-peer mode.
- One unconnected control socket continues to carry hello, ACK, repair, and
  completion traffic.
- Raw non-GSO and GSO `2, 3, 4, 6, 8, 12`, including odd groups and final short
  datagrams.
- Partial sendmmsg completion, `EAGAIN`, `ENOBUFS`, deadline, cancellation,
  zero progress, and exact retry position.
- Correct fallback before and after connection.
- Actual syscall telemetry increments inside the raw callback.
- Message, iovec, control, and slab lifetime remains valid under
  `GODEBUG=checkptr=2` or equivalent coverage.

### Harness and decision

- 1 GiB proof is required and binary-bound before 3 GiB.
- File payload and framing counters are independently exact.
- Selected public addresses, UDP carrier, engine, and zero relay/TCP payload
  are mandatory.
- Missing telemetry, SHA, resources, or health evidence rejects a sample.
- Low capacity never starts a transfer and three failures postpone a block.
- No post-start outlier replacement.
- Disk-safe source reuse and exact cleanup preserve hashes without payloads.
- Boot, OOM, memory, kernel, network, leak, and cleanup failures invalidate and
  postpone the host block; they never rank or reject the active candidate.
- Peak-frontier and hard-ceiling decisions are deterministic fixtures.

Run focused package and script tests, Linux cross-build tests, race/checkptr
coverage where applicable, full `mise run check`, local smoke, and independent
review before any live candidate matrix.

## Completion

The acceptance objective completes only when current artifacts prove:

- exactly three accepted 3 GiB public-UDP normal-file transfers per direction,
  every run above 2.0 Gbps with exact carrier and payload accounting on the
  two-vCPU Hetzner VM.

The investigation may terminate with the full hard-ceiling evidence contract
and the retained fastest stable implementation, but that outcome explicitly
marks the acceptance objective unmet. It must not be reported or recorded as
goal completion.

No average, peak screenshot, TCP result, framed stream, missing field, or
historical intention substitutes for those artifacts.
