# Multipath QUIC (MP-QUIC) in mp-quic-go

This document is the authoritative reference for the multipath implementation in `github.com/AeonDave/mp-quic-go`:

- What is implemented (features and non-goals)
- How multipath is negotiated and wired
- How the scheduler, congestion control, duplication and reinjection interact
- How paths are created, validated and managed
- How to integrate custom logic safely

For usage snippets, see `docs/MULTIPATH_EXAMPLES.md`.

## Goals

- Preserve standard QUIC behavior when multipath is disabled (drop-in replacement for upstream quic-go).
- Keep the wire format RFC 9000-compliant (no PathID in the QUIC header).
- Provide production-grade multipath primitives: per-path packet numbers, per-path ACK/RTT, per-path CC, scheduling, path management, duplication and reinjection.

## Non-goals / intentional deviations

- No on-wire PathID in the QUIC short header (keeps RFC 9000 header format).
- No mandatory address advertisement: announcing additional local addresses is opt-in to avoid accidental IP disclosure.

## Feature overview

### Multipath core

- Negotiation via transport parameters (opt-in).
- Multipath controller API: `Config.MultipathController`.
- Internal PathID propagation end-to-end (packer → sent packet handler → ACK/loss events → observers).
- Datagram support (RFC 9221) remains fully available; multipath only influences *which path* a packet is sent on.

### Scheduling

- Pluggable schedulers operating on per-path metrics.
- Implemented schedulers:
  - Round-robin
  - Low-latency (RTT + load aware)
  - MinRTT (bias-based selection)
- Congestion-aware scheduler input: `PathSelectionContext.BytesInFlight`.

### Per-path packet numbers (MP-QUIC “pure”)

- Independent packet number generators per path and encryption level.
- ACK/loss tracking associated with a PathID, allowing independent per-path recovery behavior.

### Per-path congestion control (OLIA)

- OLIA coupled congestion control with shared state across paths, while maintaining per-path CWND / RTT / loss reaction.

### Packet duplication

- Policy-driven duplication during packet packing.
- Duplicates sent on alternative paths with safe buffer cloning.

### Packet reinjection

- Loss-driven reinjection on alternative paths.
- Policy controls: delay, max reinjections, preferred targets.
- Burst protection: per-path queue limits and per-path minimum reinjection interval (backoff).
- Custom reinjection target selection hook: implement `SelectReinjectionTarget(ReinjectionTargetContext) (PathID, bool)` on your controller.

### Auto-path creation and auto-advertising (opt-in)

- `Config.MultipathAutoPaths`: create additional paths automatically post-handshake.
- `Config.MultipathAutoAdvertise`: send `ADD_ADDRESS` frames for additional local IPs.
- `Config.MultipathAutoAddrs`: optional explicit list; if not set, addresses are discovered from interfaces (or a `MultiSocketManager` if used).

### Multi-socket manager (optional)

`MultiSocketManager` provides a `net.PacketConn` that can send from multiple local IPs and handle interface changes. It enables true multi-homing by selecting a local source address per packet (via packet info).

## Architecture

### Component composition

```
Conn
  ├─ MultipathController (application-facing policy + mapping)
  ├─ packetPacker.SelectPath()        → Scheduler selects a path
  ├─ shortHeaderPacket.PathID         → Tag packet with PathID
  ├─ sentPacketHandler (per-path PN)  → Track PN / bytes-in-flight / RTT per path
  ├─ PacketObserver fanout
  │    ├─ ReinjectionObserver         → builds reinjection candidates from loss events
  │    └─ MultipathControllerObserver → forwards ACK/loss/sent events to controller
  └─ sendConn / MultiSocketManager    → (optional) pick local source address per send
```

### Data flow: path selection, ACK/loss feedback

```
User configures MultipathController
         ↓
Conn.multipathController
         ↓
packetPacker.SelectPath()            (scheduler/controller decision)
         ↓
shortHeaderPacket.PathID             (packet tagged)
         ↓
sentPacketHandler.SentPacket(pathID) (per-path PN / CC / bytes-in-flight)
         ↓
ACK/loss events emitted with PathID
         ↓
multipath observers
         ↓
controller updates: OLIA / scheduler / failure detection / stats
```

### Data flow: duplication and reinjection

```
packet packing
  ├─ duplication policy check
  │    └─ clone packet buffer, send duplicate on alternative path
  └─ normal send

loss detection
  └─ reinjection manager queues retransmission on alternative path
       (delay + per-path limits + backoff)
```

## Protocol and wire format

- Standard QUIC packets remain RFC 9000 compliant.
- Multipath extension frames are supported and only parsed when multipath is enabled:
  - `ADD_ADDRESS` (0x40)
  - `PATHS` (0x41)
  - `CLOSE_PATH` (0x42)

## Path ID model

This implementation intentionally keeps the QUIC header unchanged. `PathID` is an internal label used to associate:

- sending decisions (which remote/local address pair to use),
- per-path packet numbers / RTT / congestion control state, and
- ACK/loss feedback.

Incoming packets are mapped to a `PathID` using the controller-provided mapping:

- `PathIDForPacket(remoteAddr, localAddr net.Addr) (PathID, bool)`

## Enabling multipath

Multipath activates only when:

1) You configure `Config.MultipathController`, and
2) The peer advertises multipath support via transport parameters.

If negotiation fails or the peer is non-multipath, the connection stays standard single-path QUIC.

## Controller integration: optional hooks

The controller surface is intentionally small (`SelectPath` + `PathIDForPacket`). Additional behavior is enabled by implementing optional methods:

- Path lifecycle / management:
  - `RegisterPath(PathInfo)` (called for the primary path)
  - `AddPath(PathInfo) (PathID, bool)` (used by auto-path creation when available)
  - `ValidatePath(PathID)` (used to mark newly created paths as active)
  - `HandleAddAddressFrame(*wire.AddAddressFrame)` (to react to peer advertisements)
- Feedback / metrics:
  - `UpdatePathState(PathID, PathStateUpdate)` (RTT, validation, failure hints)
  - `OnPacketSent(PathID, ByteCount)`, `OnPacketAcked(PathID)`, `OnPacketLost(PathID)`

### Scheduling input

`SelectPath` receives a `PathSelectionContext` that includes:

- `AckOnly`: when the connection is only trying to send ACKs (no application data),
- `HasRetransmission`: when retransmissions are pending,
- `BytesInFlight`: a congestion-aware hint (populated from the sent packet handler).

### Path failure detection → `PotentiallyFailed`

If your controller implements `UpdatePathState`, the connection will conservatively infer path failures and set `PathStateUpdate.PotentiallyFailed`:

- `timeout = max(500ms, 4×smoothedRTT)`
- if we keep sending on a path but no ACK arrives beyond the timeout, the path becomes “potentially failed”
- any ACK on that path clears the flag

Schedulers treat `PotentiallyFailed` as a strong negative signal (skip path).

## Operational notes

### Security: address advertisement

`ADD_ADDRESS` may reveal additional local IPs. Therefore:

- auto-advertising is opt-in (`MultipathAutoAdvertise`)
- you can restrict to an explicit allowlist (`MultipathAutoAddrs`)

### Performance

- In single-path mode, overhead is negligible.
- Scheduling is O(number of active paths), typically small.
- Per-path PN/RTT/CC are constant-time lookups.

## Examples

See `docs/MULTIPATH_EXAMPLES.md` for practical client/server configuration, schedulers, duplication, reinjection, auto-paths and multi-socket setups.
