# Multipath QUIC in mp-quic-go

mp-quic-go implements Multipath QUIC as specified in
[draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21).
The draft is in the RFC Editor queue, and IANA registered its code points permanently.
This document describes how the extension is negotiated and used, the public API, and the decisions taken where
the draft leaves a choice (SHOULD and MAY). For usage examples, see [MULTIPATH_EXAMPLES.md](MULTIPATH_EXAMPLES.md)
and [example/multipath](../example/multipath). [COMPLIANCE.md](COMPLIANCE.md#draft-ietf-quic-multipath-21-multipath-extension-for-quic)
maps every MUST statement of the draft to the code and the tests.

## Negotiation

Multipath is opt-in. A connection advertises the `initial_max_path_id` transport parameter if a multipath controller
is configured (`Config.MultipathController` or `Config.MultipathControllerFactory`). If both endpoints advertise it,
the connection uses multipath once the handshake completes. Otherwise it is a standard QUIC connection: no frame,
transport parameter value or packet protection detail of the extension is used, and the connection behaves like a
quic-go connection.

| Code point | Name | Kind |
|---|---|---|
| `0x3e` | `initial_max_path_id` | transport parameter |
| `0x3e`, `0x3f` | `PATH_ACK`, `PATH_ACK_ECN` | frame |
| `0x3e75` | `PATH_ABANDON` | frame |
| `0x3e76`, `0x3e77` | `PATH_STATUS_BACKUP`, `PATH_STATUS_AVAILABLE` | frame |
| `0x3e78`, `0x3e79` | `PATH_NEW_CONNECTION_ID`, `PATH_RETIRE_CONNECTION_ID` | frame |
| `0x3e7a` | `MAX_PATH_ID` | frame |
| `0x3e7b`, `0x3e7c` | `PATHS_BLOCKED`, `PATH_CIDS_BLOCKED` | frame |
| `0x3e` | `APPLICATION_ABANDON_PATH` | transport error code (`quic.ApplicationAbandonPath`) |
| `0x3e75` | `PATH_RESOURCE_LIMIT_REACHED` | transport error code (`quic.PathResourceLimitReached`) |
| `0x3e76` | `PATH_UNSTABLE_OR_POOR` | transport error code (`quic.PathUnstableOrPoor`) |
| `0x3e77` | `NO_CID_AVAILABLE_FOR_PATH` | transport error code (`quic.NoCIDAvailableForPath`) |

- `initial_max_path_id` is `Config.MaxPaths - 1`. `MaxPaths` is the number of paths that can be in use at the same
  time, including the path of the handshake. It defaults to 3, and values above 64 are reduced to 64.
- The extension needs connection IDs with a non-zero length on both sides (section 2.1 of the draft).
  `quic.Dial` and `quic.DialAddr` use 4-byte connection IDs when a controller is configured. A connection that would
  use zero-length connection IDs doesn't advertise the extension.
- A peer advertising a value above 2^32-1 causes a TRANSPORT_PARAMETER_ERROR, and a peer advertising the parameter
  with a zero-length connection ID a PROTOCOL_VIOLATION. Without a controller, the parameter is ignored, like any
  unknown transport parameter.
- The parameter is not remembered for 0-RTT. 0-RTT data is sent on path 0, and multipath is negotiated again on
  every connection.
- The frames of the extension are only accepted in 1-RTT packets, and only if both endpoints advertised the
  extension. They are only sent after the handshake completed.
- Versions of this module before IETF Multipath QUIC was implemented (v0.1.x and v0.2.x, up to v0.2.3) used an
  incompatible multipath protocol of their own (transport parameter `0x1f0f9c0d2b`, or `0x1f0f9c0d2a` for v0.1.x).
  This version ignores that transport parameter, and these versions ignore `initial_max_path_id`, so connections
  between them fall back to a single path, using standard QUIC (see the [changelog](../CHANGELOG.md)).

`ConnectionState.SupportsMultipath` reports if a connection uses the extension.

## Paths

### Path IDs and connection IDs

- Path 0 is the path of the handshake. Without multipath, it is the only path, and all code paths are those of
  quic-go.
- Path IDs are shared by both endpoints, and they are never reused. Only the client opens paths. The client uses
  the smallest unused path ID that both endpoints issued a connection ID for.
- The path of a 1-RTT packet is identified by its destination connection ID. Every path ID has its own connection
  ID sequence. Once the extension is active, the endpoints issue connection IDs with `PATH_NEW_CONNECTION_ID`
  frames for every unused path ID up to the maximum of both endpoints, so that the client can open paths without
  waiting.
- When a path is closed, the endpoint raises its maximum path ID with a `MAX_PATH_ID` frame, so that `MaxPaths`
  paths can be used again.

### Packet protection

All paths use the 1-RTT keys of the connection. The nonce of a packet combines the path ID and the packet number
(section 2.4 of the draft), so packet numbers can be reused on different paths without reusing a nonce.
mp-quic-go creates an AEAD instance per path, from the IV XORed with the path ID, and keeps using the packet number
as the per-packet part of the nonce. The nonce of path 0 is the nonce of RFC 9001. This works in FIPS 140-3 mode,
see [FIPS140.md](../FIPS140.md).

- The key phase is shared by all paths. The AEAD confidentiality and integrity limits count the packets of all
  paths.
- After a key update was confirmed, the next key update waits for 3 times the largest PTO of all paths
  (section 2.5 of the draft), unless the confidentiality limit requires it earlier.
- Receivers choose the keys of a packet per path. If a packet needs the previous keys although a packet with a lower
  packet number on the same path was decrypted with the current keys, the connection is closed with a
  KEY_UPDATE_ERROR (RFC 9001, section 6.4).

### Opening and validating paths

The client opens a path with `Conn.AddPath(*Transport)` (sending from another socket) or
`Conn.AddPathFromAddr(local, remote net.Addr)` (sending from another local address of the connection's socket, using
the packet info; `remote` nil means the server address of path 0), followed by `Path.Probe(ctx)`.

- `Probe` assigns a path ID, sends a `PATH_CHALLENGE` on the new path and returns once the path was validated.
  If no path ID can be used, the client sends `PATHS_BLOCKED` (limited by the server's maximum) or
  `PATH_CIDS_BLOCKED` (no connection ID from the server), and `Probe` waits. The server might never raise its
  maximum, so the context passed to `Probe` should have a deadline. If `MaxPaths` paths are in use,
  `Probe` returns `quic.ErrTooManyPaths`, unless an abandoned path is about to be closed.
- `PATH_CHALLENGE` frames are sent in datagrams of at least 1200 bytes, so validation also checks the path MTU
  (section 3.1 of the draft). They are retransmitted with exponential backoff. If a path isn't validated within
  3 times the PTO (RFC 9000, section 8.2.4), it is abandoned with `PATH_UNSTABLE_OR_POOR`, or with `NO_CID_AVAILABLE_FOR_PATH` if the
  server never provided a connection ID for it.
- The server creates the path when it receives the first packet that decrypts. It validates the client's address
  itself, and until then sends at most 3 times the data received on the path.
- Until a path is validated, only the frames that validate it, acknowledgments and path management frames are sent
  on it.
- If the server sent `disable_active_migration`, the client doesn't open paths to the server's handshake address:
  `AddPath` and `AddPathFromAddr` return an error. Paths to other addresses of the server, for example its preferred
  address, are allowed (section 2.2 of the draft).

### Path status and scheduling

`Path.SetStatus(quic.PathStatusBackup)` marks a path as a backup path, and signals it to the peer with
`PATH_STATUS_BACKUP`. Data is only sent on a backup path (marked by either endpoint) if no other path can be used.
`Conn.SetPathStatus(id, status)` does the same for paths that have no `Path`: path 0, paths opened by
`MultipathAutoPaths`, and, on the server, the paths opened by the client.
`Path.Switch()` makes a path the preferred path: while it can be used, data is only sent on that path.

### Abandoning and closing paths

`Path.Close()` abandons a path with `PATH_ABANDON` and the error code `APPLICATION_ABANDON_PATH`.
`Conn.ClosePath(id)` does the same for paths that have no `Path`: path 0, paths opened by `MultipathAutoPaths`, and,
on the server, the paths opened by the client. The last path that can be used can't be closed: close the connection
instead.

- An abandoned path sends no more packets. Its outstanding packets are declared lost, and their frames are
  retransmitted on other paths. Packets received on it are still acknowledged, with `PATH_ACK` frames sent on other
  paths.
- The path's state is kept for 3 times the largest PTO after both endpoints sent `PATH_ABANDON`. Then the path is
  closed, and its path ID can't be used again.
- If the peer abandons the only open path, the connection is closed with `NO_VIABLE_PATH`.

### Migration and server addresses

- Each path migrates on its own (RFC 9000, section 9, applied per path). When the server receives a non-probing
  packet from a new 4-tuple on a path, it validates that 4-tuple with a connection ID of the same path, and then
  moves the path to it. The congestion controller, RTT estimate, MTU discovery and ECN validation of that path start
  again. The server validates the previous 4-tuple as well (RFC 9000, section 9.3.3).
- The client doesn't migrate individual paths: it opens a new path and abandons the old one (section 5.1 of the
  draft). It discards packets on a path that come from another server address than the path's.
- The exception is the server's preferred address (section 2.2 of the draft): the connection ID of the
  `preferred_address` transport parameter belongs to path 0, and path 0 migrates to the preferred address once the
  client validated it. The server doesn't validate the previous 4-tuple of path 0, and drops packets received on it.
  The paths of `MultipathAutoPaths` are opened once the validation completed. See
  [PREFERRED_ADDRESS.md](PREFERRED_ADDRESS.md).
- After validating a new client address, the server sends a `NEW_TOKEN` frame. Tokens are valid for up to 4 of the
  client addresses that the server validated on the connection (section 3.1.3 of the draft).

### Closing the connection

The closing and draining periods last 3 times the largest PTO of all paths. The `CONNECTION_CLOSE` frame is sent on
the path that the last packet was received on. In the closing state, packets received on another path that can be
used are answered with a `CONNECTION_CLOSE` on that path.

## Loss recovery and congestion control

- Every path has its own packet number space, RTT estimate, congestion controller (with pacing), loss detection,
  PTO and ECN validation (RFC 9002 applied per path). The limit on the number of tracked packets applies per path.
- Once the extension is active, 1-RTT packets are acknowledged with `PATH_ACK` frames, for path 0 as well. They are
  sent on the acknowledged path if it can be used, and on another path otherwise.
- `MultipathCongestionControlReno` (the default) uses an uncoupled controller per path: the Reno controller that
  quic-go uses for single-path connections, with slow start, an increase of one datagram per window in congestion
  avoidance, a multiplicative decrease of 0.7 (as in CUBIC), and pacing.
  `MultipathCongestionControlOLIA` couples the controllers of the paths (OLIA). The OLIA controller of path 0
  continues with the state of the controller used during the handshake.
- Persistent congestion (section 7.6 of RFC 9002) is established per path, from the packets sent on the path and
  its RTT estimate, and reduces the congestion window of that path only (see [LOSS_RECOVERY.md](LOSS_RECOVERY.md)).
- Path MTU discovery runs per path. The maximum DATAGRAM frame size is the minimum over all active paths.
- Generic segmentation offload (GSO) is only used while a single path can be used.
- A path is potentially failed if no acknowledgment arrived for a packet sent longer than
  `max(500ms, 4 x smoothed RTT)` ago. Data moves to the other paths. If all available paths potentially failed and a
  backup path works, the endpoint signals the failed paths as backup paths (section 3.3 of the draft), and as
  available once they recover. While another path works, the outstanding packets of a potentially failed path are
  declared lost and retransmitted elsewhere.

## Controllers and the multipath API

The connection opens, validates, schedules and abandons the paths. A `MultipathController` selects the path of every
packet carrying data:

```go
type MultipathController interface {
	SelectPath(PathSelectionContext) (PathInfo, bool)
}
```

`PathSelectionContext.Paths` contains the paths that can send a packet now, in ascending order of their path IDs.
If the controller returns a path that is not among them, the connection selects the path itself (round robin).
A controller can implement these optional methods to be informed about the paths:

- `EnableMultipath()`: the extension became active.
- `RegisterPath(PathInfo)` and `ValidatePath(PathID)`: a path became active (path 0 when the extension becomes
  active).
- `RemovePath(PathID)`: a path was abandoned.
- `UpdatePathState(PathID, PathStateUpdate)`: a path potentially failed or recovered, and its congestion state and
  RTT changed.
- `OnPacketSent(PathID, ByteCount)`, `OnPacketAcked(PathID)` and `OnPacketLost(PathID)`, or the methods of
  `MultipathObserver`, which receive a `PathEvent` per packet. Packet numbers are per path, so identify packets by
  path ID and packet number.
- `SelectReinjectionTarget(ReinjectionTargetContext)` (`MultipathReinjectionTargetSelector`): the path that lost
  frames are retransmitted on.

The connection calls these methods from its run loop. They must not block.

Built-in controllers:

- `NewDefaultMultipathController(scheduler)` with `NewRoundRobinScheduler()`, `NewLowLatencyScheduler()` or
  `NewMinRTTScheduler(bias)`. `GetStatistics` returns the statistics of the active paths.
- `NewMultipathScheduler(policy)`, a controller for a `SchedulingPolicy`.

A controller keeps per-connection state, so `Config.MultipathController` is used by one connection at a time.
If it is already in use, the built-in controllers are cloned (without their state), and multipath is disabled for
other controllers. Servers should use `Config.MultipathControllerFactory`. `Conn.MultipathController()` returns the
controller of a connection.

Other API:

- `Conn.Paths()` returns the paths with their state (`PathStateValidating`, `PathStateActive`,
  `PathStateAbandoned`), the local status and the status signaled by the peer.
- `Path.ID()` returns the path ID once the path was opened.
- `Config.MultipathAutoPaths` makes a client open a path from every other local address of the address family of
  the server address, up to `MaxPaths` paths. `Config.MultipathAutoAddrs` overrides the local addresses.
  This needs a socket bound to an unspecified address, or a `MultiSocketManager`. With the address advertisement
  extension, it also opens paths to the addresses advertised by the server (see below).
- `MultiSocketManager` is a `net.PacketConn` that sends from one of several sockets, selected by the local address of
  the packet. Paths opened with `AddPathFromAddr` use it.
- `MultipathDuplicationPolicy` copies selected frames (STREAM data of selected streams, CRYPTO, RESET_STREAM) into a
  packet on other paths after a packet was sent. Copies are never retransmitted; the receiver discards duplicate
  stream data.
- `MultipathReinjectionPolicy` selects the path that lost frames are retransmitted on. With `SetReinjectOnPTO`, the
  frames of a path whose PTO expired are also sent on another path.

## qlog

qlog traces contain the frames of the extension (`path_ack`, `path_abandon`, `path_status_backup`,
`path_status_available`, `path_new_connection_id`, `path_retire_connection_id`, `max_path_id`, `paths_blocked`,
`path_cids_blocked`). Once the extension is active, the headers of 1-RTT packets carry the `path_id`.
ADD_ADDRESS frames are logged as `add_address` frames, and the `add_address` transport parameter as
`"add_address": true`.
Congestion control, ECN and metrics events describe path 0.

## Tests and interoperability

- `integrationtests/self/multipath_test.go` and `multipath_linux_test.go` use the public API over UDP: two paths (on
  Linux from 127.0.0.1 and 127.0.0.2) transfer data in both directions with 5% packet loss per path and direction;
  more than 100,000 packets per direction with key updates; abandoning a path and opening a new one (path ID 2);
  abandoning path 0; NAT rebinding of one path. `TestMultipathSinglePathInterop` checks that an endpoint with a
  multipath controller and one without use standard QUIC (transfer, key updates, connection migration, 0-RTT).
- `integrationtests/upstream` (a separate module) runs endpoints with a multipath controller against upstream
  quic-go v0.63.0 in both roles: handshake, 0-RTT, transfer with key updates, datagrams and HTTP/3.
- `integrationtests/fips` transfers data over two paths with and without FIPS 140-3 mode.
- `interop/multipath` runs against picoquic in Docker (build tag `picoquic`), in both roles, with and without
  multipath. Its [README](../interop/multipath/README.md) lists the results and the picoquic issues found.
- [COMPLIANCE.md](COMPLIANCE.md#conformance-tests) contains the results of further interop runs with picoquic
  (scenarios for path status, abandonment, path limits and migration, and runs against picoquic's public server).
- Interoperability with peers running v0.2.x: `TestMultipathPeerWithRemovedMultipathParameter` checks that the
  transport parameter of v0.2.x is ignored and the connection uses a single path.

## Decisions for SHOULD and MAY statements

The draft (and RFC 9000, RFC 9001 where the draft refers to them) leaves these choices to the implementation.

| Statement | Decision | Reason |
|---|---|---|
| Validation of a 4-tuple that was validated before (section 3.1) | Every new path is validated | One code path, and the validation also checks the path MTU |
| Sending data on a path that is being validated (section 3.1.2) | Only probing frames, acknowledgments and path status frames | No data sent into a path that might not work; the server is limited by the anti-amplification limit anyway |
| Use PATH_ACK and the PATH_* connection ID frames for path 0 (sections 2.3 and 3.2) | Followed once the extension is active | One format for all paths |
| Wait 3 x the largest PTO between key updates (section 2.5) | Followed with multipath; single-path connections keep the behavior of quic-go | The draft's rule applies to multipath connections |
| Keep the state of an abandoned path for 3 PTOs (section 3.4) | 3 x the largest PTO, from the later of PATH_ABANDON sent and received | Paths can have very different RTTs |
| Allocate path resources only after validation (section 7.1) | Partly: the packet number space, congestion controller and keys are created before, MTU discovery, ECN validation, scheduling and the controller notifications after validation | Validation packets need a packet number space; the number of paths is limited by `MaxPaths` |
| Limited by the own maximum path ID (section 3.2.1) | `ErrTooManyPaths`; MAX_PATH_ID is only sent when a path was closed | `MaxPaths` is the resource limit chosen by the application |
| Close a path whose PATH_ABANDON isn't answered (section 3.4) | Not done: the connection IDs of the path stay valid until the peer answers or the connection ends; all other state is removed after 3 x the largest PTO | Removing the connection IDs would make the endpoint send stateless resets to a peer that might still use them |
| Alternatives when the peer abandons the only path (section 3.4) | The connection is closed with NO_VIABLE_PATH | Simple and bounded |
| Bundle path status with PATH_NEW_CONNECTION_ID or PATH_RESPONSE (section 3.3) | A status set before validation is sent with the validation frames | Saves a packet |
| Ignore the peer's path status (section 3.3) | Backup status from either endpoint is honored | Backup is often chosen for cost reasons (metered links) |
| Disable active migration and peer address validation (RFC 9000, section 18.2) | A server whose client opens a path to its handshake address anyway validates the path and uses it | Allowed by RFC 9000 |
| Restart the minimum RTT when ACKs move to another path (section 5.4) | Not done | Informational in the draft |
| Per-path keep-alives (section 5.9) | Not sent; the keep-alive of the connection uses any path | The draft doesn't recommend them |
| Coupled congestion control (section 5.3) | Uncoupled Reno controllers by default, OLIA on request | Uncoupled control is what single-path QUIC does on every path |
| Retransmission path (sections 5.6 and 5.7) | Lost frames go to the next packet on any path; PTO probes go on the path whose PTO expired; the reinjection policy can choose a path | RFC 9002 per path, with an optional policy |
| Path MTU (section 5.8) | Discovered per path; DATAGRAM frames use the minimum | The draft's simple option |
| Delay PATH_RESPONSE without a connection ID for the path (section 3.1) | The server waits up to the validation timeout for a connection ID, then abandons the path with NO_CID_AVAILABLE_FOR_PATH | Bounded wait |
| Abandon persistently failing paths | Not automatic; the scheduler avoids them and their status is signaled. Write errors on a path's socket abandon the path with PATH_UNSTABLE_OR_POOR if another path is usable | Leaves the decision to the application |
| PATH_CIDS_BLOCKED when rotating connection IDs (section 3.2.1) | Only sent when opening a path is blocked | Rotation is opportunistic |
| Tokens for all validated addresses (section 3.1.3) | Followed, up to 4 addresses | Lets a client resume from another network |
| Signal backup when falling back to a backup path (section 3.3) | Followed, at most once per PTO and path | |
| Probing frequency and one PATH_CHALLENGE per packet (RFC 9000, section 8.2.1) | Followed | |
| Keep the connection ID when the peer's address changes (RFC 9000, section 9.5) | Not done: every 4-tuple of a path gets its own connection ID of that path | Avoids linking 4-tuples |
| Use of the preferred address and the initial server address at the same time (section 2.2) | The client migrates path 0 to the preferred address before it opens paths automatically, so that they go to the preferred address | The draft doesn't let clients assume that both addresses can be used together |

## Address advertisement (ADD_ADDRESS)

The address advertisement extension lets an endpoint announce its addresses, so that a client can open paths to the
addresses of a server. It is specific to this module, optional, and only used together with IETF Multipath QUIC.
Its code points are not registered with IANA. They are outside of the ranges of registered code points, and not
reserved values (31 * N + 27 for transport parameters, see section 18.1 of RFC 9000).

| Code point | Name | Kind |
|---|---|---|
| `0x1f0f9c0d40` | `add_address` | transport parameter (empty value) |
| `0x1f0f9c0d40` | `ADD_ADDRESS` | frame |

- A connection sends the `add_address` transport parameter if `Config.EnableAddressAdvertisement` is set, and only
  if it also sends `initial_max_path_id`. The extension is used if both endpoints send the parameter and IETF
  Multipath QUIC is used (`ConnectionState.SupportsAddressAdvertisement`). A parameter with a non-empty value is a
  TRANSPORT_PARAMETER_ERROR. Like `initial_max_path_id`, the parameter is not remembered for 0-RTT.
- Without the extension, the frame type is unknown, and receiving the frame is a FRAME_ENCODING_ERROR
  (section 12.4 of RFC 9000), unless a `Config.ExtensionFrameHandler` handles unknown frame types. With the extension, the frame is only sent and accepted in 1-RTT packets: receiving it
  in an Initial, Handshake or 0-RTT packet is a PROTOCOL_VIOLATION, like the frames of the multipath extension.
  0-RTT packets can be replayed.
- The frame is ack-eliciting, not a probing frame, and retransmitted when it is lost.

```
ADD_ADDRESS Frame {
  Type (i) = 0x1f0f9c0d40,
  Address ID (i),
  Sequence Number (i),
  IP Version (8),
  IP Address (32 or 128),
  Port (16),
}
```

- The IP version is 4 or 6, and determines the length of the address. Other values are a FRAME_ENCODING_ERROR.
- The Address ID identifies the address. The frame with the largest Sequence Number of an Address ID carries its
  current address; frames with a smaller or equal Sequence Number are ignored. mp-quic-go numbers the addresses it
  advertises from 0, with Sequence Number 0, and never changes the address of an Address ID.
- The receiver ignores unspecified, multicast and broadcast addresses, port 0, addresses that the peer already
  advertised with another Address ID, and loopback and link-local addresses unless the connection itself uses an
  address of the same kind. IPv4-mapped IPv6 addresses are treated as IPv4 addresses.
- Every endpoint advertises up to 16 addresses (`ErrTooManyAdvertisedAddresses`), and records up to 16 addresses of
  the peer. Further addresses are ignored.
- Only clients open paths (section 9 of RFC 9000). A client can open paths to the addresses advertised by the server,
  with `Conn.AddPathFromAddr(nil, addr)`, or automatically with `Config.MultipathAutoPaths`: a path is opened from the
  local address of path 0 to every advertised address of the address family of the server's handshake address, within
  `Config.MaxPaths`. `disable_active_migration` doesn't apply to these addresses (section 2.2 of the draft).
  A server only records the addresses advertised by the client.

API:

- `Conn.AdvertiseAddress(netip.AddrPort)` sends an ADD_ADDRESS frame, once the handshake completed. The application
  needs to make sure that the connection receives packets sent to the address, for example with a socket bound to an
  unspecified address.
- `Config.MultipathAutoAdvertise` makes a server advertise its local addresses when the handshake completes: the
  addresses in `Config.MultipathAutoAddrs`, or those of the network interfaces of the client's address family, except
  for the address the client sent its packets to. They are advertised with the port of the server's socket, which needs
  to be bound to an unspecified address (not a `MultiSocketManager`, whose sockets use different ports).
- `Conn.PeerAdvertisedAddresses()` returns the addresses advertised by the peer. A `MultipathController` implementing
  `MultipathAddressObserver` is notified about every new address on the connection's run loop.

Without `Config.EnableAddressAdvertisement` on both endpoints, nothing of the extension is sent, and connections behave
as described in the previous sections.

## Address discovery (OBSERVED_ADDRESS)

QUIC Address Discovery (draft-ietf-quic-address-discovery-01) is negotiated separately, and works with and without
IETF Multipath QUIC. With multipath, an OBSERVED_ADDRESS frame is sent on every path, together with the frames that
validate the path, and on every new 4-tuple of a path. `PathInfo.ObservedAddr` is the address that the peer reported
for a path. [ADDRESS_DISCOVERY.md](ADDRESS_DISCOVERY.md) describes the implementation.
