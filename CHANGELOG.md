# Changelog

## v0.3.0 (2026-10-08)

This version is based on [quic-go v0.63.0](https://github.com/quic-go/quic-go/releases/tag/v0.63.0).
v0.2.0 was based on quic-go 29cb6ff5, between v0.58.0 and v0.59.0. The quic-go release notes for v0.59.0 to v0.63.0
list all upstream changes. [docs/MAINTAINING.md](docs/MAINTAINING.md) describes how quic-go releases are merged.

Multipath is IETF Multipath QUIC ([draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21)).
It replaces the multipath protocol of v0.1.x and v0.2.0, which was specific to this module.
[docs/MP_QUIC_README.md](docs/MP_QUIC_README.md) describes the implementation.

### Incompatible changes

- The multipath protocol of earlier versions was removed, and the multipath wire format is incompatible with
  v0.2.x (v0.2.0 to v0.2.3) and v0.1.x. Multipath is negotiated with the `initial_max_path_id` transport parameter
  (`0x3e`) of IETF Multipath QUIC. Connections advertise neither the transport parameter of v0.2.x (`0x1f0f9c0d2b`)
  nor that of v0.1.x (`0x1f0f9c0d2a`), and ignore them when the peer sends them: peers running v0.2.x or v0.1.x
  don't negotiate multipath with this version, and connections with them fall back to a single path, using standard
  QUIC. Both peers need to be upgraded to use multipath. Session tickets of v0.2.x that remembered the transport
  parameter are not used for 0-RTT. The address advertisement extension (ADD_ADDRESS) is negotiated with its own
  transport parameter (see below), so v0.2.x peers don't use it either.
- Only the client opens paths, with `Conn.AddPath` or `Conn.AddPathFromAddr` and `Path.Probe`. The connection
  identifies the path of a packet by its connection ID, and opens, validates and abandons the paths itself:
  - `MultipathController.PathIDForPacket` was removed.
  - Controllers no longer create or validate paths. `AddPath`, `ValidatePath`, `UnvalidatedPaths`,
    `GetAvailablePaths`, `PathInfoForID`, `SetMaxPeerPaths` and `HandleAddAddressFrame` were removed from
    `DefaultMultipathController` and `PathSchedulerWrapper`. `RegisterPath`, `RemovePath`, `UpdatePathState` and the
    packet callbacks are notifications from the connection.
  - `PathStateUpdate.Validated` was removed: controllers only see validated paths.
  - `MultipathPathManager`, `MultipathPath` and `MultipathPathState` were removed. `Conn.Paths` returns the paths of
    a connection.
  - `NewMultipathScheduler` takes only the scheduling policy.
- `MultipathController.SelectPath` selects one of the paths in `PathSelectionContext.Paths`, the paths that can send
  a packet now. The built-in controllers don't select any path if it is empty.
- `MultipathCongestionControlReno` uses an uncoupled NewReno controller per path (section 5.3 of the draft). The
  connection-level controller that limited the sending rate of all paths together was removed, so a connection
  using several paths can send faster than before.
- Every path has its own packet number space. A packet is identified by `PathEvent.PathID` and
  `PathEvent.PacketNumber` together (and `PacketReinjectionInfo.OriginalPathID` and `PacketNumber`).
- Duplication copies the selected frames into separate packets on other paths, instead of sending copies of the
  same packet. The copies are never retransmitted. `DefaultMultipathController.EnablePacketDuplication`,
  `SetDuplicationParameters` and `ShouldDuplicatePacket` were removed: use `Config.MultipathDuplicationPolicy`.
- `Config.MaxPaths` is the number of paths of IETF Multipath QUIC that can be used at the same time, including the
  path of the handshake. It no longer limits the paths probed for RFC 9000 connection migration, which keeps track of
  up to 3 paths, as in quic-go.
- ADD_ADDRESS frames are only sent and processed if the address advertisement extension was negotiated with the
  `add_address` transport parameter (`0x1f0f9c0d40`), in addition to IETF Multipath QUIC (see below). v0.2.0 sent
  them whenever its multipath protocol was negotiated. `Config.MultipathAutoAdvertise` only has an effect together
  with `Config.EnableAddressAdvertisement`.
- `ConnectionState.SupportsMultipath` is true if the connection uses IETF Multipath QUIC.
- Go 1.26 or later is required.
- From quic-go: `ConnectionState.SupportsDatagrams` and `ConnectionState.SupportsStreamResetPartialDelivery` are
  structs with the fields `Remote` (the peer's support) and `Local` (enabled in the `Config`).
- From quic-go: `http3.ParseCapsule` was replaced by `http3.NewCapsuleParser`.
- From quic-go: qlog events identify datagrams by a checksum of their payload (`qlog.DatagramPayloadChecksum`)
  instead of a datagram ID.
- From quic-go: the fuzzers are native Go fuzz tests. The `fuzzing` directory was removed.
- `Conn.QueueRawFrame` rejects the frame types of IETF Multipath QUIC: `0x3e`, `0x3f` and `0x3e75` to `0x3e7c`,
  and those of QUIC Address Discovery: `0x9f81a6` and `0x9f81a7`.

### Standards compliance

[docs/COMPLIANCE.md](docs/COMPLIANCE.md) lists every MUST and MUST NOT statement of RFC 8999, 9000, 9001, 9002,
9114, 9204, 9221, 9297, 9368, 9369 and 9287, draft-ietf-quic-multipath-21, draft-ietf-quic-address-discovery-01 and
draft-ietf-quic-reliable-stream-reset-11, with the code that implements it and the tests that cover it, and the
SHOULD and MAY statements that are not followed, with the reasons. It also contains the results of the conformance
tests: the QUIC interop runner, h3spec, the multipath interop tests with picoquic, and fuzzing.

### 0-RTT replay protection

- A server accepts 0-RTT at most once for every session ticket (RFC 9001, section 9.2, and RFC 8446, section 8.1).
  Session tickets contain a random ID and the time they were issued. When a client uses a ticket for 0-RTT, the
  server records the ID in a `ZeroRTTReplayCache`, and rejects 0-RTT if the ID was recorded before: a replayed
  ClientHello, or a client that uses a ticket twice, continues with a 1-RTT handshake. quic-go v0.63.0 accepts 0-RTT
  with the same ticket any number of times.
- `NewZeroRTTReplayCache` keeps the IDs in memory. A ticket can be used for 0-RTT during a window after it was issued,
  and the IDs are kept for at least that window. The number of IDs is limited: once the limit is reached, 0-RTT is
  rejected. Tickets issued before the cache was created are not used for 0-RTT (RFC 8446, section 8.2).
- By default, the listeners of a `Transport` share a cache with a window of 24 hours (`DefaultZeroRTTReplayWindow`)
  for up to 2^20 tickets (`DefaultZeroRTTReplayCacheSize`). `Config.ZeroRTTReplayCache` sets another cache, which
  servers sharing session ticket keys, or a server that is restarted, can share.
- Session tickets issued by earlier versions are not used for resumption.
- New API: `ZeroRTTReplayCache`, `NewZeroRTTReplayCache`, `SessionTicketID`, `DefaultZeroRTTReplayWindow`,
  `DefaultZeroRTTReplayCacheSize` and `Config.ZeroRTTReplayCache`.

### IETF Multipath QUIC

- Negotiation: a connection advertises `initial_max_path_id` (`Config.MaxPaths` - 1) if a multipath controller is
  configured and connection IDs have a non-zero length. `quic.Dial` and `quic.DialAddr` use 4-byte connection IDs
  when a controller is configured. The extension becomes active when the handshake completes.
- Paths: shared path IDs, connection IDs per path (`PATH_NEW_CONNECTION_ID`, `PATH_RETIRE_CONNECTION_ID`), path
  validation with `PATH_CHALLENGE` frames in datagrams of at least 1200 bytes, the anti-amplification limit per path,
  `MAX_PATH_ID`, `PATHS_BLOCKED` and `PATH_CIDS_BLOCKED`.
- Packet protection: the nonce includes the path ID. Every path uses its own AEAD instances, which also works in
  FIPS 140-3 mode. Key updates are spaced by 3 times the largest PTO of all paths.
- Loss recovery and congestion control per path, acknowledgments with `PATH_ACK` frames, per-path ECN validation,
  MTU discovery and pacing.
- Path status (`PATH_STATUS_BACKUP`, `PATH_STATUS_AVAILABLE`) and abandonment (`PATH_ABANDON`). Paths that
  potentially failed are signaled as backup paths when the connection falls back to a backup path.
- The server migrates each path to a new client address on its own. The client discards packets on a path that come
  from another server address than the path's. Address validation tokens are valid for up to 4 client addresses
  validated on the connection.
- New API: `Conn.AddPathFromAddr`, `Conn.Paths`, `Conn.ClosePath`, `Conn.SetPathStatus`, `Path.ID`,
  `Path.SetStatus`, `PathState`, `PathStatus`, `PathInfo.State`, `PathInfo.Status`, `PathInfo.PeerStatus`,
  `PathSelectionContext.Paths`, `SchedulerPathInfo.Backup`, `MultipathReinjectionPolicy.SetReinjectOnPTO`,
  `ErrTooManyPaths`, and the transport error codes `ApplicationAbandonPath`, `PathResourceLimitReached`,
  `PathUnstableOrPoor` and `NoCIDAvailableForPath`.
- `Conn.SetPathStatus` sets the status of paths that have no `Path`, like `Conn.ClosePath` abandons them: path 0,
  the paths of `Config.MultipathAutoPaths`, and on a server, the paths opened by the client.
- `Conn.AddPath` opens a path of IETF Multipath QUIC if the extension was negotiated, and a path for RFC 9000
  connection migration otherwise. A client that advertised the extension can add a path before the handshake
  completed: `Path.Probe` waits for the handshake.
- `Path.Switch` makes a path the preferred path: data is only sent on it while it can be used.
- The OLIA congestion controller of path 0 continues with the state of the controller used during the handshake.
- `example/multipath` shows a client that opens a second path.

### Address advertisement

- The address advertisement extension of this module is optional, and negotiated separately: a connection sends the
  `add_address` transport parameter (`0x1f0f9c0d40`, empty) if `Config.EnableAddressAdvertisement` is set and it
  advertises IETF Multipath QUIC. The extension is used if both endpoints send the parameter and multipath is used.
  It is not remembered for 0-RTT. Without it, the ADD_ADDRESS frame type (`0x1f0f9c0d40`) is unknown.
- ADD_ADDRESS frames are only sent and accepted in 1-RTT packets. Receiving one in an Initial, Handshake or 0-RTT
  packet is a PROTOCOL_VIOLATION.
- `Conn.AdvertiseAddress` advertises an address, and `Config.MultipathAutoAdvertise` makes a server advertise its
  local addresses. Up to 16 addresses are advertised.
- `Conn.PeerAdvertisedAddresses` returns the addresses advertised by the peer, and a controller implementing
  `MultipathAddressObserver` is notified about them. Unspecified, multicast and broadcast addresses, port 0, and
  loopback and link-local addresses (unless the connection uses such an address) are ignored. Up to 16 addresses are
  recorded.
- Only clients open paths: a client with `Config.MultipathAutoPaths` opens a path to every address advertised by the
  server, within `Config.MaxPaths`. A server only records the addresses advertised by the client.
- New API: `Config.EnableAddressAdvertisement`, `ConnectionState.SupportsAddressAdvertisement`,
  `Conn.AdvertiseAddress`, `Conn.PeerAdvertisedAddresses`, `AdvertisedAddress`, `MultipathAddressObserver`,
  `ErrAddressAdvertisementNotNegotiated` and `ErrTooManyAdvertisedAddresses`.

### QUIC Address Discovery

- QUIC Address Discovery ([draft-ietf-quic-address-discovery-01](https://datatracker.ietf.org/doc/html/draft-ietf-quic-address-discovery-01)):
  an endpoint reports the address it observes for its peer in OBSERVED_ADDRESS frames (`0x9f81a6`, `0x9f81a7`).
  It is negotiated with the `address_discovery` transport parameter (`0x9f81a176`), with and without IETF Multipath
  QUIC. [docs/ADDRESS_DISCOVERY.md](docs/ADDRESS_DISCOVERY.md) describes the implementation.
- `Config.RequestObservedAddress` asks the peer to report this endpoint's address, `Config.ProvideObservedAddress`
  offers to report the peer's address. Without them, the transport parameter is not sent.
- A frame is sent on every path, including the path of the handshake, and on every new path of RFC 9000 connection
  migration or new 4-tuple of a path of IETF Multipath QUIC, together with the PATH_CHALLENGE that validates it.
  Frames are only sent in 1-RTT packets. A lost frame is replaced by a new frame on the same path.
- The transport parameter is remembered for 0-RTT. The server rejects 0-RTT if its value changed.
- New API: `Config.RequestObservedAddress`, `Config.ProvideObservedAddress`, `Conn.ObservedAddr`,
  `PathInfo.ObservedAddr` and `ConnectionState.SupportsAddressDiscovery`.

### Version negotiation

- Compatible version negotiation ([RFC 9368](https://datatracker.ietf.org/doc/html/rfc9368)) between QUIC version 1
  and QUIC version 2: a server can switch a connection to another version without a round trip.
  [docs/VERSION_NEGOTIATION.md](docs/VERSION_NEGOTIATION.md) describes the implementation.
- Both endpoints send the `version_information` transport parameter (`0x11`) on every connection, and validate the
  peer's to prevent version downgrade attacks, as required for endpoints supporting QUIC version 2 (section 4 of
  RFC 9369). quic-go v0.63.0 doesn't send or validate it.
- A server only switches versions if `Config.Versions` is set: it then uses the first version of `Config.Versions`
  that the client offered. Without `Config.Versions`, a server uses the version of the client's first flight, as
  before. A client offers all versions of `Config.Versions` that are compatible with the first one.
- After compatible version negotiation, `ConnectionState.Version` is the Negotiated Version.
- The Initial packet number space continues when the Initial keys change to those of the Negotiated Version: packet
  numbers are decoded relative to the largest packet number received so far. ngtcp2's client starts with a large
  random packet number, and its Initial packets using the Negotiated Version couldn't be decrypted otherwise.
- Session tickets and address validation tokens are specific to a QUIC version (section 5 of RFC 9369): the server
  doesn't resume sessions or accept tokens issued for another version, and the client stores them by version. The
  keys used with `tls.ClientSessionCache` and `TokenStore` are unchanged for QUIC version 1; for other versions, the
  version is appended. Session tickets issued by earlier versions are not used for resumption.
  quic-go v0.63.0 uses tickets and tokens across versions.
- A server selects the Negotiated Version using the Version Information of the client's first ClientHello, before
  crypto/tls processes it. If crypto/tls sends a HelloRetryRequest (for example to a client that supports a
  post-quantum key exchange, but sent a key share for X25519 only), the HelloRetryRequest is sent using the
  Negotiated Version, since the client takes the version of the packet carrying it as the Negotiated Version.
- `Config.InitialVersion` sets the version of a client's first flight, so that a client can start with version 1
  while preferring version 2: the Available Versions of its Version Information follow the order of
  `Config.Versions` (section 3 of RFC 9368).
- New API: `VersionNegotiationErrorCode`, the VERSION_NEGOTIATION_ERROR transport error code, and
  `Config.InitialVersion`.
- The interop runner endpoints support the `v2` test case.

### Loss recovery

- Persistent congestion ([RFC 9002, section 7.6](https://datatracker.ietf.org/doc/html/rfc9002#section-7.6)): when
  all packets sent over a long enough period are lost, the congestion window drops to the minimum window, and slow
  start begins again. With IETF Multipath QUIC, this happens per path. quic-go v0.63.0 doesn't implement it.
  [docs/LOSS_RECOVERY.md](docs/LOSS_RECOVERY.md) describes the implementation.
- A packet whose frames were retransmitted in a PTO probe packet stays in the sent packet history until it is
  acknowledged or declared lost, so that its loss counts for persistent congestion.
- qlog: `qlog.CongestionStateUpdated` has a `Trigger` field. The trigger `persistent_congestion`
  (`qlog.CongestionStateTriggerPersistentCongestion`) is logged when persistent congestion is established.
- `OLIACongestionControl.OnPersistentCongestion` reduces the window of an OLIA controller to the minimum window.

### Server's preferred address

- Servers send a preferred address, and clients migrate to it once the handshake is confirmed
  ([RFC 9000, section 9.6](https://datatracker.ietf.org/doc/html/rfc9000#section-9.6)). quic-go v0.63.0 neither sends
  the `preferred_address` transport parameter nor migrates to it. [docs/PREFERRED_ADDRESS.md](docs/PREFERRED_ADDRESS.md)
  describes the implementation.
- New API: `Transport.PreferredAddress` and `PreferredAddress`. The packets sent to the preferred address are received
  by the listener's socket, or by another Transport. Another Transport also knows the client's stateless reset tokens,
  and recognizes the stateless resets that the client sends to the preferred address.
- The server validates the path from its preferred address, and migrates once it received a non-probing packet on it.
  Then it drops the packets received on its original address.
- A client that can send to one of the addresses validates it, and migrates if the validation succeeds, using the
  connection ID of the transport parameter. Otherwise it keeps using the original address. With IETF Multipath QUIC,
  path 0 migrates, and the paths of `Config.MultipathAutoPaths` are opened once the validation completed.
- Once the client migrated to the preferred address, `disable_active_migration` doesn't prevent `Conn.AddPath`.
- A client closes the connection with a TRANSPORT_PARAMETER_ERROR if a server that uses a zero-length connection ID
  sends a preferred address (section 18.2 of RFC 9000). quic-go v0.63.0 accepts it.
- `Conn.LocalAddr` of a server returns the local address that the connection sends from after a migration, if it
  changed. quic-go v0.63.0 returns the address of the handshake.

### Greasing the QUIC Bit

- Greasing the QUIC Bit ([RFC 9287](https://datatracker.ietf.org/doc/html/rfc9287)), enabled with
  `Config.EnableQUICBitGreasing`: the `grease_quic_bit` transport parameter is sent, packets with the QUIC Bit set
  to 0 are accepted, and if the peer sent the transport parameter, the QUIC Bit of the packets sent is set at random.
  quic-go v0.63.0 doesn't implement it. [docs/GREASE_QUIC_BIT.md](docs/GREASE_QUIC_BIT.md) describes the
  implementation.
- New API: `Config.EnableQUICBitGreasing`, `ConnectionState.SupportsQUICBitGreasing`.
- Short header packets with the QUIC Bit set to 0 are passed to the connection their connection ID belongs to, if it
  enabled the extension, instead of being returned by `Transport.ReadNonQUICPacket`.
- qlog: `qlog.ParametersSet` has a `GreaseQUICBit` field.

### Changes from quic-go

A selection of the changes in quic-go v0.59.0 to v0.63.0:

- Stream priorities following RFC 9218: `Stream.SetPriority` and `SendStream.SetPriority`, and HTTP/3 priorities
  (the Priority header field and PRIORITY_UPDATE frames).
- Stream Resets with Partial Delivery: the codepoints of draft-09 to draft-11 are offered next to the draft-07 ones,
  see [docs/RELIABLE_STREAM_RESET.md](docs/RELIABLE_STREAM_RESET.md).
- New: `SendStream.TryWriteAll`, `SendStream.WriteWithLimit`, `ReceiveStream.SetReceiveFinalSizeCallback`,
  `http3.ClientConn.LocalAddr` and `RemoteAddr`.
- Session tickets with unknown transport parameters are not used for 0-RTT.
- Retransmissions are sent before new stream data.
- Path probe packets are sent from the local address the path uses.
- Support for FIPS 140-3 environments, see [FIPS140.md](FIPS140.md).
- HTTP/3: stricter validation of requests and their pseudo-header fields, and consistent error types returned from
  the stream APIs.

The fixes backported to v0.2.0 (quic-go #5538, #5539 and #5642) are replaced by the upstream versions.

### Fixes

- A retransmitted NEW_CONNECTION_ID frame retired the connection ID in use, or the one used on a path, once a
  connection ID had been used to probe or validate a path. The peer received the RETIRE_CONNECTION_ID frame in a
  packet sent to the retired connection ID, and closed the connection with a PROTOCOL_VIOLATION (RFC 9000,
  section 19.16). With multipath, transfers with packet loss often failed this way. A retransmitted frame for the
  connection ID used last for a path also put that connection ID back into the queue of unused connection IDs.
  quic-go v0.63.0 has the same problem when probing paths.
- Connection IDs in use on paths other than the current one didn't count towards the active_connection_id_limit.
  A peer could exceed the limit without the connection being closed with a CONNECTION_ID_LIMIT_ERROR (RFC 9000,
  section 5.1.1). quic-go v0.63.0 has the same problem.
- HTTP/3: a DATA or HEADERS frame received after the trailers made `Read` return an error, but the connection
  wasn't closed with H3_FRAME_UNEXPECTED (RFC 9114, section 4.1). quic-go v0.63.0 has the same problem.
- HTTP/3: a field section that referenced the QPACK dynamic table, used an invalid static table index or had a
  non-zero Required Insert Count only reset the stream. The connection is now closed with
  QPACK_DECOMPRESSION_FAILED (RFC 9204, sections 2.2.3, 3.1 and 4.5.1.1). A field section prefix with a negative
  Base used to be accepted, and is rejected the same way (RFC 9204, section 4.5.1.2). quic-go v0.63.0 has the
  same problem.
- HTTP/3: CANCEL_PUSH, PUSH_PROMISE and MAX_PUSH_ID frames were ignored on every stream. A control stream that
  started with one of them was accepted instead of being closed with H3_MISSING_SETTINGS (RFC 9114, section 6.2.1),
  the frames were accepted on request streams instead of being rejected with H3_FRAME_UNEXPECTED, a server accepted
  PUSH_PROMISE frames (section 7.2.5), CANCEL_PUSH frames for pushes it never promised (section 7.2.3) and a
  decreasing maximum push ID (section 7.2.7), and a client accepted MAX_PUSH_ID frames. A client now closes the
  connection with H3_ID_ERROR when it receives a PUSH_PROMISE or CANCEL_PUSH frame, since it never allows any push
  (section 4.6). A server also rejects a GOAWAY frame with a larger push ID than the previous one (section 5.2).
  GOAWAY, CANCEL_PUSH, MAX_PUSH_ID and SETTINGS frames on request streams are rejected with H3_FRAME_UNEXPECTED,
  also when they are malformed. quic-go v0.63.0 has the same problems.
- HTTP/3: SETTINGS frames containing the HTTP/2 settings 0x2 to 0x5 were accepted instead of closing the connection
  with H3_SETTINGS_ERROR (RFC 9114, section 7.2.4.1). Invalid values of SETTINGS_H3_DATAGRAM (RFC 9297,
  section 2.1.1) and SETTINGS_ENABLE_CONNECT_PROTOCOL, and duplicate settings, closed the connection with
  H3_FRAME_ERROR instead of H3_SETTINGS_ERROR. A SETTINGS frame that ended inside a setting closed it with
  H3_CLOSED_CRITICAL_STREAM instead of H3_FRAME_ERROR (RFC 9114, section 7.1). quic-go v0.63.0 has the same
  problems.
- HTTP/3: the peer's QPACK encoder and decoder streams were never read. Closing them wasn't detected
  (RFC 9204, section 4.2), and instructions that use the dynamic table, which neither endpoint allows, weren't
  rejected with QPACK_ENCODER_STREAM_ERROR or QPACK_DECODER_STREAM_ERROR (sections 3.2.2, 4.3 and 4.4).
  New API: `http3.ErrCodeQPACKEncoderStreamError` and `http3.ErrCodeQPACKDecoderStreamError`.
  quic-go v0.63.0 has the same problems.
- HTTP/3: GOAWAY, CANCEL_PUSH and MAX_PUSH_ID frames with a Length of 0 or more than 8 are rejected with
  H3_FRAME_ERROR right away. A server waited for the payload of a GOAWAY frame with a large Length.
- A server only answered the last PATH_CHALLENGE frame of a packet received on the current path, and didn't
  answer PATH_CHALLENGE frames in 0-RTT packets (RFC 9000, section 8.2.2). quic-go v0.63.0 answers neither.
- Once a server was probing the maximum of 3 paths for connection migration, it didn't answer a PATH_CHALLENGE
  received on one of these paths, or it gave up another path that hadn't received a packet for 5 seconds
  (RFC 9000, section 8.2.2). The limit now only applies to new paths. quic-go v0.63.0 has the same problem.
- Datagrams containing a PATH_RESPONSE frame were only expanded to 1200 bytes when they were sent to a new path.
  A PATH_RESPONSE sent on the current path, for example by a client after a NAT rebinding, was sent in a small
  packet (RFC 9000, section 8.2.2). A server only expands these datagrams within the anti-amplification limit.
  quic-go v0.63.0 has the same problem.
- A server sent the packets that probe a new client address (RFC 9000 connection migration) in datagrams of 1200
  bytes, whatever the size of the datagram received from that address, exceeding the anti-amplification limit for
  unvalidated addresses (RFC 9000, sections 8 and 9.3). They are now limited to 3 times the size of the datagram
  received. If the datagram containing the PATH_CHALLENGE couldn't be expanded to 1200 bytes, the server validates
  the path MTU with a second PATH_CHALLENGE once the address is validated, and only migrates after that
  (section 8.2.1). Of the PATH_CHALLENGE frames in a packet received on a new path, only the last one was answered.
  All of them are now answered, in as few probe packets as possible. For an address that was validated before,
  these packets are limited to 3 times the size of the datagram, or 1200 bytes for smaller datagrams.
  quic-go v0.63.0 has the same problems.
- After a client migrated (RFC 9000 connection migration), the server kept sending with the connection ID it had
  used towards the previous client address, so that the same connection ID was used towards two addresses
  (RFC 9000, section 9.5). It now uses the connection ID it used to validate the new path. It also didn't validate
  the previously active path (section 9.3.3), which lets a non-probing packet received on that path switch the
  connection back after an attacker forwarded packets from another address. quic-go v0.63.0 has the same problems.
- A client answered the PATH_CHALLENGE frames that the server sent on a path probed with `Conn.AddPath` on the
  active path instead of the probed path (RFC 9000, section 8.2.2). They are now answered from the path's
  `Transport`, using the path's connection ID. After switching away from the path used for the handshake, the
  PATH_CHALLENGE frames that the server sends to validate the previous path are answered from the `Transport` used
  for the handshake, using a connection ID that wasn't used on any other path. quic-go v0.63.0 has the same problem
  ([quic-go#5408](https://github.com/quic-go/quic-go/issues/5408)).
- After `Path.Switch`, the client kept sending with the connection ID used on the previous path, from the new
  local address (RFC 9000, section 9.5). It now uses the connection ID it used for probing the path, and retires
  the previous one. If no unused connection ID is available, for example when switching back to a path used
  before, the switch is delayed until the peer provides one. quic-go v0.63.0 has the same problem
  ([quic-go#5236](https://github.com/quic-go/quic-go/issues/5236)).
- A client processed packets from any address. It now discards packets from server addresses other than the one
  it dialed and the server's preferred address, once it started validating it (RFC 9000, section 9). With IETF
  Multipath QUIC, this already applied to 1-RTT packets on every path, and now also applies to long header packets.
  The check only applies to connections that report source addresses as `*net.UDPAddr` (see `Transport.Conn`).
  If the client dialed an unspecified IP address (for example the address of a listener on `0.0.0.0:1234`),
  it accepts packets from the address that the first packet it processed came from.
  quic-go v0.63.0 has the same problem.
- The ACK Delay of acknowledgments included the time that packets waited in the connection's queue of received
  packets, a delay that the endpoint doesn't control (RFC 9000, section 13.2.5). It is now measured from when the
  connection started processing the packets, so that the peer counts the queueing delay as part of the RTT.
  Packets that waited for their decryption keys still include that delay. quic-go v0.63.0 has the same problem
  ([quic-go#2693](https://github.com/quic-go/quic-go/issues/2693)).
- The peer's stateless reset tokens were only known to the Transport that the connection was created on. A client
  that migrated to a path added with `Conn.AddPath` didn't recognize a stateless reset that the server sent to it on
  that path, and the connection timed out instead (RFC 9000, section 10.3.1). The tokens are now known to every
  Transport the connection receives packets on. quic-go v0.63.0 has the same problem.
- A connection that detected a stateless reset itself, as a client using a zero-length connection ID does, sent a
  CONNECTION_CLOSE frame with an INTERNAL_ERROR, instead of entering the draining period without sending any further
  packets (RFC 9000, section 10.3.1). quic-go v0.63.0 has the same problem.
- `Conn.LocalAddr`, `Conn.RemoteAddr` and `Conn.ConnectionState` read the connection's socket without
  synchronization while the client switched to a new path (RFC 9000 connection migration), a data race.
  quic-go v0.63.0 has the same problem.
- With qlog enabled, a frame sent with `Conn.QueueRawFrame` made the qlog writer panic, which crashed the program.
  These frames are logged as frames of unknown type.
- qlog: a CONNECTION_CLOSE frame with an application error code was logged with the name of the transport error
  code with the same value, for example `no_error` for the application error code 0. Application error codes are
  logged as numbers. quic-go v0.63.0 has the same problem.
- QUIC version 2: a key update derived the next 1-RTT secret with the label of QUIC version 1 ("quic ku") instead
  of "quicv2 ku" (RFC 9369, section 3.3.2). Peers implementing version 2 correctly couldn't decrypt any packet sent
  after a key update, and the connection stalled. quic-go v0.63.0 has the same problem.
- A transport parameter that couldn't be parsed, or had an invalid value, closed the connection with an
  INTERNAL_ERROR instead of a TRANSPORT_PARAMETER_ERROR (RFC 9000, section 7.4). quic-go v0.63.0 has the same
  problem.
- A frame received in a packet type that doesn't permit it (e.g. a STREAM frame in a Handshake packet) closed the
  connection with a FRAME_ENCODING_ERROR instead of a PROTOCOL_VIOLATION (RFC 9000, section 12.4). quic-go v0.63.0
  has the same problem.
- Stream Resets with Partial Delivery: a RESET_STREAM_AT frame was sent as soon as the stream was canceled, with a
  final size that included the reliable data not sent yet. If this data exceeded the peer's flow control limits, the
  peer closed the connection with a FLOW_CONTROL_ERROR (section 4 of draft-ietf-quic-reliable-stream-reset-11). The
  data now consumes flow control credit when the stream is canceled, or the frame is sent once the data was sent.
  quic-go v0.63.0 has the same problem.
- Stream Resets with Partial Delivery: a STOP_SENDING frame received after a RESET_STREAM_AT frame was sent, but
  before all reliable data was sent, was answered with a RESET_STREAM frame with a smaller final size, which the
  peer treats as a FINAL_SIZE_ERROR (section 5.2 of the draft). quic-go v0.63.0 has the same problem.
- Stream Resets with Partial Delivery: a change of the error code after a RESET_STREAM_AT frame was received is
  a STREAM_STATE_ERROR, and an increase of the reliable size after the stream was canceled locally is ignored
  (section 5.2 of the draft). quic-go v0.63.0 accepts both.

- A connection ID could be issued twice on a connection, or used by two connections of a Transport, if the random
  generator produced a connection ID that was already in use (RFC 9000, sections 5.1 and 10.3.2). With the default
  connection ID length of 4 bytes, this becomes likely on a busy server. New connection IDs are now generated again
  until an unused one is found. quic-go v0.63.0 has the same problem.
- In the closing state, the packet containing the CONNECTION_CLOSE frame was sent in response to any packet,
  regardless of the size of the packets received. The packets sent to an address are now limited to 3 times the
  size of the packets received from it (RFC 9000, section 10.2.1). quic-go v0.63.0 has the same problem.
- Datagrams ending in a valid stateless reset token were only recognized as stateless resets if they started with a
  short header. Other QUIC versions might use a long header (RFC 9000, section 10.3). Stateless reset tokens are now
  compared in constant time, and looked up as HMAC values, so that the lookup doesn't leak them through timing
  (section 10.3.1). quic-go v0.63.0 has the same problems.
- A client processed Initial packets of the server that carried a token, which servers never send (RFC 9000,
  section 17.2.2). They are now dropped. quic-go v0.63.0 has the same problem.
- When more than 64 ACK ranges were received, the oldest ones were deleted, and packets with the packet numbers of
  these ranges were accepted again (RFC 9000, sections 12.3 and 13.2.3). Packets below the oldest range kept are now
  treated as duplicates. quic-go v0.63.0 has the same problem.
- A connection didn't stop when its packet numbers reached 2^62-1 (RFC 9000, section 12.3), or when the AEAD
  confidentiality limit was reached and the keys couldn't be updated (RFC 9001, section 6.6). It now closes without
  sending any further packets. The keys are updated before the confidentiality limit is reached, also if the key
  update interval is larger. quic-go v0.63.0 has the same problem.
- A post-handshake CertificateRequest was rejected with a CRYPTO_ERROR (unexpected_message), and a NewSessionTicket
  with a max_early_data_size of 0 was accepted. Both are now a PROTOCOL_VIOLATION (RFC 9001, sections 4.4 and 4.6.1).
  A server now rejects a ClientHello with a legacy_session_id (section 8.4). quic-go v0.63.0 has the same problems.
- A client migrated to a loopback address offered as the server's preferred address by a server that it reached over
  another address (RFC 9000, section 21.5.6).
- A DATAGRAM frame received without having advertised support was a FRAME_ENCODING_ERROR instead of a
  PROTOCOL_VIOLATION (RFC 9221, section 3). quic-go v0.63.0 has the same problem.
- Stream Resets with Partial Delivery: a change of the error code after a RESET_STREAM_AT frame with a reliable size
  of 0 wasn't detected (section 5.2 of draft-ietf-quic-reliable-stream-reset-11).
- HTTP/3: a stream ending in the middle of a frame was treated as the end of the message, so that a truncated
  DATA frame silently shortened the body. It is now a connection error of type H3_FRAME_ERROR (RFC 9114,
  section 7.1). A stream whose last frame might be incomplete because a write failed (e.g. after the write deadline
  expired) is reset with H3_REQUEST_CANCELLED instead of being closed, so a handler's response that is cut off by
  its write deadline now ends with a stream error instead of a truncated body. quic-go v0.63.0 has the same
  problems.
- HTTP/3: a body shorter than its Content-Length, and requests without a `:scheme` pseudo-header field, were
  accepted. They are malformed (RFC 9114, sections 4.1.2 and 4.3.1), and the stream is reset with H3_MESSAGE_ERROR.
  Responses to HEAD requests and 304, 204 and 1xx responses are not checked. A HEADERS frame on the stream of a
  CONNECT request after the request was parsed as trailers, and is now an H3_FRAME_UNEXPECTED error (section 4.4).
  quic-go v0.63.0 has the same problems.
- HTTP/3: HTTP datagrams were sent before the peer's SETTINGS frame was received, and also if the peer didn't enable
  SETTINGS_H3_DATAGRAM (RFC 9297, section 2.1.1). Sending now waits for the SETTINGS frame, and fails without the
  setting. QUIC configs that allow the peer fewer than 3 unidirectional streams are rejected by `http3.Transport`
  and `http3.Server` (RFC 9114, section 6.2). quic-go v0.63.0 has the same problems.
- HTTP/3: a GET_0RTT or HEAD_0RTT request that the server rejected with 425 (Too Early) returned the 425 response.
  It is now sent again once the handshake completed (RFC 8470, section 4.2, required by RFC 9114, section 10.9).
- Fix a panic (index out of range in `AckFrame.Length`) that took down the process. A reordered packet received
  after an ACK frame acknowledging later packets could leave an ACK due with no packets left to acknowledge, once
  the peer acknowledged that ACK frame. This applies to single-path connections and to the PATH_ACK frames of every
  path of IETF Multipath QUIC. A peer could trigger it on purpose. quic-go v0.63.0 has the same problem. Also in
  v0.2.3.
- A server sent a single PATH_CHALLENGE to validate a new client address (RFC 9000 connection migration, and new
  4-tuples of a path of IETF Multipath QUIC). If the packet containing it was acknowledged but the PATH_RESPONSE was
  lost, or the client couldn't respond, the path was never validated, and the server kept sending to the old
  address. Packets received from an address that is not validated now trigger another PATH_CHALLENGE after a PTO,
  with exponential backoff, up to 5 times (RFC 9000, section 8.2.1). A response to any of them validates the
  address. quic-go v0.63.0 has the same problem. Also in v0.2.2.
- HTTP/3: a field section that doesn't use the QPACK dynamic table can use any Base (RFC 9204, section 4.5.1.2),
  but a non-zero Delta Base reset the stream. quic-go v0.63.0 has the same problem. Also in v0.2.2.
- A connection could issue a connection ID that it had issued before (RFC 9000, section 5.1): a connection ID that
  was retired and removed was not remembered, and a new random connection ID could equal it (with a probability of
  2^-32 for every pair, with the default length of 4 bytes). With the built-in generator, a connection now generates
  its connection IDs by encrypting a counter with a format-preserving cipher (a Feistel network using AES with a key
  of the connection), which never repeats a connection ID, without remembering them. The initial connection IDs are
  never issued again. A `Transport.ConnectionIDGenerator` set by the application must never return the same
  connection ID twice. quic-go v0.63.0 has the same problem.
- A client that switched to a path (`Path.Switch`, without IETF Multipath QUIC) whose `Transport` uses a connection
  that can't set the ECN bits (a connection that doesn't implement `OOBCapablePacketConn`) panicked with "cannot use
  ECN with a basicConn" when sending the next packet. Packets are now sent without ECN marking on such a path, and ECN
  validation starts again on every new path (RFC 9000, sections 9.2 and 13.4.2), as it already did with multipath.
  quic-go v0.63.0 has the same problem.
- HTTP/3: a client treated a HEADERS frame after the response to a CONNECT request that failed (a status other
  than 2xx) as a connection error. Only DATA frames are allowed once the CONNECT method has completed
  (RFC 9114, section 4.4): the response to a failed CONNECT request can have trailers.

### Other changes

- The interop runner endpoints support the `connectionmigration` test case (the server sends a preferred address) and
  the `ecn` test case.
- A client switched to a connection ID that the server provided in a NEW_CONNECTION_ID frame as soon as the
  handshake completed, while it still sent Initial and Handshake packets, which then used the new connection ID.
  picoquic drops such long header packets, so that the handshake completed one PTO later. The client now switches
  once the handshake is confirmed. quic-go v0.63.0 switches when the handshake completes.
- [docs/MAINTAINING.md](docs/MAINTAINING.md) describes how to run the conformance tests (QUIC interop runner, h3spec,
  picoquic, mixed versions, fuzzing), and lists the changes made to quic-go's code for standards compliance.
- [docs/CONNECTION_MIGRATION.md](docs/CONNECTION_MIGRATION.md) describes connection migration without multipath,
  and the decisions for the SHOULD and MAY statements of RFC 9000 about path validation, migration and the ACK Delay.
- `Config.MaxPaths` is limited to 64, the number of paths that the OLIA congestion controller keeps track of.
  The limit also applies to configs returned by `GetConfigForClient`.

## v0.2.3 (2026-10-05)

### Bug fixes

- Fix a panic (index out of range in `AckFrame.Length`) that took down the process. A reordered packet received after
  an ACK frame acknowledging later packets could leave an ACK due with no packets left to acknowledge, once the peer
  acknowledged that ACK frame. With multipath and one path delayed by 200 µs to 2 ms, this happened in about half of
  the transfers. quic-go v0.63.0 has the same problem with reordering on a single path.
- With multipath, the server added a validated client path only in response to the highest-numbered non-probing
  packet. Since all paths share one packet number space, a path with a longer delay was only added once the other
  path went idle. The rule in RFC 9000, section 9.3 is about migrating, and adding a path doesn't change the
  address that packets on the primary path are sent to. Migration without multipath is unchanged.
- With multipath, a PATH_RESPONSE was sent through the interface that the PATH_CHALLENGE was received on, while the
  other packets on the path are sent from the path's local address and routed by the kernel (unless `PathInfo.IfIndex`
  is set). On a multihomed host with policy routing, the PATH_RESPONSE could take a different route and never reach
  the peer. It is still sent from the local address that the PATH_CHALLENGE was received on (RFC 9000, section 8.2.2).

## v0.2.2 (2026-10-05)

### Bug fixes

- If the peer didn't respond to a PATH_CHALLENGE, for example because the NEW_CONNECTION_ID frame carrying an
  unused connection ID was lost, the server never validated the path. With multipath, some lossy two-path transfers
  (3 of 40 in testing) didn't use the second path. Packets received on a path that is not validated now trigger another
  PATH_CHALLENGE after a PTO, with exponential backoff, up to 5 times (RFC 9000, section 8.2.1).
- A PATH_CHALLENGE received on a known path wasn't answered if the maximum number of paths was reached
  (RFC 9000, section 8.2.2).
- After switching paths with `Path.Switch`, the client kept sending with the connection ID used on the old path,
  and the server did the same when following the client's migration. The connection ID used to probe the new
  path is now used, and the old one is retired (RFC 9000, section 9.5). If no connection ID is available, the
  switch is delayed until the peer provides one.
- Closing a validated path didn't retire its connection ID (backport of quic-go#5798).
- Closing a path could race with the connection being closed (backport of quic-go#5823).
- HTTP/3: a DATA or HEADERS frame received after the trailers made `Read` return an error, but the connection
  wasn't closed with H3_FRAME_UNEXPECTED (RFC 9114, section 4.1).
- HTTP/3: a HEADERS frame received on a CONNECT stream was parsed as trailers. Once the CONNECT method has
  completed, the connection is now closed with H3_FRAME_UNEXPECTED (RFC 9114, section 4.4).
- HTTP/3: a field section that referenced the QPACK dynamic table, used an invalid static table index or had a
  non-zero Required Insert Count only reset the stream. The connection is now closed with
  QPACK_DECOMPRESSION_FAILED (RFC 9204, sections 2.2.3, 3.1 and 4.5.1.1). A field section prefix with a negative
  Base used to be accepted, and is rejected the same way (RFC 9204, section 4.5.1.2).
- HTTP/3: a field section that doesn't use the QPACK dynamic table can use any Base (RFC 9204, section 4.5.1.2),
  but a non-zero Delta Base reset the stream.

## v0.2.1 (2026-10-05)

### Bug fixes

- Don't retire connection IDs that are still in use when a NEW_CONNECTION_ID frame is
  retransmitted. With multipath and packet loss, the active connection ID or the one used on a
  path could be retired while still in use, and the peer closed the connection with a
  PROTOCOL_VIOLATION (RFC 9000, section 19.16). This affected most lossy two-path transfers
  in v0.2.0.
- Count connection IDs used on paths towards the active_connection_id_limit (RFC 9000,
  section 5.1.1).

## v0.2.0 (2026-10-05)

First release under the module path `github.com/qoke/mp-quic-go`. It is based on
[mp-quic-go v0.1.3](https://github.com/AeonDave/mp-quic-go/tree/v0.1.3) by AeonDave,
which is based on quic-go v0.58.0 with upstream changes up to early January 2026.

### Incompatible changes

- The module path changed from `github.com/AeonDave/mp-quic-go` to `github.com/qoke/mp-quic-go`.
- The multipath wire format changed. Peers running v0.1.x don't negotiate multipath with this version:
  connections between them fall back to a single path. Both peers need to be upgraded to use multipath.
  - Multipath is negotiated with the transport parameter `0x1f0f9c0d2b` (was `0x1f0f9c0d2a`).
  - The ADD_ADDRESS frame type changed from `0x40` to `0x1f0f9c0d40`. `0x40`-`0x42` are in the
    Specification Required range of the QUIC frame type registry, and collided with custom frames
    sent with `Conn.QueueRawFrame`, which can use them again.
  - The PATHS (`0x41`) and CLOSE_PATH (`0x42`) frames were removed. They were never sent, and they
    referred to paths by the sender's path IDs, which the receiver can't map.
    `HandlePathsFrame` and `HandleClosePathFrame` were removed from `PathSchedulerWrapper` and
    `MultipathPathManager`.
- `Conn.QueueRawFrame` returns an error for frame types used by QUIC or by the extensions implemented
  in this module, and for types that don't fit a varint. It used to panic for the latter. Existing calls
  that ignore the result still compile.
- `SchedulingPolicyMinRTT` uses `NewMinRTTScheduler(1)`. It used the LowLatency scheduler.
- Only the client opens paths (RFC 9000, section 9). A server ignores ADD_ADDRESS frames and removes
  unvalidated paths added by the application. `Config.MultipathAutoPaths` only applies to clients and
  `Config.MultipathAutoAdvertise` only to servers.
- The built-in controllers only schedule validated paths (see below).

### Security fixes

- AEAD nonce reuse across paths: in v0.1.x, every path had its own packet number generator, while all
  paths use the same 1-RTT keys and the AEAD nonce is derived from the packet number. Packets sent on
  different paths could therefore be encrypted with the same key and nonce. All paths now use a single
  connection-wide application data packet number sequence, which is not reset when a path is removed.
- New paths are validated with PATH_CHALLENGE / PATH_RESPONSE before data is sent on them. Previously,
  a peer could make an endpoint send data to arbitrary addresses using ADD_ADDRESS.
  Acknowledgements no longer mark a path as validated (RFC 9000, section 8.2).
- A client using multipath discards packets from server addresses other than the one used during the
  handshake and the addresses of its paths, and never answers a PATH_CHALLENGE from such an address
  (RFC 9000, section 9).
- Addresses advertised with ADD_ADDRESS are ignored if they are unspecified, multicast, broadcast or use
  port 0, or if they are loopback or link-local while the primary path isn't. They are de-duplicated,
  and `Config.MaxPaths` (default 3) limits the number of paths created by the peer.
- The peer's `disable_active_migration` transport parameter is honored: no packets, including probing
  packets, are sent from another local address to the address the peer used during the handshake.
- HTTP/3: the decoded size of trailer field sections is limited like that of header field sections
  (CVE-2026-40898, GHSA-vvgj-x9jq-8cj9, backported from quic-go v0.59.1).

### ACK handling and loss recovery

- Each path keeps its own sent packet history, ACK tracking and largest acknowledged packet. ACK frames
  are matched to packets by packet number, on whatever path they are received.
- Duplicate packets are detected across paths, so a packet received on two paths is processed once.
- Gaps in a path's packet numbers caused by packets sent on other paths no longer trigger immediate ACKs.
  ACKs are sent every 2 packets per path, as on a single path.
- An ACK that is due for another path is sent on whichever path is sending next. This fixes a timer
  that fired repeatedly without sending anything.
- RTT samples are taken per path, from the newest newly acknowledged packet sent on that path.
- The time threshold of loss detection and the PTO use the RTT of the path a packet was sent on.
  Using the connection RTT, which follows the fastest path, declared packets on slower paths lost.
- When a path is removed, its outstanding packets are declared lost and retransmitted on other paths,
  and the state kept for the path is released.
- The PTO timer stayed armed after all packets were acknowledged, and probe packets kept being sent
  (backported from quic-go #5538 and #5539). The `packets_in_flight` qlog metric only counts outstanding
  packets.

### Congestion control

- The connection-level congestion controller, which gates sending and pacing, now sees the packets of
  every path. It used to stay at its initial window.
- Bytes in flight are tracked per path. `PathSelectionContext.PathCongestion`, `PathEvent` and
  `GetStatistics` report each path's congestion window and bytes in flight, and the built-in controllers
  don't select a path whose congestion window is full, except for ACK-only packets, retransmissions and
  probe packets.
- ECN is validated per path.
- A path that is added later starts at the current minimum scheduler quota. It used to receive all
  traffic until it caught up with the other paths.
- OLIA can be enabled with `Config.MultipathCongestionControl = MultipathCongestionControlOLIA`.
  The per-path OLIA controllers then limit the sending rate. The OLIA window increase, RTT input and
  recovery epoch were fixed: the window grew by one packet per ACK, or not at all, and was halved for
  every lost packet. The best paths are those with the largest ℓ/rtt². New:
  `OLIACongestionControl.MaybeExitSlowStart` and `OLIAStatistics.InRecovery`.

### Path validation and management

- Paths created automatically, for addresses advertised with ADD_ADDRESS, or by the application are
  validated before use. A path is removed after 4 unanswered PATH_CHALLENGEs, sent with exponential
  backoff.
- A PATH_RESPONSE is sent on the path the PATH_CHALLENGE was received on: to the address it came from,
  from the local address it was received on (RFC 9000, section 8.2.2). It is sent right away, even when
  the send queue is full. On a 4-tuple other than the one used during the handshake, it uses a connection
  ID that isn't used on any other 4-tuple (RFC 9000, section 9.5), which is retired when the path is
  removed.
- Path probe packets and PATH_RESPONSEs use the connection's ECN setting. They were ECN-marked even if
  the connection didn't use ECN, which made the send queue panic when ECN was disabled and for
  `net.PacketConn`s other than `*net.UDPConn`.
- Without multipath, a server answers PATH_CHALLENGEs received on the current path, and sends its path
  probe packets from the local address the client's packet was received on.
- With multipath, a server treats a new client address that passed path validation as an additional
  path, instead of migrating the connection to it and resetting its congestion controller and RTT
  estimate.
- `MultipathPathManager` returns copies of its paths (fixing a data race), keeps closed paths closed and
  limits the number of closed paths it remembers. New: `RemovePath` and `SetMaxPeerPaths`.
- Paths removed from the controller by the application are noticed within a second.
- The failure detector measures the timeout from the first unacknowledged packet sent on a path, and the
  built-in controllers fall back to failed paths when all paths are considered failed.

### Controllers, duplication and reinjection

- A multipath controller keeps per-connection state, but a server used the controller in its `Config`
  for all connections, sending packets of one connection to the peer of another. A controller is now used
  by one connection at a time: if it is in use, the built-in controllers are cloned without their paths,
  and multipath is disabled for custom controllers. New: `Config.MultipathControllerFactory` and
  `Conn.MultipathController()`.
- New: `DefaultMultipathController.SetMaxPeerPaths` and `UnvalidatedPaths`,
  `PathSchedulerWrapper.RemovePath`, `SetMaxPeerPaths` and `UnvalidatedPaths`.
- Reinjection only selects the path a lost packet's frames are retransmitted on. It used to pass the lost
  frames to their handlers a second time. Per-packet reinjection counts are released.
- Duplication and reinjection only use validated paths. Duplicate packet buffers are released when the
  send queue is full.
- New: `MultipathDuplicationPolicy.SetDuplicateAllStreams`, which also applies to streams opened later.

### Sockets

- Sending from a socket bound to an unspecified address (e.g. the `[::]` socket created by `DialAddr`)
  failed with `EINVAL` once multipath was used: the unspecified address was passed as the source address.
- `Transport.WriteTo` and `MultiSocketManager.WritePacket` no longer derive the source address from the
  destination address, which failed with `ENETUNREACH` for peers that aren't on a local network.
- Fixed error handling of the `MultiSocketManager` reader and a race in `AddLocalAddr`.

### Frames

- Multipath frames are not accepted in 0-RTT packets, and frames of unknown types are only passed to the
  `ExtensionFrameHandler` for 0-RTT and 1-RTT packets.
- ADD_ADDRESS frames with an invalid address length or IP version are rejected. Frame fields that don't
  fit a varint return an error instead of panicking.

### HTTP/3

- A malformed trailer section resets the stream with `H3_MESSAGE_ERROR` (RFC 9114, section 4.1.2),
  one that can't be decoded with `H3_QPACK_DECOMPRESSION_FAILED`, and one exceeding the field section
  size limit with `H3_EXCESSIVE_LOAD`. The error used to be returned from the body's `Read` only.
- Trailer fields are validated like header fields, and fields that aren't allowed in trailers are rejected.

### Other changes

- With Go 1.26, the error carried by `tls.QUICErrorEvent` is returned from the handshake.
- The interop Docker image sets the qlog `code_version`.
- The README was rewritten for this module, and this changelog was added. Internal release notes were
  removed, and the code passes `golangci-lint` with the repository configuration.
