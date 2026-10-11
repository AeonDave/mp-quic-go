# Connection migration in mp-quic-go

Without IETF Multipath QUIC, a connection uses a single path, and connection migration works as described in
[RFC 9000, section 9](https://datatracker.ietf.org/doc/html/rfc9000#section-9): only the client migrates, either
intentionally (`Conn.AddPath`, `Path.Probe`, `Path.Switch`) or because its address changed (e.g. a NAT rebinding), and
the server follows it. The implementation is quic-go's (`path_manager.go`, `path_manager_outgoing.go`), changed where it
didn't follow the MUST statements of RFC 9000. With IETF Multipath QUIC, every path migrates on its own, see
[MP_QUIC_README.md](MP_QUIC_README.md). The server's preferred address is described in
[PREFERRED_ADDRESS.md](PREFERRED_ADDRESS.md).

## Server

When the server receives a packet from a new client address:

- It validates the path: it sends a PATH_CHALLENGE frame in a probe packet, using a connection ID of the client that
  wasn't used before (section 9.5). The probe packet is sent from the local address the packet was received on, if the
  socket reports it. It also answers every PATH_CHALLENGE frame of the packet (section 8.2.2). All these frames are
  sent in one probe packet, unless they don't fit.
- Until the client's address is validated, the probe packets sent in response to a datagram are limited to 3 times
  its size (sections 8 and 9.3.1). They are expanded to 1200 bytes if the limit allows it (sections 8.2.1 and 8.2.2).
  For a validated address that isn't the current one, e.g. the previous path, the limit is 3 times the size of the
  datagram, but at least 1200 bytes: an attacker spoofing an address that was validated before can't make the server
  send more than that. Probe packets aren't congestion controlled.
  If the datagram with the PATH_CHALLENGE couldn't be expanded, its PATH_RESPONSE only validates the client's address:
  the server then sends a second PATH_CHALLENGE in a datagram of 1200 bytes, and the path is only validated once that
  one is answered (section 8.2.1).
- If the client doesn't answer, or the PATH_RESPONSE is lost, a packet received on the path triggers another
  PATH_CHALLENGE, at the earliest one PTO after the previous one, with exponential backoff, up to 5 times
  (section 8.2.1). A PATH_RESPONSE to any of them validates the path. Without this, a lost PATH_RESPONSE would leave
  the path unvalidated, and after a NAT rebinding the server would keep sending to the old address.
- The server switches to the path when it receives the packet with the largest packet number so far on the validated
  path, if that packet is a non-probing packet (section 9.3). It then uses the connection ID it used to validate the
  path, which wasn't used towards any other address (section 9.5).
- After switching, it validates the previously active path (section 9.3.3), using the connection ID used on that path
  so far if the client provided a stateless reset token for it, and a new one otherwise. If the validation succeeds,
  a non-probing packet received on the previous path with the largest packet number so far switches the connection
  back. If an attacker forwarded copies of the client's packets from another address, this moves the connection back
  to the client's address.
- It keeps track of at most 3 paths, as quic-go does. A PATH_CHALLENGE received on one of these paths is always
  answered.

A PATH_CHALLENGE frame received on the current path, also in a 0-RTT packet, is answered in the next packet sent.
Datagrams containing PATH_CHALLENGE or PATH_RESPONSE frames are expanded to 1200 bytes, unless the anti-amplification
limit of the handshake doesn't allow sending a datagram of 1200 bytes (section 8.2.2).

## Client

- `Path.Probe` sends PATH_CHALLENGE frames from the path's `Transport`, in datagrams of 1200 bytes, using a connection
  ID that wasn't used before.
- A PATH_CHALLENGE frame received on the `Transport` of a path that isn't the active path is answered on that path:
  the PATH_RESPONSE is sent from that `Transport`, using the path's connection ID (section 8.2.2). A PATH_CHALLENGE
  received on the active path is answered in the next packet, expanded to 1200 bytes.
- After switching away from the path used for the handshake, a PATH_CHALLENGE received on the `Transport` used for the
  handshake, e.g. when the server validates the previous path (section 9.3.3), is answered from that `Transport` as
  well. Since the connection ID used on that path was retired, the PATH_RESPONSE is sent with a connection ID that
  wasn't used on any other path (section 9.5).
- If no unused connection ID is available for a path that isn't the active path, a PATH_CHALLENGE received on it is
  not answered: a PATH_RESPONSE sent on another path would make the server consider a path validated that the client
  didn't answer on.
- `Path.Switch` switches to the path's `Transport` and to the connection ID used for probing the path. The connection
  ID used so far is retired (section 9.5). When switching back to a path that was used before, its connection ID
  was retired already, and a new one is used.
- The client discards packets from server addresses other than the one it dialed and, once it started validating it,
  the server's preferred address (section 9). If the client dialed an unspecified IP address (e.g. the address of a
  listener on `0.0.0.0` or `::`), the operating system chooses the address the packets go to, usually a loopback
  address. The client then accepts packets from the dialed port until it processed the first packet, and from then on
  only packets from the address that packet came from. A server with multiple IP addresses has to answer from the
  address the client sent its packets to, which requires a socket that sets the source address of packets (packet
  info), or listening on a specific IP address.

### Wrapped connections

The check of the server address only applies to source addresses reported as `*net.UDPAddr`, which is what a
`*net.UDPConn` reports, as do most connections that wrap one. A `net.PacketConn` that reports other kinds of addresses,
for example a connection over a relay or a tunnel, might not report the address that the client sends to. Packets
received on such a connection are accepted, and the connection is responsible for only passing packets from the
server. IPv4-mapped IPv6 addresses are equal to the corresponding IPv4 addresses, so a dual-stack socket can be used.

## Acknowledgments

The ACK Delay field of an acknowledgment only includes delays that the endpoint controls (section 13.2.5). It is
measured from when the connection started processing the packet with the largest packet number, not from when the
packet was read from the socket: the time the packet waited in the connection's queue is part of the path's RTT.
Packets that waited for their decryption keys are an exception: their ACK Delay includes this time, which can be large
and is likely to be non-repeating.

## Decisions for SHOULD and MAY statements

| Statement (RFC 9000) | Decision | Reason |
|---|---|---|
| An endpoint SHOULD NOT send multiple PATH_CHALLENGE frames in a single packet (section 8.2.1) | Followed | |
| An endpoint SHOULD NOT probe a new path more frequently than it would send an Initial packet (section 8.2.1) | Followed: the client probes with exponential backoff, starting at 200 ms. The server sends a PATH_CHALLENGE on a new path, and another one when a packet arrives on the path while it is not validated, at the earliest after the PTO, with exponential backoff, up to 5 times. If the last PATH_CHALLENGE is declared lost, the path is forgotten, and the next packet on it starts a new validation | |
| An endpoint MAY include other frames with PATH_CHALLENGE and PATH_RESPONSE frames (section 8.2) | Probe packets only contain PATH_CHALLENGE, PATH_RESPONSE and OBSERVED_ADDRESS frames. On the current path, a PATH_RESPONSE is sent together with other frames | Frames other than probing frames would make the peer switch paths |
| An endpoint MAY skip the validation of a peer address that was seen recently (section 9.3) | Not followed: every new client address is validated | Simpler, and safe against spoofed addresses |
| An endpoint MAY send data to an unvalidated peer address (section 9.3) | Not followed: the server only switches to a validated path | As in quic-go. The anti-amplification limit would apply |
| After verifying a new client address, the server SHOULD send new address validation tokens (section 9.3) | Followed with IETF Multipath QUIC. Without it, not followed | As in quic-go |
| An endpoint that receives a PATH_CHALLENGE on an active path SHOULD send a non-probing packet in response (section 9.3.3) | Followed with IETF Multipath QUIC. Without it, the PATH_RESPONSE is sent in the next packet, which contains a non-probing frame (e.g. an ACK) if one is due | As in quic-go: an additional PING frame would change the packets sent on single-path connections |
| An endpoint MAY continue to use the current connection ID with a new remote address after a NAT rebinding (section 9.5) | Not followed: the server uses the connection ID it used to validate the new path | This is allowed in all cases, and doesn't depend on whether the client changed its connection ID |
| An endpoint SHOULD NOT initiate migration with a peer that requested a zero-length connection ID (section 9.5) | Left to the application: `Conn.AddPath` works with a server that uses zero-length connection IDs | As in quic-go |
| Endpoints SHOULD provide new connection IDs before peers migrate (section 9.5) | Followed: up to the peer's `active_connection_id_limit` | |
| Endpoints SHOULD include buffering delays caused by unavailability of decryption keys in the ACK Delay (section 13.2.5) | Followed | |
| When the measured acknowledgment delay is larger than max_ack_delay, an endpoint SHOULD report the measured delay (section 13.2.5) | Followed: the ACK Delay is never capped | |

## quic-go issues

These quic-go issues concern the behavior described here:

| Issue | Status |
|---|---|
| [#5408](https://github.com/quic-go/quic-go/issues/5408): PATH_RESPONSE not sent on the path of the PATH_CHALLENGE | Fixed, see above |
| [#5236](https://github.com/quic-go/quic-go/issues/5236): the connection ID doesn't change after a migration | Fixed for the client and the server |
| [#2693](https://github.com/quic-go/quic-go/issues/2693): only count intentional delays in the ACK Delay | Fixed, see above |
| [#4174](https://github.com/quic-go/quic-go/issues/4174): send DATA_BLOCKED and STREAM_DATA_BLOCKED frames when the peer's limits are 0 | Not changed. Sending these frames is a SHOULD (section 4.1 of RFC 9000). A peer that advertised a limit of 0 has to increase it before any data can be sent, so it gains nothing from the signal. The frames are sent when the sender becomes blocked at a non-zero limit |
| [#2654](https://github.com/quic-go/quic-go/issues/2654): the PTO of the application data packet number space is in the past after the handshake | Not a violation. The PTO is computed from the time the last ack-eliciting packet was sent, as in the pseudocode of RFC 9002 (appendix A.8). If the 1-RTT packets sent during the handshake weren't acknowledged by the time the handshake is confirmed, the timer fires right away, and the lost data is retransmitted |

## Limitations

- The client doesn't check the server address of packets received on a `net.PacketConn` that doesn't report
  `*net.UDPAddr` addresses (see above).

## Tests

- `connection_test.go`: answering PATH_CHALLENGE frames on the current path, in 0-RTT packets and on new paths
  (`TestConnectionServerPath*`, `TestConnectionPathChallengesInOnePacket`), the server's migration and the validation of
  the previous path (`TestConnectionPathValidation`, `TestConnectionServerMigrationValidatesPreviousPath`), the
  client's response on a probed path and its connection IDs (`TestConnectionClientPath*`), unknown server addresses
  (`TestConnectionClientDropsPacketsFromUnknownServerAddress*`), and the ACK Delay (`TestConnectionAckDelay*`).
- `path_manager_test.go`, `path_manager_outgoing_test.go` and `packet_packer_test.go`: the second path validation, the
  previous path, and the expansion of datagrams containing PATH_RESPONSE frames.
- `integrationtests/self`: `TestConnectionMigration`, `TestNATRebinding` (which checks that PATH_RESPONSE datagrams
  are expanded), and the MITM tests, which inject packets from the server address the client uses.
- `integrationtests/upstream`: an upstream quic-go client migrating to a new path with an mp-quic-go server, and the
  other way around (`TestUpstreamClientMigration`, `TestUpstreamServerMigration`). In both cases, the mp-quic-go
  endpoint sends with a new connection ID after the migration.
