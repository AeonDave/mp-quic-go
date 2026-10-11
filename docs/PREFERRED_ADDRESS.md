# Server's preferred address in mp-quic-go

A server can ask its clients to migrate their connections to another address once the handshake is confirmed
([RFC 9000, section 9.6](https://datatracker.ietf.org/doc/html/rfc9000#section-9.6)). This is useful for a server that
accepts connections on an address shared by multiple servers, e.g. an anycast address, and prefers its clients to use
an address of its own. quic-go parses the `preferred_address` transport parameter, but neither sends it nor migrates
to it. mp-quic-go implements both sides, with and without IETF Multipath QUIC (see [MP_QUIC_README.md](MP_QUIC_README.md)).

Connections without a preferred address are not affected: a server only sends the transport parameter if it is
configured, and a client only migrates if it receives it.

## Server

`Transport.PreferredAddress` configures the preferred address of the connections accepted by the Transport's
listener:

```go
tr := &quic.Transport{
	Conn: udpConn, // bound to 0.0.0.0:443
	PreferredAddress: &quic.PreferredAddress{
		IPv4: netip.MustParseAddrPort("192.0.2.10:443"),
	},
}
ln, err := tr.Listen(tlsConf, conf)
```

`PreferredAddress` has an IPv4 and an IPv6 address. Either one can be left unset (it is then sent as `0.0.0.0:0`
or `[::]:0`). The packets sent to an address are received by:

- the listener's Transport, if `IPv4Transport` (or `IPv6Transport`) is nil. Its socket needs to receive the packets sent
  to the preferred address, and to report the local address of every packet: a `net.UDPConn` bound to the unspecified
  address and the port of the preferred address, on Linux, macOS or FreeBSD, or a `MultiSocketManager` with a socket
  bound to the preferred address.
- another Transport, e.g. on a socket bound to the preferred address, or to another port. It needs to use the same
  connection ID length and the same `StatelessResetKey` as the listener's Transport. The connections of the listener
  add their connection IDs to it, so it routes their packets to them, and the client's stateless reset tokens, so it
  recognizes the stateless resets that a client sends to the preferred address (section 10.3.1 of RFC 9000). They send
  the packets of the preferred address on its socket. It must stay open as long as the listener's Transport: closing it closes the connections. The same
  Transport can receive the packets sent to both addresses.

The server recognizes the packets sent to the preferred address by their local IP address. The preferred IP addresses
therefore need to differ from the addresses that the clients connect to. `Listen` returns an error if the
configuration is invalid: no address, an address of the wrong family, an unspecified or multicast address, port 0, a
Transport without an address, the listener's own Transport, a Transport with another connection ID length or another
stateless reset key, a listener that uses zero-length connection IDs (section 18.2 of RFC 9000), or, without a
Transport for the address, a listener socket (other than a `MultiSocketManager`) that isn't bound to the unspecified
address (of a family that includes the address) and the port of the preferred address.

Every connection sends the `preferred_address` transport parameter with:

- the addresses. If the client connected to the preferred IP address of an address family, the address of that family is
  not sent. If both are left out this way, the transport parameter is not sent.
- a new connection ID with sequence number 1, and its stateless reset token. It counts towards the client's
  `active_connection_id_limit`: the server issues one connection ID less in NEW_CONNECTION_ID frames. With IETF
  Multipath QUIC, it is a connection ID of path 0 (section 2.2 of draft-ietf-quic-multipath-21).

The connection then handles the packets received on the preferred address (section 9.6.2 of RFC 9000):

- The path from the preferred address is a new path, even if the client's address didn't change. The server answers
  PATH_CHALLENGE frames received there from the preferred address, and validates the path itself, sending a
  PATH_CHALLENGE frame from the preferred address. Path probe packets use a connection ID of the client that wasn't
  used before.
- Until the path is validated, and a non-probing packet was received on it, the server keeps sending non-probing
  packets from its original address. It migrates when it then receives the packet with the largest packet number so far
  on the path (section 9.3 of RFC 9000).
- When it migrates, the server sends all packets from the preferred address, using the connection ID of the client
  used to validate the path, and retires the connection ID used so far (section 9.5 of RFC 9000). The congestion
  controller and the RTT estimate are reset, and Path MTU Discovery starts again (section 9.4 of RFC 9000).
  `Conn.LocalAddr` returns the preferred address.
- From then on, packets received on the original address are dropped. A change of the client's address on the
  preferred address (e.g. a NAT rebinding) is handled like any other migration.

## Client

The client migrates to the server's preferred address if it can send to one of the addresses:

- It chooses the address of the address family of the server address it connected to. If the server didn't send one,
  it chooses the address of the other family if its socket can send to it: an IPv6 address from an IPv6 socket
  (including a dual-stack socket bound to `::`), an IPv4 address from an IPv4 socket or from a socket bound to `::`.
  It doesn't migrate if the chosen address is the server address it already uses.
- The connection ID of the transport parameter is kept for the preferred address. It is not used for the server's
  original address, so that the client has an unused connection ID when it migrates (section 18.2 of RFC 9000).
  If the client doesn't migrate, the connection ID is used like one received in a NEW_CONNECTION_ID frame.
- Once the handshake is confirmed, the client validates the address from its current local address: it sends
  PATH_CHALLENGE frames, in datagrams of at least 1200 bytes, with exponential backoff starting at the PTO. PATH_CHALLENGE
  frames that the server sends from the preferred address are answered on that path, i.e. sent to the preferred address
  (section 8.2.2 of RFC 9000).
- When a PATH_RESPONSE frame validates the address, the client migrates: it sends all packets to the preferred
  address, using the connection ID of the transport parameter, and retires the connection ID used so far. The
  congestion controller and the RTT estimate are reset, and Path MTU Discovery starts again. `Conn.RemoteAddr` returns
  the preferred address.
- If the address is not validated within three times the larger one of the current PTO and the PTO of a new path
  (using the initial RTT, section 8.2.4 of RFC 9000), e.g. because the client can't send to it, the validation fails.
  The client retires the connection ID, and keeps using the server's original address.
- If the client migrates to a new local address (`Path.Switch`) before the validation completed, the validation starts
  again from the new address (section 9.6.3 of RFC 9000). The PATH_RESPONSE frames for PATH_CHALLENGE frames sent from
  the old address don't validate the preferred address.
- If the server sent `disable_active_migration`, the client can only migrate to a new local address (`Conn.AddPath`)
  once it migrated to the preferred address (sections 9 and 18.2 of RFC 9000).
- The preferred address is only used for the connection it was received on. It is not remembered for 0-RTT or session
  resumption (section 9.6.2 of RFC 9000).
- A client that receives a `preferred_address` transport parameter from a server that uses a zero-length connection ID
  closes the connection with a TRANSPORT_PARAMETER_ERROR (section 18.2 of RFC 9000). So does a zero-length connection
  ID in the transport parameter.

## IETF Multipath QUIC

The connection ID of the transport parameter is the connection ID with sequence number 1 of path 0, and path 0
migrates to the preferred address: this is a migration of the path, which keeps its path ID and packet number space
(section 2.2 of draft-ietf-quic-multipath-21).

- The client sends the PATH_CHALLENGE frames in path 0's packet number space. While it validates the preferred address,
  it accepts packets on path 0 from that address. After the migration, it still accepts packets from the server's
  original address on path 0.
- The server validates the 4-tuple of the preferred address like any other 4-tuple of a path (see
  [MP_QUIC_README.md](MP_QUIC_README.md)). When path 0 migrates to the preferred address, the server doesn't validate
  the previous 4-tuple: packets received on path 0 on the original address are dropped. Other paths are not affected.
- Clients can't assume that the original address and the preferred address can be used at the same time (section 2.2
  of the draft). The client opens the paths of `Config.MultipathAutoPaths` once the validation of the preferred address
  completed, to the server address of path 0: the preferred address if the migration succeeded. Paths that the
  application adds with `Conn.AddPath` go to the server address of path 0 at the time they are created.
- If the server sent `disable_active_migration`, paths to the preferred address can be opened at any time, and paths to
  the handshake address never (section 2.2 of the draft).

## Decisions for SHOULD and MAY statements

| Statement (RFC 9000) | Decision | Reason |
|---|---|---|
| A client SHOULD discard packets from a new server address it didn't migrate to (section 9.6) | Followed: the client discards packets from server addresses other than the one it connected to and the preferred address, once it started validating it (section 9). With IETF Multipath QUIC, the server addresses of each path | |
| Servers MAY communicate a preferred address of each address family (sections 9.6.1 and 18.2) | Supported: `IPv4`, `IPv6` or both | |
| The client SHOULD select one of the addresses once the handshake is confirmed, and initiate path validation (section 9.6.1) | Followed | |
| The client constructs packets using any previously unused connection ID (section 9.6.1) | The connection ID of the transport parameter is used | It is kept unused for this purpose |
| The client SHOULD send all future packets to the new address using the new connection ID, and discontinue the old address, as soon as path validation succeeds (section 9.6.1) | Followed. The old connection ID is retired | |
| The server SHOULD drop newer packets received on the old address (section 9.6.2) | Followed | |
| The server MAY continue to process delayed packets received on the old address (section 9.6.2) | Not followed: all packets received on the old address after the migration are dropped | A delayed packet might contain a PATH_CHALLENGE frame, which would need a response on the old path. The client retransmits the frames of dropped packets |
| A client that migrates before migrating to the preferred address SHOULD validate the original and the preferred address concurrently (section 9.6.3) | Followed: the validation of the preferred address starts again from the new local address, while the application's `Path` validates the original address | |
| If only the original address is validated, the client MAY migrate to its new address and keep sending to the original address (section 9.6.3) | Followed (`Path.Switch`) | |
| Servers SHOULD initiate path validation on receiving a probe packet from a new address (section 9.6.3) | Followed | |
| A client that migrates to a new address SHOULD use a preferred address of the same address family (section 9.6.3) | Followed: the address of the family of the current server address is chosen | |
| The client MAY use the connection ID of the transport parameter on any path (section 9.6.3) | The client only uses it for the preferred address | See above |

## Limitations

- The server recognizes the packets sent to the preferred address by their local IP address. A preferred address that
  differs from the client's server address only by the port can't be distinguished from it, and is therefore not sent to
  clients that connected to that IP address. A server with a single IP address per address family can therefore only
  offer the address of the other family. Clients that only migrate within the address family they connected over
  (ngtcp2's, for example) then don't migrate.
- If the listener's socket doesn't report the local address of received packets (e.g. on Windows), it can't receive the
  packets sent to the preferred address: use another Transport.
- Without IETF Multipath QUIC, the server limits the probe packets sent to a new path to 3 times the size of the datagram
  they respond to, until the client's address on that path is validated (see
  [CONNECTION_MIGRATION.md](CONNECTION_MIGRATION.md)). The client's probe packets have at least 1200 bytes, so the
  server's probe packets are expanded to 1200 bytes as well. With IETF Multipath QUIC, the limit is enforced for every
  4-tuple.

## Tests and interoperability

- `preferred_address_test.go`: the configuration, the transport parameter, the server's and the client's migration with
  and without IETF Multipath QUIC, a failed validation, a client migration during the validation, and the error for a
  server using zero-length connection IDs.
- `integrationtests/self/preferred_address_test.go`: connections to a server whose preferred IPv6 address is received by
  another Transport, with and without IETF Multipath QUIC, and a client that can't send to the preferred address.
  `multipath_linux_test.go` uses the listener's socket (bound to `0.0.0.0`) for the preferred address 127.0.0.2.
- `integrationtests/upstream`: a quic-go client ignores the preferred address.
- `interop/multipath` runs against picoquic in both roles, with and without multipath
  (`TestPicoquic*PreferredAddress*`, see its [README](../interop/multipath/README.md)).
- The interop runner endpoints support the `connectionmigration` test case. The server sends its address of the other
  address family as its preferred address.
