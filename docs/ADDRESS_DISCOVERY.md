# QUIC Address Discovery in mp-quic-go

mp-quic-go implements QUIC Address Discovery as specified in
[draft-ietf-quic-address-discovery-01](https://datatracker.ietf.org/doc/html/draft-ietf-quic-address-discovery-01).
An endpoint reports the address it observes for its peer in OBSERVED_ADDRESS frames. A client behind a NAT learns
its reflexive transport address, i.e. the address and port that the NAT translates its local address to, without
using STUN. The extension works with and without IETF Multipath QUIC (see [MP_QUIC_README.md](MP_QUIC_README.md)).

The draft doesn't register its code points with IANA yet. mp-quic-go uses the values of the draft:

| Code point | Name | Kind |
|---|---|---|
| `0x9f81a176` | `address_discovery` | transport parameter (variable-length integer) |
| `0x9f81a6` | `OBSERVED_ADDRESS` (IPv4) | frame |
| `0x9f81a7` | `OBSERVED_ADDRESS` (IPv6) | frame |

## Configuration and negotiation

Two fields of the `Config` enable the extension:

- `RequestObservedAddress` asks the peer to report the address it observes for this endpoint.
- `ProvideObservedAddress` offers to report the address observed for the peer.

The value of the `address_discovery` transport parameter follows from them: 0 if only `ProvideObservedAddress` is
set, 1 if only `RequestObservedAddress` is set, 2 if both are set. Without either field, the parameter is not sent,
and nothing changes on the wire.

OBSERVED_ADDRESS frames are sent in one direction if the receiver requested them (value 1 or 2), and the sender
offered to provide them (value 0 or 2). `ConnectionState().SupportsAddressDiscovery` reports this for both directions
once the handshake completed: `Send` if this endpoint sends frames, `Receive` if the peer does.

- A transport parameter value other than 0, 1 and 2 is a TRANSPORT_PARAMETER_ERROR.
- Like all transport parameters remembered for 0-RTT, the value is saved in session tickets, by the server (in the
  ticket) and by the client (in the session state). The server rejects 0-RTT if its value changed since the ticket
  was issued, including enabling or disabling the extension. A client that resumed with 0-RTT closes the connection
  with a PROTOCOL_VIOLATION if the server accepted 0-RTT but sent a different value.
- If this endpoint sent the transport parameter, the frame parser knows the frame types. Receiving them in an Initial
  or Handshake packet is a PROTOCOL_VIOLATION (section 12.4 of RFC 9000). Receiving them in a 0-RTT or 1-RTT packet is
  a PROTOCOL_VIOLATION if this endpoint didn't request address observations, or if the peer didn't offer to provide
  them.
- If this endpoint didn't send the transport parameter, the frame types are unknown: receiving them is a
  FRAME_ENCODING_ERROR, unless a `Config.ExtensionFrameHandler` handles them. `Conn.QueueRawFrame` rejects both
  frame types.

## Sending

```
OBSERVED_ADDRESS Frame {
  Type (i) = 0x9f81a6..0x9f81a7,
  Sequence Number (i),
  [ IPv4 (32) ],
  [ IPv6 (128) ],
  Port (16),
}
```

- An endpoint that sends OBSERVED_ADDRESS frames sends one on every path: the path used for the handshake, every path
  of IETF Multipath QUIC, and every new path of RFC 9000 connection migration, including a new address of the client
  after a NAT rebinding. Every 4-tuple of a path of IETF Multipath QUIC is a new path as well.
- The frame reports the peer's address as the endpoint sees it: the source address of the peer's packets.
  IPv4-mapped IPv6 addresses (e.g. on a dual-stack socket) are reported as IPv4 addresses.
- Frames are only sent in 1-RTT packets. The server sends its first frame in its first 1-RTT packet, together with its
  handshake messages. The client sends its first frame in its first 1-RTT packet.
- On a new path (or 4-tuple), the frame is sent in the packet that validates it, together with the PATH_CHALLENGE
  frame. For a path of IETF Multipath QUIC, this is the first packet on the path. The server sends it when it
  validates a new address of the client, the client when it probes a new path (`Path.Probe`). When the connection
  (or a path of IETF Multipath QUIC) then switches to that 4-tuple, no other frame is sent, unless the frame was lost.
- The sequence numbers increase across all paths of the connection.
- The frame is a probing frame (section 9.1 of RFC 9000): a packet that only contains probing frames doesn't make the
  server migrate the connection, or a path, to the 4-tuple the packet was received on.
- A lost frame is not retransmitted as is. If the path still uses the same 4-tuple, a new frame is sent on the same
  path, with a new sequence number and the address the path uses now. A frame sent in a probe packet to another
  4-tuple is sent again when that 4-tuple is probed again, or when the path switches to it.
- A packet on a path of IETF Multipath QUIC that only carries an OBSERVED_ADDRESS frame (and maybe a PATH_ACK frame),
  e.g. after a loss, is sent like a path validation packet, without waiting for the congestion controller, but is not
  expanded to 1200 bytes.
- OBSERVED_ADDRESS frames are neither duplicated nor reinjected on other paths.

## Receiving

- `Conn.ObservedAddr` returns the address the peer reported for the primary path, i.e. the path that `LocalAddr` and
  `RemoteAddr` refer to. With IETF Multipath QUIC, the `ObservedAddr` field of the `PathInfo` returned by
  `Conn.Paths` is the address reported for that path.
- A frame is ignored if a frame with an equal or higher sequence number was received on the same path before.
  Without IETF Multipath QUIC, all frames belong to the connection's single path.
- The addresses are reported as received. The peer might report a wrong address (section 6.1 of the draft): the
  application decides whether to trust it, e.g. by asking several peers.

## Decisions for SHOULD and MAY statements

| Statement | Decision | Reason |
|---|---|---|
| Ignore a frame with an equal or lower sequence number on the same path (section 4.1) | Followed | |
| Retransmit lost frames (section 4.1) | A new frame with the current address is sent on the same path, if the path still uses the 4-tuple of the lost frame | The address might have changed; the receiver uses the frame with the highest sequence number |
| Send the frame as early as possible (section 5) | In the first 1-RTT packet. Not in 0-RTT packets | The client hasn't received a packet from the server when it sends 0-RTT packets, so it hasn't observed anything yet. 0-RTT packets can be replayed |
| Bundle the frame with probing packets (section 5) | Followed for the packets that validate a new path or 4-tuple | |
| Send a frame when the peer's address on a path changes (section 5) | A change of the peer's address is a new path (or 4-tuple of a path of IETF Multipath QUIC), and the frame is sent with the packet that validates it | |
| Limit the rate of frames (sections 5 and 6.2) | Frames for new addresses are only sent when the connection validates them. The path managers limit the number of addresses validated at the same time (3 for RFC 9000 connection migration), so spoofed packets can't trigger more frames than path validations | The same protection as for spurious NAT rebindings, as recommended in section 6.2 |
| Don't offer address observations if the endpoint can't observe the peer's address (section 6.2) | Left to the application: `ProvideObservedAddress` is off by default | Only the application knows how the endpoint is deployed, e.g. behind a load balancer that changes addresses |
| Only request observations from trusted peers, validate them (section 6.1) | Left to the application: `RequestObservedAddress` is off by default | Out of scope of the draft |

## Limitations

- Without IETF Multipath QUIC, all frames received belong to the connection's single path. While the client probes a
  new path (`Path.Probe`), the server reports the client's address on that path in the probe packet it sends there,
  and `Conn.ObservedAddr` already returns this address before the client switched to the path.
- Without IETF Multipath QUIC, the server distinguishes the paths of a connection by the client's address only
  (like quic-go). A packet that the client sends to another address of the server, from the same address, doesn't
  start a new path, unless it is sent to the server's preferred address (see [PREFERRED_ADDRESS.md](PREFERRED_ADDRESS.md)).

## Tests and interoperability

- `address_discovery_test.go` runs connections on a simulated network with a NAT in front of the client: negotiation
  in all combinations, a lost frame, a NAT rebinding with and without IETF Multipath QUIC, RFC 9000 connection
  migration of the client, and a second path of IETF Multipath QUIC.
- `integrationtests/self/zero_rtt_test.go` checks that the server rejects 0-RTT if the transport parameter changed,
  and accepts it otherwise.
- `interop/multipath` runs against picoquic in both roles, with and without multipath (`TestPicoquic*AddressDiscovery*`,
  see its [README](../interop/multipath/README.md)).

## qlog

OBSERVED_ADDRESS frames are logged as `observed_address` frames with the fields `sequence_number`, `ip` and `port`,
and the transport parameter as `"address_discovery": <value>`.

## Example

```go
// server: report the clients' addresses
serverConfig := &quic.Config{ProvideObservedAddress: true}

// client: ask the server to report the client's address
clientConfig := &quic.Config{RequestObservedAddress: true}

conn, err := quic.DialAddr(ctx, "example.com:443", tlsConf, clientConfig)
if err != nil {
	// handle error
}
// The server sends the frame together with its handshake messages.
// It arrives soon after the handshake completed.
if addr, ok := conn.ObservedAddr(); ok {
	log.Printf("the server sees this endpoint as %s", addr)
}
```
