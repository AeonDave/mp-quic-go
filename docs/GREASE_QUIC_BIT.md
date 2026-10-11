# Greasing the QUIC Bit in mp-quic-go

The second-most significant bit of the first byte of a QUIC version 1 or 2 packet, the QUIC Bit, is always set to 1
(RFC 9000, section 17). [RFC 9287](https://datatracker.ietf.org/doc/html/rfc9287) defines the `grease_quic_bit`
transport parameter (`0x2ab2`), with which an endpoint announces that it accepts packets with the QUIC Bit set to 0.
A peer that receives it sets the QUIC Bit to an unpredictable value, so that middleboxes don't come to rely on it.
quic-go v0.63.0 doesn't implement the extension. mp-quic-go implements it, with and without IETF Multipath QUIC
(see [MP_QUIC_README.md](MP_QUIC_README.md)).

The extension is enabled with `Config.EnableQUICBitGreasing`. Connections without it are not affected: the transport
parameter isn't sent, the QUIC Bit of all packets is set, and packets with the QUIC Bit set to 0 are dropped, or
returned by `Transport.ReadNonQUICPacket`, as in quic-go.

`ConnectionState().SupportsQUICBitGreasing` says if the extension was enabled locally (`Local`) and if the peer sent
the transport parameter (`Remote`).

## Sending

An endpoint with the extension enabled:

- sends the `grease_quic_bit` transport parameter with an empty value;
- sets the QUIC Bit of every packet it sends to a random value once it processed the peer's transport parameters, if
  the peer sent `grease_quic_bit` (section 3.1). This applies to all packet types built by the connection: the
  server's Initial and Handshake packets after it processed the ClientHello, the client's Handshake and 1-RTT packets
  after it received the server's transport parameters, 0-RTT and 1-RTT packets, path probes, and the packets carrying
  a CONNECTION_CLOSE frame. The QUIC Bit is set to 0 with a probability of 1/2, using a pseudo-random generator
  seeded from `crypto/rand`. It is set before the packet is protected, since the first byte is part of the associated
  data of the AEAD. Header protection doesn't cover it.

The QUIC Bit is never set to 0:

- by a client before it received the server's transport parameters, in particular in its first Initial packets and in
  0-RTT packets sent before the handshake completes. The transport parameter is not saved in session tickets, so
  neither a client nor a server greases the QUIC Bit based on a previous connection (section 3.1);
- in Retry, Version Negotiation and Stateless Reset packets, which are sent without knowing if the peer supports the
  extension.

## Receiving

An endpoint with the extension enabled accepts packets with the QUIC Bit set to 0 (section 3):

- Long header packets of all types, including the client's Initial packets. A server decides this based on the
  `Config` passed to `Listen` (for the first Initial packet of a connection) and the `Config` returned by
  `GetConfigForClient` (for all other packets).
- Short header packets. The Transport passes them to the connection their connection ID belongs to, if that
  connection enabled the extension. All other packets that have the first two bits set to 0 are returned by
  `Transport.ReadNonQUICPacket`.
- Stateless resets with the QUIC Bit set to 0, if their token belongs to a connection that enabled the extension.
  Stateless resets for other connections need to have the QUIC Bit set (RFC 9000, section 10.3).
- Packets received after the connection was closed, while its connection IDs are still kept: they are absorbed, or
  answered with the CONNECTION_CLOSE packet (section 10.2 of RFC 9000), like packets with the QUIC Bit set.

A non-empty `grease_quic_bit` transport parameter is a TRANSPORT_PARAMETER_ERROR (section 3), and so is a duplicate.

Applications that demultiplex other protocols on the same socket using the QUIC Bit, e.g. STUN or TURN as described
in [RFC 9443](https://datatracker.ietf.org/doc/html/rfc9443), shouldn't enable the extension: the peer's packets are
then no longer distinguishable from those of other protocols by their first byte. This matters especially for
connections using zero-length connection IDs, since all short header packets with the QUIC Bit set to 0 are then
passed to the connection.

## SHOULD and MAY statements

| Statement (RFC 9287) | Decision | Reason |
|---|---|---|
| Endpoints that receive the `grease_quic_bit` transport parameter SHOULD set the QUIC Bit to an unpredictable value (section 3.1) | Followed if the extension is enabled locally. An endpoint without `Config.EnableQUICBitGreasing` never sets the QUIC Bit to 0, even if the peer sent the transport parameter | Connections without the option behave like quic-go. Greasing the QUIC Bit is an opt-in change of the wire image, since middleboxes or applications might demultiplex by the QUIC Bit |
| A client MAY set the QUIC Bit to 0 in Initial, Handshake and 0-RTT packets sent before receiving the server's transport parameters, if the server sent the transport parameter in a connection where it issued a NEW_TOKEN token less than 7 days before (section 3.1) | Not implemented: the client only greases the QUIC Bit after receiving the server's transport parameters | It would require storing the transport parameter with the token. The server side is implemented: Initial packets with the QUIC Bit set to 0 are accepted |
| Endpoints can set the QUIC Bit to 0 in Retry packets sent after processing the transport parameters (section 3.1) | Not implemented | The server sends Retry packets without processing the ClientHello |

## Tests and interoperability

- `internal/wire`: the transport parameter, and parsing long and short headers with the QUIC Bit set to 0.
- `packet_packer_test.go`, `packet_unpacker_test.go`: setting the QUIC Bit at random before the packet is sealed, and
  unpacking packets with the QUIC Bit set to 0.
- `transport_test.go`, `server_test.go`, `grease_quic_bit_test.go`: routing short header packets with the QUIC Bit set
  to 0 (also to closed connections), accepting Initial packets with the QUIC Bit set to 0, stateless resets, and the
  negotiation.
- `integrationtests/self/grease_quic_bit_test.go`: transfers between two endpoints with the extension enabled on both,
  one or neither endpoint, also with zero-length connection IDs. No packet is lost, and the QUIC Bit is only set to 0
  if both endpoints enabled the extension.
- `integrationtests/upstream`: mp-quic-go with the extension enabled doesn't grease the QUIC Bit towards quic-go.
- `interop/multipath` (`TestPicoquicServerGreaseQUICBitResetStreamAt`): picoquicdemo's server sends the transport
  parameter only if the client sent it. Both endpoints set the QUIC Bit to 0 at random. picoquicdemo's client
  doesn't send the transport parameter (`TestPicoquicClientGreaseQUICBitResetStreamAt`), and our server doesn't
  grease the QUIC Bit.
