# Version negotiation in mp-quic-go

mp-quic-go supports QUIC version 1 ([RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)) and QUIC version 2
([RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369)). It implements both version negotiation mechanisms of
[RFC 9368](https://datatracker.ietf.org/doc/html/rfc9368):

- incompatible version negotiation, using Version Negotiation packets, which costs a round trip, and
- compatible version negotiation, which switches a connection from one version to a compatible version without a
  round trip. Version 1 and version 2 are compatible with each other (section 4 of RFC 9369). No other versions are
  considered compatible.

Both endpoints send the `version_information` transport parameter (`0x11`), and validate the peer's, which prevents
version downgrade attacks. A connection that fails this validation is closed with a VERSION_NEGOTIATION_ERROR
(`0x11`, `quic.VersionNegotiationErrorCode`).

## Configuration

`Config.Versions` lists the versions, sorted by preference (descending). It defaults to `quic.SupportedVersions()`,
i.e. version 1, followed by version 2.

- A client sends its first flight using the first version (its Chosen Version), or using `Config.InitialVersion` if
  it is set. It offers all versions of `Config.Versions` that this first flight is compatible with, in the order of
  `Config.Versions`. With the default configuration, a client starts with version 1, and offers version 1 and
  version 2. A client with `Versions: []quic.Version{quic.Version2, quic.Version1}` and `InitialVersion:
  quic.Version1` starts with version 1, which every server supports, and states a preference for version 2: its
  Available Versions are version 2, followed by version 1 (section 3 of RFC 9368). Servers that use the client's
  preference (for example picoquic) then switch to version 2.
- A server accepts all versions of `Config.Versions`, and sends a Version Negotiation packet listing them (plus a
  reserved version) if a client uses another version.
- A server only switches to another version if `Config.Versions` is set (by the `Config` passed to `Listen`, or
  returned by `GetConfigForClient`). It selects the first version of `Config.Versions` that the client offered, and that
  the client's first flight is compatible with. Without `Config.Versions`, the server always uses the client's Chosen
  Version. This keeps the default behavior unchanged: a client starting with version 2 is not switched to version 1.

For example, a server with `Versions: []quic.Version{quic.Version2, quic.Version1}` switches clients that start with
version 1 and offer version 2 to version 2.

`ConnectionState().Version` is the version in use: after compatible version negotiation, the Negotiated Version.

## The version_information transport parameter

```
Version Information {
  Chosen Version (32),
  Available Versions (32) ...,
}
```

- The client sends its Chosen Version, and the versions its first flight is compatible with (including the Chosen
  Version).
- The server sends the Negotiated Version, and the versions of its `Config.Versions` as its Fully Deployed Versions.
- The parameter is sent on every connection, with or without compatible version negotiation. Peers that don't
  support RFC 9368 ignore it. It is never saved in session tickets.
- A parameter that is too short, whose length is not a multiple of 4, that contains the version 0, or (sent by a
  client) whose Chosen Version is not one of its Available Versions is a TRANSPORT_PARAMETER_ERROR.

## Compatible version negotiation

The server selects the Negotiated Version when it has received the client's first ClientHello, before crypto/tls
processes it:

- crypto/tls only provides the client's transport parameters after it decided whether to send a HelloRetryRequest,
  and after a HelloRetryRequest, only those of the second ClientHello. A HelloRetryRequest must already use the
  Negotiated Version: the client takes the CRYPTO frames received in an Initial packet as an indication of the
  Negotiated Version (section 4.1 of RFC 9369). The server therefore reads the Version Information from the
  quic_transport_parameters extension of the first ClientHello itself. crypto/tls sends a HelloRetryRequest for
  example if the client supports a post-quantum key exchange, but didn't send a key share for it.
- It closes the connection with a VERSION_NEGOTIATION_ERROR if the client's Chosen Version differs from the version
  of the client's first flight, or if the Version Information of the second ClientHello differs from that of the
  first one.
- If the first ClientHello or its transport parameters can't be parsed, crypto/tls reports the error. If the server
  sent a HelloRetryRequest without having selected a version, it doesn't switch.
- It sends Initial packets using the client's Chosen Version until then (for example, acknowledgments for a
  ClientHello that spans multiple packets), and all CRYPTO frames, Initial, Handshake and 1-RTT packets using the
  Negotiated Version afterwards. The Handshake and 1-RTT keys are derived using the Negotiated Version.
- It keeps accepting Initial packets using the client's Chosen Version until it drops the Initial keys, i.e. until it
  processes the client's first Handshake packet (which uses the Negotiated Version).
- Handshake packets using another version than the Negotiated Version are dropped.
- If the server sends a Retry, it sends it using the client's Chosen Version, before processing any transport
  parameters. After switching, the transport parameters authenticate the Retry as usual.

The client learns the Negotiated Version from the first Initial packet that uses a version other than its Chosen
Version:

- Only versions that the client offered are accepted. The packet is decrypted with the Initial keys of that version.
  The client only switches if the packet can be decrypted.
- After switching, the client sends all Initial and Handshake packets using the Negotiated Version, and drops Initial
  packets using its Chosen Version.
- Once the client processed a CRYPTO frame in an Initial packet using its Chosen Version, the Negotiated Version is
  the Chosen Version, and Initial packets using other versions are dropped.
- Retry and Handshake packets using another version than the Chosen Version are dropped before the client switched.

0-RTT:

- The client always sends 0-RTT packets using its Chosen Version, and derives the 0-RTT keys using it, even after
  switching to the Negotiated Version (section 4.1 of RFC 9369). In a datagram, an Initial packet using the
  Negotiated Version can be followed by a 0-RTT packet using the Chosen Version.
- The server accepts 0-RTT packets using the client's Chosen Version, and decrypts them with keys derived using the
  Chosen Version. 0-RTT packets using another version are dropped.

## Session tickets and tokens

Session tickets and address validation tokens are specific to the QUIC version of the connection that issued them
(section 5 of RFC 9369). After compatible version negotiation, they belong to the Negotiated Version.

- The server records the version in session tickets and tokens. It only resumes a session if the ticket was issued
  for the version of the client's first flight; other tickets result in a full handshake, without 0-RTT. Tokens
  issued for another version are ignored (NEW_TOKEN tokens) or rejected with an INVALID_TOKEN error (Retry tokens):
  a client must not switch versions between a Retry and the Initial packet carrying its token (section 4.1 of
  RFC 9369). Tickets issued by earlier versions of this module don't record the version, and are not used for
  resumption.
- The client stores session tickets and tokens by version. For version 1, it uses the keys used before (the key
  chosen by crypto/tls for the `ClientSessionCache`, the server name or address for the `TokenStore`). For other
  versions, the version is appended to the key (`<key>|quic-version=0x6b3343cf`). A connection only uses tickets and
  tokens of the version of its first flight. A client that starts with version 1 and is switched to version 2
  therefore doesn't resume the session on the next connection starting with version 1. It resumes it on a
  connection starting with version 2.
- If the `tls.Config` of a server has a `GetConfigForClient` callback, and the returned config has no
  `UnwrapSession` callback, crypto/tls decrypts the session ticket with keys that the server can't access. For such
  configs, a ticket of another version is still used for resumption, but 0-RTT is rejected.

## Validation of the Version Information (downgrade prevention)

The server:

- completes the handshake if the client's Version Information is missing, and uses the client's Chosen Version.
- validates that the client's Chosen Version matches the version in use (see above).

The client closes the connection with a VERSION_NEGOTIATION_ERROR if:

- the server's Chosen Version is not one of the versions the client offered,
- the server's Chosen Version differs from the Negotiated Version learned from the long header,
- the server's Version Information is missing, and the client switched to a different version,
- the client reacted to a Version Negotiation packet, and the server's Version Information is missing (unless the
  connection uses version 1, see section 8 of RFC 9368),
- the client reacted to a Version Negotiation packet, and the server's Available Versions are empty, or the client
  would have selected a different version from a Version Negotiation packet listing the server's Available Versions
  and the Negotiated Version.

Incompatible version negotiation:

- A client ignores Version Negotiation packets that contain its Chosen Version, Version Negotiation packets received
  after it received any other packet from the server, and all Version Negotiation packets received on the connection
  attempt it started in response to a Version Negotiation packet.
- A client selects the first version of its `Config.Versions` that the server lists, and starts a new connection
  attempt with a new TLS handshake. Compatible version negotiation can follow on this attempt (figure 1 of RFC 9368).
- A server ignores Version Negotiation packets.

## Interoperability

- [picoquic](https://github.com/private-octopus/picoquic): the interop tests in [interop/multipath](../interop/multipath)
  (build tag `picoquic`) use QUIC version 2 in both directions, including key updates, and check that a server
  preferring version 2 keeps version 1 if the client doesn't offer version 2. picoquicdemo's server doesn't switch
  versions. picoquicdemo's client (`-U 6b3343cf`) fails when a server switches to version 2, see the README there.
- [ngtcp2](https://github.com/ngtcp2/ngtcp2) (tested manually with its interop runner image): mp-quic-go's client
  starting with version 1 is switched to version 2 by ngtcp2's server (`--preferred-versions v2`). ngtcp2's client
  (`-v 0x1 --available-versions v2,v1`) is switched to version 2 by mp-quic-go's server preferring version 2, also
  when the server sends a HelloRetryRequest. Both use key updates with version 2.

## SHOULD and MAY statements

| Statement | Decision |
|---|---|
| RFC 9368, section 2: the server MAY select any other compatible version. | Implemented. A server only does so if `Config.Versions` is set. |
| RFC 9368, section 2.1: the server MAY add reserved versions to Version Negotiation packets. | Implemented: one reserved version at a random position. |
| RFC 9368, section 2.5: the client SHOULD pick an Original Version that avoids incompatible version negotiation. | The client uses `Config.InitialVersion`, or the first version of `Config.Versions`. The default is version 1, which all QUIC servers support, offering version 2. |
| RFC 9368, section 3: the server MAY use its own preference instead of the client's. | Implemented: the server uses the order of its `Config.Versions`. |
| RFC 9368, section 3: the server's Available Versions MAY be empty. | Not used: the server sends its `Config.Versions`. |
| RFC 9368, section 3: clients and servers MAY include reserved versions in their Available Versions. | Not implemented. Reserved versions are sent in Version Negotiation packets, and transport parameters are greased with reserved transport parameter IDs. |
| RFC 9368, section 4: servers MAY complete the handshake if the Version Information is missing. | Implemented. |
| RFC 9368, section 4: clients MAY complete the handshake if the Version Information is missing, unless they reacted to a Version Negotiation packet. | Implemented, unless the client switched to another version. |
| RFC 9368, section 5: server operators SHOULD use a three-step process to add or remove a version. | Not applicable to a single server: Acceptable, Offered and Fully Deployed Versions are all `Config.Versions`. Operators of deployments with multiple server instances need to roll out version changes accordingly, since a server can't configure the three sets separately. |
| RFC 9369, section 4: HTTP servers SHOULD support multiple versions. | Implemented: servers accept version 1 and version 2 by default. |
| RFC 9369, section 4: endpoints that support both versions SHOULD support compatible version negotiation. | Implemented. |
| RFC 9369, section 4.1: the client SHOULD send subsequent Initial packets using the Negotiated Version. | Implemented. |
| RFC 9369, section 4.1: the server MAY encode the QUIC version in its Retry token. | Implemented. A Retry token of another version is rejected with an INVALID_TOKEN error, instead of dropping the packet. |
| RFC 9369, section 6 (no normative keyword): clients can initiate a connection using version 2 if they are reasonably certain that the server supports it, e.g. because it issued a session ticket for version 2. | Not implemented: the client uses `Config.InitialVersion` or the first version of `Config.Versions`, even if it holds a session ticket for version 2. |
