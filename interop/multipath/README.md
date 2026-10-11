# Multipath interop tests with picoquic

These tests run mp-quic-go against [picoquic](https://github.com/private-octopus/picoquic), which implements
draft-ietf-quic-multipath (the code points of drafts 20 and 21 are the same), over real UDP on the loopback
interface. picoquicdemo runs in a Docker container that uses the host network, built from a pinned picoquic commit
(see `Dockerfile`; picotls is fetched at the commit pinned by picoquic). The application protocol is HTTP/0.9
(`hq-interop`): picoquicdemo's server answers a request for `/<n>` with `n` bytes, and so does the test server.

The version tests (`version_test.go`) check QUIC version 2 and version negotiation (see
[docs/VERSION_NEGOTIATION.md](../../docs/VERSION_NEGOTIATION.md)), the preferred address tests
(`preferred_address_test.go`) the server's preferred address (see
[docs/PREFERRED_ADDRESS.md](../../docs/PREFERRED_ADDRESS.md)), the extension tests (`extensions_test.go`) greasing
the QUIC Bit and Stream Resets with Partial Delivery (see [docs/GREASE_QUIC_BIT.md](../../docs/GREASE_QUIC_BIT.md)
and [docs/RELIABLE_STREAM_RESET.md](../../docs/RELIABLE_STREAM_RESET.md)). The tests are only built with the `picoquic`
build tag, and they need Docker and Linux (the second path uses 127.0.0.2):

```sh
go test -tags picoquic -count=1 -v ./interop/multipath/...
go test -tags picoquic -count=1 -v ./interop/multipath/... -args -logdir=/path/to/logs
```

The first run builds the image (`mp-quic-go-picoquic:<commit>`), which takes a few minutes. The qlogs of both
endpoints and the output of picoquicdemo are written to the directory given by `-logdir`, or to a new temporary
directory, which is printed and kept. Every test has its own subdirectory: `qlog-mp-quic-go` holds the qlog of
mp-quic-go, `picoquic-server` or `picoquic-client` the qlog of picoquicdemo, and `server.log` or `client.log` its
output.

| Test | Setup | Checks |
|---|---|---|
| `TestPicoquicServerMultipath` | `picoquicdemo -M` server, mp-quic-go client opens path 1 from 127.0.0.2 | multipath negotiated, path 1 validated, 10 MB download received on both paths, a key update |
| `TestPicoquicServerAbandonPaths` | as above | the client abandons path 1 (picoquic responds with `PATH_ABANDON`), opens path 2 from 127.0.0.2, abandons path 0 (picoquic responds), downloads after every step, data received on paths 0, 1 and 2 |
| `TestPicoquicServerSinglePath` | picoquicdemo server without `-M`, mp-quic-go client with a multipath controller | single path, no frames of the extension, download, a key update |
| `TestPicoquicClientMultipath` | `picoquicdemo -M -A 127.0.0.2/0` client, mp-quic-go server | picoquic reports multipath, 10 MB sent on paths 0 and 1, key updates (picoquic is asked to update after 1000 packets) |
| `TestPicoquicClientSinglePath` | picoquicdemo client without `-M`, mp-quic-go server with a multipath controller factory | single path, no frames of the extension, download, key updates |
| `TestPicoquicServerAddressDiscovery`, `...Multipath` | `picoquicdemo -J 0` server (with `-M`), mp-quic-go client with `RequestObservedAddress` and `ProvideObservedAddress` (opens path 1) | QUIC Address Discovery: the server reports the client's address on every path (`Conn.ObservedAddr`, `PathInfo.ObservedAddr`); the client sends no `OBSERVED_ADDRESS` frames, since the server didn't request them |
| `TestPicoquicClientAddressDiscovery`, `...Multipath` | `picoquicdemo -J 2` client (with `-M -A 127.0.0.2/0`), mp-quic-go server with `RequestObservedAddress` and `ProvideObservedAddress` | both endpoints send `OBSERVED_ADDRESS` frames on every path, reporting each other's address |
| `TestPicoquicServerVersion1OfferingVersion2` | picoquicdemo server, mp-quic-go client starting with QUIC version 1 and offering version 2 | the connection uses version 1 (picoquicdemo's server doesn't switch versions), download |
| `TestPicoquicServerVersion2` | picoquicdemo server, mp-quic-go client using QUIC version 2 | the connection uses version 2, download |
| `TestPicoquicClientVersion2` | `picoquicdemo -v 6b3343cf` client, mp-quic-go server | the connection uses version 2, download, key updates (with the key update label of version 2) |
| `TestPicoquicClientVersion1ServerPrefersVersion2` | picoquicdemo client (only offers version 1), mp-quic-go server preferring version 2 | the connection uses version 1, download |
| `TestPicoquicServerPreferredAddress`, `...Multipath` | picoquicdemo server with the preferred address 127.0.0.2 (`-4`) on a second port (`-p <port>:<port of the preferred address>`), with `-M`; mp-quic-go client connecting to 127.0.0.1 | the client migrates to the preferred address (with multipath: path 0), downloads |
| `TestPicoquicServerGreaseQUICBitResetStreamAt` | picoquicdemo server, mp-quic-go client with `EnableQUICBitGreasing` and `EnableStreamResetPartialDelivery` | picoquic sends `grease_quic_bit` (it only does if the client sent it) and `reset_stream_at` with the draft-07 code point; both endpoints send packets with the QUIC Bit set to 0; the client resets a request stream with a RESET_STREAM_AT frame, then downloads |
| `TestPicoquicClientGreaseQUICBitResetStreamAt` | picoquicdemo client, mp-quic-go server with `EnableQUICBitGreasing` and `EnableStreamResetPartialDelivery` | picoquic's client sends `reset_stream_at` (draft-07 code point), but not `grease_quic_bit`: no packet has the QUIC Bit set to 0 |
| `TestPicoquicClientPreferredAddress`, `...Multipath` | mp-quic-go server on 0.0.0.0 with the preferred address 127.0.0.2, picoquicdemo client (with `-M`) connecting to 127.0.0.1 | the server migrates to the preferred address, download |
| `TestPicoquicServerNATRebinding`, `...Multipath` | picoquicdemo server (with `-M`), mp-quic-go client (with path 1 from 127.0.0.2) behind a UDP relay that acts as a NAT: during a download, the relay maps the client's path 0 to a new port | picoquic validates the new address (the client receives a `PATH_CHALLENGE` on path 0) and continues sending to it, the download completes |
| `TestPicoquicServerConnectionMigration` | picoquicdemo server, mp-quic-go client without multipath, which probes a path from a new port with `Conn.AddPath`, and switches to it with `Path.Switch` | the download after the switch is received on the new port; the new `Transport` uses a connection without `OOBCapablePacketConn`, so no ECN is used on the new path |
| `TestPicoquicClientPathStatus` | `picoquicdemo -M -A 127.0.0.2/0` client, mp-quic-go server, which marks path 1 as a backup path during the download (`Conn.SetPathStatus`), and as available again later | picoquic receives `PATH_STATUS_BACKUP` and `PATH_STATUS_AVAILABLE`, sends no packet on path 1 while it is a backup path, and uses it again afterwards (picoquic's qlog) |

## Results

picoquic commit `01e124ebdf9fc50df307e01e71f2744471ddc470` (2026-10-07): all 23 tests pass.

Observations on picoquic (not caused by mp-quic-go):

- When the client switches to a connection ID that the server issued in a `NEW_CONNECTION_ID` or
  `PATH_NEW_CONNECTION_ID` frame while the handshake is still running, picoquicdemo's server drops the Handshake
  and 1-RTT packets that are coalesced with the client's last Initial packet. Section 5.1.1 of RFC 9000 allows any
  active connection ID to be used in any packet type, and upstream quic-go switches connection IDs when the handshake
  completes. The client's frames were retransmitted after a PTO, so the handshake completed one PTO later. mp-quic-go
  now switches connection IDs once the handshake is confirmed, which avoids the delay.
- picoquicdemo's server crashes (NULL dereference in `picoquic_create_packet_header`) when it receives a
  `PATH_CHALLENGE` on a path ID for which it has no connection ID of the client. This happens after the drop
  described above, since the client's `PATH_NEW_CONNECTION_ID` frames were lost. Section 3.1 of the draft lets the
  server delay its `PATH_RESPONSE` in this case. The tests open the second path after a first request was answered.
- picoquicdemo's HTTP/0.9 server doesn't handle the callback for a received `OBSERVED_ADDRESS` frame
  (`picoquic_callback_path_address_observed`): it treats it as an unexpected event on stream 0, resets that stream
  and never answers the request sent on it. The tests run picoquicdemo's server with `-J 0` (provide only), so that it
  doesn't request address observations. picoquicdemo's client handles the callback.
- picoquicdemo's `-4` option takes an IP address without a port. The port of the preferred address is the second port
  of `-p <port>:<local port>`, and the server then listens on both ports. Without it, the port is 0, and mp-quic-go
  ignores the address.
- picoquic only enables multipath if both endpoints sent `initial_max_path_id` with a value larger than 0, and
  doesn't send the transport parameter with the value 0. The draft also enables the extension with the value 0
  (only path 0, section 2.1). mp-quic-go sends 0 if `Config.MaxPaths` is 1. A picoquic client (`-M`) then doesn't
  enable the extension, while an mp-quic-go server configured this way does: the server's first 1-RTT packet after
  the handshake carries `PATH_ACK` and `PATH_RETIRE_CONNECTION_ID` frames, and picoquic closes the connection with a
  `PROTOCOL_VIOLATION`. The connection fails. In the other direction, an mp-quic-go client with `MaxPaths` 1 works with
  picoquic's server, which doesn't send the transport parameter. A server that should only use a single path with
  picoquic clients needs to be configured without a multipath controller, so that it doesn't send the transport
  parameter at all. The default (`MaxPaths` 3) is not affected.
- picoquicdemo's client, started with `-v 00000001 -U 6b3343cf` (version 1, offering version 2), doesn't complete the
  handshake when the server switches to version 2 using compatible version negotiation. It installs the Initial keys
  of version 2 when it receives the server's first Initial packet using version 2, but then treats that packet as
  empty: it acknowledges the packet without processing the ServerHello it carries. Since the packet was
  acknowledged, the server never retransmits the ServerHello, and the connection times out. There is no test for
  this case. mp-quic-go's server completes compatible version negotiation with mp-quic-go's client and with
  ngtcp2's client.
