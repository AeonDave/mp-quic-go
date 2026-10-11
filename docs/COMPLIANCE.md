# Standards compliance of mp-quic-go

This document lists, for every specification that mp-quic-go implements, each requirement stated with MUST or
MUST NOT (and SHALL, SHALL NOT, REQUIRED), where it is implemented and which tests cover it, and every SHOULD,
SHOULD NOT, RECOMMENDED and MAY statement that is not followed, with the reason. It also contains the results of the
conformance tests run against other implementations.

The documents covered are:

- QUIC: [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) (version-independent properties),
  [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) (transport), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)
  (TLS), [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) (loss detection and congestion control),
  [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) (compatible version negotiation),
  [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) (QUIC version 2),
  [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) (greasing the QUIC Bit) and
  [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) (datagrams)
- HTTP/3: [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114), [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)
  (QPACK) and [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) (HTTP Datagrams and the Capsule Protocol)
- Extensions in the RFC Editor queue or in progress:
  [draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21),
  [draft-ietf-quic-address-discovery-01](https://datatracker.ietf.org/doc/html/draft-ietf-quic-address-discovery-01)
  and [draft-ietf-quic-reliable-stream-reset-11](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11)

The state described is that of the v0.3.0 development (the `next` branch, October 2026).

## How the requirements were collected

Every sentence of the documents containing one of the keywords of BCP 14 was extracted from the text versions of the
documents, together with its section. Each sentence with MUST, MUST NOT, SHALL, SHALL NOT or REQUIRED is covered by
one row of the tables in [Requirements by document](#requirements-by-document). A row can cover several sentences of
the same topic; its section column lists the sections of all of them. The requirement column paraphrases the
sentences, so read the specification for the exact wording.

- **Implementation** names the files and functions (or methods) that implement the requirement. Paths are relative
  to the repository root. Some requirements are met by crypto/tls (the TLS 1.3 implementation of the Go standard
  library, used in QUIC mode), or by the [qpack](https://github.com/quic-go/qpack) module.
- **Tests** names the tests that check the behavior, by file. Many requirements are also exercised by the integration
  tests in `integrationtests/self` and by the interop tests, which are not repeated in every row.
- *Not applicable* marks requirements on roles that this module doesn't take (an intermediary, a proxy, a server
  that pushes), on behavior it doesn't have (processing ICMP messages), on future specifications, or on IANA.
- *Application* and *Deployment* mark requirements that the library can't meet on its own: their documentation tells
  the application what to do.
- **Not met** and **Partly met** mark the requirements listed in [Open points](#open-points). No requirement is marked this way.

SHOULD and MAY statements that are followed are not listed. The other documents in this directory explain the
decisions of their areas in more detail: [MP_QUIC_README.md](MP_QUIC_README.md),
[CONNECTION_MIGRATION.md](CONNECTION_MIGRATION.md), [PREFERRED_ADDRESS.md](PREFERRED_ADDRESS.md),
[VERSION_NEGOTIATION.md](VERSION_NEGOTIATION.md), [LOSS_RECOVERY.md](LOSS_RECOVERY.md),
[ADDRESS_DISCOVERY.md](ADDRESS_DISCOVERY.md), [GREASE_QUIC_BIT.md](GREASE_QUIC_BIT.md) and
[RELIABLE_STREAM_RESET.md](RELIABLE_STREAM_RESET.md).

## Summary

| Document | MUST statements | Implemented and tested | Not applicable | Left to the application or deployment | Not met or partly met | SHOULD / MAY not followed |
|---|---|---|---|---|---|---|
| RFC 8999 | 5 | 5 | 0 | 0 | 0 | 0 |
| RFC 9000 | 296 | 276 | 17 | 3 | 0 | 40 |
| RFC 9001 | 78 | 75 | 3 | 0 | 0 | 7 |
| RFC 9002 | 30 | 30 | 0 | 0 | 0 | 10 |
| RFC 9114 | 139 | 108 | 31 | 0 | 0 | 13 |
| RFC 9204 | 37 | 29 | 8 | 0 | 0 | 1 |
| RFC 9221 | 10 | 10 | 0 | 0 | 0 | 3 |
| RFC 9297 | 28 | 15 | 3 | 10 | 0 | 3 |
| RFC 9368 | 35 | 31 | 4 | 0 | 0 | 3 |
| RFC 9369 | 12 | 12 | 0 | 0 | 0 | 1 |
| RFC 9287 | 7 | 6 | 1 | 0 | 0 | 2 |
| draft-ietf-quic-multipath-21 | 36 | 36 | 0 | 0 | 0 | 5 |
| draft-ietf-quic-address-discovery-01 | 9 | 9 | 0 | 0 | 0 | 3 |
| draft-ietf-quic-reliable-stream-reset-11 | 17 | 17 | 0 | 0 | 0 | 2 |

Without IETF Multipath QUIC (a peer that doesn't advertise `initial_max_path_id`), the extension is not used, and a
connection is a standard RFC 9000 connection: no frame, transport parameter value, nonce or packet number space of
the extension is used. The same holds for the other extensions, which are only used when both endpoints negotiated
them. The interop results below show this with implementations that don't support them.

## Open points

All MUST statements in scope are met.

Interpretations where the specification can be read in more than one way:

- RFC 9002, section 7.3.2: the multiplicative decrease of the congestion controller is 0.7 (as in CUBIC, RFC 9438),
  not the 0.5 of the NewReno controller that RFC 9002 describes. Section 7 of RFC 9002 allows other controllers that
  follow section 3.1 of RFC 8085. This is quic-go's controller.
- RFC 9000, section 9.3: an endpoint permits a migration of its peer once the new address is validated. Until then, it
  sends to the previous address, and only answers PATH_CHALLENGE frames on the new path, so it never has to revert to a
  previous address (section 9.3.2).
- RFC 9114, section 6.2.1: frames of unknown and reserved types that arrive before SETTINGS on the control stream are
  skipped, so SETTINGS counts as the first frame. Sections 7.2.8 and 9 require such frames to have no meaning and to be
  ignored; read strictly, section 6.2.1 requires H3_MISSING_SETTINGS for them. Every other frame type before SETTINGS
  is an H3_MISSING_SETTINGS connection error.
- RFC 9297, sections 2 and 3: HTTP Datagrams and capsules are delivered to the application, which knows the protocol of
  the request (e.g. CONNECT-UDP). The application terminates requests that don't define HTTP Datagrams, and skips unknown
  capsule types.

## Fixes made while checking the requirements

The following problems were found while collecting the requirements, and fixed on the `next` branch. Most of them also
exist in quic-go v0.63.0. The [changelog](../CHANGELOG.md) describes them in more detail.

| Requirement | Problem | Commit |
|---|---|---|
| RFC 9000, 5.1 and 10.3.2 | Connection IDs could be issued twice, or used by two connections of a Transport | a0144292 |
| RFC 9000, 10.2.1 | The closing state answered every packet, regardless of the bytes received | a0144292 |
| RFC 9000, 10.3 and 10.3.1 | Stateless resets with a long header weren't recognized; tokens weren't compared in constant time | a0144292 |
| RFC 9000, 17.2.2 | A client accepted Initial packets with a token | cee26e92 |
| RFC 9000, 12.3 and 13.2.3 | Packets of deleted ACK ranges were accepted again | cee26e92 |
| RFC 9000, 12.3; RFC 9001, 6.6 | No limit on packet numbers and on the use of keys at the confidentiality limit | cee26e92 |
| RFC 9001, 4.4, 4.6.1 and 8.4 | Wrong error codes for post-handshake CertificateRequest and max_early_data_size; legacy_session_id accepted | 2e79955c |
| RFC 9000, 21.5.6 | A client migrated to a loopback preferred address of a non-loopback server | be3ab186 |
| RFC 9221, 3 | DATAGRAM frames without support were a FRAME_ENCODING_ERROR | 5057092c |
| draft-ietf-quic-reliable-stream-reset-11, 5.2 | Error code changes after a RESET_STREAM_AT frame with a reliable size of 0 weren't detected | 73b3b8c3 |
| RFC 9114, 4.1.2, 4.3.1, 4.4 and 7.1 | Truncated frames, short bodies, missing `:scheme` and HEADERS frames on CONNECT streams were accepted | 48b5db5c |
| RFC 9114, 6.2; RFC 9297, 2.1.1 | Too few unidirectional streams allowed; HTTP datagrams sent without the H3_DATAGRAM setting | e148b299 |
| RFC 9114, 10.9 (RFC 8470, 4.2) | 0-RTT requests rejected with 425 (Too Early) weren't retried | 2c2d2e7b |
| RFC 9000, 13.2.1 and 19.3 | An ACK frame without ACK ranges was sent after a reordered packet, and the process panicked (from v0.2.3) | 7ba0b1c6 |
| RFC 9000, 8.2.1 | A server never validated a new client address if the PATH_RESPONSE was lost (from v0.2.2) | 7ba0b1c6 |
| RFC 9204, 4.5.1.2 | A field section with a non-zero Delta Base that doesn't use the dynamic table reset the stream (from v0.2.2) | 7ba0b1c6 |
| RFC 9114, 4.4 | A client rejected trailers in the response to a CONNECT request that failed | 7ba0b1c6 |
| RFC 9000, 9.5 | After `Path.Switch` without an unused connection ID, the client used the previous path's connection ID | 7ba0b1c6 |
| RFC 9001, 9.2 (RFC 8446, 8) | 0-RTT was accepted any number of times with the same session ticket | fc4600c8 |
| RFC 9000, 5.1 | A connection ID that was retired and removed could be issued again | a5132aee |
| RFC 9000, 9.2 and 13.4.2 | The client panicked after switching to a path whose connection can't set the ECN bits | eed19534 |

Earlier commits on the branch fixed the problems found by the first conformance runs: CONNECTION_CLOSE after a
stateless reset (d8cf69af), the HTTP/3 frame, SETTINGS and QPACK stream rules (76a91948), compatible version
negotiation with a HelloRetryRequest (6b0063f5, 2bb49663), and the client's connection ID change during the handshake
(f52b1731).

## Conformance tests

All dates are in UTC. The final runs used the code of commit 2c2d2e7b, the last code change described in this
document. (They were built before a lint fix in that commit series, which changed `s.datagramStream.CancelWrite` to
`s.CancelWrite` in `http3.Stream.Close`: the same method, called through the embedded field.) Earlier runs are
listed with their commits. [MAINTAINING.md](MAINTAINING.md#conformance-tests) describes
how to run the tests.

### QUIC interop runner

[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) 740c05a, with the endpoints of
`interop/client` and `interop/server` built into a Docker image (`interop/Dockerfile`, Go 1.27.0). Peer images, pulled
on 2026-10-06:

| Implementation | Image | Digest |
|---|---|---|
| quic-go (upstream) | martenseemann/quic-go-interop:latest | sha256:6743eea41cb8 |
| ngtcp2 | ghcr.io/ngtcp2/ngtcp2-interop:latest | sha256:bd635531dbe2 |
| quiche | cloudflare/quiche-qns:latest | sha256:982b4ba7ba88 |
| picoquic | privateoctopus/picoquic:latest | sha256:7e4110e3260c |
| msquic | ghcr.io/microsoft/msquic/qns:main | sha256:ef95e1bc5ca7 |

**Test environment.** The runner's ns-3 network simulator couldn't forward traffic on the test host (Docker 29 adds
raw-table rules that drop packets between the simulator's networks when `br_netfilter` is loaded), and the host's
firewall was not changed. The runs used a stand-in for the simulator instead: one bridge network with the runner's
addresses, a router container that forwards between client and server and emulates the scenarios (tbf and netem for
bandwidth, delay, loss and corruption, nftables for the dropped packets of `handshakeloss`, iptables for blackholes and
NAT rebinding), and captures on its interfaces, so that the runner's checks of the packet traces work unchanged. The
setup was calibrated with upstream quic-go against itself, which reproduced the public results of
[interop.seemann.io](https://interop.seemann.io) (run of 2026-10-05) in all 22 test cases. Loss, corruption, blackhole
and rebinding are approximations of the ns-3 scenarios. The measurements (goodput, cross traffic) were not run.

**Final runs** (2026-10-06, 12:59 to 14:28, image built from commit 2c2d2e7b as described above, one run of each test
case and pair). ✓ passed, ✕ failed, ? not supported by one of the endpoints (its interop endpoint exits with code 127
for the test case).

All 22 test cases, with mp-quic-go on both sides and with upstream quic-go:

| Test case | mp-quic-go client and server | quic-go client, mp-quic-go server | mp-quic-go client, quic-go server |
|---|---|---|---|
| `handshake` | ✓ | ✓ | ✓ |
| `transfer` | ✓ | ✓ | ✓ |
| `longrtt` | ✓ | ✓ | ✓ |
| `chacha20` | ✓ | ✓ | ✓ |
| `multiplexing` | ✓ | ✓ | ✓ |
| `retry` | ✓ | ✓ | ✓ |
| `resumption` | ✓ | ✓ | ✓ |
| `zerortt` | ✓ | ✓ | ✓ |
| `http3` | ✓ | ✓ | ✓ |
| `blackhole` | ✓ | ✓ | ✓ |
| `keyupdate` | ✓ | ✓ | ✓ |
| `ecn` | ✓ | ? | ? |
| `amplificationlimit` | ✓ | ✓ | ✓ |
| `handshakeloss` | ✓ | ✓ | ✓ |
| `transferloss` | ✓ | ✓ | ✓ |
| `handshakecorruption` | ✓ | ✓ | ✓ |
| `transfercorruption` | ✓ | ✓ | ✓ |
| `ipv6` | ✓ | ✓ | ✓ |
| `v2` | ✓ | ? | ? |
| `rebind-port` | ✓ | ✓ | ✓ |
| `rebind-addr` | ✓ | ✓ | ✓ |
| `connectionmigration` | ✓ | ✕ | ? |

The test cases that cover the changes of this module, with the other implementations (mp-quic-go is the server in the
first four columns and the client in the last four):

| Test case | ngtcp2 client | picoquic client | msquic client | quiche client | ngtcp2 server | picoquic server | msquic server | quiche server |
|---|---|---|---|---|---|---|---|---|
| `handshake` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `transfer` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `chacha20` | ✓ | ✓ | ✓ | ? | ✓ | ✓ | ✓ | ✓ |
| `retry` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `resumption` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `zerortt` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `http3` | ✓ | ✓ | ? | ✓ | ✓ | ✓ | ? | ✓ |
| `keyupdate` | ✓ | ✓ | ✓ | ? | ✓ | ✓ | ✓ | ✓ |
| `ecn` | ✓ | ✓ | ? | ? | ✓ | ✓ | ? | ? |
| `v2` | ✓ | ✕ | ✓ | ? | ✓ | ✓ | ✓ | ? |
| `rebind-addr` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✕ |
| `connectionmigration` | ✕ | ✓ | ✕ | ✕ | ✕ | ✓ | ? | ? |

Every failure has the same result with upstream quic-go in the public results, or is caused by the peer:

- `connectionmigration` with mp-quic-go's server: the clients of quic-go, msquic and quiche don't migrate to a preferred
  address (they fail against every server in the public results). ngtcp2's client connects over IPv6 and doesn't
  migrate to an address of the other family. The interop server only offers its IPv4 address to such a client: it
  recognizes packets sent to the preferred address by their local IP address, so it can't offer another port of the
  address the client connected to. ngtcp2's client passes this test case against servers that do.
- `connectionmigration` with ngtcp2's server: ngtcp2's server fails this test case with every client in the public
  results. mp-quic-go's client migrates and validates the new path; the runner rejects the trace because ngtcp2's first
  packet on the new path carries no PATH_CHALLENGE.
- `rebind-addr` with quiche's server: quiche's server fails this test case with every client in the public results,
  upstream quic-go included.
- `v2` with picoquic's client: picoquic's client acknowledges the server's first Initial packet of version 2 without
  processing it, see [interop/multipath/README.md](../interop/multipath/README.md).

`connectionmigration` with picoquic and `v2` and `ecn` with ngtcp2, picoquic and msquic pass in both roles; upstream
quic-go's interop endpoints don't support these test cases.

**Earlier full matrix** (commit e0aef15a, 2026-10-06, all 22 test cases against all peers in both roles). Compared to
the public results of upstream quic-go for the same pairs, the differences were:

- Failures caused by this module, fixed since: `v2` failed with ngtcp2's client (the server kept version 1 after a
  HelloRetryRequest, fixed in 6b0063f5 and 2bb49663) and with picoquic's server (the client couldn't express "start
  with version 1, prefer version 2", fixed with `Config.InitialVersion` in 4aee0690); `rebind-addr` with picoquic's
  server failed in 4 of 9 runs, after which the client sent a CONNECTION_CLOSE in response to picoquic's stateless
  resets (RFC 9000, section 10.3.1, fixed in d8cf69af; upstream quic-go's client fails the same way). After these fixes,
  `rebind-addr` with picoquic's server passed 5 of 5 runs.
- Not supported at the time, added since: `connectionmigration` (the server's preferred address) and `ecn` in the
  interop endpoints (2cabff8a).
- Failures of the peers or the environment, with the same result for upstream quic-go: picoquic's client acknowledges
  the first Initial packet of version 2 without processing it (`v2` with mp-quic-go's server, see
  [interop/multipath/README.md](../interop/multipath/README.md)); picoquic's and msquic's servers in
  `amplificationlimit`, msquic's in `handshakeloss` and `handshakecorruption`, quiche's in `rebind-port` and
  `rebind-addr`, ngtcp2's server and quiche's client in `multiplexing` (out of file descriptors, or an UBSan abort
  in ngtcp2 at about 1000 open streams); ngtcp2's client doesn't migrate to a preferred address of the other address
  family. Three single failures were lost tshark exit codes in the runner, and passed when run again (3 of 3 each).
- Passing where upstream quic-go fails: `v2` with msquic and ngtcp2 in both roles (upstream doesn't implement version
  2 in its interop endpoints), `connectionmigration` with picoquic's server, `handshakeloss` with ngtcp2's client.

### h3spec

[h3spec](https://github.com/kazu-yamamoto/h3spec) v0.1.14 (binary `h3spec-linux-x86_64`, sha256 7f2e3232715a),
against the server of `example/` and against an `http3.Server` that accepts 0-RTT.

| Server | Date | Runs | Result |
|---|---|---|---|
| `example/` server | 2026-10-06 | 3 | 76 of 77 examples pass in every run |
| `http3.Server` accepting 0-RTT | 2026-10-06 | 2 | 76 of 77 examples pass in every run |

History: the first run (commit e0aef15a, 2026-10-06) had 12 failures in the HTTP/3 section, all of them shared with
upstream quic-go v0.63.0 and its master branch (17 failures; the 5 others are QUIC transport and QPACK checks that
this module had already fixed). They were fixed in 76a91948 (control stream and SETTINGS rules, push frames, QPACK
encoder and decoder streams). The remaining failure is the check "MUST NOT buffer a frame longer than
SETTINGS_MAX_FIELD_SECTION_SIZE": h3spec sends a GOAWAY frame with a Length of 2^30 and no payload, and expects
H3_EXCESSIVE_LOAD (or H3_GENERAL_PROTOCOL_ERROR). The server closes the connection with H3_FRAME_ERROR right away,
since a GOAWAY payload is a single variable-length integer, and RFC 9114 (section 7.1) requires H3_FRAME_ERROR for
frames whose length doesn't match their fields. No MUST statement requires H3_EXCESSIVE_LOAD here.

A separate probe (31 cases, written for this check, run on 2026-10-06 against the `example/` server) sends hand-made
control, request and QPACK streams. 28 cases end as RFC 9114, RFC 9204 and RFC 9297 require: with the required error
code, or without an error where the frame or setting is allowed. The other three:

- A reserved frame type before SETTINGS on the control stream is accepted. Section 7.2.8 of RFC 9114 allows reserved
  frame types on any stream, while a strict reading of section 6.2.1 requires SETTINGS as the first frame (see [Open points](#open-points)).
- A SETTINGS or MAX_PUSH_ID frame inside a request body is an H3_FRAME_UNEXPECTED connection error when the handler
  reads the body (`TestStreamInvalidFrame`). The probe's handler doesn't read it: after the response, the server stops
  reading the stream with H3_NO_ERROR (section 4.1 of RFC 9114), and the frames are never processed.

### Multipath interoperability with picoquic

picoquic 01e124ebdf9f (built against picotls bfa67875982a), which implements the code points of
draft-ietf-quic-multipath-21.

**Scenarios** (2026-10-06, commit 2c2d2e7b): an HTTP/0.9 client and server built on this module, run against
`picoquicdemo` on loopback, with path 0 from 127.0.0.1 and further paths from 127.0.0.2 (or another port). Each
scenario checks the qlogs of both endpoints.

| Scenario | mp-quic-go client, picoquic server | picoquic client, mp-quic-go server |
|---|---|---|
| Multipath negotiated, second path from another address or port, transfer on both paths, key updates | Pass | Pass |
| 400 MB on two paths, several key updates by either endpoint | Pass | Pass |
| PATH_STATUS_BACKUP and PATH_STATUS_AVAILABLE (picoquic stops and resumes sending on the backup path) | Pass | Pass (`TestPicoquicClientPathStatus`) |
| PATH_ABANDON by either endpoint, including path 0; transfer continues on the other paths | Pass | Pass |
| Path ID limits: MAX_PATH_ID, PATHS_BLOCKED, refusal of paths above the limit | Pass | Pass (three extra paths offered, two allowed) |
| NAT rebinding, connection ID change and migration to a new port, with and without multipath | Pass (`TestPicoquicServerNATRebinding`, `...Multipath`, `TestPicoquicServerConnectionMigration`) | Pass |
| Fallback to a single path when either endpoint doesn't offer multipath (no multipath transport parameter, frame or nonce on the wire) | Pass | Pass |
| `Config.MaxPaths` 1 (`initial_max_path_id` 0) | Single path: picoquic's server doesn't send the transport parameter | Fails: see below |

92 checks passed in 25 runs. With `MaxPaths` 1, mp-quic-go sends `initial_max_path_id` 0, which section 2.1 of the
draft defines as enabling the extension without extra paths. picoquic only enables the extension when both values are
greater than 0, and closes the connection with PROTOCOL_VIOLATION when the mp-quic-go server sends the PATH_ACK frames
of the negotiated extension. This is a picoquic issue, described in
[interop/multipath/README.md](../interop/multipath/README.md), together with the configuration that avoids it.
Earlier runs of the same scenarios (commit e0aef15a) were repeated 5 times each, and all 85 runs passed.

**Repository suite** (`go test -tags picoquic ./interop/multipath/...`, 2026-10-07, commit c832177c, picoquic
01e124ebdf9f in Docker): all 23 tests passed, and the 4 tests added in commit c832177c passed 15 runs each. They run picoquicdemo as client and as server against mp-quic-go, with and without multipath,
abandoning paths, the server's preferred address (with and without multipath), QUIC Address Discovery (with and without
multipath), greasing the QUIC Bit together with RESET_STREAM_AT, QUIC version 2 (with compatible version negotiation
from version 1), a NAT rebinding of the client and an RFC 9000 migration of the client to a new port, and PATH_STATUS
sent by the server. The migration test found a panic of the client after switching to a path whose connection can't
set the ECN bits, fixed in commit eed19534.

**Public server** (test.privateoctopus.com:4433, picoquic, 2026-10-06, commit 2c2d2e7b, IPv4): multipath negotiated,
data on two paths with a key update, PATH_STATUS (no data on the backup path), and PATH_ABANDON of paths 1 and 0 with
the transfer continuing on path 2 all passed. The first request after the handshake took 195 to 197 ms, about one round trip. Before
commit f52b1731, the client switched to a new connection ID while the handshake was running, picoquic dropped the
client's coalesced Handshake packet, and the first request took about 980 ms, one Handshake PTO longer.

### Mixed versions

A client and a server built from commit 2c2d2e7b and from v0.2.3, both configured with a multipath controller,
transferred 20 MB in all four combinations (2026-10-06). Between two endpoints of the same version, multipath was
negotiated. Between this version and v0.2.3 (in both roles), neither endpoint negotiated multipath, and the transfer
completed on a single path.

### Fuzzing

Native Go fuzzing (Go 1.27.1), `-parallel 16`, about 3 minutes and 15 seconds per target.

Final runs (2026-10-06, commit 2c2d2e7b), for the targets whose code changed in the fixes listed above:

| Package | Target | Executions | New inputs found | Result |
|---|---|---|---|---|
| internal/handshake | FuzzClientHelloTransportParameters | 697,218 | 7 | No crash |
| internal/handshake | FuzzHandshake | 8,435,484 | 56 | No crash |
| http3 | FuzzFrameParser | 18,042,839 | 22 | No crash |
| http3 | FuzzHeaderParsing | 16,851,871 | 64 | No crash |
| internal/wire | FuzzFrames | 25,841,944 | 21 | No crash |

Earlier runs of all targets (2026-10-06, commit e0aef15a with the fuzz tests extended to the extension frames and
transport parameters): FuzzFrames (20.9 million executions), FuzzTransportParameters (29.7 million), FuzzHeaderParser
(30.8 million), FuzzHandshake (5.5 million), FuzzFrameParser (11.9 million), FuzzHeaderParsing (17.3 million),
FuzzCheckFieldSection (6.0 million), FuzzParsePriority (18.9 million), FuzzFrameSorter (15.1 million), FuzzFindSNI
(23.3 million) and FuzzEncoder of qlogwriter/jsontext (12.3 million). None of them found a crash.

FuzzFrames covers every frame type, including those of multipath, ADD_ADDRESS, OBSERVED_ADDRESS and RESET_STREAM_AT,
and checks that each frame parses back to itself after serialization. FuzzTransportParameters covers the transport
parameters of the extensions and the parameters stored in session tickets. FuzzClientHelloTransportParameters parses
ClientHello messages and their transport parameters, and FuzzFrameParser covers the HTTP/3 frames, including those
of server push.

## Requirements by document

### RFC 8999: Version-Independent Properties of QUIC

[RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) has 5 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 6 | Ignore the Unused bits of Version Negotiation packets | `internal/wire/version_negotiation.go`: `ParseVersionNegotiationPacket` | `internal/wire/version_negotiation_test.go`: `TestParseVersionNegotiationPacket` |
| 6 | Ignore Version Negotiation packets without (complete) Supported Version fields | `internal/wire/version_negotiation.go`: `ParseVersionNegotiationPacket`; `connection.go`: `handleVersionNegotiationPacket` | `internal/wire/version_negotiation_test.go`: `TestParseVersionNegotiationPacketEmptyVersions`, `TestParseVersionNegotiationPacketWithInvalidLength` |
| 6 | Version Negotiation packets swap the connection IDs of the received packet | `internal/wire/version_negotiation.go`: `ComposeVersionNegotiation`; `server.go`: `maybeSendVersionNegotiationPacket` | `server_test.go`: `TestServerVersionNegotiation` |
| 7 | Authenticate the Version Negotiation packet before using another version | `internal/handshake/version_negotiation.go`: `validateVersionInformation` (RFC 9368) | `integrationtests/versionnegotiation/compatible_test.go`: `TestVersionDowngradePrevention` |

### RFC 9000: QUIC transport

[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) has 296 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 2.1 | Never reuse a stream ID | `streams_map_outgoing.go`: `openStream`; `streams_map_incoming.go`: `GetOrOpenStream` | `streams_map_outgoing_test.go`: `TestStreamsMapOutgoingOpenAndDelete`; `streams_map_incoming_test.go`: `TestStreamsMapIncomingGettingStreams` |
| 2.2 | Deliver stream data as an ordered byte stream | `frame_sorter.go`: `Push`, `Pop`; `receive_stream.go`: `readImpl` | `frame_sorter_test.go`: `TestFrameSorterRandomized`; `receive_stream_test.go`: `TestReceiveStreamReadOverlappingData` |
| 2.2 | Data at an offset doesn't change when retransmitted | `send_stream.go`: `popRetransmissionFrame` (retransmits the original STREAM frames) | `send_stream_test.go`: `TestSendStreamRetransmissions` |
| 2.2 | Only send data within the peer's flow control limits | `send_stream.go`: `popNewStreamFrame`; `flow_controller_stream.go`: `SendWindowSize`; `flow_controller_connection.go`: `SendWindowSize` | `send_stream_test.go`: `TestSendStreamFlowControlBlocked`; `flow_controller_stream_test.go`: `TestStreamSendWindow` |
| 3.2 | Create all lower-numbered streams of a type before a stream | `streams_map_incoming.go`: `GetOrOpenStream` | `streams_map_incoming_test.go`: `TestStreamsMapIncomingGettingStreams` |
| 3.3 | No STREAM, STREAM_DATA_BLOCKED or RESET_STREAM frames from a terminal or "Reset Sent" state | `send_stream.go`: `CancelWrite`, `popStreamFrame`, `getControlFrame` | `send_stream_test.go`: `TestSendStreamCancellation`, `TestSendStreamCancellationStreamRetransmission` |
| 3.5 | Answer STOP_SENDING with RESET_STREAM in "Ready" or "Send" | `send_stream.go`: `handleStopSendingFrame` | `send_stream_test.go`: `TestSendStreamStopSendingAfterWrite`, `TestSendStreamStopSendingDuringWrite` |
| 4.1 | Don't exceed the stream or connection limit | `send_stream.go`: `popNewStreamFrame`; `flow_controller_connection.go`: `AddBytesSentWithLimiter` | `send_stream_test.go`: `TestSendStreamFlowControlBlocked` |
| 4.1 | FLOW_CONTROL_ERROR when the peer exceeds a limit | `flow_controller_stream.go`: `UpdateHighestReceived`; `flow_controller_connection.go`: `IncrementHighestReceived` | `flow_controller_stream_test.go`: `TestStreamFlowControlReceiving`; `flow_controller_connection_test.go`: `TestConnectionFlowControlViolation` |
| 4.1 | Ignore MAX_DATA / MAX_STREAM_DATA that don't increase the limit | `flow_controller_connection.go`: `UpdateSendWindow`; `flow_controller_stream.go`: `UpdateSendWindow` | `flow_controller_stream_test.go`: `TestStreamSendWindow` |
| 4.2 | Don't wait for a blocked frame before sending MAX_DATA / MAX_STREAM_DATA | `flow_controller_base.go`: `hasWindowUpdate`; `receive_stream.go`: `readImpl` (window updates are queued as the application reads) | `flow_controller_stream_test.go`: `TestStreamWindowUpdate`; `flow_controller_connection_test.go`: `TestConnectionFlowControlWindowUpdate` |
| 4.4 | Keep flow control state of the unterminated direction | `receive_stream.go`: `cancelReadImpl`, `handleStreamFrameImpl` (frames after CancelRead still count); `flow_controller_stream.go`: `Abandon` | `receive_stream_test.go`: `TestReceiveStreamCancelReadAbandonsUnreadData`; `flow_controller_stream_test.go`: `TestStreamAbandoning` |
| 4.5 | Account the final size in the connection flow controller | `receive_stream.go`: `handleResetStreamFrameImpl`; `flow_controller_stream.go`: `UpdateHighestReceived` | `flow_controller_stream_test.go`: `TestStreamFlowControllerFinalOffset`; `receive_stream_test.go`: `TestReceiveStreamReset` |
| 4.5 | Don't send data at or beyond the final size | `send_stream.go`: `Close`, `write` (writes after Close fail) | `send_stream_test.go`: `TestSendStreamClose` |
| 4.6 | Stream limit above 2^60: TRANSPORT_PARAMETER_ERROR (transport parameter) or FRAME_ENCODING_ERROR (frame) | `internal/wire/transport_parameters.go`: `readNumericTransportParameter`; `internal/wire/max_streams_frame.go`: `parseMaxStreamsFrame` | `internal/wire/transport_parameter_test.go`: `TestTransportParameterErrors`; `internal/wire/max_streams_frame_test.go`: `TestParseMaxStreamsErrorsOnTooLargeStreamCount` |
| 4.6 | Don't exceed the peer's stream limit | `streams_map_outgoing.go`: `OpenStream`, `OpenStreamSync` | `streams_map_outgoing_test.go`: `TestStreamsMapOutgoingLimits` |
| 4.6 | STREAM_LIMIT_ERROR for a stream ID above the local limit | `streams_map_incoming.go`: `GetOrOpenStream` | `streams_map_incoming_test.go`: `TestStreamsMapIncomingGettingStreams`; `streams_map_test.go`: `TestStreamsMapStreamLimits` |
| 4.6 | Ignore MAX_STREAMS that don't increase the limit | `streams_map_outgoing.go`: `SetMaxStream` | `streams_map_outgoing_test.go`: `TestStreamsMapOutgoingLimits` |
| 4.6 | Don't wait for STREAMS_BLOCKED before raising the stream limit | `streams_map_incoming.go`: `deleteStream` (MAX_STREAMS queued when a stream is closed) | `streams_map_incoming_test.go`: `TestStreamsMapIncomingDeletingStreams` |
| 5.1 | Connection IDs carry no information that correlates them | `internal/protocol/connection_id.go`: `GenerateConnectionID` (crypto/rand) | `internal/protocol/connection_id_test.go`: `TestGenerateRandomConnectionIDs` |
| 5.1 | Never issue the same connection ID twice on a connection | `conn_id_permutation.go`: `connIDPermutation` (with the built-in generator, the n-th connection ID of a connection is the encryption of n with a Feistel network over the bits of the connection ID, using AES with a random key of the connection: distinct counters give distinct connection IDs, without remembering them); `conn_id_generator.go`: `issueNewConnID`, `generateUnusedConnID`, `connIDInUse` (the initial connection IDs, chosen before the connection was created, are never issued; connection IDs used by other connections of the Transport are skipped). A `Transport.ConnectionIDGenerator` set by the application must never return a connection ID twice (*Application*) | `conn_id_generator_test.go`: `TestConnIDGeneratorNeverReissuesConnIDs` (more than 2^16 connection IDs of 4 bytes), `TestConnIDGeneratorDoesntIssueInitialConnIDs`, `TestConnIDGeneratorUniqueConnIDs`; `conn_id_permutation_test.go`: `TestConnIDPermutationShortConnIDs` |
| 5.1 | No zero-length connection IDs for concurrent connections on one address | `transport.go`: `init` (zero-length connection IDs only for the single-use Transport of Dial / DialAddr) | `integrationtests/self/conn_id_test.go`: `TestConnectionIDsZeroLength` |
| 5.1.1 | Sequence numbers increase by 1 | `conn_id_generator.go`: `issueNewConnID` | `conn_id_generator_test.go`: `TestConnIDGeneratorIssueAndRetire` |
| 5.1.1 | Accept packets for an issued connection ID until it is retired | `conn_id_generator.go`: `issueNewConnID`, `RetireForPath`; `transport.go`: `Add`, `Remove` | `conn_id_generator_test.go`: `TestConnIDGeneratorIssueAndRetire`, `TestConnIDGeneratorRetiring` |
| 5.1.1 | Don't issue more connection IDs than the peer's limit | `conn_id_generator.go`: `SetMaxActiveConnIDs`, `topUp` | `conn_id_generator_test.go`: `TestConnIDGeneratorIssueAndRetire` |
| 5.1.1 | CONNECTION_ID_LIMIT_ERROR when the active connection IDs exceed the local limit | `conn_id_manager.go`: `addConnectionID` | `conn_id_manager_test.go`: `TestConnIDManagerLimit` |
| 5.1.2 | On an increased Retire Prior To, retire the connection IDs before adding the new one | `conn_id_manager.go`: `add` | `conn_id_manager_test.go`: `TestConnIDManagerRetiringConnectionIDs` |
| 5.1.2 | Don't forget a connection ID without retiring it | `conn_id_manager.go`: `add`, `queueRetireConnectionIDFrame` | `conn_id_manager_test.go`: `TestConnIDManagerRetiringConnectionIDs` |
| 5.2 | Generate a connection error or revert changes when an error is found while processing a packet | `connection.go`: `handleFrames` (a frame error closes the connection) | `connection_test.go`: `TestConnectionServerInvalidFrames` |
| 5.2.1 | Client: discard packets of another version | `connection.go`: `handleOnePacket` (acceptsVersion) | `connection_test.go`: `TestConnectionVersionNegotiation`; `internal/handshake/version_negotiation_test.go`: `TestInitialOpenersDuringCompatibleVersionNegotiation` |
| 5.2.2 | Server: drop small packets with unsupported versions | `server.go`: `handlePacketImpl` (protocol.MinUnknownVersionPacketSize) | `server_test.go`: `TestServerPacketDropping` |
| 5.2.2 | Server: drop packets in all other cases | `server.go`: `handlePacketImpl` | `server_test.go`: `TestServerPacketDropping` |
| 5.2.3 | Deployments with simple load balancing avoid a stateless reset oracle | Deployment: Transport.StatelessResetKey must only be shared by Transports that receive all packets of their connections (documented on the field) | - |
| 6.1 | Never send a Version Negotiation packet in response to one | `server.go`: `handlePacketImpl` (Version Negotiation packets are dropped) | `server_test.go`: `TestServerPacketDropping` |
| 6.2 | Client: abandon the attempt on a Version Negotiation packet, unless it processed another packet, or the packet lists its version | `connection.go`: `handleVersionNegotiationPacket` | `connection_test.go`: `TestConnectionVersionNegotiation`, `TestConnectionVersionNegotiationInvalidPackets` |
| 7 | The handshake provides authenticated key exchange, authenticated transport parameters, authenticated version negotiation, ALPN | `internal/handshake/crypto_setup.go` (TLS 1.3 using crypto/tls); `internal/handshake/version_negotiation.go`: `validateVersionInformation` | `integrationtests/self/handshake_test.go`: `TestHandshake`; `internal/handshake/crypto_setup_test.go`: `TestTransportParameters`; `integrationtests/versionnegotiation/compatible_test.go`: `TestVersionDowngradePrevention` |
| 7 | Negotiate an application protocol | crypto/tls (QUIC mode requires ALPN); `internal/handshake/tls_config_go127.go`: `setupConfigForServer` | `integrationtests/self/handshake_test.go`: `TestALPN` |
| 7.2 | Client's initial Destination Connection ID is at least 8 bytes | `internal/protocol/connection_id.go`: `GenerateConnectionIDForInitial` | `internal/protocol/connection_id_test.go`: `TestGenerateRandomLengthDestinationConnectionIDs` |
| 7.2 | Client uses the same Destination Connection ID until it receives a packet | `connection.go`: `handleLongHeaderPacket`; `conn_id_manager.go`: `ChangeInitialConnID` | `connection_test.go`: `TestConnectionHandshakeClient` |
| 7.2 | Client discards Initial packets with another Source Connection ID once it received one | `connection.go`: `handleLongHeaderPacket` | `connection_test.go`: `TestConnectionServerInvalidPackets` |
| 7.2 | Client changes the Destination Connection ID only for the first Initial or Retry | `connection.go`: `handleRetryPacket`, `handleUnpackedLongHeaderPacket` | `connection_test.go`: `TestConnectionRetryAfterReceivedPacket` |
| 7.2 | Server sets the Destination Connection ID from the first Initial | `server.go`: `handleInitialImpl` | `server_test.go`: `TestServerCreateConnection` |
| 7.3 | Transport parameters match the connection IDs used | `connection.go`: `checkTransportParameters` | `connection_test.go`: `TestConnectionTransportParameterValidationFailureClient`, `TestConnectionTransportParameterValidationFailureServer` |
| 7.3 | Missing or mismatching initial_source_connection_id / original_destination_connection_id / retry_source_connection_id: TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `unmarshal`; `connection.go`: `checkTransportParameters` | `internal/wire/transport_parameter_test.go`: `TestTransportParameterErrors`; `connection_test.go`: `TestConnectionTransportParameterValidationFailureClient` |
| 7.4 | Invalid transport parameter values: TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `unmarshal`, `readNumericTransportParameter` | `internal/wire/transport_parameter_test.go`: `TestTransportParameterErrors` |
| 7.4 | Don't send a transport parameter twice | `internal/wire/transport_parameters.go`: `Marshal` | `internal/wire/transport_parameter_test.go`: `TestMarshalAndUnmarshalTransportParameters`, `TestTransportParameterRejectsDuplicateParameters` |
| 7.4.1 | New transport parameters define whether they are remembered for 0-RTT | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket` (documented per parameter) | `internal/wire/transport_parameter_test.go`: `TestTransportParametersFromSessionTicket` |
| 7.4.1 | Don't use remembered ack_delay_exponent, max_ack_delay, connection IDs, preferred_address, stateless_reset_token | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket` (not stored) | `internal/wire/transport_parameter_test.go`: `TestTransportParametersFromSessionTicket` |
| 7.4.1 | Client remembers the other parameters and only uses them in 0-RTT | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket`; `connection.go`: `restoreTransportParameters` | `connection_test.go`: `TestConnection0RTTTransportParameters`; `integrationtests/self/zero_rtt_test.go`: `Test0RTTWithIncreasedStreamLimit` |
| 7.4.1 | Server accepting 0-RTT doesn't reduce limits; rejects 0-RTT if remembered values can't be supported | `internal/handshake/crypto_setup.go`: `handleDataFromSessionState`; `internal/wire/transport_parameters.go`: `ValidFor0RTT` | `internal/handshake/crypto_setup_test.go`: `Test0RTTRejectionOnTransportParametersChanged`; `integrationtests/self/zero_rtt_test.go`: `Test0RTTRejectedOnStreamLimitDecrease`, `Test0RTTRejectedOnConnectionWindowDecrease` |
| 7.4.2 | Ignore unknown transport parameters | `internal/wire/transport_parameters.go`: `unmarshal` | `internal/wire/transport_parameter_test.go`: `TestTransportParameterUnknownParameters` |
| 7.5 | Buffer at least 4096 bytes of out-of-order CRYPTO data | `crypto_stream.go`: `HandleCryptoFrame` (protocol.MaxCryptoStreamOffset, 16 KB) | `crypto_stream_test.go`: `TestCryptoStreamMaxOffset` |
| 7.5 | CRYPTO_BUFFER_EXCEEDED if the buffer isn't expanded | `crypto_stream.go`: `HandleCryptoFrame` | `crypto_stream_test.go`: `TestCryptoStreamMaxOffset` |
| 7.5 | Acknowledge packets with discarded CRYPTO frames | `crypto_stream.go`: `HandleCryptoFrame` (already received data is dropped, the packet is acknowledged) | `crypto_stream_test.go`: `TestCryptoStreamReceiveDataAfterFinish` |
| 8, 8.1 | Limit data sent to an unvalidated address to 3 times the data received | `internal/ackhandler/sent_packet_handler.go`: `isAmplificationLimited`, `isPathAmplificationLimited`; `path_manager.go`: `HandlePacket` (path probes) | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerAmplificationLimitServer`; `connection_test.go`: `TestConnectionServerPathProbeAmplificationLimit` |
| 8.1 | Count all bytes of datagrams attributed to the connection | `connection.go`: `handleOnePacket` (ReceivedBytes before parsing) | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerAmplificationLimitServer` |
| 8.1 | Client pads datagrams with Initial packets to 1200 bytes | `packet_packer.go`: `initialPaddingLen` | `packet_packer_test.go`: `TestPackLongHeaders`; `integrationtests/self/mtu_test.go`: `TestInitialPacketSize` |
| 8.1 | Client sends on PTO, an Initial of 1200 bytes or a Handshake packet | `internal/ackhandler/sent_packet_handler.go`: `setLossDetectionTimer`, `OnLossDetectionTimeout` (peerCompletedAddressValidation) | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerAmplificationLimitClient` |
| 8.1.1 | Tokens tell how they were provided (Retry or NEW_TOKEN) | `internal/handshake/token_generator.go`: `NewRetryToken`, `NewToken`, `DecodeToken` | `internal/handshake/token_generator_test.go`: `TestTokenGeneratorValidToken` |
| 8.1.2 | Client repeats the Retry token in all Initial packets | `connection.go`: `handleRetryPacket`; `packet_packer.go`: `SetToken` | `connection_test.go`: `TestConnectionRetryDrops`; `server_test.go`: `TestServerRetry` |
| 8.1.3 | Client includes the NEW_TOKEN token in all Initial packets | `client.go`: `Dial` (TokenStore.Pop); `packet_packer.go`: `SetToken` | `integrationtests/self/handshake_test.go`: `TestTokensFromNewTokenFrames` |
| 8.1.3 | Retry tokens are only used for the current connection attempt | `connection.go`: `handleRetryPacket` (never stored in the TokenStore) | `integrationtests/self/handshake_test.go`: `TestTokensFromNewTokenFrames` |
| 8.1.3 | NEW_TOKEN tokens are unlinkable and unique | `internal/handshake/token_protector.go`: `NewToken` (AEAD with a random nonce) | `internal/handshake/token_protector_test.go`: `TestTokenProtectorEncodeAndDecode` |
| 8.1.3 | Only send tokens to the server that issued them | `token_store.go`; `connection.go` (token store key: server name) | `token_store_test.go`: `TestTokenStoreMultipleOrigins` |
| 8.1.3 | Server validates tokens in Initial packets | `server.go`: `validateToken`, `handleInitialImpl` | `server_test.go`: `TestServerTokenValidation` |
| 8.1.4 | Address validation tokens are difficult to guess and integrity-protected | `internal/handshake/token_protector.go`: `NewToken`, `DecodeToken` (AES-GCM, key derived with HKDF, random nonce) | `internal/handshake/token_protector_test.go`: `TestTokenProtectorEncodeAndDecode`, `TestTokenProtectorInvalidTokens` |
| 8.1.4 | NEW_TOKEN tokens encode the client's IP address; another address gets no address validation | `internal/handshake/token_generator.go`: `NewToken`, `encodeRemoteAddr`; `server.go`: `validateToken` | `internal/handshake/token_generator_test.go`: `TestTokenGeneratorValidToken`; `server_test.go`: `TestServerTokenValidation` |
| 8.1.4 | Limit the replay of tokens | `internal/handshake/token_generator.go`: `DecodeToken`; `server.go`: `validateToken` (tokens expire: Transport.MaxTokenAge, Retry tokens after 5 s) | `server_test.go`: `TestServerTokenValidation` |
| 8.2.1 | Unpredictable data in every PATH_CHALLENGE | `path_manager.go`: `HandlePacketOnLocalAddr`; `path_manager_outgoing.go`: `enqueueProbe`; `multipath_path.go`: `startPathValidation` (crypto/rand) | `path_manager_test.go`: `TestPathManagerIntentionalMigration`; `path_manager_outgoing_test.go`: `TestPathManagerOutgoingPathProbing` |
| 8.2.1 | Expand datagrams with PATH_CHALLENGE to 1200 bytes (unless amplification-limited, then validate again with 1200 bytes); don't discard small probing datagrams | `packet_packer.go`: `PackPathProbePacket`, `pathValidationPadding`; `path_manager.go`: `ChallengeNotExpanded`, `PopDueChallenge` | `path_manager_test.go`: `TestPathManagerChallengeNotExpanded`; `packet_packer_test.go`: `TestPackPathProbePacket`; `connection_test.go`: `TestConnectionServerPathProbeAmplificationLimit` |
| 8.2.2, 19.17 | Echo the PATH_CHALLENGE data in a PATH_RESPONSE, without delay | `connection.go`: `queuePathResponses`; `path_manager.go`: `HandlePacketOnLocalAddr` | `connection_test.go`: `TestConnectionServerPathChallengeOnCurrentPath`, `TestConnectionPathChallengesInOnePacket` |
| 8.2.2 | Send the PATH_RESPONSE on the path of the PATH_CHALLENGE; the initiator doesn't enforce it | `connection.go`: `respondOnProbedPath`, `handlePathResponseFrame` | `connection_test.go`: `TestConnectionClientPathResponseOnProbedPath`, `TestConnectionServerPathChallengesOnNewPath` |
| 8.2.2 | Expand datagrams with PATH_RESPONSE to 1200 bytes, within the anti-amplification limit | `packet_packer.go`: `pathValidationPadding` | `packet_packer_test.go`: `TestPackPathResponsePadding`, `TestPackCoalescedPathResponsePadding`; `integrationtests/self/nat_rebinding_test.go`: `TestNATRebinding` |
| 8.2.2 | One PATH_RESPONSE per PATH_CHALLENGE | `framer.go`: `QueueControlFrame` (PATH_RESPONSE frames are not retransmitted); `connection.go`: `queuePathResponses` | `framer_test.go`: `TestFramerPacksSinglePathResponsePerPacket`, `TestFramerDetectsFramePathResponseDoS` |
| 8.2.3 | Validate again with an expanded datagram if the PATH_CHALLENGE wasn't expanded | `path_manager.go`: `HandlePathResponseFrame`, `ChallengeNotExpanded` | `path_manager_test.go`: `TestPathManagerChallengeNotExpanded`, `TestPathManagerChallengeNotExpandedLost` |
| 9 | No migration before the handshake is confirmed | `connection.go`: `sendPackets` (path probes only after confirmation); `path_manager_outgoing.go`: `switchToPath` (only validated paths); `multipath_path.go` (paths only after confirmation) | `connection_test.go`: `TestConnectionMigration` |
| 9, 18.2 | With disable_active_migration, no packets from a new local address to the handshake address, unless the client used the preferred address | `connection.go`: `addSinglePath`, `AddPath` | `connection_test.go`: `TestConnectionMigration`; `multipath_path_test.go`: `TestMultipathAddPath`; `preferred_address_test.go`: `TestConnectionServerPreferredAddressMigration` |
| 9 | If the peer migrates anyway: drop the packets or validate the path | `path_manager.go`: `HandlePacketOnLocalAddr` (the path is validated) | `connection_test.go`: `TestConnectionMigrationServer` |
| 9 | Validate every new peer address | `path_manager.go`: `HandlePacketOnLocalAddr`; `multipath_path.go` | `path_manager_test.go`: `TestPathManagerNATRebinding`; `connection_test.go`: `TestConnectionPathValidation` |
| 9 | Client discards packets from unknown server addresses | `connection.go`: `handleOnePacket`, `isKnownServerAddr0` | `connection_test.go`: `TestConnectionClientDropsPacketsFromUnknownServerAddress`, `TestConnectionClientDropsPacketsFromUnknownServerAddressEndToEnd` |
| 9.3 | After permitting a migration, send to the new address and validate it; protect against attacks when sending to an unvalidated address | `path_manager.go`: `HandlePacketOnLocalAddr`, `SwitchToPathOnLocalAddr` (the migration is permitted once the new address is validated; no data is sent to unvalidated addresses) | `connection_test.go`: `TestConnectionMigrationServer`; `path_manager_test.go`: `TestPathManagerNATRebinding` |
| 9.3.2 | Revert to the last validated address if a validation fails; without one, close silently | `path_manager.go`: `SwitchToPathOnLocalAddr` (the connection only switches to validated addresses, so it never needs to revert) | `path_manager_test.go`: `TestPathManagerNATRebinding` |
| 9.3.3 | Validate the previously active path after an apparent migration | `path_manager.go`: `AddPreviousPath`; `connection.go`: `switchToNewPath` | `connection_test.go`: `TestConnectionServerMigrationValidatesPreviousPath`; `path_manager_test.go`: `TestPathManagerPreviousPath` |
| 9.4 | New path: packets of the old path don't count, congestion controller and RTT estimate are reset | `internal/ackhandler/sent_packet_handler.go`: `MigratedPath`, `MigratedPathForPath`; `internal/utils/rtt_stats.go`: `ResetForPathMigration`; `internal/congestion/cubic_sender.go`: `OnConnectionMigration` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerMigratedPathWithPathProbes`; `internal/congestion/cubic_sender_test.go`: `TestCubicSenderResetAfterConnectionMigration`; `internal/utils/rtt_stats_test.go`: `TestRTTStatsResetForPathMigration` |
| 9.4 | The PATH_CHALLENGE retransmission timer is not more aggressive than the PTO | `path_manager_outgoing.go`: `Probe` (starts at 200 ms, the PTO of a path without RTT sample, see internal/utils/rtt_stats.go:PTO, and doubles); `multipath_path.go`: `startPathValidation`; `preferred_address.go`: `startPreferredAddrValidation` (start at the PTO, and double); `path_manager.go`: `pathChallenges.retryDue` (a server sends another PATH_CHALLENGE to an unvalidated client address when it receives a packet from it, at the earliest after the PTO, doubling, up to 5 times; also used by `multipath_tuple_manager.go`) | `path_manager_outgoing_test.go`: `TestPathManagerOutgoingRetransmissions`; `multipath_path_test.go`: `TestMultipathClientPathValidationTimeout`; `path_manager_test.go`: `TestPathManagerRetryPathChallenge`, `TestPathManagerAcknowledgedPathChallengeLostResponse`; `multipath_tuple_manager_test.go`: `TestTupleManagerRetryPathChallenge`; `connection_test.go`: `TestConnectionPathValidationRetry` |
| 9.5 | Never use a connection ID from more than one local address or towards more than one peer address | `conn_id_manager.go`: `GetConnIDForPath`, `UseConnIDForPath`, `HasConnIDForPath` (a switch with `Path.Switch` waits for an unused connection ID), `UseConnIDForTuple`; `connection.go`: `switchToNewPath`, `respondOnProbedPath` | `connection_test.go`: `TestConnectionClientPathSwitchConnectionID`, `TestConnectionConnectionIDChanges`; `conn_id_manager_test.go`: `TestConnIDManagerMultipathUseConnIDForTuple` |
| 9.6.1 | If the preferred address can't be validated, keep using the original address | `preferred_address.go`: `preferredAddrValidationFailed` | `preferred_address_test.go`: `TestConnectionClientPreferredAddressValidationFailure` |
| 9.6.2, 21.5.3 | Validate the preferred address before migrating; no non-probing frames before | `preferred_address.go`: `startPreferredAddrValidation`, `handlePreferredAddrTimers` | `preferred_address_test.go`: `TestConnectionClientPreferredAddressMigration` |
| 9.6.2 | Server keeps sending from its original address until the client migrated and the path is validated; it probes from the preferred address | `preferred_address.go`; `path_manager.go`: `HandlePacketOnLocalAddr` | `preferred_address_test.go`: `TestConnectionServerPreferredAddressMigration` |
| 9.6.2 | Don't use the preferred address for other connections, including resumed ones | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket` (not stored) | `internal/wire/transport_parameter_test.go`: `TestTransportParametersFromSessionTicket` |
| 9.6.3 | Abandon validating the original address once the preferred address is validated | `preferred_address.go` | `preferred_address_test.go`: `TestConnectionClientPreferredAddressValidationAfterMigration` |
| 9.6.3 | Server protects against attacks if packets on the preferred address come from another client address | `path_manager.go`: `HandlePacketOnLocalAddr` (the new 4-tuple is validated, amplification limit) | `preferred_address_test.go`: `TestConnectionServerPreferredAddressMigration`; `connection_test.go`: `TestConnectionServerPathProbeAmplificationLimit` |
| 9.7 | IPv6 flow labels minimize linkability | Not applicable: the module doesn't set flow labels; the operating system does | - |
| 10.1 | The idle timeout is at least 3 PTO | `connection.go`: `nextIdleTimeoutTime` | `connection_test.go`: `TestConnectionIdleTimeout` |
| 10.2.1 | Closing state: send at most 3 times the data received (per address, including unvalidated addresses) | `closed_conn.go`: `handlePacket` | `closed_conn_test.go`: `TestClosedLocalConnectionAmplificationLimit` |
| 10.2.2 | Draining state: send no packets | `connection.go`: `handleCloseError` (remote close: closedRemoteConn) | `connection_test.go`: `TestConnectionRemoteClose` |
| 10.2.3 | CONNECTION_CLOSE in 1-RTT packets after confirmation | `packet_packer.go`: `packConnectionClose` (Initial and Handshake keys are dropped on confirmation) | `packet_packer_test.go`: `TestPackConnectionClose1RTT` |
| 10.2.3 | Application CONNECTION_CLOSE becomes 0x1c with an empty reason in Initial / Handshake packets | `packet_packer.go`: `packConnectionClose` | `packet_packer_test.go`: `TestPackConnectionCloseCoalesced` |
| 10.3, 11 | Use CONNECTION_CLOSE if possible; no stateless reset with connection state | `connection.go`: `handleCloseError`; `transport.go`: `maybeSendStatelessReset` (only for unknown connection IDs) | `connection_test.go`: `TestConnectionClose`; `transport_test.go`: `TestTransportStatelessResetSending` |
| 10.3, 10.3.3 | A stateless reset is smaller than the packet that triggered it | `transport.go`: `maybeSendStatelessReset`, `sendStatelessReset` (21 bytes, only in response to larger packets) | `transport_test.go`: `TestTransportStatelessResetSending` |
| 10.3 | Discard packets too small to be valid | `internal/wire/header.go`: `ParsePacket`; `packet_unpacker.go` | `internal/wire/header_test.go`: `TestHeaderEOF`; `packet_unpacker_test.go`: `TestUnpackErrors` |
| 10.3 | Stateless resets use a short header | `transport.go`: `sendStatelessReset` | `transport_test.go`: `TestTransportStatelessResetSending` |
| 10.3, 10.3.1 | Treat any packet ending in a valid token as a stateless reset (also long headers), when it can't be associated or decrypted | `transport.go`: `maybeHandleStatelessReset`; `connection.go`: `handleOnePacket`, `handleShortHeaderPacket` | `transport_test.go`: `TestTransportStatelessResetReceiving`, `TestTransportStatelessResetLongHeader`; `connection_test.go`: `TestConnectionStatelessResetReceived`, `TestConnectionStatelessResetLongHeader` |
| 10.3.1 | Only check tokens of connection IDs in use, not retired ones | `conn_id_manager.go`: `updateConnectionID`, `IsActiveStatelessResetToken` | `conn_id_manager_test.go`: `TestConnIDManagerConnIDRotation`, `TestConnIDManagerMultipathStatelessResetTokens` |
| 10.3.1 | Compare tokens without leaking them | `transport.go`: `maybeHandleStatelessReset` (tokens are stored and looked up as HMAC-SHA256 values with a random key); `conn_id_manager.go`: `IsActiveStatelessResetToken` (crypto/subtle) | `transport_test.go`: `TestTransportStatelessResetTokenLookup` |
| 10.3.1 | After a stateless reset: draining, no more packets | `connection.go`: `handleCloseError` | `connection_test.go`: `TestConnectionStatelessResetReceived`, `TestConnectionStatelessReset` |
| 10.3.2 | Tokens are difficult to guess, one per connection ID | `stateless_reset.go`: `GetStatelessResetToken` (HMAC-SHA256 of the connection ID; random tokens without a key) | `stateless_reset_test.go`: `TestStatelessResetter` |
| 10.3.2 | Same connection ID length for all connections sharing a key | `transport.go`: `init` (one connection ID length per Transport) | `transport_test.go`: `TestTransportPacketHandling` |
| 10.3.2 | A connection ID and static key aren't used for another connection | `conn_id_generator.go`: `issueNewConnID`; `server.go`: `handleInitialImpl` (connection IDs registered with the Transport are not used again); `transport.go`: `doDial`, `AddWithConnID` | `conn_id_generator_test.go`: `TestConnIDGeneratorUniqueConnIDs`; `transport_test.go`: `TestTransportConnIDCollision` |
| 11.1 | Fatal errors are signaled with CONNECTION_CLOSE | `connection.go`: `closeLocal`, `handleCloseError`, `sendConnectionClose` | `connection_test.go`: `TestConnectionClose` |
| 11.2 | RESET_STREAM is only sent by the application | `send_stream.go`: `CancelWrite`, `handleStopSendingFrame` (STOP_SENDING from the peer's application) | `send_stream_test.go`: `TestSendStreamCancellation` |
| 12.2 | Process coalesced packets individually, continue after decryption failures | `connection.go`: `handleOnePacket` | `connection_test.go`: `TestConnectionUnpackCoalescedPacket`; `internal/wire/header_test.go`: `TestCoalescedPacketParsing` |
| 12.2 | Don't coalesce packets with different connection IDs | `packet_packer.go`: `PackCoalescedPacket` (one destination connection ID per datagram) | `packet_packer_test.go`: `TestPackLongHeaders` |
| 12.3, 17.2.3 | Packet numbers increase, are never reused | `internal/ackhandler/packet_number_generator.go`: `Pop`; `internal/ackhandler/sent_packet_history.go`: `checkSequentialPacketNumberUse` | `internal/ackhandler/packet_number_generator_test.go`: `TestSkippingPacketNumberGenerator`; `internal/ackhandler/sent_packet_history_test.go`: `TestSentPacketHistoryNonSequentialPacketNumberUse` |
| 12.3 | Close without sending when the packet number reaches 2^62-1 | `connection.go`: `sendPackets` (the connection is closed without CONNECTION_CLOSE before a packet number reaches the maximum) | `connection_test.go`: `TestConnectionPacketNumberExhaustion` |
| 12.3 | Discard duplicates, after removing packet protection | `connection.go`: `handleLongHeaderPacket`, `handleShortHeaderPacket` (IsPotentiallyDuplicate after unpacking); `internal/ackhandler/received_packet_history.go`: `IsPotentiallyDuplicate` | `internal/ackhandler/received_packet_handler_test.go`: `TestPacketDuplicateDetection`; `internal/ackhandler/received_packet_history_test.go`: `TestReceivedPacketHistoryDuplicateDetection` |
| 12.4 | Packets contain at least one frame; an empty payload is a PROTOCOL_VIOLATION | `packet_unpacker.go`: `unpackLongHeaderPacket`, `unpackShortHeaderPacket` | `packet_unpacker_test.go`: `TestUnpackLongHeaderEmptyPayload`, `TestUnpackShortHeaderEmptyPayload` |
| 12.4, 17.2.4, 12.5 | Frames in a packet type that doesn't permit them: PROTOCOL_VIOLATION; frames are only sent in their packet number spaces | `internal/wire/frame_parser.go`: `ParseType` (frame type / encryption level check); `packet_packer.go` | `internal/wire/frame_parser_test.go`: `TestFrameAllowedAtEncLevel`, `TestFrameParserFrames` |
| 12.4 | Unknown frame types: FRAME_ENCODING_ERROR | `internal/wire/frame_parser.go`: `ParseType` | `internal/wire/frame_parser_test.go`: `TestFrameParserInvalidFrameType` |
| 12.4 | Frame types use the shortest encoding | internal/wire (frame types are written with quicvarint.Append) | `internal/wire/ack_frame_test.go`: `TestWriteACKGolden` |
| 13.1 | Acknowledge a packet only after it was decrypted and its frames processed | `connection.go`: `handleUnpackedShortHeaderPacket`, `handleUnpackedLongHeaderPacket` | `connection_test.go`: `TestConnectionUnpacking` |
| 13.2.1 | Acknowledge Initial and Handshake packets immediately, 0-RTT and 1-RTT packets within max_ack_delay | `internal/ackhandler/received_packet_tracker.go`: `ReceivedPacket`, `GetAlarmTimeout` | `internal/ackhandler/received_packet_tracker_test.go`: `TestReceivedPacketTrackerGenerateACKs`, `TestAppDataReceivedPacketTrackerAlarmTimeout` |
| 13.2.1 | At most one ACK-only packet per ack-eliciting packet; none for non-ack-eliciting packets | `internal/ackhandler/received_packet_tracker.go`: `ReceivedPacket`, `shouldQueueACK` | `internal/ackhandler/received_packet_tracker_test.go`: `TestAppDataReceivedPacketTrackerAckEverySecondPacket`, `TestReceivedPacketTrackerGenerateACKs` |
| 13.2.1 | Don't make every otherwise non-ack-eliciting packet ack-eliciting | `packet_packer.go`: `composeNextPacket` (a PING every 20 non-ack-eliciting packets) | `packet_packer_test.go`: `TestPackEvery20thPacketAckEliciting` |
| 13.2.3 | Keep ACK ranges unless packets in them won't be accepted; keep the largest packet number | `internal/ackhandler/received_packet_history.go`: `ReceivedPacket`, `DeleteBelow` (packets below a dropped range are treated as duplicates); `internal/ackhandler/received_packet_tracker.go` | `internal/ackhandler/received_packet_history_test.go`: `TestReceivedPacketHistoryMaxNumAckRanges`; `internal/ackhandler/received_packet_handler_test.go`: `TestAckRangePruning` |
| 13.2.5 | The ACK Delay only includes delays the endpoint controls | `connection.go`: `ackTime`; `internal/ackhandler/received_packet_tracker.go`: `GetAckFrame` | `connection_test.go`: `TestConnectionAckDelayExcludesQueueingDelay` |
| 13.2.6, 17.2.3 | ACK frames in the packet number space of the acknowledged packets; 0-RTT packets are acknowledged in 1-RTT packets | `internal/ackhandler/received_packet_handler.go`: `GetAckFrame`; `packet_packer.go` | `internal/ackhandler/received_packet_handler_test.go`: `TestGenerateACKsForPacketNumberSpaces`, `TestReceive0RTTAnd1RTT`; `packet_packer_test.go`: `TestPack0RTTPacketNoACK` |
| 13.3 | RESET_STREAM content doesn't change when retransmitted | `send_stream.go`: `sendStreamResetStreamHandler` (the same frame is queued again) | `send_stream_test.go`: `TestSendStreamCancellationResetStreamRetransmission` |
| 13.3 | Retransmit HANDSHAKE_DONE until acknowledged | `connection.go`: `handleHandshakeComplete` (control frame, retransmitted when lost) | `connection_test.go`: `TestConnectionHandshakeServer` |
| 13.3 | Accept packets with outdated frames | `flow_controller_connection.go`: `UpdateSendWindow`; `streams_map_outgoing.go`: `SetMaxStream` | `flow_controller_stream_test.go`: `TestStreamSendWindow`; `streams_map_outgoing_test.go`: `TestStreamsMapOutgoingLimits` |
| 13.3 | Losses reduce the congestion window | `internal/ackhandler/sent_packet_handler.go`: `detectLostPackets`; `internal/congestion/cubic_sender.go`: `OnCongestionEvent` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerCongestion`; `internal/congestion/cubic_sender_test.go`: `TestCubicSenderSlowStartPacketLoss` |
| 13.4.1 | Report received ECN markings | `internal/ackhandler/received_packet_tracker.go`: `ReceivedPacket`, `GetAckFrame`; `sys_conn_oob.go`: `ReadPacket` | `internal/ackhandler/received_packet_tracker_test.go`: `TestAppDataReceivedPacketTrackerECN`; `sys_conn_oob_test.go`: `TestReadECNFlagsIPv4` |
| 13.4.2.1, 13.4.2.2 | ECN validation: don't fail on ACKs that don't increase the largest acknowledged; disable ECN when validation fails | `internal/ackhandler/ecn.go`: `HandleNewlyAcked`, `failIfMangled` | `internal/ackhandler/ecn_test.go`: `TestECNACKReordering`, `TestECNValidationFailures`, `TestECNManglingAllPacketsMarkedCE` |
| 14 | Only use paths with a maximum datagram size of at least 1200 bytes | `internal/protocol/protocol.go` (MinInitialPacketSize); `mtu_discoverer.go` (never below 1200) | `mtu_discoverer_test.go`: `TestMTUDiscovererMTUDiscovery` |
| 14 | No IP fragmentation; set the DF bit | `sys_conn_df_linux.go`: `setDF`; `sys_conn_df_windows.go`: `setDF`; `sys_conn_df_darwin.go`: `setDF` | `sys_conn_df_darwin_test.go`: `TestIPFragmentation` |
| 14 | Don't close on datagrams that violate size constraints | `server.go`: `handlePacketImpl` (dropped) | `server_test.go`: `TestServerPacketDropping` |
| 14.1 | Client expands datagrams with Initial packets to 1200 bytes | `packet_packer.go`: `initialPaddingLen` | `packet_packer_test.go`: `TestPackLongHeaders`; `integrationtests/self/mtu_test.go`: `TestInitialPacketSize` |
| 14.1 | Server expands datagrams with ack-eliciting Initial packets to 1200 bytes | `packet_packer.go`: `initialPaddingLen` | `packet_packer_test.go`: `TestPackLongHeaders` |
| 14.1 | Server discards Initial packets in datagrams smaller than 1200 bytes | `server.go`: `handlePacketImpl` | `server_test.go`: `TestServerPacketDropping` |
| 14.1 | Server limits data before address validation | `internal/ackhandler/sent_packet_handler.go`: `isAmplificationLimited` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerAmplificationLimitServer` |
| 14.2 | Stop sending on paths that can't carry 1200 bytes | Not applicable: the module never determines a PMTU below 1200 bytes (no ICMP processing, DPLPMTUD starts at 1200) | - |
| 14.2.1 | ICMP message handling | Not applicable: the module doesn't process ICMP messages | - |
| 17.1 | Full packet numbers before the first ACK; afterwards a length covering twice the unacknowledged range | `internal/protocol/packet_number.go`: `PacketNumberLengthForHeader`; `internal/ackhandler/sent_packet_handler.go`: `PeekPacketNumber` | `internal/protocol/packet_number_test.go`: `TestPacketNumberLengthForHeader` |
| 17.2, 17.3.1 | Discard packets with the fixed bit 0 (unless greasing was negotiated, RFC 9287) | `internal/wire/header.go`: `IsPotentialQUICPacket`, `parseHeader`; `internal/wire/short_header.go`: `parseShortHeader`; `transport.go`: `handlePacket` | `internal/wire/header_test.go`: `TestErrorIfReservedBitNotSet`; `internal/wire/short_header_test.go`: `TestParseShortHeaderNoQUICBit` |
| 17.2 | Connection IDs are at most 20 bytes in version 1; longer ones are dropped | `internal/wire/header.go`: `parseLongHeader`; `internal/protocol/connection_id.go` | `internal/wire/header_test.go`: `TestErrorOnTooLongDestinationConnectionID`, `TestParseConnIDTooLong` |
| 17.2, 17.3.1 | Reserved bits are 0; non-zero after removing protection is a PROTOCOL_VIOLATION | `internal/wire/extended_header.go`; `internal/wire/short_header.go`: `AppendShortHeader`; `packet_unpacker.go`: `unpackLongHeaderPacket`, `unpackShortHeaderPacket` | `packet_unpacker_test.go`: `TestUnpackLongHeaderIncorrectReservedBits`, `TestUnpackShortHeaderIncorrectReservedBits` |
| 17.2.1 | Clients ignore the Unused bits of Version Negotiation packets | `internal/wire/version_negotiation.go`: `ParseVersionNegotiationPacket` | `internal/wire/version_negotiation_test.go`: `TestParseVersionNegotiationPacket` |
| 17.2.1 | Version Negotiation packets: version 0, connection IDs swapped | `internal/wire/version_negotiation.go`: `ComposeVersionNegotiation`; `server.go`: `maybeSendVersionNegotiationPacket` | `server_test.go`: `TestServerVersionNegotiation`; `internal/wire/version_negotiation_test.go`: `TestComposeVersionNegotiationWithReservedVersion` |
| 17.2.1 | No version-specific connection ID rules in the decision; one Version Negotiation packet per datagram | `server.go`: `handlePacketImpl`, `maybeSendVersionNegotiationPacket` (wire.ParseArbitraryLenConnectionIDs) | `server_test.go`: `TestServerVersionNegotiation` |
| 17.2.2 | Server Initial packets have no token; a client discards Initial packets with a token | `packet_packer.go`: `getLongHeader` (the server sets no token); `connection.go`: `handleLongHeaderPacket` | `connection_test.go`: `TestConnectionClientDropsInvalidInitialPackets` |
| 17.2.3 | No 0-RTT packets once 1-RTT packets are processed | `packet_packer.go`: `maybeGetAppDataPacketFor0RTT`; `internal/handshake/crypto_setup.go`: `Get0RTTSealer` | `connection_test.go`: `TestConnectionClientDrop0RTT` |
| 17.2.5 | Client ignores the Unused bits of Retry packets | `internal/wire/header.go`: `parseLongHeader` | `internal/wire/header_test.go`: `TestParseRetryPacket` |
| 17.2.5.1 | Retry: new Source Connection ID; client discards a Retry with an unchanged one, uses the new one | `server.go`: `sendRetryPacket`; `connection.go`: `handleRetryPacket` | `server_test.go`: `TestServerRetry`; `connection_test.go`: `TestConnectionRetryDrops` |
| 17.2.5.1 | One Retry per datagram | `server.go`: `handleInitialImpl`, `sendRetry` | `server_test.go`: `TestServerRetry` |
| 17.2.5.2 | At most one Retry, none after an Initial | `connection.go`: `handleRetryPacket` | `connection_test.go`: `TestConnectionRetryDrops`, `TestConnectionRetryAfterReceivedPacket` |
| 17.2.5.2 | Discard Retry packets with an invalid integrity tag | `connection.go`: `handleRetryPacket`; `internal/handshake/retry.go`: `GetRetryIntegrityTag` | `connection_test.go`: `TestConnectionRetryDrops`; `integrationtests/self/mitm_test.go`: `TestMITMForgedRetryPacket` |
| 17.2.5.2 | Discard Retry packets without a token | `internal/wire/header.go`: `parseLongHeader` | `internal/wire/header_test.go`: `TestParseRetryEOF` |
| 17.2.5.2 | Client keeps its Source Connection ID after a Retry | `connection.go`: `handleRetryPacket` | `connection_test.go`: `TestConnectionRetryDrops` |
| 17.2.5.3 | Same handshake message after a Retry, packet numbers continue | `internal/ackhandler/sent_packet_handler.go`: `ResetForRetry` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerRetry` |
| 17.4 | Spin bit: disabled, ignored on receipt | `internal/wire/short_header.go`: `AppendShortHeader` (spin bit always 0),parseShortHeader (ignored) | `internal/wire/short_header_test.go`: `TestWriteShortHeaderPacket` |
| 18.2 | Server-only transport parameters from a client, preferred_address with zero-length connection IDs: TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `unmarshal`, `readPreferredAddress`; `connection.go`: `checkTransportParameters`; `transport.go` (no preferred address with zero-length connection IDs) | `internal/wire/transport_parameter_test.go`: `TestTransportParameterPreferredAddressFromClient`, `TestTransportParameterPreferredAddressZeroLengthConnectionID`, `TestTransportParameterErrors`; `preferred_address_test.go`: `TestConnectionClientPreferredAddressZeroLengthConnID` |
| 18.2 | active_connection_id_limit is at least 2 | `internal/wire/transport_parameters.go`: `readNumericTransportParameter` | `internal/wire/transport_parameter_test.go`: `TestTransportParameterErrors` |
| 19.3 | Handle both ACK frame types | `internal/wire/ack_frame.go`: `parseAckFrame` | `internal/wire/ack_frame_test.go`: `TestParseACKECN` |
| 19.3.1 | Negative packet numbers in ACK ranges: FRAME_ENCODING_ERROR | `internal/wire/ack_frame.go`: `parseAckFrame` | `internal/wire/ack_frame_test.go`: `TestParseACKRejectFirstBlockLargerThanLargestAcked` |
| 19.4 | RESET_STREAM for a send-only stream: STREAM_STATE_ERROR | `streams_map.go`: `getReceiveStream` | `streams_map_test.go`: `TestStreamsMapHandleReceiveStreamFrames` |
| 19.5 | STOP_SENDING for a not yet created local stream or a receive-only stream: STREAM_STATE_ERROR | `streams_map.go`: `getSendStream` | `streams_map_test.go`: `TestStreamsMapHandleSendStreamFrames` |
| 19.6 | CRYPTO frames beyond the limit: CRYPTO_BUFFER_EXCEEDED | `crypto_stream.go`: `HandleCryptoFrame` | `crypto_stream_test.go`: `TestCryptoStreamMaxOffset` |
| 19.7 | NEW_TOKEN tokens are not empty | `connection.go`: `handleHandshakeComplete` (tokens are never empty); `internal/wire/new_token_frame.go`: `parseNewTokenFrame` | `internal/wire/new_token_frame_test.go`: `TestParseNewTokenFrameRejectsEmptyTokens` |
| 19.7 | Clients don't send NEW_TOKEN; a server receiving one: PROTOCOL_VIOLATION | `connection.go`: `handleNewTokenFrame` | `connection_test.go`: `TestConnectionServerInvalidFrames` |
| 19.8 | STREAM frames for a not yet created local stream or a send-only stream: STREAM_STATE_ERROR | `streams_map.go`: `getReceiveStream` | `streams_map_test.go`: `TestStreamsMapHandleReceiveStreamFrames` |
| 19.8 | STREAM frames beyond 2^62-1: FRAME_ENCODING_ERROR | `internal/wire/stream_frame.go`: `ParseStreamFrame` | `internal/wire/stream_frame_test.go`: `TestParseStreamFrameRejectsOverflow` |
| 19.9, 19.10 | Respect and enforce MAX_DATA and MAX_STREAM_DATA | `flow_controller_connection.go`: `IncrementHighestReceived`; `flow_controller_stream.go`: `UpdateHighestReceived`; `send_stream.go`: `popNewStreamFrame` | `flow_controller_connection_test.go`: `TestConnectionFlowControlViolation`; `flow_controller_stream_test.go`: `TestStreamFlowControlReceiving`; `send_stream_test.go`: `TestSendStreamFlowControlBlocked` |
| 19.10 | MAX_STREAM_DATA for a not yet created local stream or a receive-only stream: STREAM_STATE_ERROR | `streams_map.go`: `getSendStream` | `streams_map_test.go`: `TestStreamsMapHandleSendStreamFrames` |
| 19.11 | MAX_STREAMS above 2^60: FRAME_ENCODING_ERROR | `internal/wire/max_streams_frame.go`: `parseMaxStreamsFrame` | `internal/wire/max_streams_frame_test.go`: `TestParseMaxStreamsErrorsOnTooLargeStreamCount` |
| 19.11 | MAX_STREAMS: ignore decreases, respect the limit, STREAM_LIMIT_ERROR for violations | `streams_map_outgoing.go`: `SetMaxStream`, `OpenStream`; `streams_map_incoming.go`: `GetOrOpenStream` | `streams_map_outgoing_test.go`: `TestStreamsMapOutgoingLimits`; `streams_map_incoming_test.go`: `TestStreamsMapIncomingGettingStreams` |
| 19.13 | STREAM_DATA_BLOCKED for a send-only stream: STREAM_STATE_ERROR | `streams_map.go`: `HandleStreamDataBlockedFrame`, `getReceiveStream` | `streams_map_test.go`: `TestStreamsMapHandleReceiveStreamFrames` |
| 19.14 | STREAMS_BLOCKED above 2^60: FRAME_ENCODING_ERROR | `internal/wire/streams_blocked_frame.go`: `parseStreamsBlockedFrame` | `internal/wire/streams_blocked_frame_test.go`: `TestParseStreamsBlockedFrameErrorOnTooLargeStreamCount` |
| 19.15 | NEW_CONNECTION_ID with a length of 0 or above 20: FRAME_ENCODING_ERROR | `internal/wire/new_connection_id_frame.go`: `parseNewConnectionIDFrame` | `internal/wire/new_connection_id_frame_test.go`: `TestParseNewConnectionIDZeroLengthConnID`, `TestParseNewConnectionIDInvalidConnIDLength` |
| 19.15 | No NEW_CONNECTION_ID with zero-length connection IDs; receiving one then: PROTOCOL_VIOLATION | `conn_id_generator.go`: `SetMaxActiveConnIDs`; `conn_id_manager.go`: `add` | `conn_id_manager_test.go`: `TestConnIDManagerZeroLengthConnectionID` |
| 19.15 | Duplicate NEW_CONNECTION_ID frames are not an error | `conn_id_manager.go`: `add`, `addConnectionID` | `conn_id_manager_test.go`: `TestConnIDManagerRetransmittedNewConnectionIDFrames` |
| 19.15 | Retire Prior To above the Sequence Number: FRAME_ENCODING_ERROR | `internal/wire/new_connection_id_frame.go`: `parseNewConnectionIDFrame` | `internal/wire/new_connection_id_frame_test.go`: `TestParseNewConnectionIDRetirePriorToLargerThanSequenceNumber` |
| 19.15 | Ignore Retire Prior To that doesn't increase; retire new connection IDs below it | `conn_id_manager.go`: `add` | `conn_id_manager_test.go`: `TestConnIDManagerRetiringConnectionIDs` |
| 19.16 | RETIRE_CONNECTION_ID for an unsent sequence number or the packet's own connection ID: PROTOCOL_VIOLATION | `conn_id_generator.go`: `RetireForPath` | `conn_id_generator_test.go`: `TestConnIDGeneratorIssueAndRetire` |
| 19.16 | RETIRE_CONNECTION_ID to an endpoint with zero-length connection IDs: PROTOCOL_VIOLATION | `conn_id_generator.go`: `RetireForPath` | `conn_id_generator_test.go`: `TestConnIDGeneratorZeroLengthRetire` |
| 19.20 | No HANDSHAKE_DONE before the handshake completes | `connection.go`: `handleHandshakeComplete` | `connection_test.go`: `TestConnectionHandshakeServer` |
| 19.20 | Server receiving HANDSHAKE_DONE: PROTOCOL_VIOLATION | `connection.go`: `handleHandshakeDoneFrame` | `connection_test.go`: `TestConnectionServerInvalidFrames` |
| 19.21 | Extension frames are only sent if negotiated, are congestion controlled and ack-eliciting | `internal/wire/frame_parser.go` (DATAGRAM, ACK_FREQUENCY, RESET_STREAM_AT, multipath, ADD_ADDRESS, OBSERVED_ADDRESS are only enabled if negotiated); `internal/ackhandler/ack_eliciting.go`: `IsFrameAckEliciting` | `internal/wire/frame_parser_test.go`: `TestFrameParserDatagramUnsupported`, `TestFrameParserResetStreamAtUnsupported`; `internal/ackhandler/ack_eliciting_test.go`: `TestIsFrameTypeAckEliciting` |
| 21.5, 21.12 | Requirements on future extensions and versions | Not applicable to an implementation | - |
| 21.11 | Endpoints sharing a stateless reset key receive all packets of their connections; no stateless reset for connections that could be active elsewhere | Deployment: documented on Transport.StatelessResetKey | - |
| 22.1.2, 22.1.3, 22.1.4, 22.2, 22.3, 22.4, 22.5 | IANA registry rules | Not applicable to an implementation. Reserved versions (0x?a?a?a?a) and transport parameter IDs (31 * N + 27) are only used for greasing: internal/protocol/version.go:generateReservedVersion; `internal/wire/transport_parameters.go`: `Marshal` | `internal/wire/version_negotiation_test.go`: `TestComposeVersionNegotiationWithReservedVersion` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 2.2 | MAY offer out-of-order delivery of stream data | Not offered: streams are ordered byte streams, as in quic-go. |
| 3.5 | MAY defer RESET_STREAM until outstanding data is acknowledged or lost | Not done: RESET_STREAM is sent right away; data declared lost afterwards is not retransmitted. |
| 4 | SHOULD provide an interface for the TLS stack to communicate its buffering limits | Not provided: crypto/tls has no such interface. CRYPTO data is buffered up to a fixed 16 KB (protocol.MaxCryptoStreamOffset), well above the required 4096 bytes. |
| 4.1, 19.12, 19.13 | SHOULD send (and periodically resend) STREAM_DATA_BLOCKED / DATA_BLOCKED when blocked | Sent once when the sender becomes blocked at a non-zero limit (quic-go issue #4174); not sent for limits of 0 and not repeated. A receiver that advertised 0 must raise the limit anyway; the idle timeout is handled by keep-alives (Config.KeepAlivePeriod). |
| 4.2 | MAY send MAX_DATA / MAX_STREAM_DATA several times per round trip | Not done: window updates are sent when the remaining window drops below the update threshold; lost updates are retransmitted. |
| 4.5 | SHOULD treat data at or beyond the final size as FINAL_SIZE_ERROR, even after a stream is closed | Followed while the stream exists. Frames for streams that were closed and deleted are ignored: no per-stream state is kept after a stream completed. |
| 5.1.1 | MAY exceed the peer's limit using Retire Prior To; MAY issue a new connection ID when an unused one is used; MAY limit the total number of connection IDs | Not done: connection IDs are issued up to min(active_connection_id_limit, 6) and replaced when retired. |
| 5.2.3 | Servers without migration support SHOULD send disable_active_migration | No API to send the transport parameter (as in quic-go). Servers support migration; deployments that can't route migrated packets need their own solution. |
| 6.3, 15 | MAY send packets with reserved versions / advertise reserved versions | Reserved versions are only sent in Version Negotiation packets (one per packet), not used as the version of packets. |
| 7.4.1 | MAY remember max_idle_timeout, max_udp_payload_size and disable_active_migration and reject 0-RTT; MAY close if 0-RTT uses updated parameters | Not done: these parameters don't affect the client's 0-RTT data. Remembered limits are enforced (section 7.4.1). |
| 8.1 | MAY consider the address validated if the peer uses a connection ID with 64 bits of entropy | Not done: the default connection ID length is 4 bytes; the address is validated by Handshake packets, tokens or path validation. |
| 8.1.3 | MAY discard Initial packets without the expected token | Not done: the server sends a Retry if configured (Transport.VerifySourceAddress). |
| 8.1.4 | NEW_TOKEN tokens SHOULD NOT be accepted multiple times | Not followed: tokens are only limited by their lifetime (Transport.MaxTokenAge, default 24 hours). Detecting reuse would need state shared by all servers that accept the token. |
| 8.2.4 | SHOULD abandon path validation on a timer of 3 PTO | Followed for IETF Multipath QUIC paths, the server's preferred address and server-side validation. For RFC 9000 migration, Path.Probe probes until its context is canceled: the application chooses the timeout. |
| 9.2, 9.3 | MAY defer path validation / skip it for recently seen addresses | Not done: every new peer address is validated right away (see CONNECTION_MIGRATION.md). |
| 9.3 | Server SHOULD send new tokens after validating a new client address | Followed with IETF Multipath QUIC. Without it, not followed, as in quic-go: the client has a token from the handshake. |
| 9.3.3 | A PATH_CHALLENGE on an active path SHOULD be answered with a non-probing packet | Followed with IETF Multipath QUIC. Without it, the PATH_RESPONSE goes in the next packet, which contains a non-probing frame (e.g. an ACK) if one is due (see CONNECTION_MIGRATION.md). |
| 9.4 | MAY keep the congestion state for port-only changes | Not done: the congestion controller and RTT estimate are reset on every migration. |
| 9.5 | MAY keep the connection ID after a NAT rebinding | Not done: a new connection ID is used for every new 4-tuple (see CONNECTION_MIGRATION.md). |
| 9.5 | SHOULD NOT migrate with a peer that uses zero-length connection IDs | Left to the application: Conn.AddPath works with such servers, as in quic-go. |
| 9.6.2 | Server MAY process delayed packets on the old address after a preferred address migration | Not done: they are dropped (see PREFERRED_ADDRESS.md). |
| 9.6.3 | Client MAY use the preferred_address connection ID on any path | Only used for the preferred address (see PREFERRED_ADDRESS.md). |
| 9.7 | SHOULD set IPv6 flow labels (RFC 6437) | Left to the operating system: Go's net package can't set flow labels per packet. Linux sets flow labels automatically (net.ipv6.auto_flowlabels). |
| 10, 9 | MAY discard connection state without a validated path | Not done: the connection stays until the idle timeout. |
| 10.2.1 | MAY keep the packet protection keys in the closing state | Not done: the keys are dropped, and the CONNECTION_CLOSE packet is repeated (with exponential backoff, within 3 times the bytes received). |
| 10.2.2 | MAY send a CONNECTION_CLOSE when receiving one / MAY move from closing to draining | Not done, as in quic-go. |
| 10.3 | SHOULD make all packets 22 bytes longer than the requested connection ID length | Not followed: short header packets are only padded so that the header protection sample can be taken (4 bytes of payload). Packets are rarely that small (an ACK-only packet carrying a 4-byte connection ID has at least 25 bytes). |
| 10.3 | SHOULD send a stateless reset one byte shorter than a packet of 43 bytes or less | Not followed: stateless resets always have 21 bytes, and are only sent in response to larger packets, so they are always shorter than the packet that triggered them. |
| 10.3 | MAY send a stateless reset in response to a long header packet | Not done. |
| 10.3.2 | MAY treat a repeated stateless reset token as a PROTOCOL_VIOLATION | Not done. |
| 12.4 | MAY treat a frame type with an overlong encoding as a PROTOCOL_VIOLATION | Not done: the frame type is accepted. |
| 13 | MAY wait to collect frames before sending | Not done: packets are sent when the application writes, paced by the congestion controller. |
| 14.1 | MAY close the connection on Initial packets in small datagrams | Not done: the packets are dropped. |
| 17.2.1 | Servers SHOULD set 0x40 in Version Negotiation packets | Followed. |
| 17.2.5.3 | MAY reject a changed ClientHello after a Retry; MAY abort if the client reset its packet numbers | Not done. |
| 17.4 | Spin bit: OPTIONAL; RECOMMENDED to set a random value when disabled | The spin bit is not implemented, and always sent as 0, as in quic-go. Peers ignore it. |
| 19.18 | MAY close on a PATH_RESPONSE that doesn't match a PATH_CHALLENGE | Not done: it is ignored (it might answer an earlier challenge of a path that was abandoned). |
| 21.5.6 | MAY refuse loopback addresses; SHOULD NOT migrate to a loopback address offered by a non-loopback server | Followed for the server's preferred address (a loopback preferred address is ignored unless the server address is a loopback address) and for ADD_ADDRESS. Other connections and migrations are left to the application. |
| 21.5.6 | MAY reduce request forgery risk by not sending tokens, avoiding ports, retiring connection IDs with patterns | Not done. |
| 21.6, 21.7, 21.9 | Deployments SHOULD mitigate Slowloris, stream fragmentation and peer DoS | Limits: incoming stream limits, the frame sorter's gap limit (TestFrameSorterTooManyGaps), the control frame queue limit (TestFramerDetectsFrameDoS), the server's accept queue and handshake limits. Further limits (per IP address) are left to the application. |

### RFC 9001: Using TLS to secure QUIC

[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) has 78 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 4, 4.9 | Retransmitted CRYPTO data uses the keys (encryption level) it was first sent with | `crypto_stream_manager.go`; `packet_packer.go`: `maybeGetCryptoPacket` (one crypto stream per encryption level) | `crypto_stream_manager_test.go`: `TestCryptoStreamManager`; `packet_packer_test.go`: `TestPackRetransmissions` |
| 4.1.2 | Server sends HANDSHAKE_DONE as soon as the handshake completes | `connection.go`: `handleHandshakeComplete` | `connection_test.go`: `TestConnectionHandshakeServer` |
| 4.1.3 | CRYPTO data of a previous encryption level beyond the received data: PROTOCOL_VIOLATION | `crypto_stream.go`: `HandleCryptoFrame` | `crypto_stream_test.go`: `TestCryptoStreamReceiveDataAfterFinish` |
| 4.1.3 | Unconsumed data of a previous encryption level when keys change: PROTOCOL_VIOLATION | `crypto_stream.go`: `Finish`; `connection.go`: `handleHandshakeEvents` | `crypto_stream_test.go`: `TestCryptoStreamFinishWithQueuedData`; `crypto_stream_manager_test.go`: `TestCryptoStreamManagerFinishEncryptionLevel` |
| 4.2 | Only TLS 1.3 | `internal/handshake/tls_config_go127.go`: `setupConfigForClient`, `setupConfigForServer` (MinVersion TLS 1.3; crypto/tls requires TLS 1.3 for QUIC) | `internal/handshake/tls_config_go126_test.go`: `TestMinimumTLSVersion` |
| 4.4 | Client authenticates the server | crypto/tls certificate verification (tls.Config of the application) | `integrationtests/self/handshake_test.go`: `TestHandshakeServerMismatch` |
| 4.4 | No post-handshake client authentication; a client receiving a post-handshake CertificateRequest: PROTOCOL_VIOLATION | crypto/tls (never sends one); `internal/handshake/crypto_setup.go`: `checkPostHandshakeMessages` | `internal/handshake/crypto_setup_test.go`: `TestPostHandshakeCertificateRequest` |
| 4.6.1 | max_early_data_size is 0xffffffff; a client receiving another value: PROTOCOL_VIOLATION | crypto/tls (QUIC mode); `internal/handshake/crypto_setup.go`: `checkPostHandshakeMessages` | `internal/handshake/crypto_setup_test.go`: `TestNewSessionTicketEarlyDataSize` |
| 4.6.2 | A server rejecting 0-RTT doesn't process 0-RTT packets | `internal/handshake/crypto_setup.go`: `rejected0RTT`, `Get0RTTOpener` (no 0-RTT keys are installed) | `integrationtests/self/zero_rtt_test.go`: `Test0RTTRejectedOnStreamLimitDecrease`, `Test0RTTRejectedWhenDisabled` |
| 4.6.2 | After 0-RTT rejection, the client resets all streams | `streams_map.go`: `ResetFor0RTT`, `UseResetMaps`; `framer.go`: `Handle0RTTRejection` | `streams_map_test.go`: `TestStreamsMap0RTTRejection`; `framer_test.go`: `TestFramer0RTTRejection` |
| 4.8 | Every TLS alert is fatal | `internal/handshake/crypto_setup.go`: `wrapError` (CRYPTO_ERROR 0x100 + alert) | `internal/handshake/crypto_setup_test.go`: `TestHandleQUICErrorEvent` |
| 4.9 | New data at the highest available encryption level | `packet_packer.go`: `PackCoalescedPacket` | `packet_packer_test.go`: `TestPackLongHeaders` |
| 4.9.1 | Client drops Initial keys when it first sends a Handshake packet; server when it first processes one; no Initial packets afterwards | `connection.go`: `sendPackedCoalescedPacket`, `handleUnpackedLongHeaderPacket`, `dropEncryptionLevel` | `connection_test.go`: `TestConnectionHandshakeClient`, `TestConnectionHandshakeServer` |
| 4.9.2 | Drop Handshake keys when the handshake is confirmed | `connection.go`: `handleHandshakeConfirmed` | `connection_test.go`: `TestConnectionHandshakeClient` |
| 4.9.3 | Server drops 0-RTT keys 3 PTO after the handshake completed | `internal/handshake/crypto_setup.go`: `Get1RTTOpener` | `internal/handshake/crypto_setup_test.go`: `Test0RTT` |
| 5.1, 5.2 | Initial secrets use HKDF-Expand-Label | `internal/handshake/initial_aead.go`: `computeSecrets`; `internal/handshake/hkdf.go`: `hkdfExpandLabel` | `internal/handshake/initial_aead_test.go`: `TestComputeClientKeyAndIV`; `internal/handshake/hkdf_test.go`: `TestHKDF` |
| 5.3, 5.4.1 | Only cipher suites with a header protection scheme | `internal/handshake/cipher_suite.go`: `getCipherSuite`; `internal/handshake/header_protector.go`: `newHeaderProtector` (AES and ChaCha20, the cipher suites crypto/tls offers for QUIC) | `integrationtests/self/handshake_test.go`: `TestHandshakeCipherSuites` |
| 5.3 | Don't reject ClientHellos offering unknown cipher suites | crypto/tls | `integrationtests/self/handshake_test.go`: `TestHandshakeCipherSuites` |
| 5.3, 6.6 | Count packets per key, update keys before the confidentiality limit, stop using keys that reached it | `internal/handshake/updatable_aead.go`: `seal`, `shouldInitiateKeyUpdate`, `ConfidentialityLimitReached`; `internal/handshake/crypto_setup.go`: `Get1RTTSealer`; `connection.go`: `run` (no further packets once the limit is reached) | `internal/handshake/updatable_aead_test.go`: `TestInitiateKeyUpdateAfterSendingMaxPackets`, `TestConfidentialityLimitReached`; `connection_test.go`: `TestConnectionConfidentialityLimitReached` |
| 5.4.2 | Discard packets too short for the header protection sample | `packet_unpacker.go`: `unpackShortHeader`, `unpackLongHeader` | `packet_unpacker_test.go`: `TestUnpackErrors` |
| 5.5 | Discard packets that can't be unprotected, including apparent key updates | `internal/handshake/updatable_aead.go`: `Open`, `openForPath` | `integrationtests/self/key_update_test.go`: `TestKeyUpdates`; `internal/handshake/updatable_aead_test.go`: `TestReorderedPacketAfterKeyUpdate` |
| 5.6 | 0-RTT only on request of the application, under an application profile | `transport.go`: `DialEarly` (0-RTT only with DialEarly / ListenEarly); http3 (0-RTT only for safe requests, see RFC 9114 section 10.9) | `integrationtests/self/zero_rtt_test.go`: `Test0RTTDisabledOnDial`; `integrationtests/self/http_0rtt_test.go`: `TestHTTP0RTT` |
| 5.6 | Server never protects packets with 0-RTT keys | `internal/handshake/crypto_setup.go` (0-RTT sealer only on the client) | `packet_packer_test.go`: `TestPackLongHeaders` |
| 5.6 | Client discards 0-RTT packets | `connection.go`: `handleLongHeaderPacket` | `connection_test.go`: `TestConnectionClientDrop0RTT` |
| 5.6 | No 0-RTT packets after installing 1-RTT keys | `packet_packer.go`: `maybeGetAppDataPacketFor0RTT`; `internal/handshake/crypto_setup.go`: `Get0RTTSealer` | `connection_test.go`: `TestConnectionClientDrop0RTT` |
| 5.7 | 1-RTT packets are only processed after the handshake completed | `internal/handshake/crypto_setup.go`: `Get1RTTOpener` (has1RTTOpener); `connection.go`: `handleShortHeaderPacket` (buffered until then) | `connection_test.go`: `TestConnectionPacketBuffering` |
| 6 | No TLS KeyUpdate messages; receiving one: 0x010a | crypto/tls (QUIC mode rejects KeyUpdate with unexpected_message) | `internal/handshake/crypto_setup_test.go`: `TestHandleQUICErrorEvent` |
| 6.1 | No key update before confirmation | `internal/handshake/updatable_aead.go`: `updateAllowed` | `internal/handshake/updatable_aead_test.go`: `TestAllowsFirstKeyUpdateImmediately` |
| 6.1 | No further key update before a packet of the current phase is acknowledged | `internal/handshake/updatable_aead.go`: `updateAllowed`, `setLargestAcked` | `internal/handshake/updatable_aead_test.go`: `TestRejectFrequentKeyUpdates`, `TestKeyUpdateEnforceACKKeyPhase` |
| 6.1, 6.3 | Keep old keys until a packet with the new keys was unprotected; keep current and next keys | `internal/handshake/updatable_aead.go`: `rollKeys`, `startKeyDropTimer` | `internal/handshake/updatable_aead_test.go`: `TestReorderedPacketAfterKeyUpdate`, `TestDropsKeys3PTOsAfterKeyUpdate` |
| 6.2 | Update the send keys in response to a key update, before acknowledging | `internal/handshake/updatable_aead.go`: `openForPath`, `rollKeys` | `integrationtests/self/key_update_test.go`: `TestKeyUpdates`; `internal/handshake/updatable_aead_test.go`: `TestFastKeyUpdatesByPeer` |
| 6.3 | No timing side channel on key updates | `internal/handshake/updatable_aead.go`: `rollKeys` (the next keys are derived in advance) | `integrationtests/self/key_update_test.go`: `TestKeyUpdates` |
| 6.4 | Higher packet numbers use the same or newer keys; old keys after newer ones: KEY_UPDATE_ERROR | `internal/handshake/updatable_aead.go`: `openForPath`, `errOldKeysForHigherPacketNumber` | `internal/handshake/updatable_aead_test.go`: `TestKeyUpdateKeyPhaseSkipping`, `TestMultipathKeyUpdateErrorForOldKeysOnHigherPacketNumber` |
| 6.6 | Count packets that fail authentication; AEAD_LIMIT_REACHED at the integrity limit; stop using the connection | `internal/handshake/updatable_aead.go`: `openForPath` (invalidPacketLimit); `connection.go`: `handleUnpackError` | `internal/handshake/updatable_aead_test.go`: `TestAEADLimitReached`, `TestMultipathAEADLimitReached` |
| 6.6 | Cipher suites define AEAD limits | `internal/protocol/params.go` (InvalidPacketLimitAES, InvalidPacketLimitChaCha) | `internal/handshake/updatable_aead_test.go`: `TestAEADLimitReached` |
| 8.1 | ALPN is used; no common protocol: no_application_protocol (0x0178) | crypto/tls (QUIC mode requires ALPN) | `integrationtests/self/handshake_test.go`: `TestALPN` |
| 8.2 | quic_transport_parameters is sent; missing: missing_extension (0x016d) | `internal/handshake/crypto_setup.go` (tls.QUICConn.SetTransportParameters); crypto/tls | `internal/handshake/crypto_setup_test.go`: `TestTransportParameters` |
| 8.2 | The extension isn't used with TLS over TCP | Not applicable: the module only uses TLS for QUIC | - |
| 8.3 | No EndOfEarlyData | crypto/tls (QUIC mode) | `internal/handshake/crypto_setup_test.go`: `Test0RTT` |
| 8.3 | CRYPTO frames in 0-RTT packets: PROTOCOL_VIOLATION | `internal/wire/frame_parser.go`: `ParseType` | `internal/wire/frame_parser_test.go`: `TestFrameAllowedAtEncLevel` |
| 8.4 | No TLS middlebox compatibility mode | crypto/tls (QUIC mode) | `integrationtests/self/handshake_test.go`: `TestHandshake` |
| 9.2 | Implement and use the replay protections of TLS 1.3 | Single-use tickets (section 8.1 of RFC 8446), which crypto/tls doesn't implement: `internal/handshake/session_ticket.go`: `newSessionTicket` (random ID and issue time in every ticket); `internal/handshake/crypto_setup.go`: `handleSessionTicket` (0-RTT is only accepted if the `ZeroRTTReplayCache` hasn't seen the ticket); `zero_rtt_replay.go`: `zeroRTTReplayCache.UseTicket` (a ticket is only used for 0-RTT within a window after it was issued, IDs are kept for at least that window, tickets issued before the cache was created are rejected as in section 8.2 of RFC 8446); `transport.go`: `createServer` (one cache per Transport unless `Config.ZeroRTTReplayCache` is set). The cache protects one server instance, as section 8 of RFC 8446 requires; servers sharing ticket keys can share a cache | `internal/handshake/crypto_setup_test.go`: `Test0RTTReplay`; `zero_rtt_replay_test.go`: `TestZeroRTTReplayCacheSingleUse`, `TestZeroRTTReplayCacheExpiry`, `TestZeroRTTReplayCacheLimit`; `integrationtests/self/zero_rtt_test.go`: `Test0RTTReplay` |
| 9.2 | Session ticket contents are opaque to the client | `internal/handshake/session_ticket.go` (server-only encoding) | `internal/handshake/session_ticket_test.go`: `TestMarshalUnmarshalSessionTicket` |
| 9.2 | Applications and extensions describe 0-RTT replay handling | http3 (RFC 9114 section 10.9; Request.TLS.HandshakeComplete); extensions: multipath frames are not allowed in 0-RTT, OBSERVED_ADDRESS isn't sent in 0-RTT, ADD_ADDRESS isn't allowed in 0-RTT | `multipath_test.go`: `TestMultipathFramesIn0RTTPackets`; `packet_packer_test.go`: `TestPack0RTTPacketWithoutObservedAddress` |
| 9.3 | Pad the packet with the ClientHello | `packet_packer.go`: `initialPaddingLen` | `integrationtests/self/mtu_test.go`: `TestInitialPacketSize` |
| 9.4 | Requirement on future header protection schemes | Not applicable to an implementation | - |
| 9.5 | Header protection, packet number recovery and packet protection without timing side channels | `internal/handshake/header_protector.go`, internal/handshake/aead.go (crypto/aes, crypto/cipher, chacha20 primitives); `packet_unpacker.go` | `packet_unpacker_test.go`: `TestUnpackHeaderDecryption` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 4.5 | Clients SHOULD NOT reuse session tickets | Left to crypto/tls: its ClientSessionCache keeps the latest ticket of a server, which can be used by more than one connection until the server sends a new one. |
| 4.6.2 | After 0-RTT rejection, SHOULD treat an ACK of a 0-RTT packet as a PROTOCOL_VIOLATION | Not done: the 0-RTT packets are removed from the sent packet history when 0-RTT is rejected, and acknowledgments for them are ignored. |
| 4.8 | MAY use a generic error code for TLS alerts | Not done: the alert is sent as CRYPTO_ERROR (0x100 + alert). |
| 4.9.3 | MAY discard 0-RTT keys once all 0-RTT packets were received | Not done: the server drops them 3 PTO after the handshake completed. |
| 6.5 | SHOULD wait 3 PTO after the previous key update was acknowledged before the next one | Followed with IETF Multipath QUIC (section 2.5 of the multipath draft). Without it, as in quic-go, key updates are spaced by a number of packets (protocol.KeyUpdateInterval, 100,000 packets, after a first update at 100 packets), and only after a packet of the current key phase was acknowledged. |
| 6.6 | MAY use higher AEAD limits for smaller packets | Not done. |
| 8.4 | Server SHOULD treat a ClientHello with a non-empty legacy_session_id as a PROTOCOL_VIOLATION | Followed: the server checks the first ClientHello, which it parses for compatible version negotiation (internal/handshake/version_negotiation.go). |

### RFC 9002: QUIC loss detection and congestion control

[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) has 30 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 5.1 | No RTT sample unless the ACK newly acknowledges an ack-eliciting packet (and the largest acknowledged) | `internal/ackhandler/sent_packet_handler.go`: `ReceivedAck` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerRTTAckEliciting` |
| 5.2 | min_rtt is the first sample, then the minimum | `internal/utils/rtt_stats.go`: `UpdateRTT` | `internal/utils/rtt_stats_test.go`: `TestRTTStatsMinRTT` |
| 5.3 | Use min(ack_delay, max_ack_delay); don't subtract the ACK delay below min_rtt | `internal/ackhandler/sent_packet_handler.go`: `ReceivedAck`; `internal/utils/rtt_stats.go`: `UpdateRTT` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerRTTAckDelays`; `internal/utils/rtt_stats_test.go`: `TestRTTStatsMaxAckDelay` |
| 6.1.2 | The time threshold is at least kGranularity | `internal/ackhandler/sent_packet_handler.go`: `detectLostPackets` (protocol.TimerGranularity) | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerDelayBasedLossDetection` |
| 6.2 | A PTO doesn't declare packets lost | `internal/ackhandler/sent_packet_handler.go`: `OnLossDetectionTimeout` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPTO` |
| 6.2.1 | The PTO period is at least kGranularity | `internal/utils/rtt_stats.go`: `PTO` | `internal/utils/rtt_stats_test.go`: `TestRTTStatsComputePTO`, `TestRTTStatsPTOWithShortRTT` |
| 6.2.1 | With Initial and Handshake packets in flight, the earlier PTO | `internal/ackhandler/sent_packet_handler.go`: `getPTOTimeAndSpace` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPacketNumberSpacesPTO` |
| 6.2.1 | No Application Data PTO before the handshake is confirmed | `internal/ackhandler/sent_packet_handler.go`: `getPTOTimeAndSpace` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPacketNumberSpacesPTO` |
| 6.2.1 | The PTO backs off exponentially | `internal/ackhandler/sent_packet_handler.go`: `OnLossDetectionTimeout`, `scalePTO` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPTO` |
| 6.2.1 | No PTO while a loss timer is set | `internal/ackhandler/sent_packet_handler.go`: `setLossDetectionTimer` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerDelayBasedLossDetection` |
| 6.2.2 | Reset the timers when Initial or Handshake keys are discarded | `internal/ackhandler/sent_packet_handler.go`: `DropPackets` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPacketNumberSpacesPTO` |
| 6.2.2.1 | Server doesn't arm the PTO while amplification-limited | `internal/ackhandler/sent_packet_handler.go`: `setLossDetectionTimer`, `isAmplificationLimited` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerAmplificationLimitServer` |
| 6.2.2.1 | Client arms the PTO until its Handshake packets are acknowledged; sends a Handshake packet or a padded Initial | `internal/ackhandler/sent_packet_handler.go`: `setLossDetectionTimer`, `hasOutstandingCryptoPackets`; `packet_packer.go`: `PackPTOProbePacket` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerAmplificationLimitClient`; `packet_packer_test.go`: `TestPackInitialProbePacket` |
| 6.2.4 | A PTO sends at least one ack-eliciting probe packet | `internal/ackhandler/sent_packet_handler.go`: `OnLossDetectionTimeout`, `QueueProbePacket`; `packet_packer.go`: `PackPTOProbePacket` (adds a PING if needed) | `packet_packer_test.go`: `TestPackInitialProbePacket`, `TestPack1RTTProbePacket`; `connection_test.go`: `TestConnectionPTOProbePackets` |
| 6.4 | Discarding keys removes the recovery state and bytes in flight | `internal/ackhandler/sent_packet_handler.go`: `DropPackets` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPacketNumberSpacesPTO` |
| 7 | Other controllers conform to section 3.1 of RFC 8085 | `internal/congestion/cubic_sender.go` (loss-based AIMD with slow start, recovery and pacing; the multiplicative decrease is 0.7, as in CUBIC, RFC 9438); `multipath_olia.go` (OLIA, RFC 6356 family) | `internal/congestion/cubic_sender_test.go`: `TestCubicSenderSlowStartPacketLoss`; `multipath_api_test.go`: `TestMultipathOLIA` |
| 7 | Don't exceed the congestion window, except for PTO probes | `internal/ackhandler/sent_packet_handler.go`: `SendMode`; `internal/congestion/cubic_sender.go`: `CanSend` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerCongestion` |
| 7.3.1 | Exit slow start on loss or an ECN-CE increase | `internal/congestion/cubic_sender.go`: `OnCongestionEvent`; `internal/ackhandler/sent_packet_handler.go`: `ReceivedAck` (ECN-CE) | `internal/congestion/cubic_sender_test.go`: `TestCubicSenderSlowStartPacketLoss`; `internal/ackhandler/ecn_test.go`: `TestECNCongestionDetection` |
| 7.3.2 | Recovery: ssthresh is half the congestion window | Different controller (RFC 9002 section 7 allows it): the window is reduced to 0.7 times its size, as in CUBIC (RFC 9438), which quic-go uses for its Reno mode as well (internal/congestion/cubic_sender.go:OnCongestionEvent, renoBeta) | `internal/congestion/cubic_sender_test.go`: `TestCubicSenderSlowStartPacketLoss` |
| 7.3.2 | The window is the reduced ssthresh before recovery ends | `internal/congestion/cubic_sender.go`: `OnCongestionEvent` | `internal/congestion/cubic_sender_test.go`: `TestCubicSenderSlowStartPacketLoss` |
| 7.3.3 | Congestion avoidance increases by at most one datagram per window | `internal/congestion/cubic_sender.go`: `maybeIncreaseCwnd` | `internal/congestion/cubic_sender_test.go`: `TestCubicSenderLimitCwndIncreaseInCongestionAvoidance` |
| 7.4 | Don't ignore losses of packets sent after the earliest acknowledged packet | `internal/ackhandler/sent_packet_handler.go`: `detectLostPackets` (no losses are ignored) | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPacketBasedLossDetection` |
| 7.5 | Probe packets aren't blocked by congestion control, and count as in flight | `internal/ackhandler/sent_packet_handler.go`: `SendMode`, `SentPacket` | `internal/ackhandler/sent_packet_handler_test.go`: `TestSentPacketHandlerPTO` |
| 7.6.2 | Persistent congestion: two ack-eliciting packets; the window drops to the minimum | `internal/ackhandler/sent_packet_handler.go`: `updatePersistentCongestion`; `internal/congestion/cubic_sender.go`: `OnPersistentCongestion` | `internal/ackhandler/sent_packet_handler_persistent_congestion_test.go`: `TestSentPacketHandlerPersistentCongestion`; `internal/congestion/cubic_sender_test.go`: `TestCubicSenderPersistentCongestion`; `integrationtests/self/persistent_congestion_test.go`: `TestPersistentCongestion` |
| 7.7 | Pace or limit bursts | `internal/congestion/pacer.go`; `internal/congestion/cubic_sender.go`: `TimeUntilSend` | `internal/congestion/pacer_test.go`: `TestPacerPacing`; `connection_test.go`: `TestConnectionPacketPacing` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 5.2 | SHOULD set min_rtt to the newest sample after persistent congestion | Not followed: min_rtt is kept. It is only used to adjust RTT samples for the ACK delay, and a migration resets it (internal/utils/rtt_stats.go:ResetForPathMigration). |
| 5.3 | SHOULD ignore the peer's max_ack_delay until the handshake is confirmed | Not followed, as in quic-go: the ACK delay of 1-RTT acknowledgments is always capped at max_ack_delay. Initial and Handshake acknowledgments carry no ACK delay. |
| 6.2.2 | The initial RTT SHOULD be 333 ms | Not followed, as in quic-go: 100 ms (internal/utils/rtt_stats.go:DefaultInitialRTT); without an RTT sample, the PTO is 200 ms. A client can use the RTT stored with a token (Config.TokenStore). |
| 6.2.2 | The PATH_CHALLENGE / PATH_RESPONSE delay SHOULD NOT be an RTT sample | Not followed for paths of IETF Multipath QUIC: until a packet sent on the path is acknowledged, it is the only RTT measurement of the path, and the scheduler uses it to compare paths. RFC 9000 connection migration resets the RTT estimate and doesn't use it. |
| 6.2.4 | On PTO, SHOULD also send ack-eliciting packets in other packet number spaces with data in flight | Not followed, as in quic-go: the probe packets are sent in the packet number space whose timer expired. |
| 6.2.4, 7.4 | MAY declare packets in flight lost on PTO; MAY ignore losses of undecryptable packets | Not done. |
| 7.2 | SHOULD use an initial window of 10 datagrams (at most max(14720, 2 * max_datagram_size)) | Not followed, as in quic-go: the initial window is 32 datagrams (internal/congestion/cubic_sender.go:initialCongestionWindow), paced over the RTT. |
| 7.3.2 | (MUST in section 7.3.2) ssthresh is half the window on loss | The controller differs from RFC 9002's NewReno: the multiplicative decrease is 0.7, as in CUBIC (RFC 9438), as in quic-go. RFC 9002 section 7 allows other controllers that follow section 3.1 of RFC 8085. |
| 7.3.2 | MAY use PRR | Not done: the window is reduced on entering recovery. |
| 7.6.2 | Persistent congestion SHOULD consider all packet number spaces | Only the packet number space of the acknowledgment (MAY in section 7.6.2), see LOSS_RECOVERY.md. |

### RFC 9114: HTTP/3

[RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) has 139 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 3.1, 3.3 | Verify the server certificate for the origin; reuse a connection only for that origin | `http3/transport.go`: `dial` (tls.Config.ServerName is the request's host; crypto/tls verifies the certificate),getClient (one connection per host, no coalescing across origins) | `http3/transport_test.go`: `TestTransportDialHostname`, `TestTransportConnectionReuse` |
| 3.1.2 | Only "https" without other agreement | `http3/transport.go`: `roundTripOpt` (other schemes are rejected) | `http3/transport_test.go`: `TestRequestValidation` |
| 3.2 | Send SNI | `http3/transport.go`: `dial` (tls.Config.ServerName; crypto/tls sends SNI for domain names) | `http3/transport_test.go`: `TestTransportDialHostname` |
| 3.2, 6.2.1, 7.2.4, 7.2.4.2 | SETTINGS is the first frame of the control stream, sent right away and only once | `http3/conn.go`: `openControlStream`; `http3/server_conn.go`: `openControlStream`; `http3/client.go`: `newClientConn` | `http3/server_test.go`: `TestServerSettings`; `http3/client_test.go`: `TestClientSettings` |
| 4.1 | One request per stream | `http3/client.go`: `roundTrip`, `openRequestStream` | `http3/client_test.go`: `TestClientRequest` |
| 4.1 | Multiple requests, responses after the final response, or invalid frame sequences: malformed / H3_FRAME_UNEXPECTED | `http3/server_conn.go`: `handleRequestStream`; `http3/stream.go`: `Read`, `ReadResponse` | `http3/server_test.go`: `TestServerFramesAfterRequestTrailers`, `TestServerFirstFrameNotHeaders`; `http3/client_test.go`: `TestClientFramesAfterResponseTrailers` |
| 4.1 | PUSH_PROMISE on a push stream | Not applicable: server push is never enabled (no MAX_PUSH_ID is sent), every push stream is an H3_ID_ERROR | `http3/conn_test.go`: `TestConnRejectPushStream` |
| 4.1, 4.2 | No Transfer-Encoding or other connection-specific fields; TE only "trailers"; violations are malformed | `http3/headers.go`: `validateRegularHeaderField`; `http3/request_writer.go`: `encodeHeaders` | `http3/headers_test.go`: `TestRequestHeadersValidation`, `TestResponseHeaderParsingValidation`; `http3/request_writer_test.go`: `TestRequestWriterGetRequestGzip` |
| 4.1 | Client closes the stream after the request, independently of the response | `http3/client.go`: `doRequest` | `http3/client_test.go`: `TestClientRequest` |
| 4.1 | Server closes the stream after the final response | `http3/server_conn.go`: `handleRequestStream` | `http3/server_test.go`: `TestServerRequestHandling` |
| 4.1 | Clients keep complete responses after their request was reset | `http3/client.go`: `doRequest` (errors sending the body don't affect the response) | `http3/client_test.go`: `TestClientRequest` |
| 4.1.1 | H3_REQUEST_REJECTED only for unprocessed requests; never sent by clients | `http3/server.go`: `handleConn` (only for streams arriving during graceful shutdown); `http3/transport.go`: `canRetryRequest` | `http3/server_test.go`: `TestServerGracefulShutdown`; `http3/transport_test.go`: `TestTransportConnectionRedial` |
| 4.1.2, 4.2, 4.3.1, 4.4 | Requirements for intermediaries and proxies | Not applicable: http3 is no intermediary | - |
| 4.1.2 | Malformed requests and responses: H3_MESSAGE_ERROR stream error; clients don't accept them | `http3/server_conn.go`: `handleRequestStream`; `http3/stream.go`: `ReadResponse`; `http3/body.go`: `checkContentLengthViolation`, `Read` (Content-Length mismatches in both directions) | `http3/headers_test.go`: `TestRequestHeadersValidation`; `http3/client_test.go`: `TestClientResponseValidation`, `TestClientResponseWithoutContent`; `http3/body_test.go`: `TestResponseBodyLengthLimiting`, `TestBodyShorterThanContentLength` |
| 4.2 | Lowercase field names; uppercase is malformed | `http3/request_writer.go`: `encodeHeaders`, `writeHeaders`; `http3/response_writer.go`: `writeHeader` (lowercased); `http3/headers.go`: `validateHeaderFieldNameAndValue` | `http3/headers_test.go`: `TestRequestHeadersValidation` |
| 4.2.1 | Concatenate multiple cookie fields with "; " | `http3/headers.go`: `requestFromHeaders` | `http3/headers_test.go`: `TestCookieHeader` |
| 4.3 | Only defined pseudo-header fields, request ones in requests, response ones in responses, none in trailers; violations are malformed | `http3/headers.go`: `parseHeaders`, `parseTrailers` | `http3/headers_test.go`: `TestRequestHeadersValidation`, `TestResponseHeaderParsingValidation`, `TestResponseTrailerParsingValidation` |
| 4.3 | Pseudo-header fields before regular fields | `http3/headers.go`: `parseHeaders`; `http3/request_writer.go`: `encodeHeaders` | `http3/headers_test.go`: `TestRequestHeadersValidation` |
| 4.3.1 | No userinfo in :authority | `http3/request_writer.go`: `encodeHeaders` (uses the host only); `http3/headers.go`: `requestFromHeaders` (rejects it) | `http3/headers_test.go`: `TestRequestHeadersValidation` |
| 4.3.1 | :method, :scheme, :path exactly once (except CONNECT); :path not empty ("/"); :authority or Host, not empty, equal | `http3/headers.go`: `parseHeaders`, `requestFromHeaders`; `http3/request_writer.go`: `encodeHeaders` | `http3/headers_test.go`: `TestRequestHeadersValidation`, `TestRequestHeaderParsingWithHostHeader` |
| 4.3.2 | Responses carry :status | `http3/headers.go`: `updateResponseFromHeaders` | `http3/headers_test.go`: `TestResponseHeaderParsingValidation` |
| 4.4 | CONNECT requests: :method CONNECT, :authority, no :scheme and :path | `http3/request_writer.go`: `encodeHeaders`; `http3/headers.go`: `requestFromHeaders` | `http3/request_writer_test.go`: `TestRequestWriterConnect`; `http3/headers_test.go`: `TestRequestHeadersConnectValidation` |
| 4.4 | On a CONNECT stream, known frames other than DATA: H3_FRAME_UNEXPECTED | `http3/stream.go`: `Read`; `http3/server_conn.go`: `handleRequestStream`; `http3/client.go`: `openRequestStream` (a HEADERS frame after the CONNECT request or its response is not parsed as trailers) | `http3/server_test.go`: `TestServerConnectStreamHeadersFrame` |
| 4.6, 6.2.2, 7.2.5, 10.4 | Server push | Not applicable: the client never sends MAX_PUSH_ID and the server never pushes; every push stream is an H3_ID_ERROR (client) or H3_STREAM_CREATION_ERROR (server) | `http3/conn_test.go`: `TestConnRejectPushStream` |
| 5.2 | No new requests after GOAWAY | `http3/client.go`: `openRequestStream` | `http3/client_test.go`: `TestClientConnGoAway`, `TestClientConnGoAwayConcurrent` |
| 5.2 | GOAWAY identifiers don't increase; an increase is an H3_ID_ERROR | `http3/server.go`: `handleConn` (one GOAWAY); `http3/client.go`: `handleControlStream`; `http3/server_conn.go`: `handleControlStream` | `http3/client_test.go`: `TestClientConnGoAwayFailures`; `http3/server_test.go`: `TestServerControlStreamPushFrames` |
| 5.4 | Without GOAWAY, assume sent requests might have been processed | `http3/transport.go`: `canRetryRequest` (only H3_REQUEST_REJECTED or unopened streams are retried) | `http3/transport_test.go`: `TestTransportConnectionRedial` |
| 6.1 | Server-initiated bidirectional streams: H3_STREAM_CREATION_ERROR | `http3/client.go`: `HandleBidirectionalStream` | `http3/client_test.go`: `TestClientConnHandleBidirectionalStream` |
| 6.2 | Allow at least 3 unidirectional streams | `config.go`: `populateConfig` (default 100); `http3/transport.go`: `init`, `` http3/server.go:serveListener (QUIC configs that allow fewer are rejected) | `http3/transport_test.go`: `TestTransportQUICConfigUniStreams` |
| 6.2, 6.2.3, 9 | Unknown or reserved stream types are ignored (reading aborted), never an error; streams closed before their type are tolerated | `http3/conn.go`: `handleUnidirectionalStream` | `http3/conn_test.go`: `TestConnResetUnknownUniStream`; `http3/client_test.go`: `TestRawClientConnHandleUnidirectionalStream` |
| 6.2, 9 | Extensions are negotiated before use; their settings default to disabled | `http3/conn.go`: `sendDatagram` (H3_DATAGRAM); `http3/client.go`: `roundTrip` (Extended CONNECT) | `http3/conn_test.go`: `TestConnDatagramFailures`; `http3/client_test.go`: `TestClientExtendedConnect` |
| 6.2.1 | First control frame other than SETTINGS: H3_MISSING_SETTINGS | `http3/conn.go`: `handleControlStream` (frames of unknown and reserved types before it are skipped, see [Open points](#open-points)) | `http3/conn_test.go`: `TestConnControlStreamFailures` |
| 6.2.1, 6.2.2 | Second control stream or a client push stream: H3_STREAM_CREATION_ERROR | `http3/conn.go`: `handleUnidirectionalStream` | `http3/conn_test.go`: `TestConnRejectDuplicateStreams`, `TestConnRejectPushStream` |
| 6.2.1 | The control stream isn't closed; closure is H3_CLOSED_CRITICAL_STREAM | `http3/conn.go`: `handleControlStream`, `isCriticalStreamClosed` | `http3/conn_test.go`: `TestConnControlStreamFailures` |
| 7.1, 10.8 | Frame payloads contain exactly their fields; extra or missing bytes: H3_FRAME_ERROR | `http3/frames.go`: `parseSettingsFrame`, `parseSingleVarIntPayload`, `parseGoAwayFrame`, `parsePriorityUpdateFrame` | `http3/frames_test.go`: `TestParserSettingsFrameTruncatedSetting`, `TestParserSingleVarIntFrameInvalidLength`, `TestParserGoAwayFrame` |
| 7.1 | A truncated last frame at the end of a stream: H3_FRAME_ERROR | `http3/frames.go`: `ParseNext`; `http3/stream.go`: `Read`, `ReadResponse`; `http3/server_conn.go`: `handleRequestStream`; `http3/stream.go`: `Close` (a stream whose last frame might be incomplete after a failed write is reset, not closed) | `http3/stream_test.go`: `TestStreamTruncatedFrame`, `TestStreamCloseAfterFailedWrite`; `http3/server_test.go`: `TestServerTruncatedHeadersFrame`; `http3/frames_test.go`: `TestParserTruncatedFrame`; `integrationtests/self/http_test.go`: `TestHTTPDeadlines` |
| 7.2.1, 7.2.2 | DATA and HEADERS only on request streams; on the control stream: H3_FRAME_UNEXPECTED | `http3/conn.go`: `handleControlStream` | `http3/conn_test.go`: `TestConnControlStreamFailures` |
| 7.2.3 | CANCEL_PUSH only on the control stream; push IDs never promised: H3_ID_ERROR | `http3/conn.go`: `handleControlStream`; `http3/stream.go`: `Read` | `http3/server_test.go`: `TestServerControlStreamPushFrames`, `TestServerPushFramesOnRequestStream`; `http3/client_test.go`: `TestClientPushFramesOnRequestStream` |
| 7.2.4 | A second SETTINGS frame or one on another stream: H3_FRAME_UNEXPECTED | `http3/conn.go`: `handleControlStream`; `http3/stream.go`: `Read` | `http3/conn_test.go`: `TestConnControlStreamFailures`; `http3/stream_test.go`: `TestStreamInvalidFrame` |
| 7.2.4 | No duplicate setting identifiers | `http3/frames.go`: `Append` (settingsFrame); parseSettingsFrame (duplicates are an H3_SETTINGS_ERROR) | `http3/frames_test.go`: `TestParserSettingsFrameDuplicateSettings` |
| 7.2.4, 7.2.4.1 | Ignore unknown and reserved settings | `http3/frames.go`: `parseSettingsFrame` | `http3/frames_test.go`: `TestParserSettingsFrame` |
| 7.2.4.1 | HTTP/2 settings: H3_SETTINGS_ERROR | `http3/frames.go`: `parseSettingsFrame` | `http3/frames_test.go`: `TestParserSettingsFrameHTTP2Settings` |
| 7.2.4.2 | No frames or requests invalid for the peer's settings | `http3/conn.go`: `sendDatagram`; `http3/client.go`: `roundTrip` (Extended CONNECT only if enabled) | `http3/client_test.go`: `TestClientExtendedConnect`; `http3/conn_test.go`: `TestConnDatagramFailures` |
| 7.2.4.2 | 0-RTT uses remembered settings; the server only accepts 0-RTT with compatible settings, and sends all non-default settings | `http3/settings_0rtt.go`: `settingsForSessionTicket`, `settingsCompatibleFor0RTT`; `http3/server.go`: `ConfigureTLSConfig`; `http3/client.go` | `http3/settings_0rtt_test.go`: `TestSettingsCompatibleFor0RTT`; `integrationtests/self/http_0rtt_test.go`: `TestHTTP0RTTWithChangedServerSettings` |
| 7.2.5 | PUSH_PROMISE on the control stream, from a client, or to a server: H3_FRAME_UNEXPECTED | `http3/conn.go`: `handleControlStream`; `http3/stream.go`: `Read` | `http3/server_test.go`: `TestServerControlStreamPushFrames`, `TestServerPushFramesOnRequestStream` |
| 7.2.6 | GOAWAY with a non client-bidirectional stream ID: H3_ID_ERROR; GOAWAY off the control stream: H3_FRAME_UNEXPECTED | `http3/client.go`: `handleControlStream`; `http3/stream.go`: `Read` | `http3/client_test.go`: `TestClientConnGoAwayFailures`; `http3/stream_test.go`: `TestStreamInvalidFrame` |
| 7.2.7 | MAX_PUSH_ID only on the control stream, only from clients, never decreasing | `http3/conn.go`: `handleControlStream`; `http3/server_conn.go`: `handleControlStream` | `http3/server_test.go`: `TestServerControlStreamPushFrames`; `http3/client_test.go`: `TestClientPushFramesOnRequestStream` |
| 7.2.8 | Reserved frame types have no meaning | `http3/frames.go`: `ParseNext` (skipped) | `http3/frames_test.go`: `TestParserUnknownFrameType` |
| 7.2.8 | HTTP/2 frame types: H3_FRAME_UNEXPECTED | `http3/frames.go`: `ParseNext` | `http3/frames_test.go`: `TestParserReservedFrameType` |
| 8 | Unknown error codes are equivalent to H3_NO_ERROR | `http3/error.go` (error codes are passed to the application without further meaning) | `http3/error_test.go`: `TestErrorConversion` |
| 9 | Ignore unknown values of extensible elements | `http3/frames.go`: `ParseNext`, `parseSettingsFrame`; `http3/conn.go`: `handleUnidirectionalStream` | `http3/frames_test.go`: `TestParserUnknownFrameType`; `http3/conn_test.go`: `TestConnResetUnknownUniStream` |
| 10.3 | Invalid field names or values are malformed | `http3/headers.go`: `validateHeaderFieldNameAndValue`, `validateRegularHeaderField` | `http3/headers_test.go`: `TestRequestHeadersValidation` |
| 10.6 | Don't compress confidential and attacker-controlled data together | QPACK uses no dynamic table (http3/conn.go: capacity 0), and response bodies are only gzip-compressed by the application; http3 never compresses on its own | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 10.9 | Apply the anti-replay mitigations of RFC 8470 with 0-RTT | `http3/client.go`: `roundTrip` (0-RTT only for GET_0RTT / HEAD_0RTT; a 425 response is retried after the handshake); `http3/server_conn.go`: `handleRequestStream` (Request.TLS.HandshakeComplete is false for requests received in 0-RTT, the handler can answer 425) | `integrationtests/self/http_0rtt_test.go`: `TestHTTP0RTT`, `TestHTTP0RTTTooEarly` |
| 11.2.1, 11.2.2, 11.2.3, 11.2.4 | IANA registry rules | Not applicable to an implementation | - |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 3.1 | Clients SHOULD fall back to TCP-based HTTP when QUIC fails | Left to the application: http3.Transport only speaks HTTP/3. Applications combine it with net/http, as in upstream quic-go. |
| 3.3 | MAY reuse a connection for other authorities; SHOULD NOT open more than one connection per IP address and port | Not followed: http3.Transport keeps one connection per host name (and port), as in quic-go. Two host names served from the same address use two connections. |
| 3.3, 5.2 | SHOULD send GOAWAY before closing | Followed by Server.Shutdown. Server.Close, ClientConn.CloseWithError and the Transport close the connection with H3_NO_ERROR without a GOAWAY frame, as in quic-go. |
| 4.1.1 | Servers abandoning a response SHOULD use H3_REQUEST_CANCELLED | A handler that panics resets the stream with H3_INTERNAL_ERROR, which describes the cause better; http.ErrAbortHandler is handled the same way. |
| 4.2.1 | MAY split the Cookie header into several field lines | Not done. |
| 4.2.2 | SHOULD NOT send field sections larger than the peer's SETTINGS_MAX_FIELD_SECTION_SIZE | Not followed: the setting is parsed (Settings) but not used to limit requests or responses, as in quic-go. A peer rejects such messages. |
| 4.6, 7.2.3, 7.2.5, 10.5 | Server push | Not applicable: push is not supported. |
| 5.2 | After GOAWAY, SHOULD cancel requests with higher IDs | Followed by the server (H3_REQUEST_REJECTED). Clients never send GOAWAY. |
| 5.2 | Clients MAY send GOAWAY | Not done. |
| 6.2 | SHOULD give each unidirectional stream at least 1,024 bytes of flow control credit | Followed by default (InitialStreamReceiveWindow 512 KB); an application can configure less. |
| 7.2.4.1 | SHOULD include at least one reserved (greasing) setting | Not followed, as in quic-go. |
| 8.1 | SHOULD sometimes use reserved error codes instead of H3_NO_ERROR | Not followed, as in quic-go. |
| 10.5.1 | MAY send field sections above the peer's limit | See 62. |

### RFC 9204: QPACK

[RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) has 37 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 2.1, 2.2 | Encoder and decoder keep the order of field lines | github.com/quic-go/qpack (Encoder.WriteField, Decoder.Decode); `http3/headers.go`: `parseHeaders` | `http3/headers_test.go`: `TestRequestHeaderParsing`, `TestHeadersConcatenation` |
| 2.1.1, 2.1.2, 3.2.2, 3.2.3, 4.3.1 | Encoder rules for the dynamic table and blocked streams | The encoder (github.com/quic-go/qpack) never uses the dynamic table, never blocks a stream and sends no encoder instructions; no encoder stream is opened | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 2.1.2, 2.2.1, 2.2.3, 4.5.1.1, 4.5.1.2 | Decoder: blocked streams beyond the limit, invalid Required Insert Count, Base or dynamic table references: QPACK_DECOMPRESSION_FAILED | `http3/qpack.go`: `checkFieldSection` (the dynamic table capacity is 0, so the Encoded Required Insert Count must be 0, the Sign bit 0, and there are no dynamic table references; any Delta Base is accepted, and rewritten to 0 for the decoder) | `http3/qpack_test.go`: `TestCheckFieldSection`, `FuzzCheckFieldSection` |
| 2.2.2.1, 3.2 | Section Acknowledgments after dynamic table references; duplicate entries | Not applicable: field sections referencing the dynamic table are rejected, and no dynamic table exists | `http3/qpack_test.go`: `TestCheckFieldSection` |
| 2.2.3, 3.1, 3.2.2, 4.3.1 | Encoder stream instructions: invalid references, entries larger than the capacity, capacity above the limit: QPACK_ENCODER_STREAM_ERROR | `http3/conn.go`: `handleQPACKEncoderStream` (only Set Dynamic Table Capacity 0 is accepted) | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 3.1 | Invalid static table index in a field line: QPACK_DECOMPRESSION_FAILED | `http3/qpack.go`: `checkFieldSection` | `http3/qpack_test.go`: `TestCheckFieldSection` |
| 3.2.3 | A server that remembered a non-zero capacity sends the same value | Not applicable: SETTINGS_QPACK_MAX_TABLE_CAPACITY is never sent (0) | - |
| 4.1.1 | Decode integers of up to 62 bits | `http3/qpack.go`: `readQPACKVarInt`; github.com/quic-go/qpack | `http3/qpack_test.go`: `TestCheckFieldSection` |
| 4.2 | At most one encoder and one decoder stream | `http3/conn.go` (no QPACK streams are opened) | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 4.2 | A second encoder or decoder stream: H3_STREAM_CREATION_ERROR | `http3/conn.go`: `handleUnidirectionalStream` | `http3/conn_test.go`: `TestConnRejectDuplicateStreams` |
| 4.2 | The streams aren't closed; closure is H3_CLOSED_CRITICAL_STREAM | `http3/conn.go`: `handleQPACKStreamReadError` | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 4.2 | Allow the peer to open both streams | `http3/conn.go`: `handleUnidirectionalStream`; `config.go` (3 or more unidirectional streams) | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 4.4.1, 4.4.3 | Decoder stream: Section Acknowledgment without outstanding field sections, Insert Count Increment of 0 or beyond the sent count: QPACK_DECODER_STREAM_ERROR | `http3/conn.go`: `handleQPACKDecoderStream` (only Stream Cancellation is accepted) | `http3/conn_test.go`: `TestConnQPACKStreams` |
| 4.5.4, 7.1.3 | Never-indexed literals are forwarded as literals | Not applicable: http3 is no intermediary, and no field is ever indexed | - |
| 7.4 | Values too large to decode: QPACK_DECOMPRESSION_FAILED (stream error on request streams) | `http3/stream.go`: `ReadResponse`; `http3/server_conn.go`: `handleRequestStream` (qpack errors reset the stream with QPACK_DECOMPRESSION_FAILED) | `http3/headers_test.go`: `TestQpackError`; `http3/client_test.go`: `TestClientResponseHeadersQPACKConnectionError` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 2.1, 3.2.3 | MAY insert entries into the dynamic table; MAY raise the capacity after 0-RTT | Not done: neither endpoint uses the dynamic table (capacity 0), as in quic-go. Field sections are encoded with the static table and literals. |

### RFC 9221: Unreliable datagram extension

[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) has 10 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 3 | Only send DATAGRAM frames after receiving a non-zero max_datagram_frame_size, and not larger | `connection.go`: `SendDatagram`, `supportsDatagrams` | `connection_test.go`: `TestConnectionDatagrams`; `integrationtests/self/datagram_test.go`: `TestDatagramSizeLimit` |
| 3 | DATAGRAM frames without having advertised support: PROTOCOL_VIOLATION | `internal/wire/frame_parser.go`: `ParseType` | `internal/wire/frame_parser_test.go`: `TestFrameParserDatagramUnsupported` |
| 3 | DATAGRAM frames larger than the advertised size: PROTOCOL_VIOLATION | `connection.go`: `handleDatagramFrame` | `connection_test.go`: `TestConnectionDatagrams` |
| 3 | 0-RTT: the server doesn't reduce max_datagram_frame_size; the client validates the new value | `internal/wire/transport_parameters.go`: `ValidFor0RTT`, `ValidForUpdate` | `integrationtests/self/zero_rtt_test.go`: `Test0RTTRejectedOnDatagramsDisabled`; `internal/wire/transport_parameter_test.go`: `TestTransportParametersValidAfter0RTT` |
| 3 | Application protocols define their reaction to the absence of the parameter | http3 (RFC 9297: H3_SETTINGS_ERROR if H3_DATAGRAM is enabled without QUIC datagram support): http3/conn.go:handleControlStream | `http3/conn_test.go`: `TestConnInconsistentDatagramSupport` |
| 5, 6 | DATAGRAM frames only in 0-RTT and 1-RTT packets | `packet_packer.go`: `composeNextPacket`; `internal/wire/frame_type.go` (isAllowedAtEncLevel) | `internal/wire/frame_parser_test.go`: `TestFrameAllowedAtEncLevel`; `packet_packer_test.go`: `TestPackDatagramFrames` |
| 5.4 | Congestion control: delay or drop | `datagram_queue.go`: `Add`, `Peek` (frames wait in a bounded queue until a packet can be sent) | `datagram_queue_test.go`: `TestDatagramQueuePeekAndPop` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 3 | RECOMMENDED to send max_datagram_frame_size 65535 | Not followed, as in quic-go: 16383 is sent (internal/wire/datagram_frame.go:MaxDatagramSize). DATAGRAM frames can't be split, so the path MTU limits them to far less anyway. |
| 5.1 | SHOULD offer an API to prioritize DATAGRAM frames | Not offered: DATAGRAM frames are sent before STREAM data, in the order they were queued. |
| 5.2 | MAY notify the application of datagram loss or acknowledgment | Not done. |

### RFC 9297: HTTP Datagrams and the Capsule Protocol

[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) has 28 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 2 | HTTP Datagrams only for requests that support them; datagrams for requests without datagram semantics abort the request with H3_DATAGRAM_ERROR | Application: http3 delivers datagrams to their request stream (Stream.ReceiveDatagram, RequestStream.ReceiveDatagram); the protocol using the request (e.g. CONNECT-UDP) defines their semantics and aborts the request | - |
| 2.1 | Quarter Stream ID too large or not parseable: H3_DATAGRAM_ERROR | `http3/conn.go`: `receiveDatagrams` | `http3/conn_test.go`: `TestConnDatagramFailures` |
| 2.1 | Only send datagrams while the stream's send side is open | `http3/state_tracking_stream.go`: `SendDatagram` | `http3/state_tracking_stream_test.go`: `TestDatagramSending` |
| 2.1 | Drop datagrams for closed or unknown streams | `http3/state_tracking_stream.go`: `enqueueDatagram`; `http3/conn.go`: `receiveDatagrams` | `http3/state_tracking_stream_test.go`: `TestDatagramReceiving` |
| 2.1.1 | SETTINGS_H3_DATAGRAM is 0 or 1; other values: H3_SETTINGS_ERROR | `http3/frames.go`: `parseSettingsFrame` | `http3/frames_test.go`: `TestParserSettingsFrameDatagramInvalidValue` |
| 2.1.1 | No QUIC DATAGRAM frames before H3_DATAGRAM was sent and received with 1 | `http3/conn.go`: `sendDatagram` (waits for the peer's SETTINGS, and fails without support on both sides) | `http3/conn_test.go`: `TestConnSendDatagramRequiresSettings` |
| 2.1.1 | 0-RTT: the server doesn't lower SETTINGS_H3_DATAGRAM; a client that stores it validates it | `http3/settings_0rtt.go`: `settingsCompatibleFor0RTT` (the server rejects 0-RTT if the setting changed); the client doesn't store settings | `http3/settings_0rtt_test.go`: `TestSettingsCompatibleFor0RTT` |
| 3.2 | Skip unknown capsule types | Application: http3/capsule.go:Next returns every capsule with its type; the protocol using capsules skips unknown ones | `http3/capsule_test.go`: `TestCapsuleParsing` |
| 3.2, 3.4 | Capsule Protocol header field and the messages using it | Application: http3 doesn't interpret the Capsule-Protocol header field; protocols using capsules (e.g. WebTransport) check it | - |
| 3.3 | Capsule errors are malformed messages; truncated capsules | `http3/capsule.go`: `Next`, `Read` (io.ErrUnexpectedEOF for truncated capsules) | `http3/capsule_test.go`: `TestCapsuleTruncation`, `TestCapsuleParsing` |
| 3.5 | Intermediaries re-encoding datagrams | Not applicable: http3 is no intermediary | - |
| 5.4 | IANA registry rules | Not applicable to an implementation | - |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 2.1 | SHOULD buffer datagrams for streams that can't be created yet because of stream limits | Not done: datagrams for unknown streams are dropped. |
| 2.1.1 | Clients MAY store SETTINGS_H3_DATAGRAM for 0-RTT | Not done: the client doesn't store the server's settings, and doesn't send datagrams before receiving them. |
| 3.4 | SHOULD send the Capsule-Protocol header field | Left to the protocols using capsules: http3 provides the capsule parser and writer only. |

### RFC 9368: Compatible version negotiation

[RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) has 35 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 2.1 | Version Negotiation packets list every Offered Version | `server.go`: `maybeSendVersionNegotiationPacket` (Config.Versions, plus a reserved version) | `server_test.go`: `TestServerVersionNegotiation`; `internal/wire/version_negotiation_test.go`: `TestComposeVersionNegotiationWithReservedVersion` |
| 2.1 | Client selects a mutually supported version from a Version Negotiation packet, or aborts | `connection.go`: `handleVersionNegotiationPacket`; `internal/protocol/version.go`: `ChooseSupportedVersion` | `connection_test.go`: `TestConnectionVersionNegotiation`, `TestConnectionVersionNegotiationNoMatch`; `integrationtests/versionnegotiation/handshake_test.go`: `TestClientSupportsMoreVersionsThanServer` |
| 2.1 | Clients never send, servers ignore Version Negotiation packets | `server.go`: `handlePacketImpl`; `connection.go`: `handleVersionNegotiationPacket` | `server_test.go`: `TestServerPacketDropping`; `connection_test.go`: `TestConnectionServerInvalidPackets` |
| 2.2 | No compatibility unless specified | `internal/protocol/version.go`: `IsCompatibleVersion` (only versions 1 and 2) | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiation` |
| 2.3 | Server selects a supported version compatible with the Chosen Version; aborts if the first flight can't be converted | `internal/handshake/version_negotiation.go`: `negotiateVersion`, `negotiateVersionFromClientHello` | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiation`; `internal/handshake/version_negotiation_test.go`: `TestCompatibleVersionNegotiationClientHelloSplit` |
| 2.3, 4, 7.1, 7.3 | Requirements on version specifications | Not applicable to an implementation (RFC 9369 specifies them for versions 1 and 2) | - |
| 2.3 | Validations of the Negotiated Version apply to the converted first flight | `internal/handshake/crypto_setup.go`: `SwitchVersion` (the ClientHello is processed under the Negotiated Version) | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiation` |
| 3 | Version Information is exchanged and authenticated in both directions | `internal/wire/transport_parameters.go`: `Marshal`, `readVersionInformation` (version_information transport parameter) | `internal/wire/transport_parameter_test.go`: `TestVersionInformationTransportParameter` |
| 3 | The Chosen Version is one of the client's Available Versions | `internal/wire/transport_parameters.go`: `Marshal`; `connection.go` (client Version Information) | `internal/wire/transport_parameter_test.go`: `TestVersionInformationTransportParameter` |
| 4 | Ignore Version Negotiation packets listing the Original Version, and all of them after reacting to one | `connection.go`: `handleVersionNegotiationPacket` (versionNegotiated) | `connection_test.go`: `TestConnectionVersionNegotiationInvalidPackets`; `integrationtests/versionnegotiation/compatible_test.go`: `TestIncompatibleFollowedByCompatibleVersionNegotiation` |
| 4 | Parse the peer's Version Information; failures (length, version 0, Chosen Version missing from Available Versions) close the connection with TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `readVersionInformation`; `internal/handshake/version_negotiation.go` | `internal/wire/transport_parameter_test.go`: `TestVersionInformationTransportParameter`; `internal/handshake/version_negotiation_test.go`: `TestInvalidVersionInformationIsTransportParameterError` |
| 4 | Server checks the client's Chosen Version against the version in use: VERSION_NEGOTIATION_ERROR | `internal/handshake/version_negotiation.go`: `validateVersionInformation` | `internal/handshake/version_negotiation_test.go`: `TestServerRejectsMismatchingChosenVersion`, `TestServerRejectsChangedVersionInformation` |
| 4 | Client checks: missing Version Information after reacting to Version Negotiation, Chosen Version not offered or different from the long header version, Available Versions that would have led to another choice: VERSION_NEGOTIATION_ERROR | `internal/handshake/version_negotiation.go`: `validateVersionInformation` | `internal/handshake/version_negotiation_test.go`: `TestClientValidatesServerVersionInformation`; `integrationtests/versionnegotiation/compatible_test.go`: `TestVersionDowngradePrevention` |
| 6 | ALPN tokens only with the versions they are defined for | ALPN is chosen by the application; RFC 9369 allows the application protocols of version 1 over version 2. http3.Transport uses only version 1 by default | `http3/transport_test.go`: `TestTransportMultipleQUICVersions` |
| 6 | After incompatible version negotiation, the new attempt negotiates ALPN again | `connection.go`: `handleVersionNegotiationPacket` (a new connection attempt with a new TLS handshake) | `integrationtests/versionnegotiation/compatible_test.go`: `TestIncompatibleFollowedByCompatibleVersionNegotiation` |
| 8 | Special handling of QUIC version 1 without Version Information | `internal/handshake/version_negotiation.go`: `validateVersionInformation` | `integrationtests/versionnegotiation/compatible_test.go`: `TestVersionNegotiationToVersion1` |
| 8 | Implement this mechanism for negotiating versions other than version 1 | `internal/handshake/version_negotiation.go` | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiation` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 1.2, 5 | Server deployments SHOULD add or remove versions in three steps, waiting the Maximum Segment Lifetime | Not applicable to a single server: Acceptable, Offered and Fully Deployed Versions are all Config.Versions. Deployments with several server instances need to roll out version changes accordingly. |
| 3 | The server's Available Versions MAY be empty | Not used: the server sends its Config.Versions. |
| 3 | MAY include reserved versions in the Available Versions | Not done. Reserved versions are sent in Version Negotiation packets, and transport parameters are greased with reserved IDs. |

### RFC 9369: QUIC version 2

[RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) has 12 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 3 | Version 2 implements version 1 with the listed differences (salt, labels, Retry key, packet types) | `internal/handshake/initial_aead.go`: `computeSecrets`; `internal/handshake/hkdf.go`; `internal/handshake/retry.go`: `GetRetryIntegrityTag`; `internal/wire/header.go`: `parseLongHeader`; `internal/handshake/updatable_aead.go`: `hkdfKeyUpdateLabel` | `internal/handshake/initial_aead_test.go`: `TestClientInitial`; `internal/handshake/retry_test.go`: `TestRetryIntegrityTagWithTestVectors`; `internal/wire/extended_header_test.go`: `TestWritesInitialPacketVersion2`; `internal/handshake/updatable_aead_test.go`: `TestKeyUpdateLabel` |
| 4 | Send, process and validate version_information | `internal/wire/transport_parameters.go`; `internal/handshake/version_negotiation.go`: `validateVersionInformation` | `integrationtests/versionnegotiation/compatible_test.go`: `TestVersionDowngradePrevention` |
| 4.1 | Retry uses the original version; the client doesn't switch versions between the Retry and its next Initial | `server.go`: `sendRetryPacket`; `connection.go`: `handleRetryPacket`; `version_negotiation.go`: `acceptsVersion` | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiationWithRetry` |
| 4.1 | After a Retry, the transport parameters authenticate it | `connection.go`: `checkTransportParameters` | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiationWithRetry` |
| 4.1 | The server sends all CRYPTO frames in the Negotiated Version (also a HelloRetryRequest) | `internal/handshake/version_negotiation.go`: `negotiateVersionFromClientHello`; `internal/handshake/crypto_setup.go`: `SwitchVersion` | `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiationWithHelloRetryRequest` |
| 4.1 | The server keeps the Initial keys of the original version until it processed a Handshake packet | `internal/handshake/crypto_setup.go`: `GetInitialOpener` | `internal/handshake/version_negotiation_test.go`: `TestInitialOpenersDuringCompatibleVersionNegotiation` |
| 4.1 | Handshake and 1-RTT packets use the Negotiated Version; packets of other versions are dropped | `version_negotiation.go`: `acceptsVersion`, `switchVersion` | `version_negotiation_test.go`: `TestConnectionClientDropsOtherVersions`, `TestConnectionAcceptsOtherVersion` |
| 4.1 | No 0-RTT packets in the Negotiated Version | `packet_packer.go`: `get0RTTVersion` | `packet_packer_test.go`: `TestPack0RTTPacketUsingChosenVersion`; `integrationtests/versionnegotiation/compatible_test.go`: `TestCompatibleVersionNegotiationWith0RTT` |
| 5 | Session tickets and tokens are scoped to their version | `internal/handshake/session_ticket.go`: `restrictSessionTicketsToVersion`, `unwrapSessionForVersion`; `internal/handshake/token_generator.go`: `encodeTokenVersion`, `decodeTokenVersion`; `version_negotiation.go`: `versionedTokenStoreKey` | `internal/handshake/session_ticket_test.go`: `TestSessionTicketsScopedToVersion`; `internal/handshake/token_generator_test.go`: `TestTokenGeneratorVersion`; `integrationtests/versionnegotiation/compatible_test.go`: `TestSessionResumptionScopedToVersion` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| - | Clients can start with version 2 if they know that the server supports it, e.g. from a session ticket (section 6, no keyword) | Not done: the client starts with Config.InitialVersion or the first version of Config.Versions, even if it holds a session ticket for version 2. |

### RFC 9287: Greasing the QUIC Bit

[RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) has 7 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 3 | A non-empty grease_quic_bit: TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `unmarshal` | `internal/wire/transport_parameter_test.go`: `TestGreaseQUICBitTransportParameter` |
| 3 | An endpoint advertising grease_quic_bit accepts packets with the QUIC Bit 0 | `internal/wire/header.go`: `ParsePacketWithGreasedQUICBit`; `internal/wire/short_header.go`: `ParseShortHeaderWithGreasedQUICBit`; `transport.go`: `handleGreasedShortHeaderPacket`; `server.go`: `handlePacketImpl` | `grease_quic_bit_test.go`: `TestConnectionAcceptsGreasedQUICBit`; `transport_test.go`: `TestTransportGreasedQUICBit`; `server_test.go`: `TestServerGreasedQUICBitInitial` |
| 3.1 | Clients only clear the QUIC Bit after learning that the server supports it | `packet_packer.go`: `EnableQUICBitGreasing`, `maybeGreaseQUICBit` (enabled when the peer's transport parameters are processed) | `grease_quic_bit_test.go`: `TestConnectionGreaseQUICBitNegotiation`; `packet_packer_test.go`: `TestPackGreasedQUICBit` |
| 3.1 | Servers clear it only after processing the client's transport parameters, never based on earlier connections | `connection.go`: `applyTransportParameters`; `internal/wire/transport_parameters.go`: `MarshalForSessionTicket` (not stored) | `grease_quic_bit_test.go`: `TestConnectionGreaseQUICBitNotRestored`, `TestConnectionGreaseQUICBitNegotiation` |
| 3.2 | Extensions using the QUIC Bit negotiate it | Not applicable: no extension uses the QUIC Bit | - |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 3.1 | Endpoints that receive grease_quic_bit SHOULD set the QUIC Bit to an unpredictable value | Followed if Config.EnableQUICBitGreasing is set. Without it, the QUIC Bit is never set to 0, even if the peer sent the transport parameter: greasing changes the wire image, and middleboxes or applications might demultiplex by the QUIC Bit, so it is opt-in. |
| 3.1 | A client MAY clear the QUIC Bit before receiving the server's transport parameters, with a recent NEW_TOKEN token from a server that sent grease_quic_bit | Not implemented: it would require storing the transport parameter with the token. Servers accept Initial packets with the QUIC Bit set to 0. |

### draft-ietf-quic-multipath-21: Multipath extension for QUIC

[draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21) has 36 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 2 | Without initial_max_path_id from both endpoints, nothing of the extension is used | `multipath.go`: `maybeAdvertiseMultipath`, `maybeNegotiateMultipath`; `connection.go`: `handleFrame` (multipath frames without negotiation: PROTOCOL_VIOLATION); `internal/wire/frame_parser.go`: `EnableMultipath` | `multipath_test.go`: `TestMultipathNegotiation`; `integrationtests/self/multipath_test.go`: `TestMultipathSinglePathInterop`; `interop/multipath/picoquic_test.go`: `TestPicoquicServerSinglePath` |
| 2.1 | initial_max_path_id is at most 2^32-1; larger values: TRANSPORT_PARAMETER_ERROR | `multipath.go`: `localInitialMaxPathID`, `checkMultipathTransportParameters` (endpoints with multipath configured; others ignore the parameter) | `multipath_test.go`: `TestMultipathTransportParameterValidation`; `internal/wire/transport_parameter_test.go`: `TestInitialMaxPathIDTransportParameter` |
| 2.1 | Non-zero-length connection IDs when advertising; a parameter received with a zero-length connection ID: PROTOCOL_VIOLATION | `transport.go`: `Dial`, `init` (no zero-length connection IDs with multipath); `multipath.go`: `checkMultipathTransportParameters`; `connection.go`: `handleRetryPacket` | `multipath_test.go`: `TestMultipathNegotiationZeroLengthConnectionID`, `TestMultipathZeroLengthConnectionIDPeerAdvertises`, `TestMultipathRetryZeroLengthConnectionID`, `TestMultipathDialAddrConnectionIDLength` |
| 2.1 | Cipher suites with nonces shorter than 12 bytes: TRANSPORT_PARAMETER_ERROR | `internal/handshake/crypto_setup.go`: `EnableMultipath` | `multipath_test.go`: `TestMultipathCipherSuiteCheck`; `internal/handshake/crypto_setup_test.go`: `TestEnableMultipathWithShortNonce` |
| 2.1 | initial_max_path_id isn't remembered for 0-RTT | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket`, `unmarshal` | `internal/wire/transport_parameter_test.go`: `TestInitialMaxPathIDNotSavedInSessionTicket`; `multipath_test.go`: `TestMultipathNotRememberedFor0RTT` |
| 2.3 | ACK frames for 0-RTT and 1-RTT packets are still processed | `connection.go`: `handleAckFrame` | `multipath_test.go`: `TestMultipathAckFrames` |
| 3.1 | A new path uses a new connection ID of an unused path ID | `multipath_path.go`: `openPath`, `nextPathIDToOpen` | `multipath_open_test.go`: `TestMultipathOpenPath`; `multipath_path_test.go`: `TestMultipathClientOpenPath` |
| 3.1 | Packets on a path use connection IDs of that path ID | `multipath_send.go`: `pathDestConnID`; `conn_id_manager.go`: `GetConnIDForPath` | `packet_packer_test.go`: `TestPackMultipathPacket`; `conn_id_manager_test.go`: `TestConnIDManagerMultipathAddAndGet` |
| 3.1 | Validate new paths (the client's peer address, the server before sending data), including a datagram of 1200 bytes | `multipath_path.go`: `startPathValidation`, `newServerPath`; `multipath_send.go`: `sendMultipathProbePacket` (PATH_CHALLENGE in datagrams of at least 1200 bytes) | `multipath_open_test.go`: `TestMultipathServerValidatesPath`; `multipath_path_test.go`: `TestMultipathServerNewPath`; `multipath_migration_test.go`: `TestMultipathServerPathMigrationValidatesPathMTU` |
| 3.1 | PATH_RESPONSE on the path of the PATH_CHALLENGE, with a connection ID of that path ID | `multipath_path.go`: `handleMultipathPacketOnPath`, `sendMultipathProbeToTuple` | `multipath_test.go`: `TestMultipathPathResponse`; `multipath_path_test.go`: `TestMultipathPathResponseOnOtherTuple` |
| 3.1 | A path that fails validation isn't used and is closed with PATH_ABANDON | `multipath_path.go`: `handleMultipathTimers`, `abandonPath` | `multipath_path_test.go`: `TestMultipathClientPathValidationTimeout`; `multipath_open_test.go`: `TestMultipathOpenPathTimeout` |
| 3.1.2 | A new 4-tuple on a path is a migration of that path, using connection IDs of its path ID | `multipath_path.go`: `migrateMultipathPath`, `pathMigrationManager` | `multipath_migration_test.go`: `TestMultipathServerPathMigration`; `multipath_lifecycle_test.go`: `TestMultipathNATRebindingEndToEnd` |
| 3.2.1 | No connection IDs for path IDs above the maximum | `conn_id_generator.go`: `issueForUnusedPaths`, `SetPeerMaxPathID` | `conn_id_generator_test.go`: `TestConnIDGeneratorMultipathMaxPathID` |
| 3.2.2 | Rotate only to connection IDs of the same path ID | `conn_id_manager.go` (one connection ID manager per path ID) | `conn_id_manager_test.go`: `TestConnIDManagerMultipathRotation` |
| 3.4 | Close paths with PATH_ABANDON; retire the peer's connection IDs of the path; answer a PATH_ABANDON with one | `multipath_path.go`: `abandonPath`, `markPathAbandoned`; `multipath.go`: `handlePathAbandonFrame`; `conn_id_manager.go`: `AbandonPath` | `multipath_path_test.go`: `TestMultipathPeerAbandonsPath`; `multipath_lifecycle_test.go`: `TestMultipathAbandonPathEndToEnd`; `conn_id_manager_test.go`: `TestConnIDManagerMultipathAbandonPath`; `interop/multipath/picoquic_test.go`: `TestPicoquicServerAbandonPaths` |
| 3.4 | Path IDs are never reused | `multipath_path.go`: `nextPathIDToOpen`; `multipath.go`: `closePathID` | `integrationtests/self/multipath_linux_test.go`: `TestMultipathAbandonAndOpenPath`; `multipath_abandon_test.go`: `TestMultipathOpenPathWhileClosingPath` |
| 3.4.3 | When the state of a path is deleted, its unacknowledged packets are lost | `internal/ackhandler/sent_packet_handler.go`: `AbandonPath`, `RemovePath` | `internal/ackhandler/sent_packet_handler_multipath_test.go`: `TestSentPacketHandlerMultipathAbandonPath`, `TestSentPacketHandlerMultipathRemovePath0` |
| 4 | Multipath frames only in 1-RTT packets; elsewhere PROTOCOL_VIOLATION | `internal/wire/frame_parser.go`: `ParseType`; `packet_packer.go` | `internal/wire/frame_parser_test.go`: `TestFrameAllowedAtEncLevel`; `multipath_test.go`: `TestMultipathFramesIn0RTTPackets` |
| 4 | Path IDs above the announced maximum: PROTOCOL_VIOLATION | `multipath.go`: `checkPathID` | `multipath_test.go`: `TestMultipathFramesPathIDTooLarge` |
| 4 | Frames for paths that can't be processed anymore are ignored | `multipath.go`: `handleMultipathFrame`, `isClosed` | `multipath_test.go`: `TestMultipathPathAbandonUnusedPath`; `multipath_abandon_test.go`: `TestMultipathAbandonedPathRetention` |
| 4.3 | Path status sequence numbers increase; older or equal ones are ignored | `multipath_path.go`: `queuePathStatusFrame`; `multipath.go`: `handlePathStatusFrame` | `multipath_test.go`: `TestMultipathPathStatusFrames`; `multipath_status_test.go`: `TestMultipathPathStatusSending` |
| 4.6 | MAX_PATH_ID: at most 2^32-1, not below initial_max_path_id (PROTOCOL_VIOLATION), decreases ignored | `internal/wire/max_path_id_frame.go`; `multipath.go`: `handleMaxPathIDFrame`, `raiseMaxPathID` | `internal/wire/max_path_id_frame_test.go`: `TestParseMaxPathIDFrameLargerThanMaxPathID`; `multipath_test.go`: `TestMultipathMaxPathIDFrame` |
| 4.7 | PATHS_BLOCKED / PATH_CIDS_BLOCKED with values above the local maximum or the next sequence number: PROTOCOL_VIOLATION | `multipath.go`: `handleMultipathFrame`, `handlePathCIDsBlockedFrame` | `multipath_test.go`: `TestMultipathPathsBlockedFrame`, `TestMultipathPathCIDsBlockedFrame` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 3.2.1 | An endpoint that can't open a path SHOULD send MAX_PATH_ID or close paths | Path.Probe returns ErrTooManyPaths when the local Config.MaxPaths is reached; MAX_PATH_ID is only sent when a path was closed. Config.MaxPaths is the resource limit chosen by the application. |
| 3.2.2 | MAY send PATH_CIDS_BLOCKED when rotating connection IDs | Only sent when opening a path is blocked; rotation is opportunistic. |
| 3.4 | MAY close the connection if the peer doesn't answer a PATH_ABANDON | Not done: the connection IDs of the path stay valid until the peer answers or the connection ends; all other state is removed after 3 times the largest PTO. Removing the connection IDs would make the endpoint send stateless resets to a peer that might still use them. |
| 3.4 | When the only path is abandoned, MAY try another path, or wait for one | Not done: the connection is closed with NO_VIABLE_PATH, which is simple and bounded. |
| 7.1 | SHOULD allocate path resources only after validation | Partly: the packet number space, congestion controller and keys are created when the path is opened, since validation packets need them; MTU discovery, ECN validation, scheduling and the controller notifications start after validation. Config.MaxPaths bounds the number of paths. |

### draft-ietf-quic-address-discovery-01: QUIC Address Discovery

[draft-ietf-quic-address-discovery-01](https://datatracker.ietf.org/doc/html/draft-ietf-quic-address-discovery-01) has 9 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 3 | address_discovery values other than 0, 1, 2: TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `readNumericTransportParameter` | `address_discovery_test.go`: `TestAddressDiscoveryTransportParameter` |
| 3 | 0-RTT: both endpoints remember the value; a server accepting 0-RTT keeps it | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket`, `ValidFor0RTT`, `ValidForUpdate` | `internal/wire/transport_parameter_test.go`: `TestAddressDiscoveryTransportParameterFor0RTT`; `integrationtests/self/zero_rtt_test.go`: `Test0RTTRejectedOnAddressDiscoveryChanged`, `Test0RTTWithAddressDiscovery` |
| 4.1 | Sequence numbers increase within the connection | `address_discovery.go`: `AppendObservedAddress`, `probeFrame` (one counter for all paths) | `address_discovery_test.go`: `TestAddressDiscoverySendsFrameOnEveryPath`, `TestAddressDiscoveryProbeFrames` |
| 4.1 | OBSERVED_ADDRESS only in the application data packet number space | `internal/wire/frame_parser.go`: `ParseType`, `EnableObservedAddress`; `packet_packer.go` (not in 0-RTT packets either) | `internal/wire/frame_parser_test.go`: `TestFrameParserEnableObservedAddress`; `packet_packer_test.go`: `TestPack0RTTPacketWithoutObservedAddress` |
| 4.1 | Retransmissions on the path of the original frame | `address_discovery.go`: `OnLost` (a new frame with the current address on the same path) | `address_discovery_test.go`: `TestAddressDiscoveryLostFrame`, `TestAddressDiscoveryLostFrameEndToEnd` |
| 4.1 | Only send to peers that requested observations | `address_discovery.go`: `HasObservedAddress`; `connection.go`: `addressDiscoveryState` | `address_discovery_test.go`: `TestAddressDiscoveryNegotiation`, `TestAddressDiscoveryReceiveOnly` |
| 4.1 | Frames received without having requested them: PROTOCOL_VIOLATION | `address_discovery.go`: `handleObservedAddressFrame` | `address_discovery_test.go`: `TestAddressDiscoveryUnexpectedFrame` |
| 5 | Send OBSERVED_ADDRESS on every new path | `address_discovery.go`: `addPath`, `probeFrame`, `switchPath`; `connection.go`: `observedAddrProbeFrame` | `address_discovery_test.go`: `TestAddressDiscoverySendsFrameOnEveryPath`, `TestAddressDiscoveryNATRebinding`, `TestAddressDiscoveryMultipath`, `TestAddressDiscoveryClientMigration` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 4.1 | Lost frames SHOULD be retransmitted | A new frame with the current address (and a new sequence number) is sent on the same path, if the path still uses the 4-tuple of the lost frame: the address might have changed. |
| 5 | Send the frame as early as possible | In the first 1-RTT packet, not in 0-RTT packets: the client hasn't observed the server's address when it sends 0-RTT packets, and 0-RTT packets can be replayed. |
| 6.2 | Don't offer observations when the address can't be observed; limit spurious frames | Left to the application (Config.ProvideObservedAddress is off by default). Frames for new addresses are only sent when the connection validates them, which the path managers limit. |

### draft-ietf-quic-reliable-stream-reset-11: Stream Resets with Partial Delivery

[draft-ietf-quic-reliable-stream-reset-11](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11) has 17 MUST statements. Every one of them is covered by a row of this table.

| Section | Requirement | Implementation | Tests |
|---|---|---|---|
| 3 | A non-empty reset_stream_at: TRANSPORT_PARAMETER_ERROR | `internal/wire/transport_parameters.go`: `unmarshal` (both code points) | `internal/wire/transport_parameter_test.go`: `TestResetStreamAtTransportParameterCodepoints`, `TestTransportParameterErrors` |
| 3 | Only send RESET_STREAM_AT if the peer advertised support | `send_stream.go`: `enableResetStreamAt`, `CancelWrite` (RESET_STREAM otherwise); `streams_map_outgoing.go`: `EnableResetStreamAt` | `send_stream_test.go`: `TestSendStreamResetStreamAtCancelBeforeSend`; `streams_map_test.go`: `TestStreamsMap0RTTResetStreamAt` |
| 3 | 0-RTT: remember the server's support; a server accepting 0-RTT doesn't disable it | `internal/wire/transport_parameters.go`: `MarshalForSessionTicket`, `ValidFor0RTT`, `ValidForUpdate` | `internal/wire/transport_parameter_test.go`: `TestTransportParametersValidFor0RTT`, `TestTransportParametersValidAfter0RTT`, `TestSessionTicketLegacyResetStreamAtTransportParameter` |
| 4 | Reliable Size above the Final Size: FRAME_ENCODING_ERROR | `internal/wire/reset_stream_frame.go`: `parseResetStreamFrame` | `internal/wire/reset_stream_frame_test.go`: `TestParseResetStreamAtSizeTooLarge` |
| 4 | RESET_STREAM_AT respects the flow control limits; violations: FLOW_CONTROL_ERROR | `send_stream.go`: `CancelWrite`, `maybeQueueDeferredResetStreamFrame` (the frame waits until the data up to the reliable size fits); `receive_stream.go`: `handleResetStreamFrameImpl` | `send_stream_test.go`: `TestSendStreamResetStreamAtReservesFlowControlCredit`, `TestSendStreamResetStreamAtFlowControlBlocked`; `integrationtests/self/reset_stream_at_test.go`: `TestResetStreamAt` |
| 4 | RESET_STREAM_AT only in the application data packet number space | `internal/wire/frame_parser.go`: `ParseType`; `internal/wire/frame_type.go` | `internal/wire/frame_parser_test.go`: `TestFrameAllowedAtEncLevel` |
| 4, 5.2 | Retransmit lost RESET_STREAM_AT frames and the data up to the reliable size until both are acknowledged | `send_stream.go`: `sendStreamResetStreamHandler`, `resendLimit` | `send_stream_test.go`: `TestSendStreamResetStreamAtRetransmissions`, `TestSendStreamResendLimit` |
| 5 | Deliver the data up to the Reliable Size reliably | `send_stream.go`: `popRetransmissionFrame`, `resendLimit`, `reliableOffset` | `send_stream_test.go`: `TestSendStreamResetStreamAtCancelAfterSend`, `TestSendStreamResetStreamAtRandomized` |
| 5.2 | The Reliable Size never increases | `send_stream.go`: `CancelWrite`, `handleStopSendingFrame` (one RESET_STREAM_AT; a STOP_SENDING reduces it to 0) | `send_stream_test.go`: `TestSendStreamResetStreamAtStopSendingAfterCancelation` |
| 5.2 | The receiver uses the smallest Reliable Size, ignoring increases | `receive_stream.go`: `handleResetStreamFrameImpl` | `receive_stream_test.go`: `TestReceiveStreamResetStreamAtReliableSizeIncrease`, `TestReceiveStreamMultipleResetStreamAt` |
| 5.2 | Error code and final size don't change; a change: STREAM_STATE_ERROR or FINAL_SIZE_ERROR | `send_stream.go`: `handleStopSendingFrame` (same error code and final size); `receive_stream.go`: `handleResetStreamFrameImpl` (also for RESET_STREAM_AT frames with a Reliable Size of 0, internal/wire/reset_stream_frame.go:IsResetStreamAt); `flow_controller_stream.go`: `UpdateHighestReceived` | `receive_stream_test.go`: `TestReceiveStreamResetStreamAtErrorCodeChange`, `TestReceiveStreamResetStreamAtFinalSizeChange`; `send_stream_test.go`: `TestSendStreamResetStreamAtStopSendingKeepsFinalSize` |

SHOULD and MAY statements that are not followed, or not followed in all cases:

| Section | Statement | Decision and reason |
|---|---|---|
| 5, 5.2 | MAY use RESET_STREAM when no data is to be delivered | RESET_STREAM is sent, which peers without the extension understand as well. |
| 5.2 | MAY send multiple RESET_STREAM_AT frames to reduce the Reliable Size | Not supported by the API: CancelWrite only has an effect once. A STOP_SENDING frame reduces the reliable size to 0 (RESET_STREAM). |
