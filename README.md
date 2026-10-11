<div align="center" style="margin-bottom: 15px;">
  <img src="./assets/quic-go-logo.png" width="700" height="auto">
</div>

# mp-quic-go: QUIC with Multipath Support

`github.com/qoke/mp-quic-go` is a maintained fork of [quic-go](https://github.com/quic-go/quic-go) with Multipath QUIC
([draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21)).
It continues the [original mp-quic-go](https://github.com/AeonDave/mp-quic-go) by AeonDave, which added multipath support to quic-go.
All credit for the QUIC implementation goes to the quic-go authors, and for the original multipath work to the authors of mp-quic-go.

quic-go implements QUIC ([RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000), [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001), [RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002)) in Go, with support for HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)), QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)), the Extensible Prioritization Scheme for HTTP ([RFC 9218](https://datatracker.ietf.org/doc/html/rfc9218)), and HTTP Datagrams ([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297)).

Multipath is opt-in. When it is not negotiated, a connection is standard single-path QUIC and behaves like quic-go.

[docs/COMPLIANCE.md](docs/COMPLIANCE.md) lists every MUST statement of the implemented RFCs and drafts with the code
and the tests that cover it, the SHOULD and MAY statements that are not followed, and the results of the conformance
tests (QUIC interop runner, h3spec, multipath interop with picoquic, fuzzing).

## Installation

```bash
go get github.com/qoke/mp-quic-go@latest
```

```go
import (
	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
)
```

This module is based on quic-go v0.63.0.
Its API is that of quic-go, extended with multipath configuration fields and types. To switch from quic-go, replace the import paths.

Go 1.26 or later is required.

## Multipath Features

- IETF Multipath QUIC (draft-ietf-quic-multipath-21), negotiated with the `initial_max_path_id` transport parameter,
  using the code points registered by IANA
- Paths opened by the client with `Conn.AddPath` or `Conn.AddPathFromAddr`, or automatically from all local addresses
- Per-path packet number spaces, loss recovery, RTT estimation, congestion control, ECN validation and MTU discovery
- Path status (available or backup), path abandonment and per-path migration of the client's address
- Path scheduling: RoundRobin, LowLatency and MinRTT schedulers, or a custom `MultipathController`
- Congestion control: an uncoupled Reno controller per path (the controller quic-go uses), or coupled OLIA
  controllers (opt-in)
- Duplication of selected frames on other paths, and reinjection of lost frames on a selected path
- Optional multi-socket manager for multiple local addresses and interface changes
- Optional address advertisement (`ADD_ADDRESS`), negotiated separately: a server announces its other addresses, and
  the client opens paths to them
- QUIC Address Discovery (draft-ietf-quic-address-discovery-01, `OBSERVED_ADDRESS`), with and without multipath:
  an endpoint learns the address its peer observes on every path, e.g. the address of a NAT
  (see [docs/ADDRESS_DISCOVERY.md](docs/ADDRESS_DISCOVERY.md))

Multipath is used if both endpoints configure a multipath controller. Versions of this module up to v0.2.x
(v0.2.0 to v0.2.3) used an incompatible multipath protocol of their own: connections with them fall back to a single
path, using standard QUIC (see the [changelog](CHANGELOG.md)). The address advertisement extension is negotiated
separately, and only used together with IETF Multipath QUIC.

## Quick Start

```go
// client
config := &quic.Config{
	MaxPaths: 3,
	MultipathController: quic.NewDefaultMultipathController(
		quic.NewRoundRobinScheduler(),
	),
}

conn, err := quic.DialAddr(context.Background(), "localhost:4242", tlsConf, config)
if err != nil {
	// handle error
}
if !conn.ConnectionState().SupportsMultipath {
	// the server doesn't support multipath: the connection uses a single path
}

// open a second path, sending from another socket
udpConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
path, err := conn.AddPath(&quic.Transport{Conn: udpConn})
if err != nil {
	// handle error
}
if err := path.Probe(context.Background()); err != nil {
	// handle error
}
```

A controller keeps per-connection state. On a server, use `Config.MultipathControllerFactory` to create one controller per connection:

```go
// server
config := &quic.Config{
	MultipathControllerFactory: func() quic.MultipathController {
		return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
	},
}
ln, err := quic.ListenAddr("0.0.0.0:4242", tlsConf, config)
```

[example/multipath](example/multipath) is a complete example, and [docs/MULTIPATH_EXAMPLES.md](docs/MULTIPATH_EXAMPLES.md)
shows automatic paths, path status, custom controllers, duplication, reinjection and the multi-socket manager.

## Standard QUIC Features

- Unreliable Datagram Extension ([RFC 9221](https://datatracker.ietf.org/doc/html/rfc9221))
- Datagram Packetization Layer Path MTU Discovery ([RFC 8899](https://datatracker.ietf.org/doc/html/rfc8899))
- QUIC Version 2 ([RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369))
- Compatible Version Negotiation ([RFC 9368](https://datatracker.ietf.org/doc/html/rfc9368)), see [docs/VERSION_NEGOTIATION.md](docs/VERSION_NEGOTIATION.md)
- Persistent congestion ([RFC 9002, section 7.6](https://datatracker.ietf.org/doc/html/rfc9002#section-7.6)), see [docs/LOSS_RECOVERY.md](docs/LOSS_RECOVERY.md)
- Server's preferred address ([RFC 9000, section 9.6](https://datatracker.ietf.org/doc/html/rfc9000#section-9.6)): servers send it, clients migrate to it, see [docs/PREFERRED_ADDRESS.md](docs/PREFERRED_ADDRESS.md)
- Greasing the QUIC Bit ([RFC 9287](https://datatracker.ietf.org/doc/html/rfc9287)), see [docs/GREASE_QUIC_BIT.md](docs/GREASE_QUIC_BIT.md)
- qlog tracing (draft-ietf-quic-qlog-main-schema / draft-ietf-quic-qlog-quic-events)
- Stream Resets with Partial Delivery ([draft-ietf-quic-reliable-stream-reset-11](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11), interoperating with implementations of draft-07), see [docs/RELIABLE_STREAM_RESET.md](docs/RELIABLE_STREAM_RESET.md)
- Stream priorities following the RFC 9218 urgency and incremental parameters

For use in FIPS 140-3 environments, see [FIPS140.md](FIPS140.md).

## Documentation

- [Standards compliance](docs/COMPLIANCE.md): every MUST statement with its implementation and tests, the SHOULD and MAY statements that are not followed, and the conformance test results
- [Multipath QUIC in mp-quic-go](docs/MP_QUIC_README.md): negotiation, paths, API, and the decisions for the SHOULD and MAY statements of the draft
- [Multipath usage examples](docs/MULTIPATH_EXAMPLES.md): paths, scheduling, congestion control, address advertisement and address discovery
- [QUIC Address Discovery](docs/ADDRESS_DISCOVERY.md): negotiation, sending and receiving OBSERVED_ADDRESS frames, and the decisions for the SHOULD and MAY statements of the draft
- [Version negotiation](docs/VERSION_NEGOTIATION.md): compatible version negotiation between QUIC version 1 and 2, and the decisions for the SHOULD and MAY statements of RFC 9368 and RFC 9369
- [Loss recovery](docs/LOSS_RECOVERY.md): persistent congestion, and the decisions for the SHOULD and MAY statements of RFC 9002 section 7.6
- [Server's preferred address](docs/PREFERRED_ADDRESS.md): configuration, the migration of server and client, and the decisions for the SHOULD and MAY statements of RFC 9000 section 9.6
- [Connection migration](docs/CONNECTION_MIGRATION.md): path validation and migration without multipath, the ACK Delay, and the decisions for the SHOULD and MAY statements of RFC 9000 sections 8, 9 and 13.2.5
- [Stream Resets with Partial Delivery](docs/RELIABLE_STREAM_RESET.md): code points, negotiation, and the decisions for the SHOULD and MAY statements of the draft
- [Greasing the QUIC Bit](docs/GREASE_QUIC_BIT.md): sending and receiving packets with the QUIC Bit set to 0, and the decisions for the SHOULD and MAY statements of RFC 9287
- [Changelog](CHANGELOG.md)
- [Maintenance, upstream synchronization and conformance tests](docs/MAINTAINING.md)
- API reference: https://pkg.go.dev/github.com/qoke/mp-quic-go
- quic-go documentation (applies to single-path usage): https://quic-go.net/docs/

## Testing

```bash
go test ./...
```

Multipath tests only:

```bash
go test -run Multipath ./...
```

Interoperability with picoquic (needs Docker and Linux):

```bash
go test -tags picoquic -count=1 ./interop/multipath/...
```

[docs/MAINTAINING.md](docs/MAINTAINING.md#conformance-tests) describes the other conformance tests: the QUIC interop
runner, h3spec and fuzzing.

## License

The code is licensed under the MIT license. The logo and brand assets are excluded from the MIT license.
See `assets/LICENSE.md` for the full usage policy and details.
