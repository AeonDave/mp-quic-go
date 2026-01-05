<div align="center" style="margin-bottom: 15px;">
  <img src="./assets/quic-go-logo.png" width="700" height="auto">
</div>

# mp-quic-go: QUIC with Multipath Support

mp-quic-go is a fork of [quic-go](https://github.com/quic-go/quic-go) that adds production-grade multipath QUIC while keeping full compatibility with standard QUIC.
All credits for the base implementation go to the original authors.

quic-go implements QUIC ([RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000), [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001), [RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002)) in Go, with support for HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)), QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)), and HTTP Datagrams ([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297)).

## Multipath QUIC Features

This fork extends quic-go with:

- Multiple path scheduling algorithms: RoundRobin, LowLatency, MinRTT (bias-based)
- Per-path packet numbers, RTT tracking, and congestion control (OLIA)
- Packet duplication with configurable policies and target counts
- Packet reinjection with preferred paths, queue limits, and backoff
- Runtime path management (add, validate, activate, close)
- Transport parameter negotiation for opt-in multipath
- Optional multi-socket manager for hot-plug interfaces and local address fan-out
- Full RFC 9000 compatibility in single-path mode

## Quick Start: Multipath

```go
import quic "github.com/AeonDave/mp-quic-go"

config := &quic.Config{
    MaxPaths: 5,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewRoundRobinScheduler(),
    ),
}

conn, err := quic.DialAddr(context.Background(), "localhost:4242", tlsConf, config)
if err != nil {
    // handle error
}

// Multipath activates only when both peers advertise support.
// If the peer is not multipath-aware, the connection stays single-path.
```

## Auto-Path Creation + ADD_ADDRESS (Opt-in)

```go
config := &quic.Config{
    MaxPaths:              5,
    MultipathController:   quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler()),
    MultipathAutoPaths:     true,
    MultipathAutoAdvertise: true,
    // Optional allowlist:
    // MultipathAutoAddrs: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("10.0.0.2")},
}
```

## Multipath Policies

### Packet Duplication

```go
dup := quic.NewMultipathDuplicationPolicy()
dup.Enable()
dup.SetDuplicatePathCount(2) // original + one duplicate

a := &quic.Config{
    MaxPaths: 3,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewLowLatencyScheduler(),
    ),
    MultipathDuplicationPolicy: dup,
}
```

### Packet Reinjection

```go
reinjection := quic.NewMultipathReinjectionPolicy()
reinjection.Enable()
reinjection.SetReinjectionDelay(50 * time.Millisecond)
reinjection.SetMaxReinjections(2)
reinjection.SetMaxReinjectionQueuePerPath(4)
reinjection.SetMinReinjectionInterval(20 * time.Millisecond)

config := &quic.Config{
    MaxPaths: 3,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewMinRTTScheduler(0.7),
    ),
    MultipathReinjectionPolicy: reinjection,
}
```

## Multi-Socket Manager (Optional)

The multi-socket manager provides a `net.PacketConn` that can send from multiple local IPs and react to interface changes.
It can be used with `Dial` / `Listen`:

```go
base, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
mgr, _ := quic.NewMultiSocketManager(quic.MultiSocketManagerConfig{BaseConn: base})
_ = mgr.SetLocalAddrs([]net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("10.0.0.2")})

conn, err := quic.Dial(context.Background(), mgr, serverAddr, tlsConf, config)
```

## Standard QUIC Features

- Unreliable Datagram Extension ([RFC 9221](https://datatracker.ietf.org/doc/html/rfc9221))
- Datagram Packetization Layer Path MTU Discovery ([RFC 8899](https://datatracker.ietf.org/doc/html/rfc8899))
- QUIC Version 2 ([RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369))
- qlog tracing (draft-ietf-quic-qlog-main-schema / draft-ietf-quic-qlog-quic-events)
- Stream Resets with Partial Delivery (draft-ietf-quic-reliable-stream-reset)

## Documentation

- Architecture & implementation guide: `docs/MP_QUIC_README.md`
- Usage examples: `docs/MULTIPATH_EXAMPLES.md`
- GoDoc: https://pkg.go.dev/github.com/AeonDave/mp-quic-go
- Upstream QUIC docs: https://quic-go.net/docs/

## Installation

```bash
go get -u github.com/AeonDave/mp-quic-go
```

## Requirements

- Go 1.21 or later
- For multipath: Linux, macOS, or Windows with multiple network interfaces

## Testing

```bash
go test ./...
```

Multipath-specific tests:

```bash
go test -v -run TestMultipath
```

## Compatibility with Upstream quic-go

- Drop-in replacement for standard quic-go
- Multipath is opt-in and negotiated via transport parameters
- Standard QUIC behavior is preserved when multipath is disabled

## Differences from Upstream quic-go

| Feature | Upstream | This Fork |
|---------|----------|-----------|
| Multiple paths | No | Yes |
| Path scheduling | No | RoundRobin, LowLatency, MinRTT |
| Congestion control | NewReno | NewReno + OLIA |
| Packet duplication | No | Yes |
| Packet reinjection | No | Yes |
| Per-path packet numbers | No | Yes |
| Path limits | Fixed | Configurable (`MaxPaths`) |
| Path statistics | Limited | Per-path stats and RTT |
| Multi-socket manager | No | Optional |

## License

The code is licensed under the MIT license. The logo and brand assets are excluded from the MIT license.
See `assets/LICENSE.md` for the full usage policy and details.
