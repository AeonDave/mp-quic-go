# Multipath QUIC Examples

This document provides practical examples for using multipath features in mp-quic-go.

## Basic Multipath Setup

Multipath is negotiated via transport parameters. Both endpoints must configure a `MultipathController`, otherwise the connection stays single-path.

### Simple Client

```go
package main

import (
    "context"
    "crypto/tls"

    quic "github.com/AeonDave/mp-quic-go"
)

func main() {
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"h3"},
    }

    config := &quic.Config{
        MaxPaths: 3,
        MultipathController: quic.NewDefaultMultipathController(
            quic.NewRoundRobinScheduler(),
        ),
    }

    conn, err := quic.DialAddr(context.Background(), "example.com:443", tlsConf, config)
    if err != nil {
        panic(err)
    }
    defer conn.CloseWithError(0, "")

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        panic(err)
    }

    _, _ = stream.Write([]byte("hello multipath"))
}
```

### Simple Server

```go
package main

import (
    "context"
    "crypto/tls"

    quic "github.com/AeonDave/mp-quic-go"
)

func main() {
    cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
    if err != nil {
        panic(err)
    }

    tlsConf := &tls.Config{
        Certificates: []tls.Certificate{cert},
        NextProtos:   []string{"h3"},
    }

    config := &quic.Config{
        MaxPaths: 3,
        MultipathController: quic.NewDefaultMultipathController(
            quic.NewRoundRobinScheduler(),
        ),
    }

    listener, err := quic.ListenAddr("localhost:4242", tlsConf, config)
    if err != nil {
        panic(err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept(context.Background())
        if err != nil {
            return
        }
        go func() {
            defer conn.CloseWithError(0, "")
            for {
                stream, err := conn.AcceptStream(context.Background())
                if err != nil {
                    return
                }
                _ = stream.Close()
            }
        }()
    }
}
```

## Scheduling Algorithms

### RoundRobin Scheduler

```go
config := &quic.Config{
    MaxPaths: 3,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewRoundRobinScheduler(),
    ),
}
```

### LowLatency Scheduler

```go
config := &quic.Config{
    MaxPaths: 3,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewLowLatencyScheduler(),
    ),
}
```

### MinRTT Scheduler (Bias-Based)

```go
config := &quic.Config{
    MaxPaths: 3,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewMinRTTScheduler(0.7), // 70% RTT, 30% load
    ),
}
```

## Auto-Path Creation + ADD_ADDRESS (Opt-in)

Auto-path creation and address advertisement are disabled by default.

```go
config := &quic.Config{
    MaxPaths:              5,
    MultipathController:   quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler()),
    MultipathAutoPaths:     true, // create additional paths post-handshake
    MultipathAutoAdvertise: true, // advertise local addresses (ADD_ADDRESS)
    // Optional allowlist instead of interface discovery:
    // MultipathAutoAddrs: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("10.0.0.2")},
}
```

## OLIA Congestion Control

```go
shared := quic.NewOLIASharedState()
cc1 := quic.NewOLIACongestionControl(0, shared, 1280)
cc2 := quic.NewOLIACongestionControl(1, shared, 1280)
```

## Packet Duplication

```go
dup := quic.NewMultipathDuplicationPolicy()
dup.Enable()
dup.SetDuplicatePathCount(2)

config := &quic.Config{
    MaxPaths: 3,
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewRoundRobinScheduler(),
    ),
    MultipathDuplicationPolicy: dup,
}
```

## Packet Reinjection

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
        quic.NewLowLatencyScheduler(),
    ),
    MultipathReinjectionPolicy: reinjection,
}
```

### Custom Reinjection Target Selection

```go
type customController struct {
    quic.MultipathController
}

func (c *customController) SelectReinjectionTarget(ctx quic.ReinjectionTargetContext) (quic.PathID, bool) {
    if len(ctx.Candidates) == 0 {
        return quic.InvalidPathID, false
    }
    return ctx.Candidates[0].ID, true
}
```

## Path Failure Detection (PotentiallyFailed)

Path failure detection is conservative and only updates controller state when the controller implements:

```go
UpdatePathState(pathID quic.PathID, update quic.PathStateUpdate)
```

If implemented, schedulers will automatically skip paths marked as `PotentiallyFailed`.

## Multi-Socket Manager (Optional)

```go
base, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
manager, _ := quic.NewMultiSocketManager(quic.MultiSocketManagerConfig{BaseConn: base})
_ = manager.SetLocalAddrs([]net.IP{
    net.ParseIP("192.168.1.10"),
    net.ParseIP("10.0.0.2"),
})

conn, err := quic.Dial(context.Background(), manager, serverAddr, tlsConf, config)
if err != nil {
    panic(err)
}
```

## Monitoring and Statistics

```go
controller := quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())

stats := controller.GetStatistics()
for pathID, st := range stats {
    fmt.Printf("path %d rtt=%v inFlight=%d cwnd=%d\n", pathID, st.SmoothedRTT, st.BytesInFlight, st.CongestionWindow)
}
```

## Notes

- Multipath is opt-in and negotiated. If the peer does not support it, the connection stays single-path.
- `BytesInFlight` is populated from the sent packet handler and can be used for congestion-aware scheduling.
- The multi-socket manager is optional. It helps when you need to bind multiple local IPs or handle interface changes.

For architecture and implementation details, see `MP_QUIC_README.md`.
