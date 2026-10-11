# Multipath QUIC Examples

These examples show how to use IETF Multipath QUIC
([draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21)) with mp-quic-go.
[example/multipath](../example/multipath) is a complete program: a server and a client that opens a second path and
uploads data on both paths. [MP_QUIC_README.md](MP_QUIC_README.md) describes the implementation.

## Enabling Multipath

Both endpoints configure a multipath controller. If one of them doesn't, the connection uses a single path and
behaves like a quic-go connection. Peers running v0.2.x of this module (or v0.1.x) use an older multipath protocol,
which this version doesn't speak: connections with them use a single path as well.

### Client

```go
config := &quic.Config{
    MaxPaths: 3, // path 0 and up to 2 more paths
    MultipathController: quic.NewDefaultMultipathController(
        quic.NewRoundRobinScheduler(),
    ),
}

conn, err := quic.DialAddr(ctx, "example.com:443", tlsConf, config)
if err != nil {
    return err
}
if !conn.ConnectionState().SupportsMultipath {
    // the server doesn't support IETF Multipath QUIC: the connection uses a single path
}
```

### Server

A controller keeps the state of one connection, so a server creates one for every connection:

```go
config := &quic.Config{
    MaxPaths: 3,
    MultipathControllerFactory: func() quic.MultipathController {
        return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
    },
}

ln, err := quic.ListenAddr("0.0.0.0:4242", tlsConf, config)
```

The server doesn't open paths. It accepts the paths that the client opens.

## Opening Paths

Only the client opens paths. Paths can be opened once the handshake completed; a path added earlier is opened when
it is probed.

From another socket (works on all platforms):

```go
udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
if err != nil {
    return err
}
tr := &quic.Transport{Conn: udpConn}
path, err := conn.AddPath(tr)
if err != nil {
    return err
}
// Probe opens the path and validates it.
if err := path.Probe(ctx); err != nil {
    return err
}
id, _ := path.ID()
log.Printf("opened path %d", id)
```

The Transport needs to stay open until the connection is closed. Closing it terminates the connection, without
sending a CONNECTION_CLOSE frame, so close the connection first.

From another local address of the connection's socket (needs a socket bound to an unspecified address, or a
`MultiSocketManager`):

```go
path, err := conn.AddPathFromAddr(&net.UDPAddr{IP: net.ParseIP("192.168.1.10")}, nil) // nil: the server address of path 0
if err != nil {
    return err
}
if err := path.Probe(ctx); err != nil {
    return err
}
```

`Probe` returns `quic.ErrTooManyPaths` if `MaxPaths` paths are in use. If the server sent the
`disable_active_migration` transport parameter, paths to its handshake address can't be opened.

### Path Status, Switching and Closing

```go
// Only send data on this path if no other path can be used. The status is signaled to the server.
_ = path.SetStatus(quic.PathStatusBackup)

// Send data only on this path, as long as it can be used.
_ = path.Switch()

// Abandon the path. The last path that can be used can't be closed.
_ = path.Close()

// Set the status of a path that the application didn't open itself, e.g. path 0 (the path of the handshake).
_ = conn.SetPathStatus(0, quic.PathStatusBackup)

// Abandon a path that the application didn't open itself.
_ = conn.ClosePath(0)

for _, p := range conn.Paths() {
    log.Printf("path %d: %s -> %s, %s, status %s, peer status %s",
        p.ID, p.LocalAddr, p.RemoteAddr, p.State, p.Status, p.PeerStatus)
}
```

### Automatic Paths

A client can open a path from every other local address after the handshake:

```go
config := &quic.Config{
    MaxPaths:            3,
    MultipathController: quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler()),
    MultipathAutoPaths:  true,
    // Optional: the local addresses to use, instead of the addresses of the network interfaces.
    // MultipathAutoAddrs: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("10.0.0.2")},
}
```

Only addresses of the address family of the server address are used, up to `MaxPaths` paths.
No paths are opened if the server disabled active migration.

### Address Advertisement

With the address advertisement extension, a server announces other addresses of its own, and the client opens paths
to them. The extension is specific to this module: it is optional, negotiated with its own transport parameter
(`add_address`, `0x1f0f9c0d40`), and only used together with IETF Multipath QUIC. Other implementations ignore the
transport parameter. Both endpoints enable it:

```go
// server: the socket is bound to an unspecified address, so it receives packets sent to all local addresses
serverConfig := &quic.Config{
    MultipathControllerFactory: func() quic.MultipathController {
        return quic.NewDefaultMultipathController(nil)
    },
    EnableAddressAdvertisement: true,
    // advertise the local addresses when the handshake completes
    MultipathAutoAdvertise: true,
}

// client: opens a path to every address advertised by the server, up to MaxPaths paths
clientConfig := &quic.Config{
    MultipathController:        quic.NewDefaultMultipathController(nil),
    EnableAddressAdvertisement: true,
    MultipathAutoPaths:         true,
}
```

The application can also advertise an address itself, and open paths to the peer's addresses:

```go
// on the server
err := conn.AdvertiseAddress(netip.MustParseAddrPort("192.0.2.10:443"))

// on the client
for _, a := range conn.PeerAdvertisedAddresses() {
    path, err := conn.AddPathFromAddr(nil, net.UDPAddrFromAddrPort(a.Addr))
    if err != nil {
        continue
    }
    if err := path.Probe(ctx); err != nil {
        log.Printf("path to %s failed: %v", a.Addr, err)
    }
}
```

A server only records the addresses advertised by a client. `ConnectionState().SupportsAddressAdvertisement` reports
if the extension is used.

### Address Discovery

With QUIC Address Discovery (draft-ietf-quic-address-discovery-01), an endpoint reports the address it observes for
its peer in OBSERVED_ADDRESS frames, on every path. A client behind a NAT learns the address and port that the NAT
maps each of its paths to. The extension is negotiated on its own, and also works without multipath:

```go
// server: report the address observed for the client on every path
serverConfig := &quic.Config{
    MultipathControllerFactory: func() quic.MultipathController {
        return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
    },
    ProvideObservedAddress: true,
}

// client: ask the server to report the addresses it observes
clientConfig := &quic.Config{
    MultipathController:    quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler()),
    RequestObservedAddress: true,
}
```

```go
// the address of the primary path, as seen by the server
if addr, ok := conn.ObservedAddr(); ok {
    log.Printf("path 0 is seen as %s", addr)
}
// the address of every path
for _, p := range conn.Paths() {
    if p.ObservedAddr.IsValid() {
        log.Printf("path %d (%s) is seen as %s", p.ID, p.LocalAddr, p.ObservedAddr)
    }
}
```

`ConnectionState().SupportsAddressDiscovery` reports in which directions frames are sent. The peer can report a
wrong address, so the application decides whether to trust it. [ADDRESS_DISCOVERY.md](ADDRESS_DISCOVERY.md)
describes the implementation.

## Scheduling

The controller selects the path of every packet carrying data, among the paths that can send a packet now.

```go
quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler())
quic.NewDefaultMultipathController(quic.NewMinRTTScheduler(0.7)) // 70% RTT, 30% load
quic.NewMultipathScheduler(quic.SchedulingPolicyMinRTT)
```

### Custom Controller

```go
type lowestIDController struct{}

func (lowestIDController) SelectPath(ctx quic.PathSelectionContext) (quic.PathInfo, bool) {
    // ctx.Paths are the paths that can be used, in ascending order of their path IDs.
    // Backup paths are only included if no other path can be used.
    if len(ctx.Paths) == 0 {
        return quic.PathInfo{}, false
    }
    return ctx.Paths[0], true
}

// Optional: informed when a path becomes active and when it is abandoned.
func (lowestIDController) RegisterPath(info quic.PathInfo) { log.Printf("path %d active", info.ID) }
func (lowestIDController) RemovePath(id quic.PathID)       { log.Printf("path %d abandoned", id) }
```

The connection calls the controller from its run loop, so the methods must not block.
If `SelectPath` returns a path that is not in `ctx.Paths`, the connection selects the path itself.

## Congestion Control

Every path has its own congestion controller, RTT estimate, loss detection and pacing. `Config.MultipathCongestionControl`
selects how the controllers of the paths relate to each other:

- `quic.MultipathCongestionControlReno` (the default): every path has its own controller, the Reno controller that
  quic-go uses for single-path connections (slow start, an increase of one datagram per window in congestion
  avoidance, a multiplicative decrease of 0.7, persistent congestion). The controllers are not coupled
  (section 5.3 of the draft): a connection using two paths can send about twice as fast as a single-path connection
  on a shared bottleneck.
- `quic.MultipathCongestionControlOLIA`: the controllers are coupled with OLIA (opportunistic linked increases),
  so that the paths together are not more aggressive than a single connection on a shared bottleneck, and traffic
  moves to the less congested paths. The OLIA controller of path 0 continues with the state of the controller used
  during the handshake.

```go
config := &quic.Config{
    MultipathController:        quic.NewDefaultMultipathController(quic.NewMinRTTScheduler(1)),
    MultipathCongestionControl: quic.MultipathCongestionControlOLIA,
}
```

Without multipath, the setting has no effect: the connection uses the default controller of quic-go. The
congestion state of the paths is available to a controller through `UpdatePathState` (`PathStateUpdate`) and
`GetStatistics`.

## Duplication

After a packet was sent on one path, copies of selected frames are sent on other paths.
The copies are never retransmitted.

```go
dup := quic.NewMultipathDuplicationPolicy()
dup.Enable()
dup.SetDuplicatePathCount(2) // the original packet and one copy
dup.AddStreamForDuplication(streamID)

config := &quic.Config{
    MultipathController:        quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler()),
    MultipathDuplicationPolicy: dup,
}
```

## Reinjection

The reinjection policy selects the path that lost frames are retransmitted on.

```go
reinjection := quic.NewMultipathReinjectionPolicy()
reinjection.Enable()
reinjection.SetReinjectionDelay(50 * time.Millisecond)
reinjection.SetMaxReinjections(2)
reinjection.SetMaxReinjectionQueuePerPath(4)
reinjection.SetMinReinjectionInterval(20 * time.Millisecond)
// Also send the frames of a path whose probe timeout expired on another path.
reinjection.SetReinjectOnPTO(true)

config := &quic.Config{
    MultipathController:        quic.NewDefaultMultipathController(quic.NewLowLatencyScheduler()),
    MultipathReinjectionPolicy: reinjection,
}
```

A controller can choose the path itself:

```go
func (c *myController) SelectReinjectionTarget(ctx quic.ReinjectionTargetContext) (quic.PathID, bool) {
    if len(ctx.Candidates) == 0 {
        return quic.InvalidPathID, false
    }
    return ctx.Candidates[0].ID, true
}
```

## Path Failures

The connection marks a path as potentially failed if no acknowledgment arrived for a packet sent longer than
`max(500ms, 4 x smoothed RTT)` ago, and moves the data to the other paths. A controller implementing
`UpdatePathState(quic.PathID, quic.PathStateUpdate)` is informed through `PathStateUpdate.PotentiallyFailed`.

## Multi-Socket Manager

```go
base, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10)})
manager, _ := quic.NewMultiSocketManager(quic.MultiSocketManagerConfig{BaseConn: base})
_, _ = manager.AddLocalAddr(net.ParseIP("10.0.0.2"))

conn, err := quic.Dial(ctx, manager, serverAddr, tlsConf, config)
if err != nil {
    return err
}
path, err := conn.AddPathFromAddr(&net.UDPAddr{IP: net.ParseIP("10.0.0.2")}, nil)
```

## Statistics

```go
// The controller of a connection (a clone of the controller in the Config, if that one is in use).
controller := conn.MultipathController().(*quic.DefaultMultipathController)
for id, st := range controller.GetStatistics() {
    fmt.Printf("path %d: rtt=%v sent=%d lost=%d\n", id, st.SmoothedRTT, st.PacketsSent, st.PacketsLost)
}
```

A `MultipathObserver` receives an event for every packet sent, acknowledged and lost. Packet numbers are per path,
so identify packets by `PathEvent.PathID` and `PathEvent.PacketNumber`.
