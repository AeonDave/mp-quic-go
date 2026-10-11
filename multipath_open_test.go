package quic

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"
	"github.com/AeonDave/mp-quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// filteringRouter is a simnet router that drops the packets for which drop returns true.
// It can rewrite the addresses of packets, like a NAT.
// It records the addresses of the packets it delivers.
type filteringRouter struct {
	simnet.PerfectRouter

	mx   sync.Mutex
	drop func(simnet.Packet) bool
	// rewrite returns the packet that is delivered instead of the packet sent, and false if the packet is dropped
	rewrite func(simnet.Packet) (simnet.Packet, bool)
	// number of packets delivered, by source address (after rewriting) and destination address (before rewriting)
	delivered map[[2]string]int
}

// Delivered returns the number of packets delivered from one address to another.
func (r *filteringRouter) Delivered(from, to net.Addr) int {
	r.mx.Lock()
	defer r.mx.Unlock()

	return r.delivered[[2]string{from.String(), to.String()}]
}

func (r *filteringRouter) SetDrop(drop func(simnet.Packet) bool) {
	r.mx.Lock()
	defer r.mx.Unlock()

	r.drop = drop
}

func (r *filteringRouter) SetRewrite(rewrite func(simnet.Packet) (simnet.Packet, bool)) {
	r.mx.Lock()
	defer r.mx.Unlock()

	r.rewrite = rewrite
}

func (r *filteringRouter) SendPacket(p simnet.Packet) error {
	r.mx.Lock()
	drop := r.drop
	rewrite := r.rewrite
	r.mx.Unlock()
	if drop != nil && drop(p) {
		return nil
	}
	to := p.To
	if rewrite != nil {
		var ok bool
		p, ok = rewrite(p)
		if !ok {
			return nil
		}
	}
	r.mx.Lock()
	if r.delivered == nil {
		r.delivered = make(map[[2]string]int)
	}
	r.delivered[[2]string{p.From.String(), to.String()}]++
	r.mx.Unlock()
	return r.PerfectRouter.SendPacket(p)
}

var (
	multipathTestClientAddr  = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}
	multipathTestServerAddr  = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9002}
	multipathTestClientAddr2 = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9003}
)

// A multipathPathTestPair is a client and a server connection that negotiated IETF Multipath QUIC,
// running on a simulated network. The client has a second Transport that it can use to open a path.
// It must be used inside a synctest bubble.
type multipathPathTestPair struct {
	multipathTestConnPair
	router    *filteringRouter
	clientTr2 *Transport
}

type multipathPathTestOpts struct {
	rtt time.Duration
	// if set, the latency of every packet
	latency                func(simnet.Packet) time.Duration
	clientConf, serverConf func(*Config)
	// if set, IETF Multipath QUIC is not used
	withoutMultipath bool
	// if set, the router rewrites the packets from the start of the connection, see filteringRouter.SetRewrite
	rewrite func(simnet.Packet) (simnet.Packet, bool)
}

func newMultipathPathTestPair(t *testing.T, opts multipathPathTestOpts) *multipathPathTestPair {
	t.Helper()
	if opts.rtt == 0 {
		opts.rtt = 10 * time.Millisecond
	}
	router := &filteringRouter{rewrite: opts.rewrite}
	n := &simnet.Simnet{Router: router}
	settings := simnet.NodeBiDiLinkSettings{Latency: opts.rtt / 2, LatencyFunc: opts.latency}
	clientConn := n.NewEndpoint(multipathTestClientAddr, settings)
	clientConn2 := n.NewEndpoint(multipathTestClientAddr2, settings)
	serverConn := n.NewEndpoint(multipathTestServerAddr, settings)
	require.NoError(t, n.Start())

	var clientEvents, serverEvents events.Recorder
	clientConf := multipathTestConfig(!opts.withoutMultipath, protocol.PerspectiveClient, &clientEvents)
	clientConf.DisablePathMTUDiscovery = true
	if opts.clientConf != nil {
		opts.clientConf(clientConf)
	}
	serverConf := multipathTestConfig(!opts.withoutMultipath, protocol.PerspectiveServer, &serverEvents)
	serverConf.DisablePathMTUDiscovery = true
	if opts.serverConf != nil {
		opts.serverConf(serverConf)
	}
	clientTr := &Transport{Conn: clientConn}
	clientTr2 := &Transport{Conn: clientConn2}
	serverTr := &Transport{Conn: serverConn}
	ln, err := serverTr.ListenEarly(generateTLSConfig(), serverConf)
	require.NoError(t, err)

	p := &multipathPathTestPair{
		multipathTestConnPair: multipathTestConnPair{
			clientEvents: &clientEvents,
			serverEvents: &serverEvents,
			clientTr:     clientTr,
			serverTr:     serverTr,
			ln:           ln,
		},
		router:    router,
		clientTr2: clientTr2,
	}
	t.Cleanup(func() {
		if p.client != nil {
			p.client.CloseWithError(0, "")
		}
		ln.Close()
		clientTr.Close()
		clientTr2.Close()
		serverTr.Close()
		require.NoError(t, n.Close())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := clientTr.Dial(ctx, multipathTestServerAddr, generateTLSConfigWithServerName("localhost"), clientConf)
	require.NoError(t, err)
	p.client = client
	server, err := ln.Accept(ctx)
	require.NoError(t, err)
	p.server = server
	require.Equal(t, !opts.withoutMultipath, client.mp != nil)
	// wait for the handshake to be confirmed
	time.Sleep(opts.rtt)
	synctest.Wait()
	return p
}

// sentPathPackets returns the 1-RTT packets sent on a path.
func sentPathPackets(r *events.Recorder, pathID protocol.PathID) []qlog.PacketSent {
	var packets []qlog.PacketSent
	for _, ev := range r.Events(qlog.PacketSent{}) {
		ps := ev.(qlog.PacketSent)
		if ps.Header.PacketType == qlog.PacketType1RTT && ps.Header.HasPathID && ps.Header.PathID == pathID {
			packets = append(packets, ps)
		}
	}
	return packets
}

// issuedConnIDs returns the connection IDs issued for a path, according to the PATH_NEW_CONNECTION_ID frames sent.
func issuedConnIDs(r *events.Recorder, pathID protocol.PathID) []protocol.ConnectionID {
	var connIDs []protocol.ConnectionID
	for _, ev := range r.Events(qlog.PacketSent{}) {
		for _, f := range ev.(qlog.PacketSent).Frames {
			if f, ok := f.Frame.(*qlog.PathNewConnectionIDFrame); ok && f.PathID == pathID {
				connIDs = append(connIDs, f.ConnectionID)
			}
		}
	}
	return connIDs
}

// isPathValidationPacket says if a packet only contains frames that can be sent on a path
// that is being validated: PATH_CHALLENGE, PATH_RESPONSE and PATH_ACK frames.
func isPathValidationPacket(p qlog.PacketSent) bool {
	for _, f := range p.Frames {
		switch f.Frame.(type) {
		case *qlog.PathChallengeFrame, *qlog.PathResponseFrame, *qlog.AckFrame:
		default:
			return false
		}
	}
	return true
}

func hasFrame[T any](p qlog.PacketSent) bool {
	for _, f := range p.Frames {
		if _, ok := f.Frame.(T); ok {
			return true
		}
	}
	return false
}

// sentPathAbandonFrames returns the PATH_ABANDON frames sent.
func sentPathAbandonFrames(r *events.Recorder) []qlog.PathAbandonFrame {
	var frames []qlog.PathAbandonFrame
	for _, ev := range r.Events(qlog.PacketSent{}) {
		for _, f := range ev.(qlog.PacketSent).Frames {
			if f, ok := f.Frame.(*qlog.PathAbandonFrame); ok {
				frames = append(frames, *f)
			}
		}
	}
	return frames
}

// The client opens a path on another Transport, and both paths are used for sending.
// The keys are updated frequently, while both paths are used.
func TestMultipathOpenPath(t *testing.T) {
	t.Cleanup(handshake.SetKeyUpdateInterval(50))
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, path.Probe(ctx))
		// Probing a validated path returns immediately.
		require.NoError(t, path.Probe(ctx))

		data := make([]byte, 1<<20)
		rand.Read(data)
		p.transfer(t, data)
		p.close(t)

		// The client opened path ID 1.
		// The first packet uses a connection ID that the server issued for path ID 1, and packet number 0.
		// It contains a PATH_CHALLENGE, and is expanded to 1200 bytes.
		clientPackets := sentPathPackets(p.clientEvents, 1)
		require.NotEmpty(t, clientPackets)
		first := clientPackets[0]
		require.Contains(t, issuedConnIDs(p.serverEvents, 1), first.Header.DestConnectionID)
		require.Zero(t, first.Header.PacketNumber)
		require.True(t, hasFrame[*qlog.PathChallengeFrame](first))
		require.True(t, isPathValidationPacket(first))
		require.GreaterOrEqual(t, first.Raw.Length, protocol.MinInitialPacketSize)

		// The server responds on the path, using a connection ID that the client issued for path ID 1,
		// and validates the path itself.
		serverPackets := sentPathPackets(p.serverEvents, 1)
		require.NotEmpty(t, serverPackets)
		first = serverPackets[0]
		require.Contains(t, issuedConnIDs(p.clientEvents, 1), first.Header.DestConnectionID)
		require.Zero(t, first.Header.PacketNumber)
		require.True(t, hasFrame[*qlog.PathResponseFrame](first))
		require.True(t, hasFrame[*qlog.PathChallengeFrame](first))
		require.GreaterOrEqual(t, first.Raw.Length, protocol.MinInitialPacketSize)
		// The packets were sent on the 4-tuple of the path.
		require.NotZero(t, p.router.Delivered(multipathTestClientAddr2, multipathTestServerAddr))
		require.NotZero(t, p.router.Delivered(multipathTestServerAddr, multipathTestClientAddr2))

		// Both paths are used for sending data.
		for _, side := range []struct {
			name   string
			events *events.Recorder
		}{
			{name: "client", events: p.clientEvents},
			{name: "server", events: p.serverEvents},
		} {
			require.NotZero(t, countKeyUpdates(side.events), side.name)
			counts := countPathDataPackets(side.events)
			require.NotZero(t, counts[0], side.name)
			require.NotZero(t, counts[1], side.name)
			// Until the path is validated, i.e. until a PATH_RESPONSE is received,
			// the packets sent on path 1 only contain frames used for path validation.
			var numValidationPackets int
		events:
			for _, ev := range side.events.Events(qlog.PacketSent{}, qlog.PacketReceived{}) {
				switch ev := ev.(type) {
				case qlog.PacketReceived:
					for _, f := range ev.Frames {
						if _, ok := f.Frame.(*qlog.PathResponseFrame); ok {
							break events
						}
					}
				case qlog.PacketSent:
					if ev.Header.HasPathID && ev.Header.PathID == 1 {
						require.True(t, isPathValidationPacket(ev), "%s: %v", side.name, ev.Frames)
						numValidationPackets++
					}
				}
			}
			require.NotZero(t, numValidationPackets, side.name)
		}
	})
}

// A path can be opened on the connection's Transport, using the same 4-tuple as path 0
// (section 5.2 of draft-ietf-quic-multipath-21).
func TestMultipathOpenPathFromAddr(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		path, err := p.client.AddPathFromAddr(nil, nil)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, path.Probe(ctx))

		data := make([]byte, 1<<20)
		rand.Read(data)
		p.transfer(t, data)
		p.close(t)
		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			counts := countPathDataPackets(r)
			require.NotZero(t, counts[0])
			require.NotZero(t, counts[1])
		}
		require.Zero(t, p.router.Delivered(multipathTestClientAddr2, multipathTestServerAddr))
	})
}

// If the path doesn't work, path validation times out. The path is abandoned with PATH_UNSTABLE_OR_POOR.
// Until then, the client only sends PATH_CHALLENGE frames on the path, with exponential backoff.
func TestMultipathOpenPathTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{rtt: 300 * time.Millisecond})
		p.router.SetDrop(func(pkt simnet.Packet) bool {
			return pkt.From.String() == multipathTestClientAddr2.String() || pkt.To.String() == multipathTestClientAddr2.String()
		})
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		require.ErrorIs(t, path.Probe(ctx), errPathValidationFailed)
		require.ErrorIs(t, path.Probe(ctx), errPathValidationFailed)

		// path 0 can still be used
		data := make([]byte, 100<<10)
		rand.Read(data)
		p.transfer(t, data)
		p.close(t)

		var times []time.Time
		for _, ev := range p.clientEvents.EventsWithTime(qlog.PacketSent{}) {
			ps := ev.Event.(qlog.PacketSent)
			if !ps.Header.HasPathID || ps.Header.PathID != 1 {
				continue
			}
			require.Len(t, ps.Frames, 1)
			require.IsType(t, &qlog.PathChallengeFrame{}, ps.Frames[0].Frame)
			require.GreaterOrEqual(t, ps.Raw.Length, protocol.MinInitialPacketSize)
			times = append(times, ev.Time)
		}
		require.GreaterOrEqual(t, len(times), 3)
		for i := 2; i < len(times); i++ {
			require.Equal(t, 2*times[i-1].Sub(times[i-2]), times[i].Sub(times[i-1]))
		}
		require.Contains(t, sentPathAbandonFrames(p.clientEvents), qlog.PathAbandonFrame{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor})
		// the server never received a packet on the path, but it responds to the PATH_ABANDON frame
		require.Contains(t, sentPathAbandonFrames(p.serverEvents), qlog.PathAbandonFrame{PathID: 1, ErrorCode: qerr.NoError})
	})
}

// If the context passed to Probe is canceled, the path is abandoned with APPLICATION_ABANDON_PATH.
func TestMultipathOpenPathCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		p.router.SetDrop(func(pkt simnet.Packet) bool {
			return pkt.From.String() == multipathTestClientAddr2.String() || pkt.To.String() == multipathTestClientAddr2.String()
		})
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, path.Probe(ctx), context.DeadlineExceeded)
		time.Sleep(time.Second)
		require.ErrorIs(t, path.Probe(context.Background()), ErrPathClosed)
		p.close(t)
		require.Equal(t,
			[]qlog.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}},
			sentPathAbandonFrames(p.clientEvents),
		)
	})
}

// Until the server validated the client's address on a path, it only sends frames used for path validation.
func TestMultipathServerValidatesPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		// the server's packets on path 1 are lost
		p.router.SetDrop(func(pkt simnet.Packet) bool {
			return pkt.To.String() == multipathTestClientAddr2.String()
		})
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		errChan := make(chan error, 1)
		go func() { errChan <- path.Probe(context.Background()) }()

		data := make([]byte, 1<<20)
		rand.Read(data)
		p.transfer(t, data)
		require.ErrorIs(t, <-errChan, errPathValidationFailed)
		p.close(t)

		serverPackets := sentPathPackets(p.serverEvents, 1)
		require.NotEmpty(t, serverPackets)
		for _, ps := range serverPackets {
			require.True(t, isPathValidationPacket(ps), "%v", ps.Frames)
		}
		require.Contains(t, sentPathAbandonFrames(p.clientEvents), qlog.PathAbandonFrame{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor})
	})
}

// Closing a path abandons it with APPLICATION_ABANDON_PATH. Path 0 continues to be used.
func TestMultipathClosePath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		require.NoError(t, path.Probe(context.Background()))
		require.NoError(t, path.Close())

		data := make([]byte, 1<<20)
		rand.Read(data)
		p.transfer(t, data)
		p.close(t)
		require.Contains(t, sentPathAbandonFrames(p.clientEvents), qlog.PathAbandonFrame{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath})
		require.Contains(t, sentPathAbandonFrames(p.serverEvents), qlog.PathAbandonFrame{PathID: 1, ErrorCode: qerr.NoError})
		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			require.Zero(t, countPathDataPackets(r)[1])
		}
	})
}

// countPathDataPackets returns the number of packets with STREAM frames sent on every path.
func countPathDataPackets(r *events.Recorder) map[protocol.PathID]int {
	counts := make(map[protocol.PathID]int)
	for _, ev := range r.Events(qlog.PacketSent{}) {
		ps := ev.(qlog.PacketSent)
		if ps.Header.PacketType != qlog.PacketType1RTT || !ps.Header.HasPathID {
			continue
		}
		for _, f := range ps.Frames {
			if _, ok := f.Frame.(*qlog.StreamFrame); ok {
				counts[ps.Header.PathID]++
				break
			}
		}
	}
	return counts
}

// A client opens a second path, and data is sent on both paths, over UDP sockets on the loopback interface,
// using the capabilities of the platform (e.g. GSO and ECN on Linux).
// The path is opened using another Transport, or using the connection's Transport.
func TestMultipathTwoPathsTransferUDP(t *testing.T) {
	t.Run("another Transport", func(t *testing.T) {
		testMultipathTwoPathsTransferUDP(t, func(c *Conn, tr *Transport) (*Path, error) { return c.AddPath(tr) })
	})
	t.Run("same Transport", func(t *testing.T) {
		testMultipathTwoPathsTransferUDP(t, func(c *Conn, _ *Transport) (*Path, error) { return c.AddPathFromAddr(nil, nil) })
	})
}

func testMultipathTwoPathsTransferUDP(t *testing.T, addPath func(*Conn, *Transport) (*Path, error)) {
	var clientEvents, serverEvents events.Recorder
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.ListenEarly(generateTLSConfig(), multipathTestConfig(true, protocol.PerspectiveServer, &serverEvents))
	require.NoError(t, err)
	defer ln.Close()
	clientTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer clientTr.Close()
	clientTr2 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer clientTr2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := clientTr.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), multipathTestConfig(true, protocol.PerspectiveClient, &clientEvents))
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := ln.Accept(ctx)
	require.NoError(t, err)

	path, err := addPath(client, clientTr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	p := &multipathTestConnPair{client: client, server: server, clientEvents: &clientEvents, serverEvents: &serverEvents}
	data := make([]byte, 10<<20)
	rand.Read(data)
	p.transfer(t, data)
	p.close(t)

	for _, side := range []struct {
		name   string
		events *events.Recorder
	}{
		{name: "client", events: &clientEvents},
		{name: "server", events: &serverEvents},
	} {
		counts := countPathDataPackets(side.events)
		require.NotZero(t, counts[0], side.name)
		require.NotZero(t, counts[1], side.name)

		// Path MTU Discovery and ECN validation are performed on path 1, once it is validated.
		var largePackets, ecnPackets int
		for _, ps := range sentPathPackets(side.events, 1) {
			// packets used for path validation are not marked
			if hasFrame[*qlog.PathChallengeFrame](ps) || hasFrame[*qlog.PathResponseFrame](ps) {
				require.Equal(t, qlog.ECNUnsupported, ps.ECN, side.name)
				continue
			}
			if ps.Raw.Length > protocol.InitialPacketSize {
				largePackets++
			}
			if ps.ECN == qlog.ECT0 {
				ecnPackets++
			}
		}
		if client.conn.capabilities().DF {
			require.NotZero(t, largePackets, side.name)
		}
		if client.conn.capabilities().ECN {
			require.NotZero(t, ecnPackets, side.name)
		}
	}
}
