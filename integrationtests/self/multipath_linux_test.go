//go:build linux

package self_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/integrationtests/tools/israce"
	quicproxy "github.com/AeonDave/mp-quic-go/integrationtests/tools/proxy"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/qlog"

	"github.com/stretchr/testify/require"
)

// On Linux, all of 127.0.0.0/8 is routed to the loopback interface.
// These tests use a second local address, 127.0.0.2, for the second path.
var secondLocalIP = net.IPv4(127, 0, 0, 2)

func (c *lossyConn) localUDPAddr() *net.UDPAddr { return c.conn.LocalAddr().(*net.UDPAddr) }

// keyPhases returns the key phase bits used on 1-RTT packets sent or received on a path.
func (r *multipathRecorder) keyPhases(sent bool, pathID quic.PathID) []qlog.KeyPhaseBit {
	r.mx.Lock()
	defer r.mx.Unlock()

	var phases []qlog.KeyPhaseBit
	for _, kp := range []qlog.KeyPhaseBit{qlog.KeyPhaseZero, qlog.KeyPhaseOne} {
		if r.packets[pathPacketKey{sent, pathID, kp}] > 0 {
			phases = append(phases, kp)
		}
	}
	return phases
}

// framesOfType returns the recorded path management frames of type T that were sent or received.
func framesOfType[T any](r *multipathRecorder, sent bool) []recordedPathFrame {
	r.mx.Lock()
	defer r.mx.Unlock()

	var frames []recordedPathFrame
	for _, f := range r.pathFrames {
		if _, ok := f.frame.Frame.(T); ok && f.sent == sent {
			frames = append(frames, f)
		}
	}
	return frames
}

// lastSentOnPath returns the position of the last 1-RTT packet sent on a path.
func (r *multipathRecorder) lastSentOnPath(pathID quic.PathID) int {
	r.mx.Lock()
	defer r.mx.Unlock()

	return r.lastSent[pathID]
}

// findPath returns the path with the given path ID.
func findPath(paths []quic.PathInfo, id quic.PathID) (quic.PathInfo, bool) {
	for _, p := range paths {
		if p.ID == id {
			return p, true
		}
	}
	return quic.PathInfo{}, false
}

// Path 0 is used from 127.0.0.1, path 1 from 127.0.0.2. Data is transferred in both directions, while 5% of the
// packets are lost on every path in each direction.
func TestMultipathTwoAddressesTransferWithLoss(t *testing.T) {
	testMultipathTransferWithLoss(t, secondLocalIP, 4<<20)
}

// More than 100k packets are transferred in each direction, using the default key update interval.
// Every path uses multiple key phases, in both directions (section 2.5 of draft-ietf-quic-multipath-21).
func TestMultipathKeyUpdates(t *testing.T) {
	if israce.Enabled {
		t.Skip("This test transfers too much data to run with the race detector.")
	}
	const size = 180 << 20
	ln, serverEvents := listenMultipath(t, newUDPConnLocalhost(t))
	conn0 := newLossyConn(t, net.IPv4(127, 0, 0, 1), 0)
	conn1 := newLossyConn(t, secondLocalIP, 0)
	c := dialMultipath(t, ln, serverEvents, ln.Addr(), conn0, conn1)

	runBidiTransfer(t, c.client, c.server, size, scaleDuration(2*time.Minute), transferHooks{})
	require.NoError(t, c.client.CloseWithError(0, ""))
	requireNoConnectionError(t, c.clientEvents)
	requireNoConnectionError(t, c.serverEvents)

	for _, r := range []*multipathRecorder{c.clientEvents, c.serverEvents} {
		for _, sent := range []bool{true, false} {
			var total int
			for _, id := range []quic.PathID{0, 1} {
				total += r.packetCount(sent, id, false)
				// both paths were used in all key phases
				require.Equal(t, []qlog.KeyPhaseBit{qlog.KeyPhaseZero, qlog.KeyPhaseOne}, r.keyPhases(sent, id))
			}
			t.Logf("%d packets (sent: %t)", total, sent)
			require.Greater(t, total, 100_000)
		}
		r.mx.Lock()
		keyUpdates := r.keyUpdates
		r.mx.Unlock()
		t.Logf("%d key updates", keyUpdates)
		// the first key update happens early, the next ones after 100k packets
		require.GreaterOrEqual(t, keyUpdates, 2)
	}
}

// requireNoPacketsAfterAbandon checks that the endpoint sent a PATH_ABANDON frame for a path, and that no packets
// were sent on the path after the endpoint sent or received a PATH_ABANDON frame for it.
// The PATH_ABANDON frame is retransmitted if the packet carrying it is lost, or if a PTO expires.
// All copies carry the same error code, and none of them is sent on the abandoned path.
func requireNoPacketsAfterAbandon(t *testing.T, r *multipathRecorder, id quic.PathID, code qerr.TransportErrorCode) {
	t.Helper()
	var abandonSeq int
	for _, f := range framesOfType[*qlog.PathAbandonFrame](r, true) {
		frame := f.frame.Frame.(*qlog.PathAbandonFrame)
		if frame.PathID != id {
			continue
		}
		require.Equal(t, code, frame.ErrorCode)
		require.NotEqual(t, id, f.pathID, "PATH_ABANDON sent on the abandoned path")
		if abandonSeq == 0 {
			abandonSeq = f.seq
		}
	}
	require.NotZero(t, abandonSeq, "no PATH_ABANDON sent for path %d", id)
	for _, f := range framesOfType[*qlog.PathAbandonFrame](r, false) {
		if f.frame.Frame.(*qlog.PathAbandonFrame).PathID == id && f.seq < abandonSeq {
			abandonSeq = f.seq
		}
	}
	require.Less(t, r.lastSentOnPath(id), abandonSeq, "packets sent on path %d after it was abandoned", id)
}

// Path 1 is abandoned by the client during a transfer. The server responds with a PATH_ABANDON frame.
// The transfer continues on path 0. A new path opened from 127.0.0.2 uses path ID 2: path IDs are never reused
// (section 3.4 of draft-ietf-quic-multipath-21). It is used until the end of the transfer.
func TestMultipathAbandonAndOpenPath(t *testing.T) {
	const size = 8 << 20
	ln, serverEvents := listenMultipath(t, newUDPConnLocalhost(t))
	conn0 := newLossyConn(t, net.IPv4(127, 0, 0, 1), 0)
	conn1 := newLossyConn(t, secondLocalIP, 0)
	c := dialMultipath(t, ln, serverEvents, ln.Addr(), conn0, conn1)
	conn2 := newLossyConn(t, secondLocalIP, 0)
	tr2 := &quic.Transport{Conn: conn2}
	addTracer(tr2)
	t.Cleanup(func() {
		c.client.CloseWithError(0, "")
		tr2.Close()
	})

	path2Open := make(chan struct{})
	var path2 *quic.Path
	runBidiTransfer(t, c.client, c.server, size, scaleDuration(30*time.Second), transferHooks{
		client: func(offset int) {
			switch offset {
			case size / 4:
				require.NoError(t, c.path1.Close())
			case size / 2:
				ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
				defer cancel()
				p, err := c.client.AddPath(tr2)
				require.NoError(t, err)
				require.NoError(t, p.Probe(ctx))
				path2 = p
				close(path2Open)
			}
		},
		server: func(offset int) {
			if offset == size/2 {
				select {
				case <-path2Open:
				case <-time.After(scaleDuration(10 * time.Second)):
				}
			}
		},
	})
	id, ok := path2.ID()
	require.True(t, ok)
	require.Equal(t, quic.PathID(2), id)
	paths := c.client.Paths()
	p, ok := findPath(paths, 2)
	require.True(t, ok)
	require.Equal(t, quic.PathStateActive, p.State)
	require.Equal(t, conn2.localUDPAddr().String(), p.LocalAddr.String())
	if p, ok := findPath(paths, 1); ok {
		require.Equal(t, quic.PathStateAbandoned, p.State)
	}
	require.NoError(t, c.client.CloseWithError(0, ""))
	requireNoConnectionError(t, c.clientEvents)

	// path 2 carried data in both directions
	sent, rcvd := conn2.dataPackets()
	t.Logf("path 2: %d data packets sent, %d received", sent, rcvd)
	require.Greater(t, sent, uint64(100))
	require.Greater(t, rcvd, uint64(100))
	for _, r := range []*multipathRecorder{c.clientEvents, c.serverEvents} {
		require.NotZero(t, r.packetCount(true, 2, true))
		require.NotZero(t, r.packetCount(false, 2, true))
	}
	requireNoPacketsAfterAbandon(t, c.clientEvents, 1, qerr.ApplicationAbandonPath)
	requireNoPacketsAfterAbandon(t, c.serverEvents, 1, qerr.NoError)
}

// Path 0 is abandoned by the client during a transfer. The transfer is completed on path 1.
func TestMultipathAbandonPath0(t *testing.T) {
	const size = 8 << 20
	ln, serverEvents := listenMultipath(t, newUDPConnLocalhost(t))
	conn0 := newLossyConn(t, net.IPv4(127, 0, 0, 1), 0)
	conn1 := newLossyConn(t, secondLocalIP, 0)
	c := dialMultipath(t, ln, serverEvents, ln.Addr(), conn0, conn1)

	var once sync.Once
	runBidiTransfer(t, c.client, c.server, size, scaleDuration(30*time.Second), transferHooks{
		client: func(offset int) {
			if offset >= size/3 {
				once.Do(func() {
					require.NoError(t, c.client.ClosePath(0))
					conn1.resetCounters()
				})
			}
		},
	})
	require.Equal(t, conn1.localUDPAddr().String(), c.client.LocalAddr().String())
	require.Equal(t, conn1.localUDPAddr().String(), c.server.RemoteAddr().String())
	require.EqualError(t, c.path1.Close(), "cannot close the last usable path")
	require.NoError(t, c.client.CloseWithError(0, ""))
	requireNoConnectionError(t, c.clientEvents)

	sent, rcvd := conn1.dataPackets()
	t.Logf("path 1: %d data packets sent, %d received after path 0 was abandoned", sent, rcvd)
	require.Greater(t, sent, uint64(100))
	require.Greater(t, rcvd, uint64(100))
	requireNoPacketsAfterAbandon(t, c.clientEvents, 0, qerr.ApplicationAbandonPath)
	requireNoPacketsAfterAbandon(t, c.serverEvents, 0, qerr.NoError)
}

// Path 1 is rebound by a NAT during a transfer: the client's packets on path 1 arrive from a new address.
// The server migrates path 1 to the new address. Path 0 is not affected (section 5.1 of
// draft-ietf-quic-multipath-21).
func TestMultipathNATRebinding(t *testing.T) {
	const size = 4 << 20
	ln, serverEvents := listenMultipath(t, newUDPConnLocalhost(t))
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	conn0 := newLossyConn(t, net.IPv4(127, 0, 0, 1), 0)
	conn1 := newLossyConn(t, secondLocalIP, 0)
	c := dialMultipath(t, ln, serverEvents, proxy.LocalAddr(), conn0, conn1)
	serverPaths := c.server.Paths()
	path0, ok := findPath(serverPaths, 0)
	require.True(t, ok)
	path1, ok := findPath(serverPaths, 1)
	require.True(t, ok)
	require.NotEqual(t, path0.RemoteAddr.String(), path1.RemoteAddr.String())
	c.serverEvents.mx.Lock()
	challengesBefore := len(c.serverEvents.pathFrames)
	c.serverEvents.mx.Unlock()

	newConn := newUDPConnLocalhost(t)
	var once sync.Once
	runBidiTransfer(t, c.client, c.server, size, scaleDuration(30*time.Second), transferHooks{
		client: func(offset int) {
			if offset >= size/3 {
				once.Do(func() { require.NoError(t, proxy.SwitchConn(conn1.localUDPAddr(), newConn)) })
			}
		},
	})

	// The server migrated path 1 to the new address, and kept path 0.
	require.Eventually(t, func() bool {
		p, ok := findPath(c.server.Paths(), 1)
		return ok && p.RemoteAddr.String() == newConn.LocalAddr().String()
	}, scaleDuration(time.Second), time.Millisecond)
	serverPaths = c.server.Paths()
	p, ok := findPath(serverPaths, 0)
	require.True(t, ok)
	require.Equal(t, quic.PathStateActive, p.State)
	require.Equal(t, path0.RemoteAddr.String(), p.RemoteAddr.String())
	p, ok = findPath(serverPaths, 1)
	require.True(t, ok)
	require.Equal(t, quic.PathStateActive, p.State)
	require.NoError(t, c.client.CloseWithError(0, ""))
	requireNoConnectionError(t, c.clientEvents)

	// the server validated the new address of path 1 only
	var challenges int
	c.serverEvents.mx.Lock()
	newFrames := c.serverEvents.pathFrames[challengesBefore:]
	c.serverEvents.mx.Unlock()
	for _, f := range newFrames {
		if _, ok := f.frame.Frame.(*qlog.PathChallengeFrame); ok && f.sent {
			require.Equal(t, quic.PathID(1), f.pathID)
			challenges++
		}
	}
	require.NotZero(t, challenges)
	for _, f := range framesOfType[*qlog.PathAbandonFrame](c.serverEvents, true) {
		t.Fatalf("unexpected PATH_ABANDON frame: %#v", f.frame.Frame)
	}
}

// The listener's socket is bound to the unspecified address, and receives the packets sent to the preferred
// address 127.0.0.2. The client connects to 127.0.0.1.
func TestPreferredAddressSameTransport(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		name := "without multipath"
		if multipath {
			name = "with multipath"
		}
		t.Run(name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			require.NoError(t, err)
			port := conn.LocalAddr().(*net.UDPAddr).Port
			preferred := netip.AddrPortFrom(netip.AddrFrom4([4]byte(secondLocalIP.To4())), uint16(port))
			tr := &quic.Transport{Conn: conn, PreferredAddress: &quic.PreferredAddress{IPv4: preferred}}
			addTracer(tr)
			defer tr.Close()
			ln, err := tr.Listen(getTLSConfig(), preferredAddressConfig(multipath))
			require.NoError(t, err)
			defer ln.Close()

			clientTr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
			addTracer(clientTr)
			defer clientTr.Close()
			testPreferredAddressMigration(t, ln, clientTr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, preferred, multipath)
		})
	}
}
