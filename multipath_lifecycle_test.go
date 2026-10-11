package quic

import (
	"context"
	"crypto/rand"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"
	"github.com/AeonDave/mp-quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// sentFrames returns the frames of type T sent in 1-RTT packets, and the paths of the packets they were sent in.
func sentFrames[T any](r *events.Recorder) (frames []T, paths []protocol.PathID) {
	for _, ev := range r.Events(qlog.PacketSent{}) {
		ps := ev.(qlog.PacketSent)
		if ps.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		for _, f := range ps.Frames {
			if f, ok := f.Frame.(T); ok {
				frames = append(frames, f)
				paths = append(paths, ps.Header.PathID)
			}
		}
	}
	return frames, paths
}

func randomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func sameAddr(a, b net.Addr) bool { return a.String() == b.String() }

// openPath opens a path on the client's second Transport, and waits until the server validated it as well.
func (p *multipathPathTestPair) openPath(t *testing.T) *Path {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path, err := p.client.AddPath(p.clientTr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	// the server validates the path one RTT later
	time.Sleep(time.Second)
	synctest.Wait()
	return path
}

// The client abandons a path. The PATH_ABANDON frame is sent on path 0, and the server responds exactly once.
// Both endpoints close the path 3 PTOs later: they remove its connection IDs, and increase their maximum path ID.
// The path ID is never used again: the next path uses the next path ID.
func TestMultipathAbandonPathEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			clientConf: func(c *Config) { c.MaxPaths = 2 },
			serverConf: func(c *Config) { c.MaxPaths = 2 },
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path := p.openPath(t)
		p.transfer(t, randomData(1<<20))
		serverPath1ConnIDs := issuedConnIDs(p.serverEvents, 1)
		clientPath1ConnIDs := issuedConnIDs(p.clientEvents, 1)
		require.NotEmpty(t, serverPath1ConnIDs)
		require.NotEmpty(t, clientPath1ConnIDs)
		// the connection ID that the client currently uses on path 1
		clientPackets := sentPathPackets(p.clientEvents, 1)
		activeConnID := clientPackets[len(clientPackets)-1].Header.DestConnectionID

		require.NoError(t, path.Close())
		require.ErrorIs(t, path.Probe(ctx), ErrPathClosed)
		// Path ID 1 is still in use. Opening another path waits until path ID 1 is closed.
		path2, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		probeErr := make(chan error, 1)
		go func() { probeErr <- path2.Probe(ctx) }()
		// The connection IDs of path 1 are still registered.
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		_, ok := (*packetHandlerMap)(p.serverTr).Get(activeConnID)
		require.True(t, ok)
		p.transfer(t, randomData(100<<10))
		require.NoError(t, <-probeErr)
		id, ok := path2.mp.pathID()
		require.True(t, ok)
		require.Equal(t, protocol.PathID(2), id)
		// the connection IDs of path 1 were removed
		for _, connID := range serverPath1ConnIDs {
			_, ok := (*packetHandlerMap)(p.serverTr).Get(connID)
			require.False(t, ok)
		}
		for _, connID := range clientPath1ConnIDs {
			_, ok := (*packetHandlerMap)(p.clientTr2).Get(connID)
			require.False(t, ok)
		}
		p.transfer(t, randomData(1<<20))
		p.close(t)

		abandons, paths := sentFrames[*qlog.PathAbandonFrame](p.clientEvents)
		require.Equal(t, []*qlog.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}}, abandons)
		require.Equal(t, []protocol.PathID{0}, paths)
		abandons, paths = sentFrames[*qlog.PathAbandonFrame](p.serverEvents)
		require.Equal(t, []*qlog.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}}, abandons)
		require.Equal(t, []protocol.PathID{0}, paths)
		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			maxPathIDs, _ := sentFrames[*qlog.MaxPathIDFrame](r)
			require.Equal(t, []*qlog.MaxPathIDFrame{{MaximumPathID: 2}}, maxPathIDs)
			counts := countPathDataPackets(r)
			require.NotZero(t, counts[1])
			require.NotZero(t, counts[2])
		}
	})
}

// The client abandons path 0, while path 1 is active (draft-ietf-quic-multipath-21, figure 5).
// The connection keeps using path 1, and LocalAddr and RemoteAddr refer to path 1.
func TestMultipathAbandonPath0EndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		path := p.openPath(t)
		require.True(t, sameAddr(multipathTestClientAddr, p.client.LocalAddr()))
		require.True(t, sameAddr(multipathTestClientAddr, p.server.RemoteAddr()))

		require.NoError(t, p.client.ClosePath(0))
		require.True(t, sameAddr(multipathTestClientAddr2, p.client.LocalAddr()))
		require.True(t, sameAddr(multipathTestServerAddr, p.client.RemoteAddr()))
		p.transfer(t, randomData(1<<20))
		require.True(t, sameAddr(multipathTestClientAddr2, p.server.RemoteAddr()))
		require.True(t, sameAddr(multipathTestServerAddr, p.server.LocalAddr()))
		// the last usable path can't be closed
		require.EqualError(t, path.Close(), "cannot close the last usable path")

		// path 0 is closed eventually, the connection still works
		time.Sleep(time.Second)
		p.transfer(t, randomData(100<<10))
		require.NotZero(t, p.client.ConnectionStats().SmoothedRTT)
		p.close(t)

		abandons, paths := sentFrames[*qlog.PathAbandonFrame](p.clientEvents)
		require.Equal(t, []*qlog.PathAbandonFrame{{PathID: 0, ErrorCode: qerr.ApplicationAbandonPath}}, abandons)
		require.Equal(t, []protocol.PathID{1}, paths)
		// The server responds on path 1, and acknowledges the packet that contained the PATH_ABANDON frame.
		var found bool
		for _, ps := range sentPathPackets(p.serverEvents, 1) {
			if !hasFrame[*qlog.PathAbandonFrame](ps) {
				continue
			}
			require.False(t, found, "PATH_ABANDON sent more than once")
			found = true
			for _, f := range ps.Frames {
				switch f := f.Frame.(type) {
				case *qlog.PathAbandonFrame:
					require.Equal(t, qlog.PathAbandonFrame{PathID: 0, ErrorCode: qerr.NoError}, *f)
				case *qlog.AckFrame:
					require.True(t, f.HasPathID)
				}
			}
			require.True(t, hasFrame[*qlog.AckFrame](ps))
		}
		require.True(t, found)
		// after abandoning path 0, no data is sent on it
		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			var abandoned bool
			for _, ev := range r.Events(qlog.PacketSent{}) {
				ps := ev.(qlog.PacketSent)
				if hasFrame[*qlog.PathAbandonFrame](ps) {
					abandoned = true
				}
				if abandoned && ps.Header.PacketType == qlog.PacketType1RTT {
					require.Equal(t, protocol.PathID(1), ps.Header.PathID)
				}
			}
		}
	})
}

// Conn.ClosePath abandons paths that the application didn't open using AddPath, e.g. path 0.
// The server can abandon the paths opened by the client.
func TestMultipathConnClosePath(t *testing.T) {
	t.Run("without multipath", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newMultipathTestConnPair(t, true, false)
			require.EqualError(t, p.client.ClosePath(0), "IETF Multipath QUIC is not used")
			require.EqualError(t, p.server.ClosePath(0), "IETF Multipath QUIC is not used")
			p.transfer(t, randomData(10<<10))
		})
	})

	t.Run("before completion of the handshake", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			clientPacketConn, serverPacketConn, closeNetwork := newSimnetLink(t, 10*time.Millisecond)
			defer closeNetwork()
			serverTr := &Transport{Conn: serverPacketConn}
			defer serverTr.Close()
			ln, err := serverTr.ListenEarly(generateTLSConfig(), multipathTestConfig(true, protocol.PerspectiveServer, &events.Recorder{}))
			require.NoError(t, err)
			defer ln.Close()
			clientTr := &Transport{Conn: clientPacketConn}
			defer clientTr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				conn, err := clientTr.Dial(ctx, serverPacketConn.LocalAddr(), generateTLSConfigWithServerName("localhost"), multipathTestConfig(true, protocol.PerspectiveClient, &events.Recorder{}))
				if err == nil {
					<-ctx.Done()
					conn.CloseWithError(0, "")
				}
			}()
			// the server accepts the connection before the handshake completes
			conn, err := ln.Accept(ctx)
			require.NoError(t, err)
			select {
			case <-conn.HandshakeComplete():
				t.Fatal("handshake completed too early")
			default:
			}
			require.EqualError(t, conn.ClosePath(0), "IETF Multipath QUIC is not used")
			<-conn.HandshakeComplete()
			require.EqualError(t, conn.ClosePath(0), "cannot close the last usable path")
			cancel()
		})
	})

	t.Run("path 0 and the server", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newMultipathPathTestPair(t, multipathPathTestOpts{})
			require.EqualError(t, p.client.ClosePath(0), "cannot close the last usable path")
			require.EqualError(t, p.server.ClosePath(0), "cannot close the last usable path")
			require.ErrorIs(t, p.client.ClosePath(1), ErrPathClosed)
			require.ErrorIs(t, p.server.ClosePath(1), ErrPathClosed)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			path := p.openPath(t)
			path2, err := p.client.AddPath(p.clientTr2)
			require.NoError(t, err)
			require.NoError(t, path2.Probe(ctx))
			time.Sleep(time.Second)
			synctest.Wait()
			require.Len(t, p.server.Paths(), 3)

			// the server abandons path 1, the client abandons path 0
			require.NoError(t, p.server.ClosePath(1))
			require.ErrorIs(t, p.server.ClosePath(1), ErrPathClosed)
			require.NoError(t, p.client.ClosePath(0))
			require.ErrorIs(t, p.client.ClosePath(0), ErrPathClosed)
			require.ErrorIs(t, p.client.ClosePath(42), ErrPathClosed)
			p.transfer(t, randomData(100<<10))
			require.ErrorIs(t, path.Probe(ctx), ErrPathClosed)
			require.EqualError(t, p.client.ClosePath(2), "cannot close the last usable path")
			p.close(t)

			abandons, _ := sentFrames[*qlog.PathAbandonFrame](p.serverEvents)
			require.ElementsMatch(t, []*qlog.PathAbandonFrame{
				{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath},
				{PathID: 0, ErrorCode: qerr.NoError},
			}, abandons)
			abandons, _ = sentFrames[*qlog.PathAbandonFrame](p.clientEvents)
			require.ElementsMatch(t, []*qlog.PathAbandonFrame{
				{PathID: 0, ErrorCode: qerr.ApplicationAbandonPath},
				{PathID: 1, ErrorCode: qerr.NoError},
			}, abandons)
			// after abandoning paths 0 and 1, data is sent on path 2
			require.NotZero(t, countPathDataPackets(p.clientEvents)[2])
		})
	})
}

// The client abandons path 0 right after it validated path 1, while the server is still validating path 1:
// the client's PATH_RESPONSE was lost. Path 1 is open, so the server abandons path 0 instead of closing the connection
// (section 3.4 of draft-ietf-quic-multipath-21). Its PATH_ABANDON frame is sent once it validated path 1,
// using a retransmitted PATH_CHALLENGE.
func TestMultipathAbandonPath0WhileServerValidatesPath1(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		// The client's second datagram on path 1 contains its PATH_RESPONSE.
		var numSent atomic.Int32
		p.router.SetDrop(func(pkt simnet.Packet) bool {
			return sameAddr(pkt.From, multipathTestClientAddr2) && numSent.Add(1) == 2
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		require.NoError(t, path.Probe(ctx))
		require.NoError(t, p.client.closeMultipathPath(0))

		p.transfer(t, randomData(1<<20))
		require.True(t, sameAddr(multipathTestClientAddr2, p.server.RemoteAddr()))
		p.close(t)

		clientPackets := sentPathPackets(p.clientEvents, 1)
		require.GreaterOrEqual(t, len(clientPackets), 2)
		require.True(t, hasFrame[*qlog.PathResponseFrame](clientPackets[1]))
		// The client's PATH_ABANDON frame might be retransmitted: the server can't acknowledge it before it validated
		// path 1, unless it sends a PATH_ACK frame together with its retransmitted PATH_CHALLENGE.
		abandons, paths := sentFrames[*qlog.PathAbandonFrame](p.clientEvents)
		require.NotEmpty(t, abandons)
		for i, f := range abandons {
			require.Equal(t, qlog.PathAbandonFrame{PathID: 0, ErrorCode: qerr.ApplicationAbandonPath}, *f)
			require.Equal(t, protocol.PathID(1), paths[i])
		}
		abandons, paths = sentFrames[*qlog.PathAbandonFrame](p.serverEvents)
		require.Equal(t, []*qlog.PathAbandonFrame{{PathID: 0, ErrorCode: qerr.NoError}}, abandons)
		require.Equal(t, []protocol.PathID{1}, paths)
		// the server retransmitted its PATH_CHALLENGE on path 1
		challenges, paths := sentFrames[*qlog.PathChallengeFrame](p.serverEvents)
		require.Len(t, challenges, 2)
		require.Equal(t, []protocol.PathID{1, 1}, paths)
	})
}

// A lost PATH_ABANDON frame is retransmitted. The peer responds once.
func TestMultipathAbandonPathLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		path := p.openPath(t)

		// all packets sent by the client on path 0 are lost for a while
		p.router.SetDrop(func(pkt simnet.Packet) bool {
			return sameAddr(pkt.From, multipathTestClientAddr) && sameAddr(pkt.To, multipathTestServerAddr)
		})
		require.NoError(t, path.Close())
		time.Sleep(time.Second)
		p.router.SetDrop(nil)
		time.Sleep(2 * time.Second)
		p.transfer(t, randomData(100<<10))
		p.close(t)

		abandons, _ := sentFrames[*qlog.PathAbandonFrame](p.clientEvents)
		require.Greater(t, len(abandons), 1)
		for _, f := range abandons {
			require.Equal(t, qlog.PathAbandonFrame{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}, *f)
		}
		abandons, _ = sentFrames[*qlog.PathAbandonFrame](p.serverEvents)
		require.Equal(t, []*qlog.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}}, abandons)
		// both endpoints closed the path, and increased their maximum path ID
		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			maxPathIDs, _ := sentFrames[*qlog.MaxPathIDFrame](r)
			require.Equal(t, []*qlog.MaxPathIDFrame{{MaximumPathID: 3}}, maxPathIDs)
		}
	})
}

// Packets that are still in flight on a path when it is abandoned arrive after the PATH_ABANDON frame
// that was sent on a faster path. They are processed during the retention period, and acknowledged on
// another path (section 3.4.3 of draft-ietf-quic-multipath-21). They don't trigger a stateless reset,
// since the connection IDs of the path are still registered (section 3.4.2).
func TestMultipathAbandonedPathReordering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// path 1 is a lot slower in the direction from the client to the server
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			latency: func(pkt simnet.Packet) time.Duration {
				if sameAddr(pkt.From, multipathTestClientAddr2) {
					return 200 * time.Millisecond
				}
				return 5 * time.Millisecond
			},
		})
		path := p.openPath(t)
		transferDone := make(chan struct{})
		go func() {
			defer close(transferDone)
			p.transfer(t, randomData(5<<20))
		}()
		// wait until the client sent data on path 1
		for countPathDataPackets(p.clientEvents)[1] == 0 {
			time.Sleep(time.Millisecond)
		}
		require.NoError(t, path.Close())
		closed := time.Now()
		clientPackets := sentPathPackets(p.clientEvents, 1)
		activeConnID := clientPackets[len(clientPackets)-1].Header.DestConnectionID
		// the packets that are in flight on path 1 arrive at the server in the next 200ms
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		_, ok := (*packetHandlerMap)(p.serverTr).Get(activeConnID)
		require.True(t, ok)
		<-transferDone
		// wait for the packets in flight on path 1 to arrive
		time.Sleep(time.Second)
		p.close(t)

		// the server sent the PATH_ABANDON frame before it received the last packets on path 1
		var abandonTime time.Time
		for _, ev := range p.serverEvents.EventsWithTime(qlog.PacketSent{}) {
			if hasFrame[*qlog.PathAbandonFrame](ev.Event.(qlog.PacketSent)) {
				abandonTime = ev.Time
				break
			}
		}
		require.False(t, abandonTime.IsZero())
		require.Less(t, abandonTime.Sub(closed), 50*time.Millisecond)
		// Events are recorded in the order they happened.
		var numReceivedAfterAbandon int
		var ackedOnPath0 bool
		for _, ev := range p.serverEvents.EventsWithTime(qlog.PacketSent{}, qlog.PacketReceived{}) {
			if ev.Time.Before(abandonTime) {
				continue
			}
			switch e := ev.Event.(type) {
			case qlog.PacketReceived:
				if e.Header.HasPathID && e.Header.PathID == 1 {
					numReceivedAfterAbandon++
					ackedOnPath0 = false
				}
			case qlog.PacketSent:
				// these packets are acknowledged using PATH_ACK frames sent on path 0
				if e.Header.PacketType != qlog.PacketType1RTT {
					continue
				}
				require.Equal(t, protocol.PathID(0), e.Header.PathID)
				for _, f := range e.Frames {
					if ack, ok := f.Frame.(*qlog.AckFrame); ok && ack.PathID == 1 && numReceivedAfterAbandon > 0 {
						ackedOnPath0 = true
					}
				}
			}
		}
		require.NotZero(t, numReceivedAfterAbandon)
		require.True(t, ackedOnPath0)
	})
}

// A NAT rebinding changes the client's address on path 1. The server validates the new address using a
// connection ID of path 1, and migrates path 1 to it (section 3.1.2 of draft-ietf-quic-multipath-21).
// Path 0 is not affected.
func TestMultipathNATRebindingEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		p.openPath(t)
		p.transfer(t, randomData(1<<20))
		var path1ConnIDsBefore []protocol.ConnectionID
		for _, ps := range sentPathPackets(p.serverEvents, 1) {
			path1ConnIDsBefore = append(path1ConnIDsBefore, ps.Header.DestConnectionID)
		}
		numServerPackets := len(sentPathPackets(p.serverEvents, 1))

		// the NAT in front of the client's second address changes its mapping
		natAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 5), Port: 9010}
		p.router.SetRewrite(func(pkt simnet.Packet) (simnet.Packet, bool) {
			switch {
			case sameAddr(pkt.From, multipathTestClientAddr2):
				pkt.From = natAddr
			case sameAddr(pkt.To, natAddr):
				pkt.To = multipathTestClientAddr2
			case sameAddr(pkt.To, multipathTestClientAddr2):
				// the old mapping is gone
				return pkt, false
			}
			return pkt, true
		})
		p.transfer(t, randomData(1<<20))
		p.close(t)

		require.NotZero(t, p.router.Delivered(natAddr, multipathTestServerAddr))
		require.NotZero(t, p.router.Delivered(multipathTestServerAddr, natAddr))
		// path 0 was not migrated
		require.True(t, sameAddr(multipathTestClientAddr, p.server.conn.RemoteAddr()))
		require.True(t, sameAddr(natAddr, p.server.mp.paths[1].conn.RemoteAddr()))
		// The server validated the new address with a PATH_CHALLENGE, using a connection ID of path 1
		// that wasn't used before. After migrating, it validated the previous address, using a connection ID
		// it used there (section 9.3.3 of RFC 9000). That validation failed, since the old mapping is gone.
		var numValidatedNew, numValidatedPrev int
		clientPath1ConnIDs := issuedConnIDs(p.clientEvents, 1)
		for _, ps := range sentPathPackets(p.serverEvents, 1)[numServerPackets:] {
			require.Contains(t, clientPath1ConnIDs, ps.Header.DestConnectionID)
			if !hasFrame[*qlog.PathChallengeFrame](ps) {
				continue
			}
			if slices.Contains(path1ConnIDsBefore, ps.Header.DestConnectionID) {
				numValidatedPrev++
			} else {
				numValidatedNew++
			}
		}
		require.Equal(t, 1, numValidatedNew)
		require.Equal(t, 1, numValidatedPrev)
		// the server sent a token that is valid for the new address
		tokens, _ := sentFrames[*qlog.NewTokenFrame](p.serverEvents)
		require.Len(t, tokens, 2)
	})
}

// A path that the client marked as a backup path before opening it is not used for sending data,
// neither by the client nor by the server (section 3.3 of draft-ietf-quic-multipath-21).
// The status is sent together with the PATH_CHALLENGE that opens the path.
func TestMultipathBackupPathEndToEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := p.client.AddPath(p.clientTr2)
		require.NoError(t, err)
		require.NoError(t, path.SetStatus(PathStatusBackup))
		require.NoError(t, path.Probe(ctx))
		// the server validates the path one RTT later
		time.Sleep(time.Second)
		p.transfer(t, randomData(1<<20))

		// path 0 is abandoned: the backup path is used now
		require.NoError(t, p.client.closeMultipathPath(0))
		p.transfer(t, randomData(100<<10))
		p.close(t)

		first := sentPathPackets(p.clientEvents, 1)[0]
		require.True(t, hasFrame[*qlog.PathChallengeFrame](first))
		require.True(t, hasFrame[*qlog.PathStatusFrame](first))
		statusFrames, _ := sentFrames[*qlog.PathStatusFrame](p.clientEvents)
		require.Equal(t, []*qlog.PathStatusFrame{{PathID: 1, SequenceNumber: 0, Backup: true}}, statusFrames)

		for _, r := range []*events.Recorder{p.clientEvents, p.serverEvents} {
			var abandoned bool
			var dataOnPath1 int
			for _, ev := range r.Events(qlog.PacketSent{}) {
				ps := ev.(qlog.PacketSent)
				if hasFrame[*qlog.PathAbandonFrame](ps) {
					abandoned = true
				}
				if ps.Header.PathID != 1 || !hasFrame[*qlog.StreamFrame](ps) {
					continue
				}
				if !abandoned {
					t.Fatal("data sent on the backup path")
				}
				dataOnPath1++
			}
			require.NotZero(t, dataOnPath1)
		}
	})
}

// Keep-alives are not bound to path 0: they keep the connection alive after path 0 was abandoned.
func TestMultipathKeepAliveAfterAbandoningPath0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			clientConf: func(c *Config) {
				c.KeepAlivePeriod = 100 * time.Millisecond
				c.MaxIdleTimeout = 500 * time.Millisecond
			},
			serverConf: func(c *Config) { c.MaxIdleTimeout = 500 * time.Millisecond },
		})
		p.openPath(t)
		require.NoError(t, p.client.closeMultipathPath(0))

		// the connection is idle for much longer than the idle timeout
		time.Sleep(5 * time.Second)
		require.NoError(t, p.client.Context().Err())
		require.NoError(t, p.server.Context().Err())
		p.transfer(t, randomData(10<<10))
		p.close(t)

		pings, paths := sentFrames[*qlog.PingFrame](p.clientEvents)
		require.Greater(t, len(pings), 10)
		require.Equal(t, protocol.PathID(1), paths[len(paths)-1])
	})
}
