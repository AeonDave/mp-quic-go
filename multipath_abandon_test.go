package quic

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// acceptServerPath makes the client open a path, and validates it (server only).
func (tc *mpPathTestConn) acceptServerPath(t *testing.T, id protocol.PathID, clientAddr net.Addr) *MockSendConn {
	t.Helper()
	c := tc.conn
	require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(id, 0)))
	pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
	tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
	_, err := tc.receivePacket(t, id, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
	require.NoError(t, err)
	numProbes := len(tc.probes)
	require.NoError(t, c.triggerSending(monotime.Now()))
	challenges, _ := sentProbeFrames(tc.probes[numProbes:], id)
	require.NotEmpty(t, challenges)
	_, err = tc.receivePacket(t, id, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
	require.NoError(t, err)
	require.Equal(t, mpPathActive, c.mp.paths[id].state)
	return pathConn
}

// newMockPathConnWithLocalAddr returns a mock sendConn for a path, that sends from localAddr.
func newMockPathConnWithLocalAddr(mockCtrl *gomock.Controller, remoteAddr, localAddr net.Addr) *MockSendConn {
	conn := NewMockSendConn(mockCtrl)
	conn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	conn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	conn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
	return conn
}

// closeTestPath calls Close on the path, and processes the request on the connection's run loop.
func (tc *mpPathTestConn) closeTestPath(t *testing.T, p *Path) error {
	t.Helper()
	errChan := make(chan error, 1)
	go func() { errChan <- p.Close() }()
	synctest.Wait()
	require.NoError(t, tc.conn.handleMultipathEvents(monotime.Now()))
	synctest.Wait()
	select {
	case err := <-errChan:
		return err
	default:
		t.Fatal("Close should have returned")
		return nil
	}
}

// issuedConnIDsForPath returns the connection IDs issued for a path.
func (tc *mpPathTestConn) issuedConnIDsForPath(pathID protocol.PathID) []protocol.ConnectionID {
	var connIDs []protocol.ConnectionID
	if p := tc.conn.connIDGenerator.path(pathID); p != nil {
		for _, connID := range p.active {
			connIDs = append(connIDs, connID)
		}
	}
	return connIDs
}

func requireConnIDsRegistered(t *testing.T, c *Conn, pathID protocol.PathID, connIDs []protocol.ConnectionID, registered bool) {
	t.Helper()
	require.NotEmpty(t, connIDs)
	for _, connID := range connIDs {
		id, ok := c.connIDGenerator.PathForConnID(connID)
		require.Equal(t, registered, ok, "connection ID %s", connID)
		if registered {
			require.Equal(t, pathID, id)
		}
	}
}

// After abandoning a path, its state is retained for 3 PTOs after both endpoints sent a PATH_ABANDON frame
// (section 3.4 of draft-ietf-quic-multipath-21). If the peer doesn't send its PATH_ABANDON frame in time,
// all state except for our connection IDs is removed, and the path keeps counting towards the limit.
// Once the path is closed, its connection IDs are removed, and the maximum path ID is increased by one.
func TestMultipathAbandonedPathRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 2, 2)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)
		path1ConnIDs := tc.issuedConnIDsForPath(1)
		path1ConnID := path1ConnIDs[0]
		queuedFrames(c)

		require.NoError(t, tc.closeTestPath(t, p))
		abandonTime := monotime.Now()
		frames := queuedFrames(c)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}},
			pathAbandonFramesFor(frames, 1),
		)
		path := c.mp.paths[1]
		require.Equal(t, mpPathAbandoned, path.state)
		require.Equal(t, abandonTime.Add(3*path.abandonPTO), path.retainUntil)
		require.Equal(t, path.retainUntil, c.mp.nextTimeout())
		// The connection IDs are still registered, so that packets in flight don't trigger stateless resets.
		requireConnIDsRegistered(t, c, 1, path1ConnIDs, true)

		// Packets received on the path are processed, and acknowledged on another path.
		processed, err := tc.receivePacket(t, 1, tc.remoteAddr, packetInfo{}, 100, &wire.PingFrame{})
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, []protocol.PathID{1}, c.receivedPacketHandler.AckDuePaths(monotime.Now()))
		// PATH_ACK frames for the path are ignored
		require.NoError(t, handleTestFrame(t, c,
			&wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 100}}},
			protocol.Encryption1RTT,
		))

		// A lost PATH_ABANDON frame is retransmitted.
		require.Len(t, frames, 1)
		frames[0].Handler.OnLost(frames[0].Frame)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}},
			pathAbandonFramesFor(queuedFrames(c), 1),
		)

		// The peer doesn't respond in time.
		// All state of the path is removed, except for our connection IDs.
		tc.advanceToNextMultipathTimeout(t)
		require.Equal(t, monotime.Now(), path.retainUntil)
		require.True(t, path.zombie)
		require.Contains(t, c.mp.paths, protocol.PathID(1))
		require.Nil(t, c.sentPacketHandler.GetPathRTTStats(1))
		require.Empty(t, c.receivedPacketHandler.AckDuePaths(monotime.Now()))
		requireConnIDsRegistered(t, c, 1, path1ConnIDs, true)
		require.Equal(t, protocol.PathID(2), c.mp.localMaxPathID)
		require.Empty(t, multipathFramesOfType[*wire.MaxPathIDFrame](queuedFrames(c)))
		require.Zero(t, c.mp.nextTimeout())
		// packets received on the path are dropped
		processed, err = c.handleOnePacket(getShortHeaderPacket(t, tc.remoteAddr, path1ConnID, 2, make([]byte, 100)), 0)
		require.NoError(t, err)
		require.False(t, processed)
		// frames for the path are ignored
		for _, f := range []wire.Frame{
			newTestPathNewConnectionIDFrame(1, 5),
			&wire.PathStatusFrame{PathID: 1, SequenceNumber: 10, Backup: true},
			&wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: c.connIDGenerator.NextSequenceNumber(1)},
			&wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 100}}},
		} {
			require.NoError(t, handleTestFrame(t, c, f, protocol.Encryption1RTT), "%#v", f)
		}
		require.False(t, c.peerConnIDs.HasConnID(1))
		require.Empty(t, queuedFrames(c))
		// The path ID still counts towards the limit. Path ID 2 can be used, but no other path ID.
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		tc.openTestPath(t, tc.newTestPath(pathConn))
		errChan := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		requireProbeResult(t, errChan, ErrTooManyPaths)
		// a lost PATH_ABANDON frame is still retransmitted
		frames[0].Handler.OnLost(frames[0].Frame)
		require.Len(t, pathAbandonFramesFor(queuedFrames(c), 1), 1)

		// Eventually, the peer responds. The path is closed 3 PTOs later.
		time.Sleep(time.Second)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1}, protocol.Encryption1RTT))
		require.Empty(t, pathAbandonFrames(queuedFrames(c)))
		require.Equal(t, monotime.Now().Add(3*max(c.maxPTO(false), path.abandonPTO)), path.retainUntil)
		tc.advanceToNextMultipathTimeout(t)
		require.NotContains(t, c.mp.paths, protocol.PathID(1))
		require.NotContains(t, c.mp.pathIDs, protocol.PathID(1))
		require.True(t, c.mp.isClosed(1))
		requireConnIDsRegistered(t, c, 1, path1ConnIDs, false)
		require.Equal(t, protocol.PathID(3), c.mp.localMaxPathID)
		frames = queuedFrames(c)
		require.Equal(t, []*wire.MaxPathIDFrame{{MaximumPathID: 3}}, multipathFramesOfType[*wire.MaxPathIDFrame](frames))
		// the PATH_ABANDON frame isn't retransmitted any more
		h := &pathAbandonFrameHandler{conn: c}
		h.OnLost(&wire.PathAbandonFrame{PathID: 1})
		require.Empty(t, queuedFrames(c))

		// frames for the closed path ID are ignored
		for _, f := range []wire.Frame{
			&wire.PathAbandonFrame{PathID: 1},
			&wire.PathStatusFrame{PathID: 1, SequenceNumber: 10, Backup: true},
			&wire.PathNewConnectionIDFrame{PathID: 1, SequenceNumber: 5, ConnectionID: protocol.ParseConnectionID([]byte{9, 9, 9, 9})},
			&wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0},
			&wire.PathCIDsBlockedFrame{PathID: 1, NextSequenceNumber: 10},
			&wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: []wire.AckRange{{Smallest: 0, Largest: 100}}},
		} {
			require.NoError(t, handleTestFrame(t, c, f, protocol.Encryption1RTT), "%#v", f)
		}
		require.Empty(t, queuedFrames(c))
		require.NotContains(t, c.peerConnIDs.paths, protocol.PathID(1))

		// The path ID is never used again. Once the peer increases its maximum path ID, path ID 3 can be used.
		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 3}, protocol.Encryption1RTT))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(3, 0)))
		require.Equal(t, protocol.PathID(3), tc.openTestPath(t, tc.newTestPath(pathConn)))
	})
}

// The peer abandons a path. We reply with a PATH_ABANDON frame, once,
// and close the path 3 PTOs later (section 3.4 of draft-ietf-quic-multipath-21).
func TestMultipathPeerAbandonsPathRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 2, 2)
		c := tc.conn
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		tc.acceptServerPath(t, 1, clientAddr)
		path1ConnIDs := tc.issuedConnIDsForPath(1)
		queuedFrames(c)

		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor}, protocol.Encryption1RTT))
		abandonTime := monotime.Now()
		frames := queuedFrames(c)
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}}, pathAbandonFrames(frames))
		path := c.mp.paths[1]
		require.True(t, path.abandonRcvd)
		require.False(t, c.peerConnIDs.HasConnID(1))
		// a retransmission of the peer's PATH_ABANDON frame is not answered again
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor}, protocol.Encryption1RTT))
		require.Empty(t, queuedFrames(c))
		// a lost reply is retransmitted
		frames[0].Handler.OnLost(frames[0].Frame)
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}}, pathAbandonFrames(queuedFrames(c)))

		require.Equal(t, abandonTime.Add(3*path.abandonPTO), c.mp.nextTimeout())
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.isClosed(1))
		requireConnIDsRegistered(t, c, 1, path1ConnIDs, false)
		require.Equal(t, []*wire.MaxPathIDFrame{{MaximumPathID: 3}}, multipathFramesOfType[*wire.MaxPathIDFrame](queuedFrames(c)))
		// packets on the closed path don't create a new path
		_, ok := c.connIDGenerator.PathForConnID(path1ConnIDs[0])
		require.False(t, ok)
		processed, err := c.handleOnePacket(getShortHeaderPacket(t, clientAddr, path1ConnIDs[0], 3, make([]byte, 100)), 0)
		require.NoError(t, err)
		require.False(t, processed)
	})
}

// A path ID that the peer abandoned before it was used is closed 3 PTOs later.
// The maximum path ID is increased by one.
func TestMultipathPeerAbandonsUnusedPathRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 2, 2)
		c := tc.conn
		path2ConnIDs := tc.issuedConnIDsForPath(2)
		queuedFrames(c)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 2}, protocol.Encryption1RTT))
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 2, ErrorCode: qerr.NoError}}, pathAbandonFrames(queuedFrames(c)))
		requireConnIDsRegistered(t, c, 2, path2ConnIDs, true)

		require.Equal(t, monotime.Now().Add(3*c.maxPTO(false)), c.mp.nextTimeout())
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.isClosed(2))
		require.Empty(t, c.mp.unusedAbandoned)
		requireConnIDsRegistered(t, c, 2, path2ConnIDs, false)
		require.Equal(t, []*wire.MaxPathIDFrame{{MaximumPathID: 3}}, multipathFramesOfType[*wire.MaxPathIDFrame](queuedFrames(c)))

		// Once the peer increases its maximum path ID, a connection ID is issued for path ID 3, but not for path ID 2.
		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 4}, protocol.Encryption1RTT))
		var pathIDs []protocol.PathID
		for _, f := range multipathFramesOfType[*wire.PathNewConnectionIDFrame](queuedFrames(c)) {
			pathIDs = append(pathIDs, f.PathID)
		}
		require.Equal(t, []protocol.PathID{3}, pathIDs)
	})
}

// A lost MAX_PATH_ID frame is retransmitted, unless a MAX_PATH_ID frame with a larger value was sent since
// (section 4.6 of draft-ietf-quic-multipath-21).
func TestMultipathMaxPathIDRetransmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		queuedFrames(c)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 2}, protocol.Encryption1RTT))
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 3}, protocol.Encryption1RTT))
		queuedFrames(c)
		tc.advanceToNextMultipathTimeout(t)
		var maxPathIDs []ackhandler.Frame
		for _, f := range queuedFrames(c) {
			if _, ok := f.Frame.(*wire.MaxPathIDFrame); ok {
				maxPathIDs = append(maxPathIDs, f)
			}
		}
		require.Len(t, maxPathIDs, 2)
		slices.SortFunc(maxPathIDs, func(a, b ackhandler.Frame) int {
			return cmp.Compare(a.Frame.(*wire.MaxPathIDFrame).MaximumPathID, b.Frame.(*wire.MaxPathIDFrame).MaximumPathID)
		})
		require.Equal(t, &wire.MaxPathIDFrame{MaximumPathID: 4}, maxPathIDs[0].Frame)
		require.Equal(t, &wire.MaxPathIDFrame{MaximumPathID: 5}, maxPathIDs[1].Frame)
		maxPathIDs[0].Handler.OnLost(maxPathIDs[0].Frame)
		require.Empty(t, queuedFrames(c))
		maxPathIDs[1].Handler.OnLost(maxPathIDs[1].Frame)
		require.Equal(t, []*wire.MaxPathIDFrame{{MaximumPathID: 5}}, multipathFramesOfType[*wire.MaxPathIDFrame](queuedFrames(c)))
	})
}

// While an abandoned path is being closed, Probe waits for the path ID to become available,
// instead of returning ErrTooManyPaths.
func TestMultipathOpenPathWhileClosingPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 1, 1)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)
		require.NoError(t, tc.closeTestPath(t, p))
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1}, protocol.Encryption1RTT))

		p2 := tc.newTestPath(pathConn)
		errChan := probeMultipathPath(t.Context(), p2)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		requireProbeBlocked(t, errChan)
		queuedFrames(c)

		// path 1 is closed, and our maximum path ID is increased
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.isClosed(1))
		// the server's maximum path ID now prevents opening a path
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Equal(t,
			[]*wire.PathsBlockedFrame{{MaximumPathID: 1}},
			multipathFramesOfType[*wire.PathsBlockedFrame](queuedFrames(c)),
		)
		requireProbeBlocked(t, errChan)
		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 2}, protocol.Encryption1RTT))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		id, ok := p2.mp.pathID()
		require.True(t, ok)
		require.Equal(t, protocol.PathID(2), id)
	})
}

// If the peer doesn't respond to our PATH_ABANDON frame in time, the abandoned path becomes a zombie, which keeps
// counting towards the limit. A path waiting for the abandoned path to be closed can't be opened anymore:
// Probe returns ErrTooManyPaths when the path becomes a zombie, no other event is needed.
func TestMultipathOpenPathWhileClosingPathZombie(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 1, 1)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)
		require.NoError(t, tc.closeTestPath(t, p))

		errChan := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		requireProbeBlocked(t, errChan)

		// the peer doesn't respond to the PATH_ABANDON frame
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.paths[1].zombie)
		require.Zero(t, c.mp.nextTimeout())
		requireProbeResult(t, errChan, ErrTooManyPaths)
		require.Empty(t, c.mp.pendingOpens)
	})
}

// When path 0 is abandoned, the connection uses the path with the lowest path ID as its primary path:
// LocalAddr, RemoteAddr and ConnectionStats refer to it (draft-ietf-quic-multipath-21, figure 5).
func TestMultipathPrimaryPathAfterAbandoningPath0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		path0Addr := c.RemoteAddr()
		require.Equal(t, tc.remoteAddr, path0Addr)
		clientAddr1 := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		clientAddr2 := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 6), Port: 5678}
		pathConn1 := tc.acceptServerPath(t, 1, clientAddr1)
		pathConn2 := tc.acceptServerPath(t, 2, clientAddr2)
		c.sentPacketHandler.GetPathRTTStats(1).UpdateRTT(123*time.Millisecond, 0)
		path1RTT := c.sentPacketHandler.GetPathRTTStats(1).SmoothedRTT()
		require.NotEqual(t, c.rttStats.SmoothedRTT(), path1RTT)
		queuedFrames(c)

		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 0}, protocol.Encryption1RTT))
		require.Equal(t, []*wire.PathAbandonFrame{{PathID: 0, ErrorCode: qerr.NoError}}, pathAbandonFrames(queuedFrames(c)))
		require.Equal(t, protocol.PathID(1), c.mp.primaryPathID)
		require.Equal(t, clientAddr1, c.RemoteAddr())
		require.Equal(t, pathConn1.LocalAddr(), c.LocalAddr())
		require.Equal(t, path1RTT, c.ConnectionStats().SmoothedRTT)

		// when path 1 is abandoned, path 2 becomes the primary path
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1}, protocol.Encryption1RTT))
		require.Equal(t, protocol.PathID(2), c.mp.primaryPathID)
		require.Equal(t, clientAddr2, c.RemoteAddr())

		// Path 0 is closed eventually. The connection is still usable.
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.isClosed(0))
		require.True(t, c.mp.isClosed(1))
		require.Equal(t, clientAddr2, c.RemoteAddr())
		// ACK frames acknowledge packets sent on path 0, they are ignored now
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 1000}}}, protocol.Encryption1RTT))
		require.NoError(t, handleTestFrame(t, c, &wire.RetireConnectionIDFrame{SequenceNumber: 1}, protocol.Encryption1RTT))
		require.NoError(t, handleTestFrame(t, c, &wire.NewConnectionIDFrame{SequenceNumber: 10, ConnectionID: protocol.ParseConnectionID([]byte{9, 9, 9, 9})}, protocol.Encryption1RTT))

		// the CONNECTION_CLOSE is sent on path 2
		var closePath protocol.PathID
		pathConn2.EXPECT().Write(gomock.Any(), uint16(0), gomock.Any())
		tc.packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(_ *qerr.ApplicationError, _ protocol.ByteCount, _ protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
				closePath = pathID
				return &coalescedPacket{buffer: getPacketBuffer(), shortHdrPacket: &shortHeaderPacket{PathID: uint64(pathID)}}, nil
			},
		)
		_, err := c.sendConnectionClose(&qerr.ApplicationError{})
		require.NoError(t, err)
		require.Equal(t, protocol.PathID(2), closePath)
	})
}

// If no path can be used for sending, no CONNECTION_CLOSE is sent.
func TestMultipathConnectionCloseWithoutUsablePath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		c.markPathAbandoned(c.mp.paths[0], monotime.Now(), nil)
		_, err := c.sendConnectionClose(&qerr.ApplicationError{})
		require.EqualError(t, err, "no path to send the CONNECTION_CLOSE on")
	})
}

// After the connection was closed, a packet received on a path is answered with a packet containing the
// CONNECTION_CLOSE frame, sent on that path: it uses a connection ID of that path (section 3.1 of
// draft-ietf-quic-multipath-21). Packets received on abandoned paths are not answered (section 3.4).
func TestMultipathConnectionClosePacketsForEveryPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		c.sentFirstPacket = true
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		pathConn1 := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		tc.openTestPath(t, tc.newTestPath(pathConn1))
		tc.openTestPath(t, tc.newTestPath(newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})))
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 2}, protocol.Encryption1RTT))
		c.mp.lastRcvdPathID = 1

		tc.packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(_ *qerr.ApplicationError, _ protocol.ByteCount, _ protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
				buf := getPacketBuffer()
				buf.Data = fmt.Appendf(buf.Data, "close on path %d", pathID)
				return &coalescedPacket{buffer: buf, shortHdrPacket: &shortHeaderPacket{PathID: uint64(pathID)}}, nil
			},
		).Times(2)
		// the CONNECTION_CLOSE is sent on path 1, the path that the last packet was received on
		pathConn1.EXPECT().Write([]byte("close on path 1"), uint16(0), gomock.Any())
		replaced := make(map[string][]protocol.PathID)
		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), 3*c.maxPTO(false)).Do(
			func(connIDs []protocol.ConnectionID, packet []byte, _ time.Duration) {
				for _, connID := range connIDs {
					id, ok := c.connIDGenerator.PathForConnID(connID)
					require.True(t, ok)
					replaced[string(packet)] = append(replaced[string(packet)], id)
				}
			},
		).Times(3)
		c.handleCloseError(&closeError{err: &qerr.ApplicationError{ErrorCode: 42}})

		require.Len(t, replaced, 3)
		for packet, pathIDs := range replaced {
			slices.Sort(pathIDs)
			pathIDs = slices.Compact(pathIDs)
			switch packet {
			case "close on path 0":
				require.Equal(t, []protocol.PathID{0}, pathIDs)
			case "close on path 1":
				require.Equal(t, []protocol.PathID{1}, pathIDs)
			case "":
				// the abandoned path, and the unused path
				require.Equal(t, []protocol.PathID{2, 3}, pathIDs)
			default:
				t.Fatalf("unexpected packet: %q", packet)
			}
		}
	})
}

// The application can close path 0. The last usable path can't be closed.
func TestMultipathClosePath0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		closePath := func(id protocol.PathID) error {
			errChan := make(chan error, 1)
			go func() { errChan <- c.closeMultipathPath(id) }()
			synctest.Wait()
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			synctest.Wait()
			return <-errChan
		}
		require.EqualError(t, closePath(0), "cannot close the last usable path")
		require.Equal(t, mpPathActive, c.mp.paths[0].state)

		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConnWithLocalAddr(tc.mockCtrl, tc.remoteAddr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 2345})
		require.NotEqual(t, pathConn.LocalAddr(), c.LocalAddr())
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)
		queuedFrames(c)
		require.NoError(t, closePath(0))
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 0, ErrorCode: qerr.ApplicationAbandonPath}},
			pathAbandonFramesFor(queuedFrames(c), 0),
		)
		require.Equal(t, mpPathAbandoned, c.mp.paths[0].state)
		require.Equal(t, protocol.PathID(1), c.mp.primaryPathID)
		require.Equal(t, pathConn.LocalAddr(), c.LocalAddr())
		require.ErrorIs(t, closePath(0), ErrPathClosed)
		require.ErrorIs(t, closePath(5), ErrPathClosed)
		require.EqualError(t, tc.closeTestPath(t, p), "cannot close the last usable path")
	})
}
