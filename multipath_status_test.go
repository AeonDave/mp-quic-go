package quic

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// setTestPathStatus calls SetStatus on the path, and processes the request on the connection's run loop.
func (tc *mpPathTestConn) setTestPathStatus(t *testing.T, p *Path, status PathStatus) {
	t.Helper()
	require.NoError(t, p.SetStatus(status))
	require.NoError(t, tc.conn.handleMultipathEvents(monotime.Now()))
}

func queuedPathStatusFrames(c *Conn) ([]*wire.PathStatusFrame, []ackhandler.Frame) {
	frames := queuedFrames(c)
	var statusFrames []*wire.PathStatusFrame
	var all []ackhandler.Frame
	for _, f := range frames {
		if sf, ok := f.Frame.(*wire.PathStatusFrame); ok {
			statusFrames = append(statusFrames, sf)
			all = append(all, f)
		}
	}
	return statusFrames, all
}

// Path.SetStatus signals the status of a path using PATH_STATUS_AVAILABLE and PATH_STATUS_BACKUP frames.
// Every path has its own sequence number space (section 4.3 of draft-ietf-quic-multipath-21).
// A lost frame is only retransmitted if it contains the latest status of the path.
func TestMultipathPathStatusSending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p1 := tc.newTestPath(pathConn)
		tc.openTestPath(t, p1)
		p2 := tc.newTestPath(pathConn)
		tc.openTestPath(t, p2)
		queuedFrames(c)

		tc.setTestPathStatus(t, p1, PathStatusBackup)
		statusFrames, frames1 := queuedPathStatusFrames(c)
		require.Equal(t, []*wire.PathStatusFrame{{PathID: 1, SequenceNumber: 0, Backup: true}}, statusFrames)
		// setting the same status again doesn't send a frame
		tc.setTestPathStatus(t, p1, PathStatusBackup)
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Empty(t, statusFrames)
		tc.setTestPathStatus(t, p1, PathStatusAvailable)
		statusFrames, frames2 := queuedPathStatusFrames(c)
		require.Equal(t, []*wire.PathStatusFrame{{PathID: 1, SequenceNumber: 1}}, statusFrames)
		// path 2 uses its own sequence numbers
		tc.setTestPathStatus(t, p2, PathStatusBackup)
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Equal(t, []*wire.PathStatusFrame{{PathID: 2, SequenceNumber: 0, Backup: true}}, statusFrames)

		// The first frame is outdated. It is not retransmitted.
		frames1[0].Handler.OnLost(frames1[0].Frame)
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Empty(t, statusFrames)
		// The second frame contains the latest status.
		frames2[0].Handler.OnLost(frames2[0].Frame)
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Equal(t, []*wire.PathStatusFrame{{PathID: 1, SequenceNumber: 1}}, statusFrames)

		// a frame for an abandoned path is not retransmitted
		require.NoError(t, tc.closeTestPath(t, p1))
		frames2[0].Handler.OnLost(frames2[0].Frame)
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Empty(t, statusFrames)
		require.ErrorIs(t, p1.SetStatus(PathStatusBackup), ErrPathClosed)

		require.EqualError(t, p2.SetStatus(PathStatusUnknown), "invalid path status: unknown")
		require.EqualError(t, p2.SetStatus(PathStatus(42)), "invalid path status: PathStatus(42)")
		require.EqualError(t, (&Path{}).SetStatus(PathStatusBackup), "path status requires IETF Multipath QUIC")
	})
}

// A status set before the path is validated is sent together with the PATH_CHALLENGE that validates the path
// (section 4.3 of draft-ietf-quic-multipath-21).
func TestMultipathPathStatusBeforeValidation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		queuedFrames(c)
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		require.NoError(t, p.SetStatus(PathStatusBackup))
		errChan := probeMultipathPath(t.Context(), p)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, protocol.PathID(1), tc.probes[0].pathID)
		require.Len(t, tc.probes[0].frames, 2)
		require.IsType(t, &wire.PathChallengeFrame{}, tc.probes[0].frames[0].Frame)
		require.Equal(t, &wire.PathStatusFrame{PathID: 1, SequenceNumber: 0, Backup: true}, tc.probes[0].frames[1].Frame)
		statusFrames, _ := queuedPathStatusFrames(c)
		require.Empty(t, statusFrames)

		// a lost frame is retransmitted with the next PATH_CHALLENGE
		tc.probes[0].frames[1].Handler.OnLost(tc.probes[0].frames[1].Frame)
		tc.advanceToNextMultipathTimeout(t)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 2)
		require.Len(t, tc.probes[1].frames, 2)
		require.Equal(t, &wire.PathStatusFrame{PathID: 1, SequenceNumber: 0, Backup: true}, tc.probes[1].frames[1].Frame)
		requireProbeBlocked(t, errChan)
	})
}

// A status received for a path ID that is not in use yet is applied when the path is opened.
// The same sequence number can be used on different paths.
func TestMultipathPeerPathStatusForUnusedPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 0, SequenceNumber: 3}, protocol.Encryption1RTT))
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 1, SequenceNumber: 3, Backup: true}, protocol.Encryption1RTT))
		require.Contains(t, c.mp.pendingPeerStatus, protocol.PathID(1))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		tc.acceptServerPath(t, 1, clientAddr)
		path := c.mp.paths[1]
		require.True(t, path.hasPeerStatus)
		require.Equal(t, peerPathStatus{seq: 3, backup: true}, path.peerStatus)
		require.True(t, path.isBackup())
		require.Empty(t, c.mp.pendingPeerStatus)
		require.Equal(t, peerPathStatus{seq: 3}, c.mp.paths[0].peerStatus)
	})
}

// sendTestDataPackets sends up to n data packets, and returns the paths they were sent on.
func (tc *mpPathTestConn) sendTestDataPackets(t *testing.T, n int) (paths []protocol.PathID, pns map[protocol.PathID][]protocol.PacketNumber) {
	t.Helper()
	pns = make(map[protocol.PathID][]protocol.PacketNumber)
	tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
		if len(paths) == n {
			return shortHeaderPacket{}, errNothingToPack
		}
		paths = append(paths, pathID)
		p := tc.appendDataPacket(buf, 100, pathID)
		pns[pathID] = append(pns[pathID], p.PacketNumber)
		return p, nil
	}
	require.NoError(t, tc.conn.triggerSending(monotime.Now()))
	tc.appendPacket = nil
	return paths, pns
}

func requireOnlyPath(t *testing.T, paths []protocol.PathID, id protocol.PathID) {
	t.Helper()
	require.NotEmpty(t, paths)
	for _, p := range paths {
		require.Equal(t, id, p, "packets sent on paths %v", paths)
	}
}

// Data is only sent on a backup path if no available path can be used (section 3.3 of draft-ietf-quic-multipath-21).
// A path is a backup path if the peer or the application marked it as a backup path.
func TestMultipathBackupPathScheduling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)

		// both paths are used
		paths, _ := tc.sendTestDataPackets(t, 4)
		require.Contains(t, paths, protocol.PathID(0))
		require.Contains(t, paths, protocol.PathID(1))

		// the peer marks path 1 as a backup path
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 1, SequenceNumber: 0, Backup: true}, protocol.Encryption1RTT))
		paths, _ = tc.sendTestDataPackets(t, 4)
		requireOnlyPath(t, paths, 0)

		// the peer marks path 1 as available, but the application marks it as a backup path
		require.NoError(t, handleTestFrame(t, c, &wire.PathStatusFrame{PathID: 1, SequenceNumber: 1}, protocol.Encryption1RTT))
		paths, _ = tc.sendTestDataPackets(t, 4)
		require.Contains(t, paths, protocol.PathID(1))
		tc.setTestPathStatus(t, p, PathStatusBackup)
		paths, _ = tc.sendTestDataPackets(t, 4)
		requireOnlyPath(t, paths, 0)

		// If path 0 can't be used any more, data is sent on the backup path.
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 0}, protocol.Encryption1RTT))
		paths, _ = tc.sendTestDataPackets(t, 4)
		requireOnlyPath(t, paths, 1)
	})
}

// If all available paths potentially failed, data is sent on a backup path. The connection then signals the
// failed paths as backup paths, and signals them as available again once they recover (section 3.3 of
// draft-ietf-quic-multipath-21). The status of a path is changed at most once per PTO.
func TestMultipathPotentiallyFailedPathStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)
		tc.setTestPathStatus(t, p, PathStatusBackup)
		queuedFrames(c)

		paths, _ := tc.sendTestDataPackets(t, 3)
		requireOnlyPath(t, paths, 0)
		// The packets sent on path 0 are not acknowledged.
		// The path is considered potentially failed once the failure timeout expires.
		require.Equal(t, monotime.Now().Add(minPathFailureTimeout+1), c.mp.nextTimeout())
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.failures.potentiallyFailed(0))
		statusFrames, _ := queuedPathStatusFrames(c)
		require.Equal(t, []*wire.PathStatusFrame{{PathID: 0, SequenceNumber: 0, Backup: true}}, statusFrames)
		require.True(t, c.mp.paths[0].autoBackup)
		// data is sent on the backup path now
		paths, _ = tc.sendTestDataPackets(t, 3)
		requireOnlyPath(t, paths, 1)
		// The packets sent on path 0 were declared lost, and a PING frame was sent on path 0.
		require.Len(t, tc.pathPackets, 1)
		ping := tc.pathPackets[0]
		require.Equal(t, protocol.PathID(0), ping.pathID)
		require.Equal(t, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, ping.frames)

		// path 0 recovers: the PING frame is acknowledged
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 0, HasPathID: true, AckRanges: ackRangesFor([]protocol.PacketNumber{ping.pn})}, protocol.Encryption1RTT))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.False(t, c.mp.failures.potentiallyFailed(0))
		// Data is sent on path 0 again.
		paths, pns := tc.sendTestDataPackets(t, 3)
		requireOnlyPath(t, paths, 0)
		// The status was changed less than a PTO ago, so the change is not signaled yet.
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Empty(t, statusFrames)
		require.True(t, c.mp.paths[0].autoBackup)
		pto := c.rttStats.PTO(true)
		require.Equal(t, c.mp.paths[0].autoBackupChanged.Add(pto), c.mp.nextTimeout())
		time.Sleep(monotime.Until(c.mp.paths[0].autoBackupChanged.Add(pto)))
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 0, HasPathID: true, AckRanges: ackRangesFor(pns[0])}, protocol.Encryption1RTT))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		statusFrames, _ = queuedPathStatusFrames(c)
		require.Equal(t, []*wire.PathStatusFrame{{PathID: 0, SequenceNumber: 1}}, statusFrames)
		require.False(t, c.mp.paths[0].autoBackup)
	})
}

// If a path potentially failed while no other path works, it is still used, and its packets stay outstanding.
// Once another path is validated, the packets are declared lost, and their frames are retransmitted on the new path.
// Then only PING frames are sent on the failed path.
func TestMultipathPotentiallyFailedPathThenNewPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		queuedFrames(c)

		handler := &countingFrameHandler{}
		for i := range 3 {
			tc.sendTestPacket(0, []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: protocol.ByteCount(1000 + i)}, Handler: handler}}, nil)
		}
		tc.advanceToNextMultipathTimeout(t)
		require.True(t, c.mp.failures.potentiallyFailed(0))
		paths, _ := tc.sendTestDataPackets(t, 2)
		requireOnlyPath(t, paths, 0)
		require.Zero(t, handler.lost)
		require.Empty(t, tc.pathPackets)

		// path 1 is validated
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		tc.openTestPath(t, tc.newTestPath(pathConn))
		require.True(t, c.mp.failures.potentiallyFailed(0))
		paths, _ = tc.sendTestDataPackets(t, 3)
		require.Equal(t, 3, handler.lost)
		requireOnlyPath(t, paths, 1)
		// a PING frame is sent on path 0, to detect when it recovers
		require.Len(t, tc.pathPackets, 1)
		ping := tc.pathPackets[0]
		require.Equal(t, protocol.PathID(0), ping.pathID)
		require.Equal(t, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, ping.frames)
		var outstanding []protocol.PacketNumber
		for ev := range c.sentPacketHandler.OutstandingPackets(0) {
			outstanding = append(outstanding, ev.PacketNumber)
		}
		require.Equal(t, []protocol.PacketNumber{ping.pn}, outstanding)
	})
}

// If no backup path is available, potentially failed paths are still used, and not signaled as backup paths.
func TestMultipathPotentiallyFailedPathWithoutBackup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		tc.openTestPath(t, tc.newTestPath(pathConn))
		queuedFrames(c)

		paths, pns := tc.sendTestDataPackets(t, 4)
		require.Contains(t, paths, protocol.PathID(0))
		require.Contains(t, paths, protocol.PathID(1))
		// only the packets on path 1 are acknowledged
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: ackRangesFor(pns[1])}, protocol.Encryption1RTT))
		time.Sleep(time.Second)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.True(t, c.mp.failures.potentiallyFailed(0))
		require.False(t, c.mp.failures.potentiallyFailed(1))
		// path 1 is available, so path 0 is not used, but it's not signaled as a backup path
		paths, _ = tc.sendTestDataPackets(t, 3)
		requireOnlyPath(t, paths, 1)
		statusFrames, _ := queuedPathStatusFrames(c)
		require.Empty(t, statusFrames)
	})
}
