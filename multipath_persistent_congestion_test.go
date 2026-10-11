package quic

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// With IETF Multipath QUIC, persistent congestion (section 7.6 of RFC 9002) is established per path:
// when all packets sent on a path are lost for a long time, the congestion window of that path drops to the
// minimum window. The other paths are not affected.
func TestMultipathPersistentCongestionPerPath(t *testing.T) {
	for _, name := range []string{"NewReno", "OLIA"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testMultipathPersistentCongestionPerPath(t, name == "OLIA")
			})
		})
	}
}

func testMultipathPersistentCongestionPerPath(t *testing.T, olia bool) {
	const rtt = 10 * time.Millisecond
	tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
	c := tc.conn
	oliaState := NewOLIASharedState()
	if olia {
		// the controllers of the paths opened from now on are coupled
		c.sentPacketHandler.SetCongestionControlFactory(NewOLIACongestionControlFactory(oliaState))
	}
	require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
	pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
	pathID := tc.openTestPath(t, tc.newTestPath(pathConn))
	require.Equal(t, protocol.PathID(1), pathID)
	if olia {
		require.Equal(t, 1, oliaState.numPaths())
	}
	sph := c.sentPacketHandler
	sendPing := func(p protocol.PathID) protocol.PacketNumber {
		return tc.sendTestPacket(p, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil).PacketNumber
	}
	ackPath := func(p protocol.PathID, pns ...protocol.PacketNumber) {
		t.Helper()
		c.lastPacketReceivedTime = monotime.Now()
		require.NoError(t, handleTestFrame(t, c, &wire.AckFrame{PathID: p, HasPathID: true, AckRanges: ackRangesFor(pns)}, protocol.Encryption1RTT))
	}

	// both paths take an RTT sample
	pn0 := sendPing(0)
	pn1 := sendPing(pathID)
	time.Sleep(rtt)
	ackPath(0, pn0)
	ackPath(pathID, pn1)
	cwnd0, _, ok := sph.PathCongestionState(0)
	require.True(t, ok)
	cwnd1, _, ok := sph.PathCongestionState(pathID)
	require.True(t, ok)

	// All packets sent on the path are lost for a second. Packets sent on path 0 are acknowledged.
	time.Sleep(time.Millisecond)
	for range 10 {
		sendPing(pathID)
		ackPath(0, sendPing(0))
		time.Sleep(100 * time.Millisecond)
	}
	last := sendPing(pathID)
	time.Sleep(rtt)
	ackPath(pathID, last)

	minCwnd := 2 * protocol.ByteCount(c.config.InitialPacketSize)
	cwnd, inFlight, ok := sph.PathCongestionState(pathID)
	require.True(t, ok)
	require.Zero(t, inFlight)
	require.Less(t, cwnd, cwnd1)
	require.Equal(t, minCwnd, cwnd)
	cwnd, _, ok = sph.PathCongestionState(0)
	require.True(t, ok)
	require.Equal(t, cwnd0, cwnd)
}
