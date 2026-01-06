package ackhandler

import (
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// TestMultipathPerPathPacketHandling tests the complete per-path packet handling:
// - Per-path packet numbering
// - Per-path congestion control
// - Per-path RTT tracking
func TestMultipathPerPathPacketHandling(t *testing.T) {
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}

	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		connStats,
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)

	// Simulate multipath scenario with 2 paths
	path1 := protocol.PathID(1)
	path2 := protocol.PathID(2)

	t.Run("IndependentPacketNumbering", func(t *testing.T) {
		// Both paths should start from 0 independently
		pn1_1 := sph.pathPacketNumberManager.PopPacketNumber(path1, protocol.Encryption1RTT)
		pn2_1 := sph.pathPacketNumberManager.PopPacketNumber(path2, protocol.Encryption1RTT)

		require.Equal(t, protocol.PacketNumber(0), pn1_1, "Path 1 should start at 0")
		require.Equal(t, protocol.PacketNumber(0), pn2_1, "Path 2 should start at 0")

		// Generate 10 packets on path 1
		for i := 0; i < 10; i++ {
			sph.pathPacketNumberManager.PopPacketNumber(path1, protocol.Encryption1RTT)
		}

		// Path 2 should still be at packet 1
		pn2_2 := sph.pathPacketNumberManager.PopPacketNumber(path2, protocol.Encryption1RTT)
		require.Less(t, pn2_2, protocol.PacketNumber(5), "Path 2 should not be affected by path 1")
	})

	t.Run("IndependentCongestionControl", func(t *testing.T) {
		now := monotime.Now()

		// Send packets on path 1
		for i := 0; i < 5; i++ {
			pn := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
			sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil,
				[]Frame{{Frame: &wire.PingFrame{}}},
				protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)
		}

		// Send packets on path 2
		for i := 0; i < 5; i++ {
			pn := sph.PopPacketNumber(path2, protocol.Encryption1RTT)
			sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil,
				[]Frame{{Frame: &wire.PingFrame{}}},
				protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path2)
		}

		// Get CC instances
		cc1 := sph.getOrCreatePathCongestionControl(path1)
		cc2 := sph.getOrCreatePathCongestionControl(path2)

		// Should be different instances
		require.NotEqual(t, cc1, cc2, "Each path should have its own CC instance")

		// Both should have received OnPacketSent calls
		require.Greater(t, cc1.GetCongestionWindow(), protocol.ByteCount(0))
		require.Greater(t, cc2.GetCongestionWindow(), protocol.ByteCount(0))
	})

	t.Run("IndependentRTTTracking", func(t *testing.T) {
		now := monotime.Now()

		// Send packet on path 1
		pn1 := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
		sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)

		// ACK it after 50ms
		time.Sleep(50 * time.Millisecond)
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn1, Largest: pn1}}},
			protocol.Encryption1RTT,
			monotime.Now(),
			path1,
		)
		require.NoError(t, err)

		// Path 1 should have RTT measurement
		rtt1 := sph.pathRTTStats[path1]
		require.NotNil(t, rtt1)
		require.Greater(t, rtt1.LatestRTT(), 40*time.Millisecond)
		require.Less(t, rtt1.LatestRTT(), 60*time.Millisecond)

		// Path 2 should not have RTT yet
		rtt2 := sph.pathRTTStats[path2]
		if rtt2 != nil {
			// If it exists, should not have measurement
			require.False(t, rtt2.HasMeasurement())
		}
	})

	t.Run("ACKRoutingToCorrectPath", func(t *testing.T) {
		now := monotime.Now()

		// Send packets using global packet numbers but different paths
		pn1 := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
		sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)

		pn2 := sph.PopPacketNumber(path2, protocol.Encryption1RTT)
		sph.SentPacket(now, pn2, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path2)

		// ACK path 1's packet
		cc1Before := sph.getOrCreatePathCongestionControl(path1).GetCongestionWindow()

		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn1, Largest: pn1}}},
			protocol.Encryption1RTT,
			now.Add(10*time.Millisecond),
			path1,
		)
		require.NoError(t, err)

		// Path 1's CC should have received the ACK
		cc1After := sph.getOrCreatePathCongestionControl(path1).GetCongestionWindow()

		// In slow start, cwnd should increase when acked
		// (This might not always be true depending on CC state, but generally holds)
		require.GreaterOrEqual(t, cc1After, cc1Before, "Path 1 CC should process ACK")
	})
}

// TestOLIAIntegration tests OLIA congestion control with custom factory
func TestOLIAIntegration(t *testing.T) {
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}

	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		connStats,
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)

	// Track CC creations
	ccCreations := make(map[protocol.PathID]int)

	// Set custom factory that counts creations
	sph.SetCongestionControlFactory(func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		ccCreations[pathID]++
		// Create standard Cubic for testing
		return congestion.NewCubicSender(
			congestion.DefaultClock{},
			rttStats,
			connStats,
			initialMaxDatagramSize,
			true,
			nil,
		)
	})

	t.Run("CustomFactoryUsed", func(t *testing.T) {
		path1 := protocol.PathID(1)

		// Trigger CC creation
		cc := sph.getOrCreatePathCongestionControl(path1)
		require.NotNil(t, cc)

		// Factory should have been called
		require.Equal(t, 1, ccCreations[path1], "Factory should be called once for path 1")

		// Second call should reuse
		cc2 := sph.getOrCreatePathCongestionControl(path1)
		require.Equal(t, cc, cc2, "Should reuse existing CC instance")
		require.Equal(t, 1, ccCreations[path1], "Factory should not be called again")
	})

	t.Run("MultiplePathsUseFactory", func(t *testing.T) {
		path2 := protocol.PathID(2)
		path3 := protocol.PathID(3)

		sph.getOrCreatePathCongestionControl(path2)
		sph.getOrCreatePathCongestionControl(path3)

		require.Equal(t, 1, ccCreations[path2])
		require.Equal(t, 1, ccCreations[path3])
	})
}

// TestBackwardCompatibility ensures single-path mode still works
func TestMultipathBackwardCompatibility(t *testing.T) {
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}

	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		connStats,
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)

	t.Run("InvalidPathIDUsesGlobalCC", func(t *testing.T) {
		globalCC := sph.congestion
		pathCC := sph.getOrCreatePathCongestionControl(protocol.InvalidPathID)

		require.Equal(t, globalCC, pathCC, "InvalidPathID should return global CC")
	})

	t.Run("InvalidPathIDUsesGlobalRTT", func(t *testing.T) {
		globalRTT := sph.rttStats
		pathRTT := sph.getOrCreatePathRTTStats(protocol.InvalidPathID)

		require.Equal(t, globalRTT, pathRTT, "InvalidPathID should return global RTT")
	})

	t.Run("SinglePathModeWorks", func(t *testing.T) {
		now := monotime.Now()

		// Send packet without PathID (single-path mode)
		pn := sph.PopPacketNumber(protocol.InvalidPathID, protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, protocol.InvalidPathID)

		// ACK it
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}},
			protocol.Encryption1RTT,
			now.Add(10*time.Millisecond),
			protocol.InvalidPathID,
		)
		require.NoError(t, err)

		// Should work normally
		require.Greater(t, sph.rttStats.LatestRTT(), time.Duration(0))
	})
}

// TestMultipathACKCrossPath tests ACK handling when ACKs arrive on different paths
// than the packets were sent on. This is the core fix for the "ACK-unsent" crash.
func TestMultipathACKCrossPath(t *testing.T) {
	t.Run("ACKOnDifferentPathProcessedCorrectly", func(t *testing.T) {
		// When a packet is sent on path1 but the ACK arrives indicating path2,
		// the handler should find the correct path and process the ACK.
		rttStats := utils.NewRTTStats()
		connStats := &utils.ConnectionStats{}

		sph := NewSentPacketHandler(
			0,
			1200,
			rttStats,
			connStats,
			false,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		).(*sentPacketHandler)

		now := monotime.Now()
		path1 := protocol.PathID(1)
		path2 := protocol.PathID(2)

		// Send packets on path1
		pn1 := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
		sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)

		pn2 := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
		sph.SentPacket(now, pn2, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)

		// Initialize path2 with a lower packet number (simulating it started later)
		pn2_1 := sph.PopPacketNumber(path2, protocol.Encryption1RTT)
		sph.SentPacket(now, pn2_1, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path2)

		// Now receive an ACK on path2 for a packet number that path2 hasn't sent yet
		// but path1 has. The handler should find path1 and process the ACK there.
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn1, Largest: pn2}}},
			protocol.Encryption1RTT,
			now.Add(10*time.Millisecond),
			path2, // ACK arrives on path2
		)
		require.NoError(t, err, "ACK should be processed by finding the correct path")

		// Verify that path1's RTT was updated (proving the ACK was routed correctly)
		path1RTT := sph.pathRTTStats[path1]
		require.NotNil(t, path1RTT)
		require.True(t, path1RTT.HasMeasurement(), "Path1 should have RTT measurement from the ACK")
	})

	t.Run("ACKForLostPacketReroutedViaFallback", func(t *testing.T) {
		// If a packet was declared lost and removed from the path history, but an ACK later
		// arrives on a different path, the handler should still accept it (no protocol error)
		// using the fallback range-based path selection.
		rttStats := utils.NewRTTStats()
		connStats := &utils.ConnectionStats{}

		sph := NewSentPacketHandler(
			0,
			1200,
			rttStats,
			connStats,
			false,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		).(*sentPacketHandler)

		now := monotime.Now()
		path1 := protocol.PathID(1)
		path2 := protocol.PathID(2)

		pn1 := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
		sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)

		// Mark the packet as lost and remove it from the history to simulate GC'ed entry.
		pnSpace := sph.getAppDataPacketNumberSpace(path1)
		pnSpace.history.DeclareLost(pn1)

		// Receive an ACK on a different path; should be accepted without error via fallback.
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn1, Largest: pn1}}},
			protocol.Encryption1RTT,
			now.Add(5*time.Millisecond),
			path2,
		)
		require.NoError(t, err, "ACK for previously lost packet should be accepted via fallback path match")
	})

	t.Run("ACKForUnsentPacketIgnoredInMultipath", func(t *testing.T) {
		// In multipath mode, if an ACK references a packet number that no path has sent,
		// it should be silently ignored instead of causing a PROTOCOL_VIOLATION.
		rttStats := utils.NewRTTStats()
		connStats := &utils.ConnectionStats{}

		sph := NewSentPacketHandler(
			0,
			1200,
			rttStats,
			connStats,
			false,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		).(*sentPacketHandler)

		now := monotime.Now()
		path1 := protocol.PathID(1)
		path2 := protocol.PathID(2)

		// Send one packet on each path to establish multipath mode
		pn1 := sph.PopPacketNumber(path1, protocol.Encryption1RTT)
		sph.SentPacket(now, pn1, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path1)

		pn2 := sph.PopPacketNumber(path2, protocol.Encryption1RTT)
		sph.SentPacket(now, pn2, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, path2)

		// Verify we have multiple paths
		require.Greater(t, len(sph.appDataPackets), 1, "Should have multiple paths")

		// Now receive an ACK for a packet number higher than any path has sent
		unsentPN := protocol.PacketNumber(999)
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: unsentPN, Largest: unsentPN}}},
			protocol.Encryption1RTT,
			now.Add(10*time.Millisecond),
			path1,
		)

		// In multipath mode, this should NOT return an error - it should be ignored
		require.NoError(t, err, "ACK for unsent packet should be silently ignored in multipath mode")
	})

	t.Run("ACKForUnsentPacketErrorsInSinglePath", func(t *testing.T) {
		// In single-path mode, an ACK for an unsent packet is a PROTOCOL_VIOLATION
		// as required by RFC 9000.
		rttStats := utils.NewRTTStats()
		connStats := &utils.ConnectionStats{}

		sph := NewSentPacketHandler(
			0,
			1200,
			rttStats,
			connStats,
			false,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		).(*sentPacketHandler)

		now := monotime.Now()

		// Send packet only on InvalidPathID (single-path mode)
		pn := sph.PopPacketNumber(protocol.InvalidPathID, protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false, protocol.InvalidPathID)

		// Verify we have only one path
		require.Equal(t, 1, len(sph.appDataPackets), "Should have only one path")

		// Receive an ACK for an unsent packet
		unsentPN := pn + 100
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: unsentPN, Largest: unsentPN}}},
			protocol.Encryption1RTT,
			now.Add(10*time.Millisecond),
			protocol.InvalidPathID,
		)

		// In single-path mode, this MUST return a PROTOCOL_VIOLATION
		require.Error(t, err, "ACK for unsent packet should error in single-path mode")
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "received ACK for an unsent packet")
	})

	t.Run("ACKForUnsentPacketErrorsForHandshake", func(t *testing.T) {
		// For non-application-data encryption levels (Initial, Handshake),
		// ACK for unsent packet should always be a PROTOCOL_VIOLATION.
		rttStats := utils.NewRTTStats()
		connStats := &utils.ConnectionStats{}

		sph := NewSentPacketHandler(
			0,
			1200,
			rttStats,
			connStats,
			false,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		).(*sentPacketHandler)

		now := monotime.Now()

		// Send Initial packet
		pn := sph.PopPacketNumber(protocol.InvalidPathID, protocol.EncryptionInitial)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil,
			[]Frame{{Frame: &wire.PingFrame{}}},
			protocol.EncryptionInitial, protocol.ECNNon, 1200, false, false, protocol.InvalidPathID)

		// Receive an ACK for an unsent Initial packet
		unsentPN := pn + 100
		_, err := sph.ReceivedAck(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: unsentPN, Largest: unsentPN}}},
			protocol.EncryptionInitial,
			now.Add(10*time.Millisecond),
			protocol.InvalidPathID,
		)

		// For Initial/Handshake, this MUST always return a PROTOCOL_VIOLATION
		require.Error(t, err, "ACK for unsent Initial packet should always error")
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	})
}
