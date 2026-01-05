package quic

import (
	"net"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// TestMultipathEndToEndIntegration validates the complete multipath QUIC implementation
// combining per-path fundamentals, protocol frames, and path management
func TestMultipathEndToEndIntegration(t *testing.T) {
	t.Run("CompleteMultipathFlow", func(t *testing.T) {
		// Step 1: Initialize Path Manager
		pathManager := NewMultipathPathManager(protocol.PerspectiveClient)
		pathManager.EnableMultipath()

		// Set primary path
		primaryLocal := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		primaryRemote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321}
		pathManager.SetPrimaryPath(primaryLocal, primaryRemote)

		// Step 2: Initialize Packet Scheduler
		scheduler := NewMultipathScheduler(pathManager, SchedulingPolicyMinRTT)
		scheduler.EnableMultipath()

		// Step 3: Initialize Sent Packet Handler with per-path congestion control
		// (Not directly used in this test, but would be integrated in real connection)
		_ = ackhandler.NewSentPacketHandler(
			0,
			1200,
			utils.NewRTTStats(),
			&utils.ConnectionStats{},
			false,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		)

		// Step 4: Add a second path
		path2Local := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
		path2Remote := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001}
		path2ID := pathManager.AddPath(path2Local, path2Remote)
		require.NotEqual(t, protocol.InvalidPathID, path2ID)

		// Simulate path validation
		pathManager.ValidatePath(path2ID)

		// Step 5: Test multipath frame parsing
		frameParser := wire.NewFrameParser(false, false, false)
		frameParser.EnableMultipath()

		// Create and serialize ADD_ADDRESS frame
		addAddrFrame := &wire.AddAddressFrame{
			AddressID:      1,
			SequenceNumber: 0,
			IPVersion:      4,
			Address:        net.ParseIP("10.0.0.1").To4(),
			Port:           9000,
		}

		frameData, err := addAddrFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse the frame back
		frameType, n, err := frameParser.ParseType(frameData, protocol.Encryption1RTT)
		require.NoError(t, err)
		require.Equal(t, wire.FrameTypeAddAddress, frameType)

		parsedFrame, _, err := frameParser.ParseLessCommonFrame(frameType, frameData[n:], protocol.Version1)
		require.NoError(t, err)
		require.IsType(t, &wire.AddAddressFrame{}, parsedFrame)

		// Step 6: Test packet scheduling across multiple paths
		pathInfo1, ok := scheduler.SelectPath(PathSelectionContext{})
		require.True(t, ok)
		require.NotEqual(t, protocol.InvalidPathID, pathInfo1.ID)

		// Update path RTTs to influence scheduling
		pathManager.UpdatePathRTT(0, 100*time.Millisecond)
		pathManager.UpdatePathRTT(path2ID, 50*time.Millisecond)

		// MinRTT scheduler should prefer path2 now
		pathInfo2, ok := scheduler.SelectPath(PathSelectionContext{})
		require.True(t, ok)
		require.Equal(t, PathID(path2ID), pathInfo2.ID, "MinRTT scheduler should select path with lower RTT")

		// Step 7: Verify path usage tracking
		pathManager.RecordPathUsage(protocol.PathID(pathInfo2.ID), 1200)
		path := pathManager.GetPath(protocol.PathID(pathInfo2.ID))
		require.Equal(t, uint64(1200), path.BytesSent)

		// Step 8: Test PATHS frame
		pathsFrame := &wire.PathsFrame{
			AvailablePaths: uint64(pathManager.GetPathCount()),
			ActivePaths:    uint64(pathManager.GetActivePathCount()),
		}

		pathsData, err := pathsFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		frameType, n, err = frameParser.ParseType(pathsData, protocol.Encryption1RTT)
		require.NoError(t, err)
		require.Equal(t, wire.FrameTypePaths, frameType)

		parsedPathsFrame, _, err := frameParser.ParseLessCommonFrame(frameType, pathsData[n:], protocol.Version1)
		require.NoError(t, err)
		pathsFrameParsed := parsedPathsFrame.(*wire.PathsFrame)
		require.Equal(t, uint64(2), pathsFrameParsed.AvailablePaths)
		require.Equal(t, uint64(2), pathsFrameParsed.ActivePaths)

		// Step 9: Test path closure (Phase 2 + Phase 3)
		closeFrame := &wire.ClosePathFrame{
			PathID:       uint64(path2ID),
			ErrorCode:    0,
			ReasonPhrase: "Test completed",
		}

		closeData, err := closeFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		frameType, n, err = frameParser.ParseType(closeData, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsedCloseFrame, _, err := frameParser.ParseLessCommonFrame(frameType, closeData[n:], protocol.Version1)
		require.NoError(t, err)
		require.IsType(t, &wire.ClosePathFrame{}, parsedCloseFrame)

		// Handle the close frame
		pathManager.HandleClosePathFrame(closeFrame)

		closedPath := pathManager.GetPath(path2ID)
		require.Equal(t, MultipathPathStateClosed, closedPath.State)
		require.Equal(t, 1, pathManager.GetActivePathCount())
	})

	t.Run("RoundRobinScheduling", func(t *testing.T) {
		pathManager := NewMultipathPathManager(protocol.PerspectiveClient)
		pathManager.EnableMultipath()

		// Setup primary path
		pathManager.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)

		// Add two more paths
		path1 := pathManager.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		path2 := pathManager.AddPath(
			&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 6000},
			&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 6001},
		)

		pathManager.ValidatePath(path1)
		pathManager.ValidatePath(path2)

		// Set initial RTT values to ensure paths are considered valid
		pathManager.UpdatePathRTT(0, 50*time.Millisecond)
		pathManager.UpdatePathRTT(path1, 50*time.Millisecond)
		pathManager.UpdatePathRTT(path2, 50*time.Millisecond)

		// Use round-robin scheduler
		scheduler := NewMultipathScheduler(pathManager, SchedulingPolicyRoundRobin)
		scheduler.EnableMultipath()

		// Collect path selections
		selections := make(map[protocol.PathID]int)
		for i := 0; i < 15; i++ {
			pathInfo, ok := scheduler.SelectPath(PathSelectionContext{})
			if ok && pathInfo.ID != protocol.InvalidPathID {
				selections[protocol.PathID(pathInfo.ID)]++
			}
		}

		// At least 2 paths should be used (round-robin may skip inactive paths)
		require.GreaterOrEqual(t, len(selections), 2, "At least 2 paths should be used")
		for pathID, count := range selections {
			require.GreaterOrEqual(t, count, 1, "Path %d should be selected at least once", pathID)
		}
	})

	t.Run("PathFailoverScenario", func(t *testing.T) {
		pathManager := NewMultipathPathManager(protocol.PerspectiveClient)
		pathManager.EnableMultipath()

		// Primary path
		pathManager.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)

		// Backup path
		backupPath := pathManager.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		pathManager.ValidatePath(backupPath)

		scheduler := NewMultipathScheduler(pathManager, SchedulingPolicyMinRTT)
		scheduler.EnableMultipath()

		// Initially, primary has good RTT
		pathManager.UpdatePathRTT(0, 50*time.Millisecond)
		pathManager.UpdatePathRTT(backupPath, 100*time.Millisecond)

		pathInfo, ok := scheduler.SelectPath(PathSelectionContext{})
		require.True(t, ok)
		require.Equal(t, protocol.PathID(0), protocol.PathID(pathInfo.ID), "Should select primary path with better RTT")

		// Simulate primary path degradation
		pathManager.UpdatePathRTT(0, 500*time.Millisecond)

		pathInfo, ok = scheduler.SelectPath(PathSelectionContext{})
		require.True(t, ok)
		require.Equal(t, backupPath, protocol.PathID(pathInfo.ID), "Should failover to backup path with better RTT")

		// Close degraded primary path
		pathManager.ClosePath(0)
		require.Equal(t, 1, pathManager.GetActivePathCount())

		// Only backup path should be available now
		pathInfo, ok = scheduler.SelectPath(PathSelectionContext{})
		require.True(t, ok)
		require.Equal(t, backupPath, protocol.PathID(pathInfo.ID))
	})

	t.Run("MultipleFrameExchange", func(t *testing.T) {
		pathManager := NewMultipathPathManager(protocol.PerspectiveClient)
		pathManager.EnableMultipath()

		pathManager.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)

		frameParser := wire.NewFrameParser(false, false, false)
		frameParser.EnableMultipath()

		// Simulate multipath negotiation sequence
		var allFrameData []byte

		// 1. Announce new address
		addAddrFrame := &wire.AddAddressFrame{
			AddressID:      1,
			SequenceNumber: 0,
			IPVersion:      4,
			Address:        net.ParseIP("192.168.1.1").To4(),
			Port:           5000,
		}
		frameData, err := addAddrFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		allFrameData = append(allFrameData, frameData...)

		// 2. Send PATHS update
		pathsFrame := &wire.PathsFrame{
			AvailablePaths: 2,
			ActivePaths:    1,
		}
		frameData, err = pathsFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		allFrameData = append(allFrameData, frameData...)

		// Parse all frames
		data := allFrameData
		parsedCount := 0
		for len(data) > 0 {
			frameType, n, err := frameParser.ParseType(data, protocol.Encryption1RTT)
			require.NoError(t, err)

			_, consumed, err := frameParser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
			require.NoError(t, err)

			data = data[n+consumed:]
			parsedCount++
		}

		require.Equal(t, 2, parsedCount, "Should parse both frames")
	})
}

// TestMultipathComponentsIntegration verifies all multipath components work together
func TestMultipathComponentsIntegration(t *testing.T) {
	t.Run("AllComponentsIntegrated", func(t *testing.T) {
		// Path Manager
		pathManager := NewMultipathPathManager(protocol.PerspectiveClient)
		pathManager.EnableMultipath()
		pathManager.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)

		path2 := pathManager.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		pathManager.ValidatePath(path2)

		// Scheduler
		scheduler := NewMultipathScheduler(pathManager, SchedulingPolicyMinRTT)
		scheduler.EnableMultipath()

		// Frame Parser
		frameParser := wire.NewFrameParser(false, false, false)
		frameParser.EnableMultipath()
		require.True(t, frameParser.IsKnownFrameType(wire.FrameTypeAddAddress))
		require.True(t, frameParser.IsKnownFrameType(wire.FrameTypePaths))
		require.True(t, frameParser.IsKnownFrameType(wire.FrameTypeClosePath))

		// Per-path packet handler (implicitly tested via sent_packet_handler)
		// This would be used in real connection to route ACKs and manage per-path congestion control

		// Verify all components are initialized and working
		require.True(t, pathManager.IsMultipathEnabled())
		require.True(t, scheduler.IsMultipathEnabled())
		require.Equal(t, 2, pathManager.GetPathCount())
		require.Equal(t, 2, pathManager.GetActivePathCount())

		// Test scheduling decision
		pathManager.UpdatePathRTT(0, 100*time.Millisecond)
		pathManager.UpdatePathRTT(path2, 30*time.Millisecond)

		pathInfo, ok := scheduler.SelectPath(PathSelectionContext{})
		require.True(t, ok)
		require.Equal(t, path2, protocol.PathID(pathInfo.ID), "Should select path with lower RTT")

		// Test frame generation and parsing
		pathsFrame := &wire.PathsFrame{
			AvailablePaths: uint64(pathManager.GetPathCount()),
			ActivePaths:    uint64(pathManager.GetActivePathCount()),
		}

		frameData, err := pathsFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		frameType, n, err := frameParser.ParseType(frameData, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsed, _, err := frameParser.ParseLessCommonFrame(frameType, frameData[n:], protocol.Version1)
		require.NoError(t, err)

		parsedPaths := parsed.(*wire.PathsFrame)
		require.Equal(t, uint64(2), parsedPaths.AvailablePaths)
		require.Equal(t, uint64(2), parsedPaths.ActivePaths)
	})
}
