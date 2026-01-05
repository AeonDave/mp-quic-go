package quic

import (
	"net"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestMultipathPathManager(t *testing.T) {
	t.Run("Creation", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		require.NotNil(t, pm)
		require.False(t, pm.IsMultipathEnabled())
		require.Equal(t, 0, pm.GetPathCount())
	})

	t.Run("EnableMultipath", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		require.False(t, pm.IsMultipathEnabled())
		
		pm.EnableMultipath()
		require.True(t, pm.IsMultipathEnabled())
	})

	t.Run("SetPrimaryPath", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		
		localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321}
		
		pm.SetPrimaryPath(localAddr, remoteAddr)
		
		require.Equal(t, 1, pm.GetPathCount())
		require.Equal(t, protocol.PathID(0), pm.GetPrimaryPathID())
		
		path := pm.GetPath(0)
		require.NotNil(t, path)
		require.Equal(t, protocol.PathID(0), path.PathID)
		require.Equal(t, MultipathPathStateActive, path.State)
		require.True(t, path.Validated)
		require.Equal(t, localAddr, path.LocalAddr)
		require.Equal(t, remoteAddr, path.RemoteAddr)
	})

	t.Run("AddPath_WhenDisabled", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		
		localAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001}
		
		pathID := pm.AddPath(localAddr, remoteAddr)
		require.Equal(t, protocol.InvalidPathID, pathID)
		require.Equal(t, 0, pm.GetPathCount())
	})

	t.Run("AddPath_WhenEnabled", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		localAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
		remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001}
		
		pathID := pm.AddPath(localAddr, remoteAddr)
		require.NotEqual(t, protocol.InvalidPathID, pathID)
		require.Equal(t, protocol.PathID(1), pathID)
		require.Equal(t, 1, pm.GetPathCount())
		
		path := pm.GetPath(pathID)
		require.NotNil(t, path)
		require.Equal(t, pathID, path.PathID)
		require.Equal(t, MultipathPathStateValidating, path.State)
		require.False(t, path.Validated)
	})

	t.Run("AddMultiplePaths", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		// Add primary path
		pm.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)
		
		// Add additional paths
		pathID1 := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		pathID2 := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 6000},
			&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 6001},
		)
		
		require.Equal(t, 3, pm.GetPathCount())
		require.Equal(t, protocol.PathID(1), pathID1)
		require.Equal(t, protocol.PathID(2), pathID2)
	})

	t.Run("ValidatePath", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pathID := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		
		path := pm.GetPath(pathID)
		require.False(t, path.Validated)
		require.Equal(t, MultipathPathStateValidating, path.State)
		
		pm.ValidatePath(pathID)
		
		path = pm.GetPath(pathID)
		require.True(t, path.Validated)
		require.Equal(t, MultipathPathStateActive, path.State)
	})

	t.Run("ActivatePath", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pathID := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		
		// Cannot activate unvalidated path
		activated := pm.ActivatePath(pathID)
		require.False(t, activated)
		
		// Validate first
		pm.ValidatePath(pathID)
		
		// Now can activate (should already be active after validation)
		activated = pm.ActivatePath(pathID)
		require.True(t, activated)
		
		activePaths := pm.GetActivePaths()
		require.Len(t, activePaths, 1)
	})

	t.Run("GetActivePaths", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pm.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)
		
		pathID1 := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		pathID2 := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 6000},
			&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 6001},
		)
		
		// Validate and activate additional paths
		pm.ValidatePath(pathID1)
		pm.ValidatePath(pathID2)
		
		activePaths := pm.GetActivePaths()
		require.Len(t, activePaths, 3) // Primary + 2 additional
		
		require.Equal(t, 3, pm.GetActivePathCount())
	})

	t.Run("ClosePath", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pathID := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		pm.ValidatePath(pathID)
		
		require.Equal(t, 1, pm.GetActivePathCount())
		
		pm.ClosePath(pathID)
		
		path := pm.GetPath(pathID)
		require.Equal(t, MultipathPathStateClosed, path.State)
		require.Equal(t, 0, pm.GetActivePathCount())
	})

	t.Run("UpdatePathRTT", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pathID := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		
		rtt := 50 * time.Millisecond
		pm.UpdatePathRTT(pathID, rtt)
		
		path := pm.GetPath(pathID)
		require.Equal(t, rtt, path.RTT)
	})

	t.Run("RecordPathUsage", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pathID := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		
		path := pm.GetPath(pathID)
		initialTime := path.LastUsed
		
		time.Sleep(10 * time.Millisecond)
		
		pm.RecordPathUsage(pathID, 1200)
		
		path = pm.GetPath(pathID)
		require.Equal(t, uint64(1200), path.BytesSent)
		require.True(t, path.LastUsed.After(initialTime))
	})

	t.Run("HandleClosePathFrame", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pathID := pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		pm.ValidatePath(pathID)
		
		require.Equal(t, 1, pm.GetActivePathCount())
		
		frame := &wire.ClosePathFrame{
			PathID:       uint64(pathID),
			ErrorCode:    0,
			ReasonPhrase: "Test closure",
		}
		
		pm.HandleClosePathFrame(frame)
		
		path := pm.GetPath(pathID)
		require.Equal(t, MultipathPathStateClosed, path.State)
		require.Equal(t, 0, pm.GetActivePathCount())
	})

	t.Run("GetAllPaths", func(t *testing.T) {
		pm := NewMultipathPathManager(protocol.PerspectiveClient)
		pm.EnableMultipath()
		
		pm.SetPrimaryPath(
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
		)
		
		pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 5001},
		)
		
		pm.AddPath(
			&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 6000},
			&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 6001},
		)
		
		allPaths := pm.GetAllPaths()
		require.Len(t, allPaths, 3)
	})
}
