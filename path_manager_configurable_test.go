package quic

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestPathManagerConfigurableMaxPaths(t *testing.T) {
	t.Run("default 3 paths", func(t *testing.T) {
		var connIDs []protocol.ConnectionID
		for range 10 {
			b := make([]byte, 8)
			rand.Read(b)
			connIDs = append(connIDs, protocol.ParseConnectionID(b))
		}

		pm := newPathManager(
			func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
			func(id pathID) {},
			3,
			utils.DefaultLogger,
		)

		now := monotime.Now()
		// Create 3 paths (should succeed)
		for i := 0; i < 3; i++ {
			connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true)
			require.NotEmpty(t, frames)
			require.Equal(t, connIDs[i], connID)
		}

		// Trying to create a 4th path should fail (before timeout)
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
		require.Zero(t, connID)
		require.Empty(t, frames)
	})

	t.Run("custom 5 paths", func(t *testing.T) {
		var connIDs []protocol.ConnectionID
		for range 10 {
			b := make([]byte, 8)
			rand.Read(b)
			connIDs = append(connIDs, protocol.ParseConnectionID(b))
		}

		pm := newPathManager(
			func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
			func(id pathID) {},
			5,
			utils.DefaultLogger,
		)

		now := monotime.Now()
		// Create 5 paths (should succeed)
		for i := 0; i < 5; i++ {
			connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true)
			require.NotEmpty(t, frames)
			require.Equal(t, connIDs[i], connID)
		}

		// Trying to create a 6th path should fail (before timeout)
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
		require.Zero(t, connID)
		require.Empty(t, frames)
	})

	t.Run("custom 1 path", func(t *testing.T) {
		var connIDs []protocol.ConnectionID
		for range 5 {
			b := make([]byte, 8)
			rand.Read(b)
			connIDs = append(connIDs, protocol.ParseConnectionID(b))
		}

		pm := newPathManager(
			func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
			func(id pathID) {},
			1,
			utils.DefaultLogger,
		)

		now := monotime.Now()
		// Create 1 path (should succeed)
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000}, now, nil, true)
		require.NotEmpty(t, frames)
		require.Equal(t, connIDs[0], connID)

		// Trying to create a 2nd path should fail (before timeout)
		connID, frames, _ = pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
		require.Zero(t, connID)
		require.Empty(t, frames)
	})

	t.Run("zero defaults to 3", func(t *testing.T) {
		var connIDs []protocol.ConnectionID
		for range 10 {
			b := make([]byte, 8)
			rand.Read(b)
			connIDs = append(connIDs, protocol.ParseConnectionID(b))
		}

		pm := newPathManager(
			func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
			func(id pathID) {},
			0, // should default to 3
			utils.DefaultLogger,
		)

		now := monotime.Now()
		// Create 3 paths (should succeed)
		for i := 0; i < 3; i++ {
			connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true)
			require.NotEmpty(t, frames)
			require.Equal(t, connIDs[i], connID)
		}

		// Trying to create a 4th path should fail
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
		require.Zero(t, connID)
		require.Empty(t, frames)
	})

	t.Run("negative defaults to 3", func(t *testing.T) {
		var connIDs []protocol.ConnectionID
		for range 10 {
			b := make([]byte, 8)
			rand.Read(b)
			connIDs = append(connIDs, protocol.ParseConnectionID(b))
		}

		pm := newPathManager(
			func(id pathID) (protocol.ConnectionID, bool) { return connIDs[id], true },
			func(id pathID) {},
			-5, // should default to 3
			utils.DefaultLogger,
		)

		now := monotime.Now()
		// Create 3 paths (should succeed)
		for i := 0; i < 3; i++ {
			connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1000 + i}, now, nil, true)
			require.NotEmpty(t, frames)
			require.Equal(t, connIDs[i], connID)
		}

		// Trying to create a 4th path should fail
		connID, frames, _ := pm.HandlePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2000}, now, nil, true)
		require.Zero(t, connID)
		require.Empty(t, frames)
	})
}
