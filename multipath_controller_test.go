package quic

import (
	"net"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestDefaultMultipathController_New(t *testing.T) {
	// With scheduler
	scheduler := NewRoundRobinScheduler()
	controller := NewDefaultMultipathController(scheduler)
	require.NotNil(t, controller)
	require.Equal(t, scheduler, controller.GetScheduler())

	// Without scheduler (should default to LowLatency)
	controller2 := NewDefaultMultipathController(nil)
	require.NotNil(t, controller2)
	require.NotNil(t, controller2.GetScheduler())
}

func TestDefaultMultipathController_RegisterPath(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	pathInfo := PathInfo{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678},
	}

	controller.RegisterPath(pathInfo)

	// Verify path is registered
	controller.mu.RLock()
	state, exists := controller.paths[PathID(1)]
	controller.mu.RUnlock()

	require.True(t, exists)
	require.True(t, state.sendingAllowed)
}

func TestDefaultMultipathController_RegisterPath_Duplicate(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	pathInfo := PathInfo{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678},
	}

	controller.RegisterPath(pathInfo)
	controller.RegisterPath(pathInfo) // Register again

	// Should still have only one path
	controller.mu.RLock()
	count := len(controller.paths)
	controller.mu.RUnlock()

	require.Equal(t, 1, count)
}

func TestDefaultMultipathController_UpdatePathState(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	pathInfo := PathInfo{ID: 1}
	controller.RegisterPath(pathInfo)

	// Update state
	sendingAllowed := false
	rtt := 50 * time.Millisecond

	update := PathStateUpdate{
		SendingAllowed: &sendingAllowed,
		SmoothedRTT:    &rtt,
	}

	controller.UpdatePathState(1, update)

	// Verify updates
	controller.mu.RLock()
	state := controller.paths[PathID(1)]
	controller.mu.RUnlock()

	require.False(t, state.sendingAllowed)
	require.Equal(t, 50*time.Millisecond, state.smoothedRTT)
}

func TestDefaultMultipathController_OnPacketSent(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	pathInfo := PathInfo{ID: 1}
	controller.RegisterPath(pathInfo)

	// Send packets
	controller.OnPacketSent(1, 1200)
	controller.OnPacketSent(1, 1400)

	// Verify statistics
	controller.mu.RLock()
	state := controller.paths[PathID(1)]
	controller.mu.RUnlock()

	require.Equal(t, uint64(2), state.packetsSent)
	require.Equal(t, protocol.ByteCount(2600), state.bytesSent)
	require.False(t, state.lastPacketTime.IsZero())
}

func TestDefaultMultipathController_OnPacketLost(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	pathInfo := PathInfo{ID: 1}
	controller.RegisterPath(pathInfo)

	// Lose packets
	controller.OnPacketLost(1)
	controller.OnPacketLost(1)
	controller.OnPacketLost(1)

	// Verify statistics
	controller.mu.RLock()
	state := controller.paths[PathID(1)]
	controller.mu.RUnlock()

	require.Equal(t, uint64(3), state.packetsLost)
}

func TestDefaultMultipathController_RemovePath(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	pathInfo := PathInfo{ID: 1}
	controller.RegisterPath(pathInfo)

	// Verify registered
	controller.mu.RLock()
	_, exists := controller.paths[PathID(1)]
	controller.mu.RUnlock()
	require.True(t, exists)

	// Remove
	controller.RemovePath(1)

	// Verify removed
	controller.mu.RLock()
	_, exists = controller.paths[PathID(1)]
	controller.mu.RUnlock()
	require.False(t, exists)
}

func TestDefaultMultipathController_SelectPath(t *testing.T) {
	scheduler := NewRoundRobinScheduler()
	controller := NewDefaultMultipathController(scheduler)

	// Register paths
	path1 := PathInfo{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5678},
	}
	path2 := PathInfo{
		ID:         2,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1235},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 5679},
	}

	controller.RegisterPath(path1)
	controller.RegisterPath(path2)
	// the controller selects one of the paths passed in the context
	_, ok := controller.SelectPath(PathSelectionContext{Now: time.Now()})
	require.False(t, ok)

	// Select path
	ctx := PathSelectionContext{
		Now:     time.Now(),
		AckOnly: false,
		Paths:   []PathInfo{path1, path2},
	}

	info, ok := controller.SelectPath(ctx)
	require.True(t, ok)
	require.Contains(t, []PathInfo{path1, path2}, info)

	// Track quota
	controller.OnPacketSent(info.ID, 1200)

	// Next selection should prefer the other path (round-robin)
	info2, ok := controller.SelectPath(ctx)
	require.True(t, ok)
	require.NotEqual(t, info.ID, info2.ID)
}

func TestDefaultMultipathController_SelectPath_NoPaths(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	ctx := PathSelectionContext{Now: time.Now()}
	_, ok := controller.SelectPath(ctx)
	require.False(t, ok)
}

func TestDefaultMultipathController_SelectPath_AllBlocked(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	// Register path but mark as not sending allowed
	pathInfo := PathInfo{ID: 1}
	controller.RegisterPath(pathInfo)

	sendingAllowed := false
	controller.UpdatePathState(1, PathStateUpdate{SendingAllowed: &sendingAllowed})

	ctx := PathSelectionContext{
		Now:               time.Now(),
		HasRetransmission: false,
		Paths:             []PathInfo{pathInfo},
	}

	_, ok := controller.SelectPath(ctx)
	require.False(t, ok)

	// With retransmission, should work
	ctx.HasRetransmission = true
	_, ok = controller.SelectPath(ctx)
	require.True(t, ok)
}

func TestDefaultMultipathController_GetStatistics(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	path1 := PathInfo{ID: 1}
	path2 := PathInfo{ID: 2}
	controller.RegisterPath(path1)
	controller.RegisterPath(path2)

	// Send packets
	controller.OnPacketSent(1, 1200)
	controller.OnPacketSent(1, 1400)
	controller.OnPacketSent(2, 1000)

	// Lose packet
	controller.OnPacketLost(1)

	// Get statistics
	stats := controller.GetStatistics()
	require.Len(t, stats, 2)

	stat1 := stats[PathID(1)]
	require.Equal(t, uint64(2), stat1.PacketsSent)
	require.Equal(t, protocol.ByteCount(2600), stat1.BytesSent)
	require.Equal(t, uint64(1), stat1.PacketsLost)

	stat2 := stats[PathID(2)]
	require.Equal(t, uint64(1), stat2.PacketsSent)
	require.Equal(t, protocol.ByteCount(1000), stat2.BytesSent)
	require.Equal(t, uint64(0), stat2.PacketsLost)
}

func TestDefaultMultipathController_ConcurrentAccess(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	// Register paths
	var paths []PathInfo
	for i := 1; i <= 5; i++ {
		pathInfo := PathInfo{
			ID:         PathID(i),
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + i},
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, byte(i)), Port: 5000 + i},
		}
		controller.RegisterPath(pathInfo)
		paths = append(paths, pathInfo)
	}

	done := make(chan bool)

	// Concurrent selections
	go func() {
		for range 100 {
			ctx := PathSelectionContext{Now: time.Now(), Paths: paths}
			if info, ok := controller.SelectPath(ctx); ok {
				controller.OnPacketSent(info.ID, 1200)
			}
		}
		done <- true
	}()

	// Concurrent updates
	go func() {
		for i := range 100 {
			rtt := time.Duration(50+i) * time.Millisecond
			controller.UpdatePathState(PathID((i%5)+1), PathStateUpdate{SmoothedRTT: &rtt})
		}
		done <- true
	}()

	// Concurrent statistics
	go func() {
		for range 100 {
			_ = controller.GetStatistics()
		}
		done <- true
	}()

	// Wait for all
	for range 3 {
		<-done
	}
}

func BenchmarkDefaultMultipathController_SelectPath(b *testing.B) {
	controller := NewDefaultMultipathController(nil)

	var paths []PathInfo
	for i := 1; i <= 3; i++ {
		pathInfo := PathInfo{
			ID:         PathID(i),
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + i},
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, byte(i)), Port: 5000 + i},
		}
		controller.RegisterPath(pathInfo)
		paths = append(paths, pathInfo)

		rtt := time.Duration(50*i) * time.Millisecond
		controller.UpdatePathState(PathID(i), PathStateUpdate{SmoothedRTT: &rtt})
	}

	ctx := PathSelectionContext{Now: time.Now(), Paths: paths}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if info, ok := controller.SelectPath(ctx); ok {
			controller.OnPacketSent(info.ID, 1200)
		}
	}
}

func TestDefaultMultipathController_AllPathsPotentiallyFailed(t *testing.T) {
	controller := NewDefaultMultipathController(NewRoundRobinScheduler())
	path0 := PathInfo{
		ID:         0,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222},
	}
	controller.RegisterPath(path0)
	failed := true
	controller.UpdatePathState(0, PathStateUpdate{PotentiallyFailed: &failed})

	// If all paths are potentially failed, they're still used.
	path, ok := controller.SelectPath(PathSelectionContext{Paths: []PathInfo{path0}})
	require.True(t, ok)
	require.Equal(t, PathID(0), path.ID)
}
