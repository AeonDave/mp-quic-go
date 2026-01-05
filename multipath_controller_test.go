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
	require.Equal(t, pathInfo.ID, state.info.ID)
	require.True(t, state.sendingAllowed)
	require.False(t, state.validated)
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
	validated := true
	rtt := 50 * time.Millisecond

	update := PathStateUpdate{
		SendingAllowed: &sendingAllowed,
		Validated:      &validated,
		SmoothedRTT:    &rtt,
	}

	controller.UpdatePathState(1, update)

	// Verify updates
	controller.mu.RLock()
	state := controller.paths[PathID(1)]
	controller.mu.RUnlock()

	require.False(t, state.sendingAllowed)
	require.True(t, state.validated)
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

	// Select path
	ctx := PathSelectionContext{
		Now:     time.Now(),
		AckOnly: false,
	}

	info, ok := controller.SelectPath(ctx)
	require.True(t, ok)
	require.Contains(t, []PathID{1, 2}, info.ID)

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
	}

	_, ok := controller.SelectPath(ctx)
	require.False(t, ok)

	// With retransmission, should work
	ctx.HasRetransmission = true
	_, ok = controller.SelectPath(ctx)
	require.True(t, ok)
}

func TestDefaultMultipathController_PathIDForPacket(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5678}

	pathInfo := PathInfo{
		ID:         1,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
	}

	controller.RegisterPath(pathInfo)

	// Should find the path
	pathID, ok := controller.PathIDForPacket(remoteAddr, localAddr)
	require.True(t, ok)
	require.Equal(t, PathID(1), pathID)

	// Wrong addresses
	wrongAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 9999}
	_, ok = controller.PathIDForPacket(wrongAddr, localAddr)
	require.False(t, ok)
}

func TestDefaultMultipathController_EnablePacketDuplication(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	require.False(t, controller.enableDuplication)

	controller.EnablePacketDuplication(true)
	require.True(t, controller.enableDuplication)

	controller.EnablePacketDuplication(false)
	require.False(t, controller.enableDuplication)
}

func TestDefaultMultipathController_SetDuplicationParameters(t *testing.T) {
	controller := NewDefaultMultipathController(nil)

	require.True(t, controller.duplicationUnprobed)
	require.Equal(t, uint64(10), controller.duplicationQuota)

	controller.SetDuplicationParameters(false, 20)
	require.False(t, controller.duplicationUnprobed)
	require.Equal(t, uint64(20), controller.duplicationQuota)
}

func TestDefaultMultipathController_ShouldDuplicatePacket(t *testing.T) {
	scheduler := NewMinRTTScheduler(0.5)
	controller := NewDefaultMultipathController(scheduler)
	controller.EnablePacketDuplication(true)

	// Register two paths
	path1 := PathInfo{ID: 1}
	path2 := PathInfo{ID: 2}
	controller.RegisterPath(path1)
	controller.RegisterPath(path2)

	// Path 2 is unprobed (RTT = 0)
	rtt := 50 * time.Millisecond
	controller.UpdatePathState(1, PathStateUpdate{SmoothedRTT: &rtt})

	// Send some packets on path 1
	for i := 0; i < 5; i++ {
		controller.OnPacketSent(1, 1200)
	}

	// Should duplicate on path 2 (unprobed)
	dupPathID, shouldDup := controller.ShouldDuplicatePacket(1)
	require.True(t, shouldDup)
	require.Equal(t, PathID(2), dupPathID)
}

func TestDefaultMultipathController_ShouldDuplicatePacket_Disabled(t *testing.T) {
	controller := NewDefaultMultipathController(nil)
	// Duplication disabled by default

	path1 := PathInfo{ID: 1}
	path2 := PathInfo{ID: 2}
	controller.RegisterPath(path1)
	controller.RegisterPath(path2)

	_, shouldDup := controller.ShouldDuplicatePacket(1)
	require.False(t, shouldDup)
}

func TestDefaultMultipathController_ShouldDuplicatePacket_OnlyProbed(t *testing.T) {
	scheduler := NewMinRTTScheduler(0.5)
	controller := NewDefaultMultipathController(scheduler)
	controller.EnablePacketDuplication(true)
	controller.SetDuplicationParameters(true, 10) // Only on unprobed

	// Register two paths, both probed
	path1 := PathInfo{ID: 1}
	path2 := PathInfo{ID: 2}
	controller.RegisterPath(path1)
	controller.RegisterPath(path2)

	rtt1 := 50 * time.Millisecond
	rtt2 := 100 * time.Millisecond
	controller.UpdatePathState(1, PathStateUpdate{SmoothedRTT: &rtt1})
	controller.UpdatePathState(2, PathStateUpdate{SmoothedRTT: &rtt2})

	// Should not duplicate (both paths are probed)
	_, shouldDup := controller.ShouldDuplicatePacket(1)
	require.False(t, shouldDup)
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
	for i := 1; i <= 5; i++ {
		pathInfo := PathInfo{
			ID:         PathID(i),
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + i},
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, byte(i)), Port: 5000 + i},
		}
		controller.RegisterPath(pathInfo)
	}

	done := make(chan bool)

	// Concurrent selections
	go func() {
		for i := 0; i < 100; i++ {
			ctx := PathSelectionContext{Now: time.Now()}
			if info, ok := controller.SelectPath(ctx); ok {
				controller.OnPacketSent(info.ID, 1200)
			}
		}
		done <- true
	}()

	// Concurrent updates
	go func() {
		for i := 0; i < 100; i++ {
			rtt := time.Duration(50+i) * time.Millisecond
			controller.UpdatePathState(PathID((i%5)+1), PathStateUpdate{SmoothedRTT: &rtt})
		}
		done <- true
	}()

	// Concurrent statistics
	go func() {
		for i := 0; i < 100; i++ {
			_ = controller.GetStatistics()
		}
		done <- true
	}()

	// Wait for all
	for i := 0; i < 3; i++ {
		<-done
	}
}

func TestAddrsEqual(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	addr3 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	require.True(t, addrsEqual(addr1, addr2))
	require.False(t, addrsEqual(addr1, addr3))
	require.True(t, addrsEqual(nil, nil))
	require.False(t, addrsEqual(addr1, nil))
	require.False(t, addrsEqual(nil, addr1))
}

func BenchmarkDefaultMultipathController_SelectPath(b *testing.B) {
	controller := NewDefaultMultipathController(nil)

	for i := 1; i <= 3; i++ {
		pathInfo := PathInfo{
			ID:         PathID(i),
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000 + i},
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, byte(i)), Port: 5000 + i},
		}
		controller.RegisterPath(pathInfo)

		rtt := time.Duration(50*i) * time.Millisecond
		controller.UpdatePathState(PathID(i), PathStateUpdate{SmoothedRTT: &rtt})
	}

	ctx := PathSelectionContext{Now: time.Now()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if info, ok := controller.SelectPath(ctx); ok {
			controller.OnPacketSent(info.ID, 1200)
		}
	}
}
