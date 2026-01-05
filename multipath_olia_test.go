package quic

import (
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestOLIA_NewInstance(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	require.NotNil(t, olia)
	require.Equal(t, protocol.PathID(1), olia.pathID)
	require.Equal(t, olia.GetCongestionWindow(), defaultOLIAInitialWindow)
	require.Equal(t, olia.slowStartThreshold, defaultOLIAMaxWindow)
	require.True(t, olia.InSlowStart())

	// Should be registered in shared state
	sharedState.mu.RLock()
	_, exists := sharedState.pathOLIA[protocol.PathID(1)]
	sharedState.mu.RUnlock()
	require.True(t, exists)
}

func TestOLIA_CanSend(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Initially, should be able to send
	require.True(t, olia.CanSend(0))

	// Can send up to congestion window
	require.True(t, olia.CanSend(olia.congestionWindow-1))

	// Cannot send if bytes in flight >= cwnd
	require.False(t, olia.CanSend(olia.congestionWindow))
	require.False(t, olia.CanSend(olia.congestionWindow+1000))
}

func TestOLIA_SlowStart(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	initialCwnd := olia.GetCongestionWindow()
	require.True(t, olia.InSlowStart())

	// ACK a packet in slow start - cwnd should increase by acked bytes
	ackedBytes := protocol.ByteCount(1200)
	olia.OnPacketAcked(1, ackedBytes, 0, time.Now())

	newCwnd := olia.GetCongestionWindow()
	require.Equal(t, initialCwnd+ackedBytes, newCwnd)
	require.True(t, olia.InSlowStart())

	// ACK more packets
	for i := 0; i < 20; i++ {
		olia.OnPacketAcked(protocol.PacketNumber(i+2), ackedBytes, 0, time.Now())
	}

	// Should still be increasing
	finalCwnd := olia.GetCongestionWindow()
	require.Greater(t, finalCwnd, newCwnd)
}

func TestOLIA_ExitSlowStart(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Simulate packet loss to exit slow start
	olia.OnCongestionEvent(10, 1200, olia.congestionWindow)

	require.False(t, olia.InSlowStart())
	require.Equal(t, olia.congestionWindow, olia.slowStartThreshold)
}

func TestOLIA_CongestionEvent(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Increase cwnd first
	for i := 0; i < 10; i++ {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, time.Now())
	}

	cwndBeforeLoss := olia.GetCongestionWindow()
	require.Greater(t, cwndBeforeLoss, defaultOLIAInitialWindow)

	// Simulate congestion event
	olia.OnCongestionEvent(20, 1200, cwndBeforeLoss)

	cwndAfterLoss := olia.GetCongestionWindow()

	// Cwnd should be halved (multiplicative decrease)
	require.Equal(t, cwndAfterLoss, cwndBeforeLoss/2)

	// Should not go below minimum
	olia.congestionWindow = defaultOLIAMinWindow + 1000
	olia.OnCongestionEvent(21, 1200, olia.congestionWindow)
	require.GreaterOrEqual(t, olia.GetCongestionWindow(), defaultOLIAMinWindow)
}

func TestOLIA_SmoothedBytesBetweenLosses(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Initially zero
	require.Equal(t, protocol.ByteCount(0), olia.SmoothedBytesBetweenLosses())

	// ACK some bytes
	olia.OnPacketAcked(1, 1000, 0, time.Now())
	olia.OnPacketAcked(2, 1000, 0, time.Now())

	// Loss event
	olia.OnCongestionEvent(3, 1200, 5000)

	// ACK more bytes
	olia.OnPacketAcked(4, 2000, 0, time.Now())
	olia.OnPacketAcked(5, 2000, 0, time.Now())

	// Should return the larger interval
	smoothed := olia.SmoothedBytesBetweenLosses()
	require.Greater(t, smoothed, protocol.ByteCount(0))
}

func TestOLIA_MultiPath_EpsilonCalculation(t *testing.T) {
	sharedState := NewOLIASharedState()

	// Create two paths
	path1 := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	path2 := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)

	// Set different RTTs
	path1.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	path2.UpdateRTT(100*time.Millisecond, 100*time.Millisecond)

	// ACK packets on both paths
	for i := 0; i < 10; i++ {
		path1.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, time.Now())
		path2.OnPacketAcked(protocol.PacketNumber(i+100), 1200, 0, time.Now())
	}

	// Calculate epsilon - should not panic
	path1.calculateEpsilon()
	path2.calculateEpsilon()

	// Epsilon should be calculated
	require.NotEqual(t, 0, path1.epsilonDen)
	require.NotEqual(t, 0, path2.epsilonDen)
}

func TestOLIA_MultiPath_CoupledCongestionControl(t *testing.T) {
	sharedState := NewOLIASharedState()

	// Create three paths with different characteristics
	path1 := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	path2 := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)
	path3 := NewOLIACongestionControl(3, sharedState, protocol.InitialPacketSize)

	// Set different RTTs (path1 fastest, path3 slowest)
	path1.UpdateRTT(20*time.Millisecond, 20*time.Millisecond)
	path2.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	path3.UpdateRTT(100*time.Millisecond, 100*time.Millisecond)

	// Exit slow start for all paths
	for _, p := range []*OLIACongestionControl{path1, path2, path3} {
		p.congestionWindow = p.slowStartThreshold + 1000
		p.slowStartThreshold = p.congestionWindow - 500
	}

	// Send and ack packets on all paths
	for i := 0; i < 100; i++ {
		path1.OnPacketAcked(protocol.PacketNumber(i), 1200, 5000, time.Now())
		path2.OnPacketAcked(protocol.PacketNumber(i+1000), 1200, 5000, time.Now())
		path3.OnPacketAcked(protocol.PacketNumber(i+2000), 1200, 5000, time.Now())
	}

	// All paths should have increased their windows
	cwnd1 := path1.GetCongestionWindow()
	cwnd2 := path2.GetCongestionWindow()
	cwnd3 := path3.GetCongestionWindow()

	require.Greater(t, cwnd1, defaultOLIAInitialWindow)
	require.Greater(t, cwnd2, defaultOLIAInitialWindow)
	require.Greater(t, cwnd3, defaultOLIAInitialWindow)

	// Path with lower RTT should typically have larger window
	// (though OLIA's coupling may affect this)
	t.Logf("Path1 (20ms RTT): cwnd=%d", cwnd1)
	t.Logf("Path2 (50ms RTT): cwnd=%d", cwnd2)
	t.Logf("Path3 (100ms RTT): cwnd=%d", cwnd3)
}

func TestOLIA_UpdateRTT(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	require.Equal(t, time.Duration(0), olia.rtt)
	require.Equal(t, time.Duration(0), olia.minRTT)

	// Update RTT
	olia.UpdateRTT(50*time.Millisecond, 45*time.Millisecond)
	require.Equal(t, 50*time.Millisecond, olia.rtt)
	require.Equal(t, 45*time.Millisecond, olia.minRTT)

	// Update with new min
	olia.UpdateRTT(55*time.Millisecond, 40*time.Millisecond)
	require.Equal(t, 55*time.Millisecond, olia.rtt)
	require.Equal(t, 40*time.Millisecond, olia.minRTT)

	// Update with higher min (should not change minRTT)
	olia.UpdateRTT(60*time.Millisecond, 50*time.Millisecond)
	require.Equal(t, 60*time.Millisecond, olia.rtt)
	require.Equal(t, 40*time.Millisecond, olia.minRTT)
}

func TestOLIA_SetMaxDatagramSize(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	require.Equal(t, olia.maxDatagramSize, protocol.ByteCount(protocol.InitialPacketSize))

	newSize := protocol.ByteCount(1400)
	olia.SetMaxDatagramSize(newSize)
	require.Equal(t, olia.maxDatagramSize, newSize)
}

func TestOLIA_Reset(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Modify state
	olia.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	for i := 0; i < 20; i++ {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, time.Now())
	}
	olia.OnCongestionEvent(21, 1200, olia.congestionWindow)

	// Reset
	olia.Reset()

	// Should be back to initial state
	require.Equal(t, defaultOLIAInitialWindow, olia.congestionWindow)
	require.Equal(t, defaultOLIAMaxWindow, olia.slowStartThreshold)
	require.Equal(t, protocol.ByteCount(0), olia.loss1)
	require.Equal(t, protocol.ByteCount(0), olia.loss2)
	require.Equal(t, protocol.ByteCount(0), olia.loss3)
	require.True(t, olia.InSlowStart())
}

func TestOLIA_Unregister(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Verify registered
	sharedState.mu.RLock()
	_, exists := sharedState.pathOLIA[protocol.PathID(1)]
	sharedState.mu.RUnlock()
	require.True(t, exists)

	// Unregister
	olia.Unregister()

	// Verify unregistered
	sharedState.mu.RLock()
	_, exists = sharedState.pathOLIA[protocol.PathID(1)]
	sharedState.mu.RUnlock()
	require.False(t, exists)
}

func TestOLIA_GetStatistics(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	olia.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	olia.OnPacketAcked(1, 1200, 0, time.Now())

	stats := olia.GetStatistics()
	require.Equal(t, protocol.PathID(1), stats.PathID)
	require.Equal(t, olia.congestionWindow, stats.CongestionWindow)
	require.Equal(t, olia.slowStartThreshold, stats.SlowStartThreshold)
	require.True(t, stats.InSlowStart)
	require.Equal(t, 50*time.Millisecond, stats.RTT)
}

func TestOLIA_ZeroMaxDatagramSize(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, 0)

	// Should default to InitialPacketSize
	require.Equal(t, olia.maxDatagramSize, protocol.ByteCount(protocol.InitialPacketSize))
}

func TestOLIA_ConcurrentAccess(t *testing.T) {
	sharedState := NewOLIASharedState()
	path1 := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	path2 := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)

	path1.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	path2.UpdateRTT(100*time.Millisecond, 100*time.Millisecond)

	done := make(chan bool)

	// Concurrent operations on path1
	go func() {
		for i := 0; i < 100; i++ {
			path1.OnPacketAcked(protocol.PacketNumber(i), 1200, 5000, time.Now())
			_ = path1.CanSend(5000)
			_ = path1.GetCongestionWindow()
		}
		done <- true
	}()

	// Concurrent operations on path2
	go func() {
		for i := 0; i < 100; i++ {
			path2.OnPacketAcked(protocol.PacketNumber(i+1000), 1200, 5000, time.Now())
			_ = path2.CanSend(5000)
			_ = path2.GetCongestionWindow()
		}
		done <- true
	}()

	// Concurrent statistics retrieval
	go func() {
		for i := 0; i < 100; i++ {
			_ = path1.GetStatistics()
			_ = path2.GetStatistics()
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}

	// Should not panic
	require.NotNil(t, path1)
	require.NotNil(t, path2)
}

func TestOLIA_MaxCongestionWindow(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// ACK many packets to try to exceed max window
	for i := 0; i < 1000; i++ {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, time.Now())
	}

	// Should not exceed max window
	require.LessOrEqual(t, olia.GetCongestionWindow(), defaultOLIAMaxWindow)
}

func TestOLIA_MinCongestionWindow(t *testing.T) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	// Force window to be close to minimum
	olia.congestionWindow = defaultOLIAMinWindow + 100

	// Multiple loss events
	for i := 0; i < 10; i++ {
		olia.OnCongestionEvent(protocol.PacketNumber(i), 1200, olia.congestionWindow)
	}

	// Should not go below minimum
	require.GreaterOrEqual(t, olia.GetCongestionWindow(), defaultOLIAMinWindow)
}

func BenchmarkOLIA_OnPacketAcked(b *testing.B) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	olia.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		olia.OnPacketAcked(protocol.PacketNumber(i), 1200, 5000, time.Now())
	}
}

func BenchmarkOLIA_MultiPath_OnPacketAcked(b *testing.B) {
	sharedState := NewOLIASharedState()
	path1 := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)
	path2 := NewOLIACongestionControl(2, sharedState, protocol.InitialPacketSize)
	path3 := NewOLIACongestionControl(3, sharedState, protocol.InitialPacketSize)

	path1.UpdateRTT(50*time.Millisecond, 50*time.Millisecond)
	path2.UpdateRTT(75*time.Millisecond, 75*time.Millisecond)
	path3.UpdateRTT(100*time.Millisecond, 100*time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		switch i % 3 {
		case 0:
			path1.OnPacketAcked(protocol.PacketNumber(i), 1200, 5000, time.Now())
		case 1:
			path2.OnPacketAcked(protocol.PacketNumber(i), 1200, 5000, time.Now())
		case 2:
			path3.OnPacketAcked(protocol.PacketNumber(i), 1200, 5000, time.Now())
		}
	}
}

func BenchmarkOLIA_CanSend(b *testing.B) {
	sharedState := NewOLIASharedState()
	olia := NewOLIACongestionControl(1, sharedState, protocol.InitialPacketSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = olia.CanSend(5000)
	}
}
