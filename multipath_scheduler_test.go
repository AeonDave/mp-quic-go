package quic

import (
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestRoundRobinScheduler_SinglePath(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true},
	}

	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(1), selected.PathID)
}

func TestRoundRobinScheduler_SinglePathBlocked(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: false},
	}

	selected := scheduler.SelectPath(paths, false)
	require.Nil(t, selected)

	// With retransmission, should be selected anyway
	selected = scheduler.SelectPath(paths, true)
	require.NotNil(t, selected)
	require.Equal(t, PathID(1), selected.PathID)
}

func TestRoundRobinScheduler_NoPaths(t *testing.T) {
	scheduler := NewRoundRobinScheduler()
	selected := scheduler.SelectPath(nil, false)
	require.Nil(t, selected)

	selected = scheduler.SelectPath([]SchedulerPathInfo{}, false)
	require.Nil(t, selected)
}

func TestRoundRobinScheduler_MultiplePaths(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true},
		{PathID: 2, SendingAllowed: true},
		{PathID: 3, SendingAllowed: true},
	}

	// First selection should give path with quota 0
	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	firstPathID := selected.PathID

	// Update quota
	scheduler.UpdateQuota(firstPathID, 1200)

	// Next selection should give a different path
	selected = scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.NotEqual(t, firstPathID, selected.PathID)
	secondPathID := selected.PathID

	// Update quota
	scheduler.UpdateQuota(secondPathID, 1200)

	// Should select third path
	selected = scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.NotEqual(t, firstPathID, selected.PathID)
	require.NotEqual(t, secondPathID, selected.PathID)
}

func TestRoundRobinScheduler_RoundRobinDistribution(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true},
		{PathID: 2, SendingAllowed: true},
	}

	selections := make(map[PathID]int)

	// Select 100 times
	for i := 0; i < 100; i++ {
		selected := scheduler.SelectPath(paths, false)
		require.NotNil(t, selected)
		selections[selected.PathID]++
		scheduler.UpdateQuota(selected.PathID, 1200)
	}

	// Should be distributed evenly (50-50)
	require.Equal(t, 50, selections[PathID(1)])
	require.Equal(t, 50, selections[PathID(2)])
}

func TestRoundRobinScheduler_SkipPotentiallyFailed(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, PotentiallyFailed: true},
		{PathID: 2, SendingAllowed: true, PotentiallyFailed: false},
	}

	// Should skip path 1 and select path 2
	for i := 0; i < 10; i++ {
		selected := scheduler.SelectPath(paths, false)
		require.NotNil(t, selected)
		require.Equal(t, PathID(2), selected.PathID)
		scheduler.UpdateQuota(selected.PathID, 1200)
	}
}

func TestRoundRobinScheduler_SkipCongestionLimited(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: false, CongestionLimited: true},
		{PathID: 2, SendingAllowed: true, CongestionLimited: false},
	}

	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(2), selected.PathID)
}

func TestRoundRobinScheduler_Reset(t *testing.T) {
	scheduler := NewRoundRobinScheduler()

	scheduler.UpdateQuota(1, 1200)
	scheduler.UpdateQuota(2, 1200)
	scheduler.UpdateQuota(1, 1200)

	require.Len(t, scheduler.quotas, 2)
	require.Equal(t, uint64(2), scheduler.quotas[PathID(1)])

	scheduler.Reset()
	require.Len(t, scheduler.quotas, 0)
}

func TestLowLatencyScheduler_SinglePath(t *testing.T) {
	scheduler := NewLowLatencyScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
	}

	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(1), selected.PathID)
}

func TestLowLatencyScheduler_SelectLowestRTT(t *testing.T) {
	scheduler := NewLowLatencyScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
		{PathID: 3, SendingAllowed: true, SmoothedRTT: 150 * time.Millisecond},
	}

	// Should always select path 2 (lowest RTT)
	for i := 0; i < 10; i++ {
		selected := scheduler.SelectPath(paths, false)
		require.NotNil(t, selected)
		require.Equal(t, PathID(2), selected.PathID, "iteration %d", i)
		scheduler.UpdateQuota(selected.PathID, 1200)
	}
}

func TestLowLatencyScheduler_UnprobedPaths(t *testing.T) {
	scheduler := NewLowLatencyScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 0}, // Unprobed
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 0}, // Unprobed
	}

	selections := make(map[PathID]int)

	// For unprobed paths, should use round-robin
	for i := 0; i < 10; i++ {
		selected := scheduler.SelectPath(paths, false)
		require.NotNil(t, selected)
		selections[selected.PathID]++
		scheduler.UpdateQuota(selected.PathID, 1200)
	}

	// Should be distributed evenly
	require.Equal(t, 5, selections[PathID(1)])
	require.Equal(t, 5, selections[PathID(2)])
}

func TestLowLatencyScheduler_MixedProbedUnprobed(t *testing.T) {
	scheduler := NewLowLatencyScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 0}, // Unprobed
	}

	// Should prefer probed path with known RTT
	for i := 0; i < 10; i++ {
		selected := scheduler.SelectPath(paths, false)
		require.NotNil(t, selected)
		require.Equal(t, PathID(1), selected.PathID)
		scheduler.UpdateQuota(selected.PathID, 1200)
	}
}

func TestLowLatencyScheduler_PreferLowerRTTOverQuota(t *testing.T) {
	scheduler := NewLowLatencyScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
	}

	// Give path 1 much lower quota
	for i := 0; i < 100; i++ {
		scheduler.UpdateQuota(2, 1200)
	}

	// Should still prefer path 2 (lower RTT) despite higher quota
	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(2), selected.PathID)
}

func TestLowLatencyScheduler_SkipPotentiallyFailed(t *testing.T) {
	scheduler := NewLowLatencyScheduler()

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 10 * time.Millisecond, PotentiallyFailed: true},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond, PotentiallyFailed: false},
	}

	// Should skip path 1 even though it has lower RTT
	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(2), selected.PathID)
}

func TestMinRTTScheduler_PureRTTBias(t *testing.T) {
	scheduler := NewMinRTTScheduler(1.0) // Pure RTT optimization

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
	}

	// Give path 2 much higher quota
	for i := 0; i < 100; i++ {
		scheduler.UpdateQuota(2, 1200)
	}

	// With pure RTT bias, should still prefer path 2
	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(2), selected.PathID)
}

func TestMinRTTScheduler_BalancedBias(t *testing.T) {
	scheduler := NewMinRTTScheduler(0.5) // Balanced

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 51 * time.Millisecond}, // Slightly higher
	}

	// Give path 1 much higher quota
	for i := 0; i < 100; i++ {
		scheduler.UpdateQuota(1, 1200)
	}

	// With balanced bias, should prefer path 2 (lower quota)
	selected := scheduler.SelectPath(paths, false)
	require.NotNil(t, selected)
	require.Equal(t, PathID(2), selected.PathID)
}

func TestMinRTTScheduler_ZeroBias(t *testing.T) {
	scheduler := NewMinRTTScheduler(0.0) // Pure load balancing

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 10 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 200 * time.Millisecond},
	}

	selections := make(map[PathID]int)

	// With zero bias, should distribute evenly regardless of RTT
	for i := 0; i < 100; i++ {
		selected := scheduler.SelectPath(paths, false)
		require.NotNil(t, selected)
		selections[selected.PathID]++
		scheduler.UpdateQuota(selected.PathID, 1200)
	}

	// Should be roughly equal (allowing for small variance)
	require.InDelta(t, 50, selections[PathID(1)], 5)
	require.InDelta(t, 50, selections[PathID(2)], 5)
}

func TestMinRTTScheduler_GetStatistics(t *testing.T) {
	scheduler := NewMinRTTScheduler(0.5)

	scheduler.UpdateQuota(1, 1200)
	scheduler.UpdateQuota(1, 800)
	scheduler.UpdateQuota(2, 1400)

	stats := scheduler.GetStatistics()
	require.Len(t, stats, 2)

	require.Equal(t, uint64(2), stats[PathID(1)].PacketsSent)
	require.Equal(t, protocol.ByteCount(2000), stats[PathID(1)].BytesSent)
	require.Equal(t, uint64(2), stats[PathID(1)].Quota)

	require.Equal(t, uint64(1), stats[PathID(2)].PacketsSent)
	require.Equal(t, protocol.ByteCount(1400), stats[PathID(2)].BytesSent)
	require.Equal(t, uint64(1), stats[PathID(2)].Quota)
}

func TestMinRTTScheduler_BiasConstraints(t *testing.T) {
	// Test that bias is constrained to [0, 1]
	s1 := NewMinRTTScheduler(-0.5)
	require.Equal(t, 0.0, s1.rttBias)

	s2 := NewMinRTTScheduler(1.5)
	require.Equal(t, 1.0, s2.rttBias)

	s3 := NewMinRTTScheduler(0.5)
	require.Equal(t, 0.5, s3.rttBias)
}

func TestScheduler_ConcurrentAccess(t *testing.T) {
	schedulers := []PathScheduler{
		NewRoundRobinScheduler(),
		NewLowLatencyScheduler(),
		NewMinRTTScheduler(0.5),
	}

	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond},
	}

	for _, scheduler := range schedulers {
		done := make(chan bool)

		// Concurrent selections
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					selected := scheduler.SelectPath(paths, false)
					if selected != nil {
						scheduler.UpdateQuota(selected.PathID, 1200)
					}
				}
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Should not panic and should have processed all updates
		scheduler.Reset()
	}
}

func BenchmarkRoundRobinScheduler_SelectPath(b *testing.B) {
	scheduler := NewRoundRobinScheduler()
	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true},
		{PathID: 2, SendingAllowed: true},
		{PathID: 3, SendingAllowed: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selected := scheduler.SelectPath(paths, false)
		if selected != nil {
			scheduler.UpdateQuota(selected.PathID, 1200)
		}
	}
}

func BenchmarkLowLatencyScheduler_SelectPath(b *testing.B) {
	scheduler := NewLowLatencyScheduler()
	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond},
		{PathID: 3, SendingAllowed: true, SmoothedRTT: 75 * time.Millisecond},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selected := scheduler.SelectPath(paths, false)
		if selected != nil {
			scheduler.UpdateQuota(selected.PathID, 1200)
		}
	}
}

func BenchmarkMinRTTScheduler_SelectPath(b *testing.B) {
	scheduler := NewMinRTTScheduler(0.5)
	paths := []SchedulerPathInfo{
		{PathID: 1, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
		{PathID: 2, SendingAllowed: true, SmoothedRTT: 100 * time.Millisecond},
		{PathID: 3, SendingAllowed: true, SmoothedRTT: 75 * time.Millisecond},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selected := scheduler.SelectPath(paths, false)
		if selected != nil {
			scheduler.UpdateQuota(selected.PathID, 1200)
		}
	}
}
