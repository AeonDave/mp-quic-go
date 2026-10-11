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
	for range 100 {
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
	for range 10 {
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
	for i := range 10 {
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
	for range 10 {
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
	for range 10 {
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
	for range 100 {
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
	for range 100 {
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

	// Both paths are known to the scheduler before path 1 gets used.
	// (A path that the scheduler sees for the first time starts at the lowest quota
	// of the other paths, see TestScheduler_NewPathDoesNotCatchUp.)
	require.NotNil(t, scheduler.SelectPath(paths, false))

	// Give path 1 much higher quota
	for range 100 {
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
	for range 100 {
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
		for range 10 {
			go func() {
				for range 100 {
					selected := scheduler.SelectPath(paths, false)
					if selected != nil {
						scheduler.UpdateQuota(selected.PathID, 1200)
					}
				}
				done <- true
			}()
		}

		// Wait for all goroutines
		for range 10 {
			<-done
		}

		// Should not panic and should have processed all updates
		scheduler.Reset()
	}
}

func newTestSchedulers() map[string]PathScheduler {
	return map[string]PathScheduler{
		"RoundRobin": NewRoundRobinScheduler(),
		"LowLatency": NewLowLatencyScheduler(),
		"MinRTT":     NewMinRTTScheduler(0),
	}
}

func schedulerPathQuotas(t *testing.T, s PathScheduler) *pathQuotas {
	t.Helper()
	switch s := s.(type) {
	case *RoundRobinScheduler:
		return &s.pathQuotas
	case *LowLatencyScheduler:
		return &s.pathQuotas
	case *MinRTTScheduler:
		return &s.pathQuotas
	}
	t.Fatalf("unexpected scheduler type %T", s)
	return nil
}

// sendOnScheduler runs n rounds of SelectPath and UpdateQuota, and returns the selected path IDs.
func sendOnScheduler(t *testing.T, s PathScheduler, paths []SchedulerPathInfo, n int) []PathID {
	t.Helper()
	selected := make([]PathID, 0, n)
	for range n {
		p := s.SelectPath(paths, false)
		require.NotNil(t, p)
		selected = append(selected, p.PathID)
		s.UpdateQuota(p.PathID, 1200)
	}
	return selected
}

// requireAlternating checks that two paths share the selections evenly,
// without either path being selected more than twice in a row.
func requireAlternating(t *testing.T, selected []PathID) {
	t.Helper()
	counts := make(map[PathID]int)
	run := 0
	for i, id := range selected {
		counts[id]++
		if i > 0 && selected[i-1] == id {
			run++
		} else {
			run = 1
		}
		require.LessOrEqual(t, run, 2, "path %d selected %d times in a row: %v", id, run, selected)
	}
	require.Len(t, counts, 2, "selections: %v", selected)
	for id, c := range counts {
		require.InDelta(t, len(selected)/2, c, 1, "path %d: %v", id, selected)
	}
}

func TestScheduler_NewPathDoesNotCatchUp(t *testing.T) {
	for name, scheduler := range newTestSchedulers() {
		t.Run(name, func(t *testing.T) {
			path0 := SchedulerPathInfo{PathID: 0, SendingAllowed: true, SmoothedRTT: 20 * time.Millisecond}
			path1 := SchedulerPathInfo{PathID: 1, SendingAllowed: true, SmoothedRTT: 20 * time.Millisecond}

			for _, id := range sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0}, 1000) {
				require.Equal(t, PathID(0), id)
			}

			// Path 1 is added: the paths alternate right away,
			// instead of path 1 getting the next 1000 packets.
			requireAlternating(t, sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0, path1}, 20))

			// Path 1 disappears for a while, then returns: same thing.
			sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0}, 500)
			requireAlternating(t, sendOnScheduler(t, scheduler, []SchedulerPathInfo{path1, path0}, 20))

			// A path that was used (UpdateQuota) before it was passed to SelectPath.
			path2 := SchedulerPathInfo{PathID: 2, SendingAllowed: true, SmoothedRTT: 20 * time.Millisecond}
			scheduler.UpdateQuota(2, 1200)
			selected := sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0, path1, path2}, 30)
			counts := make(map[PathID]int)
			for _, id := range selected {
				counts[id]++
			}
			require.Len(t, counts, 3, "selections: %v", selected)
			for id, c := range counts {
				require.InDelta(t, 10, c, 1, "path %d: %v", id, selected)
			}
		})
	}
}

func TestScheduler_NewPathAfterReset(t *testing.T) {
	for name, scheduler := range newTestSchedulers() {
		t.Run(name, func(t *testing.T) {
			path0 := SchedulerPathInfo{PathID: 0, SendingAllowed: true}
			path1 := SchedulerPathInfo{PathID: 1, SendingAllowed: true}
			sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0}, 100)
			scheduler.Reset()
			sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0}, 100)
			requireAlternating(t, sendOnScheduler(t, scheduler, []SchedulerPathInfo{path0, path1}, 20))
		})
	}
}

func TestScheduler_QuotaMapsBoundedUnderPathChurn(t *testing.T) {
	const maxEntries = 3*schedulerQuotaPruneInterval + 2

	for name, scheduler := range newTestSchedulers() {
		t.Run(name, func(t *testing.T) {
			q := schedulerPathQuotas(t, scheduler)
			for i := range 20 * schedulerQuotaPruneInterval {
				// path 0 stays, the second path is a different one every time
				paths := []SchedulerPathInfo{
					{PathID: 0, SendingAllowed: true},
					{PathID: PathID(i + 1), SendingAllowed: true},
				}
				p := scheduler.SelectPath(paths, false)
				require.NotNil(t, p)
				scheduler.UpdateQuota(p.PathID, 1200)
				// packets sent on a path the scheduler is never asked about
				scheduler.UpdateQuota(PathID(1_000_000+i), 1200)

				require.LessOrEqual(t, len(q.quotas), maxEntries)
				require.LessOrEqual(t, len(q.lastSeen), maxEntries)
			}

			// once the paths settle, the counters of the old paths are dropped
			paths := []SchedulerPathInfo{
				{PathID: 0, SendingAllowed: true},
				{PathID: 1, SendingAllowed: true},
			}
			sendOnScheduler(t, scheduler, paths, 2*schedulerQuotaPruneInterval)
			require.Len(t, q.quotas, 2)
			require.Len(t, q.lastSeen, 2)
			require.Contains(t, q.quotas, PathID(0))
			require.Contains(t, q.quotas, PathID(1))

			if s, ok := scheduler.(*MinRTTScheduler); ok {
				require.Len(t, s.bytesPerPath, 2)
				require.Len(t, s.packetsPerPath, 2)
				require.Len(t, s.GetStatistics(), 2)
			}
		})
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

// Backup paths are only selected if no other path can be selected (section 3.3 of draft-ietf-quic-multipath-21),
// even if they have a lower RTT or a lower quota.
func TestSchedulersSkipBackupPaths(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scheduler func() PathScheduler
	}{
		{name: "round-robin", scheduler: func() PathScheduler { return NewRoundRobinScheduler() }},
		{name: "low latency", scheduler: func() PathScheduler { return NewLowLatencyScheduler() }},
		{name: "minimum RTT", scheduler: func() PathScheduler { return NewMinRTTScheduler(1) }},
		{name: "minimum RTT, balanced", scheduler: func() PathScheduler { return NewMinRTTScheduler(0.5) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.scheduler()
			paths := func() []SchedulerPathInfo {
				return []SchedulerPathInfo{
					{PathID: 1, SendingAllowed: true, SmoothedRTT: 5 * time.Millisecond, Backup: true},
					{PathID: 2, SendingAllowed: true, SmoothedRTT: 50 * time.Millisecond},
					{PathID: 3, SendingAllowed: true, SmoothedRTT: 10 * time.Millisecond, Backup: true},
				}
			}
			for range 10 {
				selected := s.SelectPath(paths(), false)
				require.NotNil(t, selected)
				require.Equal(t, PathID(2), selected.PathID)
				s.UpdateQuota(selected.PathID, 1200)
			}

			// the available path can't send
			p := paths()
			p[1].SendingAllowed = false
			selected := s.SelectPath(p, false)
			require.NotNil(t, selected)
			require.True(t, selected.Backup)
			// retransmissions can be sent on paths that are congestion limited
			selected = s.SelectPath(p, true)
			require.NotNil(t, selected)
			require.Equal(t, PathID(2), selected.PathID)

			// the available path potentially failed
			p = paths()
			p[1].PotentiallyFailed = true
			selected = s.SelectPath(p, false)
			require.NotNil(t, selected)
			require.True(t, selected.Backup)

			// only backup paths
			p = paths()
			p[1].Backup = true
			require.NotNil(t, s.SelectPath(p, false))
		})
	}
}
