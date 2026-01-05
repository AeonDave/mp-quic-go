package quic

import (
	"sync"
	"time"
)

// PathScheduler defines the interface for multipath scheduling algorithms.
// A PathScheduler decides which path to use for sending the next packet.
type PathScheduler interface {
	// SelectPath selects the best path for sending a packet.
	// It returns nil if no path is available for sending.
	SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo

	// UpdateQuota is called after a packet is sent on a path.
	UpdateQuota(pathID PathID, packetSize ByteCount)

	// Reset resets the scheduler state.
	Reset()
}

// SchedulerPathInfo contains information about a path for scheduling decisions.
type SchedulerPathInfo struct {
	PathID               PathID
	RemoteAddr           string
	SendingAllowed       bool
	CongestionLimited    bool
	BytesInFlight        ByteCount
	CongestionWindow     ByteCount
	SmoothedRTT          time.Duration
	RTTVar               time.Duration
	PotentiallyFailed    bool
	PacketsSent          uint64
	BytesSent            ByteCount
	PacketsLost          uint64
	PacketsRetransmitted uint64
}

// RoundRobinScheduler implements a round-robin scheduling algorithm with quotas.
// It distributes packets evenly across all available paths.
type RoundRobinScheduler struct {
	mu     sync.Mutex
	quotas map[PathID]uint64
}

// NewRoundRobinScheduler creates a new round-robin scheduler.
func NewRoundRobinScheduler() *RoundRobinScheduler {
	return &RoundRobinScheduler{
		quotas: make(map[PathID]uint64),
	}
}

// SelectPath selects the path with the lowest quota.
func (s *RoundRobinScheduler) SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}

	// Single path - return it if available
	if len(paths) == 1 {
		if !hasRetransmission && !paths[0].SendingAllowed {
			return nil
		}
		return &paths[0]
	}

	var selectedPath *SchedulerPathInfo
	var lowestQuota uint64 = ^uint64(0) // Max uint64

	for i := range paths {
		path := &paths[i]

		// Skip paths that can't send (unless retransmission)
		if !hasRetransmission && !path.SendingAllowed {
			continue
		}

		// Skip potentially failed paths
		if path.PotentiallyFailed {
			continue
		}

		// Get or initialize quota
		quota, exists := s.quotas[path.PathID]
		if !exists {
			s.quotas[path.PathID] = 0
			quota = 0
		}

		// Select path with lowest quota
		if quota < lowestQuota {
			selectedPath = path
			lowestQuota = quota
		}
	}

	return selectedPath
}

// UpdateQuota increments the quota for a path after sending a packet.
func (s *RoundRobinScheduler) UpdateQuota(pathID PathID, packetSize ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas[pathID]++
}

// Reset clears all quota counters.
func (s *RoundRobinScheduler) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas = make(map[PathID]uint64)
}

// LowLatencyScheduler implements a low-latency scheduling algorithm.
// It prefers paths with lower RTT for better latency.
type LowLatencyScheduler struct {
	mu     sync.Mutex
	quotas map[PathID]uint64
}

// NewLowLatencyScheduler creates a new low-latency scheduler.
func NewLowLatencyScheduler() *LowLatencyScheduler {
	return &LowLatencyScheduler{
		quotas: make(map[PathID]uint64),
	}
}

// SelectPath selects the path with the lowest RTT.
// For unprobed paths (RTT == 0), it uses quotas to distribute initial probing.
func (s *LowLatencyScheduler) SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}

	// Single path - return it if available
	if len(paths) == 1 {
		if !hasRetransmission && !paths[0].SendingAllowed {
			return nil
		}
		return &paths[0]
	}

	var selectedPath *SchedulerPathInfo
	var lowestRTT time.Duration
	var lowestQuota uint64 = ^uint64(0)
	hasRTTMeasurement := false

	for i := range paths {
		path := &paths[i]

		// Skip paths that can't send (unless retransmission)
		if !hasRetransmission && !path.SendingAllowed {
			continue
		}

		// Skip potentially failed paths
		if path.PotentiallyFailed {
			continue
		}

		currentRTT := path.SmoothedRTT
		quota, exists := s.quotas[path.PathID]
		if !exists {
			s.quotas[path.PathID] = 0
			quota = 0
		}

		// Case 1: We have RTT measurements, prefer lower RTT
		if currentRTT > 0 {
			hasRTTMeasurement = true
			if selectedPath == nil || lowestRTT == 0 || currentRTT < lowestRTT {
				selectedPath = path
				lowestRTT = currentRTT
				lowestQuota = quota
			} else if currentRTT == lowestRTT && quota < lowestQuota {
				// Same RTT, prefer lower quota
				selectedPath = path
				lowestQuota = quota
			}
		} else if !hasRTTMeasurement {
			// Case 2: No RTT measurements yet, use quotas for initial probing
			if selectedPath == nil || quota < lowestQuota {
				selectedPath = path
				lowestQuota = quota
			}
		}
	}

	return selectedPath
}

// UpdateQuota increments the quota for a path after sending a packet.
func (s *LowLatencyScheduler) UpdateQuota(pathID PathID, packetSize ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas[pathID]++
}

// Reset clears all quota counters.
func (s *LowLatencyScheduler) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas = make(map[PathID]uint64)
}

// MinRTTScheduler implements a minimum RTT scheduling algorithm with smoothing.
// It uses a weighted approach to balance between RTT and path utilization.
type MinRTTScheduler struct {
	mu             sync.Mutex
	quotas         map[PathID]uint64
	bytesPerPath   map[PathID]ByteCount
	packetsPerPath map[PathID]uint64
	rttBias        float64 // Bias factor for RTT vs quota balancing (0.0-1.0)
}

// NewMinRTTScheduler creates a new minimum RTT scheduler.
// rttBias controls the trade-off between RTT optimization and load balancing:
// - 1.0: Pure minimum RTT (no load balancing)
// - 0.5: Balanced between RTT and load distribution
// - 0.0: Pure load balancing (ignores RTT)
func NewMinRTTScheduler(rttBias float64) *MinRTTScheduler {
	if rttBias < 0 {
		rttBias = 0
	}
	if rttBias > 1 {
		rttBias = 1
	}
	return &MinRTTScheduler{
		quotas:         make(map[PathID]uint64),
		bytesPerPath:   make(map[PathID]ByteCount),
		packetsPerPath: make(map[PathID]uint64),
		rttBias:        rttBias,
	}
}

// SelectPath selects the path with the best score based on RTT and quota.
func (s *MinRTTScheduler) SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}

	if len(paths) == 1 {
		if !hasRetransmission && !paths[0].SendingAllowed {
			return nil
		}
		return &paths[0]
	}

	var selectedPath *SchedulerPathInfo
	var bestScore float64 = -1

	// Find paths with RTT measurements
	var minRTT time.Duration
	var maxQuota uint64
	for i := range paths {
		path := &paths[i]
		if path.SmoothedRTT > 0 && (minRTT == 0 || path.SmoothedRTT < minRTT) {
			minRTT = path.SmoothedRTT
		}
		quota := s.quotas[path.PathID]
		if quota > maxQuota {
			maxQuota = quota
		}
	}

	for i := range paths {
		path := &paths[i]

		if !hasRetransmission && !path.SendingAllowed {
			continue
		}
		if path.PotentiallyFailed {
			continue
		}

		quota := s.quotas[path.PathID]

		// Calculate normalized score (higher is better)
		var score float64
		if path.SmoothedRTT > 0 && minRTT > 0 {
			// RTT component: lower RTT = higher score
			rttScore := float64(minRTT) / float64(path.SmoothedRTT)

			// Quota component: lower quota = higher score
			quotaScore := 1.0
			if maxQuota > 0 {
				quotaScore = 1.0 - (float64(quota) / float64(maxQuota))
			}

			// Combine with bias
			score = s.rttBias*rttScore + (1-s.rttBias)*quotaScore
		} else {
			// No RTT measurement, use only quota
			if maxQuota > 0 {
				score = 1.0 - (float64(quota) / float64(maxQuota))
			} else {
				score = 1.0
			}
		}

		if score > bestScore {
			bestScore = score
			selectedPath = path
		}
	}

	return selectedPath
}

// UpdateQuota updates statistics after sending a packet.
func (s *MinRTTScheduler) UpdateQuota(pathID PathID, packetSize ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas[pathID]++
	s.bytesPerPath[pathID] += packetSize
	s.packetsPerPath[pathID]++
}

// Reset clears all statistics.
func (s *MinRTTScheduler) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas = make(map[PathID]uint64)
	s.bytesPerPath = make(map[PathID]ByteCount)
	s.packetsPerPath = make(map[PathID]uint64)
}

// GetStatistics returns scheduling statistics for monitoring and debugging.
func (s *MinRTTScheduler) GetStatistics() map[PathID]SchedulerStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := make(map[PathID]SchedulerStats)
	for pathID := range s.quotas {
		stats[pathID] = SchedulerStats{
			PacketsSent: s.packetsPerPath[pathID],
			BytesSent:   s.bytesPerPath[pathID],
			Quota:       s.quotas[pathID],
		}
	}
	return stats
}

// SchedulerStats contains statistics for a single path.
type SchedulerStats struct {
	PacketsSent uint64
	BytesSent   ByteCount
	Quota       uint64
}
