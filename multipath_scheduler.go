package quic

import (
	"slices"
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
	// Backup is set for backup paths of IETF Multipath QUIC (section 3.3 of draft-ietf-quic-multipath-21).
	// They are only selected if no other path can be selected.
	Backup bool
}

// selectNonBackupFirst selects a path using sel, avoiding backup paths:
// they are only considered if no other path can be selected.
func selectNonBackupFirst(paths []SchedulerPathInfo, sel func(skipBackup bool) *SchedulerPathInfo) *SchedulerPathInfo {
	if !slices.ContainsFunc(paths, func(p SchedulerPathInfo) bool { return p.Backup }) {
		return sel(false)
	}
	if selected := sel(true); selected != nil {
		return selected
	}
	return sel(false)
}

// RoundRobinScheduler implements a round-robin scheduling algorithm with quotas.
// It distributes packets evenly across all available paths.
type RoundRobinScheduler struct {
	mu sync.Mutex
	pathQuotas
}

// NewRoundRobinScheduler creates a new round-robin scheduler.
func NewRoundRobinScheduler() *RoundRobinScheduler {
	return &RoundRobinScheduler{pathQuotas: newPathQuotas()}
}

// SelectPath selects the path with the lowest quota.
// Backup paths are only selected if no other path can be selected.
func (s *RoundRobinScheduler) SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}
	s.observe(paths)

	// Single path - return it if available
	if len(paths) == 1 {
		if !hasRetransmission && !paths[0].SendingAllowed {
			return nil
		}
		return &paths[0]
	}

	return selectNonBackupFirst(paths, func(skipBackup bool) *SchedulerPathInfo {
		return s.selectPath(paths, hasRetransmission, skipBackup)
	})
}

func (s *RoundRobinScheduler) selectPath(paths []SchedulerPathInfo, hasRetransmission, skipBackup bool) *SchedulerPathInfo {
	var selectedPath *SchedulerPathInfo
	lowestQuota := ^uint64(0) // Max uint64

	for i := range paths {
		path := &paths[i]

		if skipBackup && path.Backup {
			continue
		}
		// Skip paths that can't send (unless retransmission)
		if !hasRetransmission && !path.SendingAllowed {
			continue
		}

		// Skip potentially failed paths
		if path.PotentiallyFailed {
			continue
		}

		quota := s.quotas[path.PathID]

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
	s.reset()
}

// LowLatencyScheduler implements a low-latency scheduling algorithm.
// It prefers paths with lower RTT for better latency.
type LowLatencyScheduler struct {
	mu sync.Mutex
	pathQuotas
}

// NewLowLatencyScheduler creates a new low-latency scheduler.
func NewLowLatencyScheduler() *LowLatencyScheduler {
	return &LowLatencyScheduler{pathQuotas: newPathQuotas()}
}

// SelectPath selects the path with the lowest RTT.
// For unprobed paths (RTT == 0), it uses quotas to distribute initial probing.
// Backup paths are only selected if no other path can be selected.
func (s *LowLatencyScheduler) SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}
	s.observe(paths)

	// Single path - return it if available
	if len(paths) == 1 {
		if !hasRetransmission && !paths[0].SendingAllowed {
			return nil
		}
		return &paths[0]
	}

	return selectNonBackupFirst(paths, func(skipBackup bool) *SchedulerPathInfo {
		return s.selectPath(paths, hasRetransmission, skipBackup)
	})
}

func (s *LowLatencyScheduler) selectPath(paths []SchedulerPathInfo, hasRetransmission, skipBackup bool) *SchedulerPathInfo {
	var selectedPath *SchedulerPathInfo
	var lowestRTT time.Duration
	lowestQuota := ^uint64(0)
	hasRTTMeasurement := false

	for i := range paths {
		path := &paths[i]

		if skipBackup && path.Backup {
			continue
		}
		// Skip paths that can't send (unless retransmission)
		if !hasRetransmission && !path.SendingAllowed {
			continue
		}

		// Skip potentially failed paths
		if path.PotentiallyFailed {
			continue
		}

		currentRTT := path.SmoothedRTT
		quota := s.quotas[path.PathID]

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
	s.reset()
}

// MinRTTScheduler implements a minimum RTT scheduling algorithm with smoothing.
// It uses a weighted approach to balance between RTT and path utilization.
type MinRTTScheduler struct {
	mu sync.Mutex
	pathQuotas
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
		pathQuotas:     newPathQuotas(),
		bytesPerPath:   make(map[PathID]ByteCount),
		packetsPerPath: make(map[PathID]uint64),
		rttBias:        rttBias,
	}
}

// SelectPath selects the path with the best score based on RTT and quota.
// Backup paths are only selected if no other path can be selected.
func (s *MinRTTScheduler) SelectPath(paths []SchedulerPathInfo, hasRetransmission bool) *SchedulerPathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(paths) == 0 {
		return nil
	}
	if s.observe(paths) {
		// drop the statistics of the paths whose quota was pruned
		for pathID := range s.bytesPerPath {
			if _, ok := s.quotas[pathID]; !ok {
				delete(s.bytesPerPath, pathID)
			}
		}
		for pathID := range s.packetsPerPath {
			if _, ok := s.quotas[pathID]; !ok {
				delete(s.packetsPerPath, pathID)
			}
		}
	}

	if len(paths) == 1 {
		if !hasRetransmission && !paths[0].SendingAllowed {
			return nil
		}
		return &paths[0]
	}

	return selectNonBackupFirst(paths, func(skipBackup bool) *SchedulerPathInfo {
		return s.selectPath(paths, hasRetransmission, skipBackup)
	})
}

func (s *MinRTTScheduler) selectPath(paths []SchedulerPathInfo, hasRetransmission, skipBackup bool) *SchedulerPathInfo {
	var selectedPath *SchedulerPathInfo
	var bestScore float64 = -1

	// Find paths with RTT measurements
	var minRTT time.Duration
	var maxQuota uint64
	for i := range paths {
		path := &paths[i]
		if skipBackup && path.Backup {
			continue
		}
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

		if skipBackup && path.Backup {
			continue
		}
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
	s.reset()
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

// schedulerQuotaPruneInterval controls how long the schedulers remember paths:
// the counters of a path that wasn't passed to SelectPath during the last
// schedulerQuotaPruneInterval calls are dropped. Pruning runs every
// schedulerQuotaPruneInterval calls.
const schedulerQuotaPruneInterval = 128

// pathQuotas holds the per-path packet counters ("quotas") the schedulers balance on:
// they prefer the paths with lower quotas. A path that joins (a new path, or one
// that was absent from the previous SelectPath call) starts at the lowest quota of
// the paths already in use, rather than at 0: otherwise it would get every packet
// until it caught up with the lifetime packet count of the older paths.
// It must be protected by the scheduler's mutex.
type pathQuotas struct {
	quotas map[PathID]uint64
	// lastSeen is the SelectPath call in which the path was last passed to SelectPath
	lastSeen map[PathID]uint64
	// calls is the number of SelectPath calls (with at least one path)
	calls uint64
}

func newPathQuotas() pathQuotas {
	return pathQuotas{
		quotas:   make(map[PathID]uint64),
		lastSeen: make(map[PathID]uint64),
	}
}

func (q *pathQuotas) reset() {
	q.quotas = make(map[PathID]uint64)
	q.lastSeen = make(map[PathID]uint64)
}

// observe registers the paths passed to SelectPath.
// Every path in paths has a quota entry afterwards.
// It reports whether the entries of paths that weren't seen recently were dropped.
func (q *pathQuotas) observe(paths []SchedulerPathInfo) (pruned bool) {
	q.calls++
	prev := q.calls - 1

	// The reference quota is the lowest quota among the paths that were already
	// passed to the previous call. If there are none (the first call, or the set
	// of paths changed completely), use the lowest quota among the paths that
	// have a quota entry.
	var ref uint64
	var haveRef bool
	for i := range paths {
		id := paths[i].PathID
		if seen, ok := q.lastSeen[id]; ok && seen == prev {
			if quota := q.quotas[id]; !haveRef || quota < ref {
				ref, haveRef = quota, true
			}
		}
	}
	if !haveRef {
		for i := range paths {
			if quota, ok := q.quotas[paths[i].PathID]; ok && (!haveRef || quota < ref) {
				ref, haveRef = quota, true
			}
		}
	}

	for i := range paths {
		id := paths[i].PathID
		if seen, ok := q.lastSeen[id]; !ok || seen != prev {
			// The path joins: don't let it catch up with the packets sent before.
			if quota := q.quotas[id]; quota < ref {
				q.quotas[id] = ref
			} else {
				q.quotas[id] = quota
			}
		}
		q.lastSeen[id] = q.calls
	}

	if q.calls%schedulerQuotaPruneInterval != 0 {
		return false
	}
	for id, seen := range q.lastSeen {
		if q.calls-seen >= schedulerQuotaPruneInterval {
			delete(q.lastSeen, id)
		}
	}
	for id := range q.quotas {
		if _, ok := q.lastSeen[id]; !ok {
			delete(q.quotas, id)
		}
	}
	return true
}
