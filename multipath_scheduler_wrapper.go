package quic

import (
	"slices"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// SchedulingPolicy defines the scheduling algorithm to use
type SchedulingPolicy int

const (
	SchedulingPolicyRoundRobin SchedulingPolicy = iota
	SchedulingPolicyMinRTT
	SchedulingPolicyLowLatency
)

// PathSchedulerWrapper is a MultipathController that selects paths using the scheduler of a SchedulingPolicy.
// It collects the statistics of the paths from the packet events (see MultipathObserver).
type PathSchedulerWrapper struct {
	mu               sync.RWMutex
	scheduler        PathScheduler
	policy           SchedulingPolicy
	multipathEnabled bool
	// statistics of the paths, by path ID
	pathStats map[PathID]*schedulerPathStats
}

// schedulerPathStats are the statistics of a path.
type schedulerPathStats struct {
	smoothedRTT time.Duration
	rttVar      time.Duration
	packetsSent uint64
	bytesSent   ByteCount
	packetsLost uint64
}

var (
	_ multipathControllerCloner = &PathSchedulerWrapper{}
	_ MultipathObserver         = &PathSchedulerWrapper{}
)

// NewMultipathScheduler creates a new multipath controller using the scheduler of the policy.
func NewMultipathScheduler(policy SchedulingPolicy) *PathSchedulerWrapper {
	var scheduler PathScheduler

	switch policy {
	case SchedulingPolicyRoundRobin:
		scheduler = NewRoundRobinScheduler()
	case SchedulingPolicyMinRTT:
		// pure minimum RTT: the path with the lowest RTT whose congestion window isn't full
		scheduler = NewMinRTTScheduler(1)
	case SchedulingPolicyLowLatency:
		scheduler = NewLowLatencyScheduler()
	default:
		scheduler = NewRoundRobinScheduler()
	}

	return &PathSchedulerWrapper{
		scheduler: scheduler,
		policy:    policy,
		pathStats: make(map[PathID]*schedulerPathStats),
	}
}

// cloneForConnection creates a scheduler with the same configuration, but without any paths.
func (s *PathSchedulerWrapper) cloneForConnection() MultipathController {
	return NewMultipathScheduler(s.policy)
}

// RemovePath is called when a path is abandoned. The statistics of the path are removed.
func (s *PathSchedulerWrapper) RemovePath(pathID PathID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pathStats, pathID)
}

// EnableMultipath is called when IETF Multipath QUIC becomes active on the connection.
func (s *PathSchedulerWrapper) EnableMultipath() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.multipathEnabled = true
}

// DisableMultipath stops updating the scheduler's quota (see RecordSent).
func (s *PathSchedulerWrapper) DisableMultipath() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.multipathEnabled = false
}

// IsMultipathEnabled returns whether multipath is enabled
func (s *PathSchedulerWrapper) IsMultipathEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.multipathEnabled
}

// RecordSent updates scheduler state after sending a packet
func (s *PathSchedulerWrapper) RecordSent(pathID protocol.PathID, packetSize uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.multipathEnabled {
		return
	}

	s.scheduler.UpdateQuota(pathID, ByteCount(packetSize))
}

// SelectPath implements MultipathController interface.
// It selects one of the paths in ctx.Paths, using the statistics collected for these paths.
// It returns false if ctx.Paths is empty, or if the scheduler doesn't select any of the paths.
func (s *PathSchedulerWrapper) SelectPath(ctx PathSelectionContext) (PathInfo, bool) {
	if len(ctx.Paths) == 0 {
		return PathInfo{}, false
	}
	s.mu.RLock()
	pathInfos := make([]SchedulerPathInfo, 0, len(ctx.Paths))
	for _, path := range ctx.Paths {
		info := SchedulerPathInfo{
			PathID:         path.ID,
			SendingAllowed: true,
			Backup:         path.isBackup(),
		}
		if stats, ok := s.pathStats[path.ID]; ok {
			info.SmoothedRTT = stats.smoothedRTT
			info.RTTVar = stats.rttVar
			info.PacketsSent = stats.packetsSent
			info.BytesSent = stats.bytesSent
			info.PacketsLost = stats.packetsLost
		}
		pathInfos = append(pathInfos, info)
	}
	s.mu.RUnlock()

	applyPathCongestion(pathInfos, ctx)
	// ACK-only packets and retransmissions may be sent on paths that are congestion limited.
	selected := s.scheduler.SelectPath(pathInfos, ctx.HasRetransmission || ctx.AckOnly)
	if selected == nil {
		return PathInfo{}, false
	}
	idx := slices.IndexFunc(ctx.Paths, func(p PathInfo) bool { return p.ID == selected.PathID })
	if idx == -1 {
		return PathInfo{}, false
	}
	return ctx.Paths[idx], true
}

// RegisterPath is called when a path becomes active.
// The statistics collected for the path are used when it is passed to SelectPath.
func (s *PathSchedulerWrapper) RegisterPath(info PathInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pathStats[info.ID]; !ok && info.ID != InvalidPathID {
		s.pathStats[info.ID] = &schedulerPathStats{}
	}
}

// OnPacketSent updates scheduler and path statistics.
func (s *PathSchedulerWrapper) OnPacketSent(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.IsPathProbe || ev.IsPathMTUProbe || !ev.AckEliciting {
		return
	}
	s.RecordSent(ev.PathID, uint64(ev.PacketSize))

	s.mu.Lock()
	defer s.mu.Unlock()
	if stats := s.pathStats[ev.PathID]; stats != nil {
		stats.packetsSent++
		stats.bytesSent += ev.PacketSize
	}
}

// OnPacketAcked updates RTT statistics for a path.
func (s *PathSchedulerWrapper) OnPacketAcked(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.SmoothedRTT == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stats := s.pathStats[ev.PathID]; stats != nil {
		stats.smoothedRTT = ev.SmoothedRTT
		stats.rttVar = ev.RTTVar
	}
}

// OnPacketLost updates the loss statistics of a path.
func (s *PathSchedulerWrapper) OnPacketLost(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.IsPathProbe || ev.IsPathMTUProbe || !ev.AckEliciting {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stats := s.pathStats[ev.PathID]; stats != nil {
		stats.packetsLost++
	}
}
