package quic

import (
	"slices"
	"sync"
	"time"
)

// DefaultMultipathController is a MultipathController that selects paths using a PathScheduler.
// The connection opens, validates and abandons the paths. It informs the controller about the active paths
// (RegisterPath and RemovePath) and the packets sent, acknowledged and lost on them.
// The controller keeps statistics for these paths, which the scheduler uses to select one of the paths passed to
// SelectPath.
type DefaultMultipathController struct {
	mu        sync.RWMutex
	scheduler PathScheduler
	paths     map[PathID]*pathState
}

var _ multipathControllerCloner = &DefaultMultipathController{}

// cloneForConnection creates a controller with the same configuration, but without any paths.
// It returns nil if the scheduler can't be cloned.
func (c *DefaultMultipathController) cloneForConnection() MultipathController {
	c.mu.RLock()
	defer c.mu.RUnlock()
	scheduler := cloneScheduler(c.scheduler)
	if scheduler == nil {
		return nil
	}
	return NewDefaultMultipathController(scheduler)
}

// pathState tracks the state of a path for scheduling decisions.
type pathState struct {
	sendingAllowed       bool
	congestionLimited    bool
	bytesInFlight        ByteCount
	congestionWindow     ByteCount
	smoothedRTT          time.Duration
	rttVar               time.Duration
	potentiallyFailed    bool
	packetsSent          uint64
	bytesSent            ByteCount
	packetsLost          uint64
	packetsRetransmitted uint64
	lastPacketTime       time.Time
}

// NewDefaultMultipathController creates a new multipath controller with the specified scheduler.
// If scheduler is nil, it defaults to LowLatencyScheduler.
func NewDefaultMultipathController(scheduler PathScheduler) *DefaultMultipathController {
	if scheduler == nil {
		scheduler = NewLowLatencyScheduler()
	}
	return &DefaultMultipathController{
		scheduler: scheduler,
		paths:     make(map[PathID]*pathState),
	}
}

// RegisterPath is called when a path becomes active.
// The controller collects statistics for the path from now on.
func (c *DefaultMultipathController) RegisterPath(info PathInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.paths[info.ID]; exists {
		return
	}
	c.paths[info.ID] = &pathState{sendingAllowed: true}
}

// UpdatePathState updates the state of a path.
func (c *DefaultMultipathController) UpdatePathState(pathID PathID, update PathStateUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state, exists := c.paths[pathID]
	if !exists {
		return
	}

	if update.SendingAllowed != nil {
		state.sendingAllowed = *update.SendingAllowed
	}
	if update.CongestionLimited != nil {
		state.congestionLimited = *update.CongestionLimited
	}
	if update.BytesInFlight != nil {
		state.bytesInFlight = *update.BytesInFlight
	}
	if update.CongestionWindow != nil {
		state.congestionWindow = *update.CongestionWindow
	}
	if update.SmoothedRTT != nil {
		state.smoothedRTT = *update.SmoothedRTT
	}
	if update.RTTVar != nil {
		state.rttVar = *update.RTTVar
	}
	if update.PotentiallyFailed != nil {
		state.potentiallyFailed = *update.PotentiallyFailed
	}
}

// OnPacketSent is called when a packet is sent on a path.
func (c *DefaultMultipathController) OnPacketSent(pathID PathID, packetSize ByteCount) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state, exists := c.paths[pathID]
	if !exists {
		return
	}

	state.packetsSent++
	state.bytesSent += packetSize
	state.lastPacketTime = time.Now()

	// Update scheduler quota
	c.scheduler.UpdateQuota(pathID, packetSize)
}

// OnPacketAcked is called when a packet is acknowledged.
func (c *DefaultMultipathController) OnPacketAcked(pathID PathID) {
	// No action needed here, statistics are tracked separately
}

// OnPacketLost is called when a packet is lost.
func (c *DefaultMultipathController) OnPacketLost(pathID PathID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state, exists := c.paths[pathID]
	if !exists {
		return
	}

	state.packetsLost++
}

// RemovePath is called when a path is abandoned. The statistics of the path are removed.
func (c *DefaultMultipathController) RemovePath(pathID PathID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.paths, pathID)
}

// SelectPath selects one of the paths in ctx.Paths for sending a packet,
// using the statistics collected for these paths.
// It returns false if ctx.Paths is empty, or if the scheduler doesn't select any of the paths.
func (c *DefaultMultipathController) SelectPath(ctx PathSelectionContext) (PathInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.scheduler == nil || len(ctx.Paths) == 0 {
		return PathInfo{}, false
	}
	schedulerPaths := make([]SchedulerPathInfo, 0, len(ctx.Paths))
	for _, path := range ctx.Paths {
		info := SchedulerPathInfo{
			PathID:         path.ID,
			SendingAllowed: true,
			Backup:         path.isBackup(),
		}
		if path.RemoteAddr != nil {
			info.RemoteAddr = path.RemoteAddr.String()
		}
		if state, ok := c.paths[path.ID]; ok {
			info.SendingAllowed = state.sendingAllowed
			info.CongestionLimited = state.congestionLimited
			info.BytesInFlight = state.bytesInFlight
			info.CongestionWindow = state.congestionWindow
			info.SmoothedRTT = state.smoothedRTT
			info.RTTVar = state.rttVar
			info.PotentiallyFailed = state.potentiallyFailed
			info.PacketsSent = state.packetsSent
			info.BytesSent = state.bytesSent
			info.PacketsLost = state.packetsLost
			info.PacketsRetransmitted = state.packetsRetransmitted
		}
		schedulerPaths = append(schedulerPaths, info)
	}
	applyPathCongestion(schedulerPaths, ctx)
	// ACK-only packets and retransmissions may be sent on paths that are congestion limited.
	ignoreCongestion := ctx.HasRetransmission || ctx.AckOnly
	selected := c.scheduler.SelectPath(schedulerPaths, ignoreCongestion)
	if selected == nil && slices.ContainsFunc(schedulerPaths, func(p SchedulerPathInfo) bool { return p.PotentiallyFailed }) {
		// If all paths are potentially failed, keep using them:
		// otherwise nothing would be sent, and a path could never recover.
		for i := range schedulerPaths {
			schedulerPaths[i].PotentiallyFailed = false
		}
		selected = c.scheduler.SelectPath(schedulerPaths, ignoreCongestion)
	}
	if selected == nil {
		return PathInfo{}, false
	}
	idx := slices.IndexFunc(ctx.Paths, func(p PathInfo) bool { return p.ID == selected.PathID })
	if idx == -1 {
		return PathInfo{}, false
	}
	return ctx.Paths[idx], true
}

// GetScheduler returns the underlying PathScheduler.
func (c *DefaultMultipathController) GetScheduler() PathScheduler {
	return c.scheduler
}

// GetStatistics returns statistics for all paths.
func (c *DefaultMultipathController) GetStatistics() map[PathID]PathStatistics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[PathID]PathStatistics)
	for pathID, state := range c.paths {
		stats[pathID] = PathStatistics{
			PathID:               pathID,
			PacketsSent:          state.packetsSent,
			BytesSent:            state.bytesSent,
			PacketsLost:          state.packetsLost,
			PacketsRetransmitted: state.packetsRetransmitted,
			SmoothedRTT:          state.smoothedRTT,
			RTTVar:               state.rttVar,
			CongestionWindow:     state.congestionWindow,
			BytesInFlight:        state.bytesInFlight,
			LastPacketTime:       state.lastPacketTime,
		}
	}
	return stats
}

// PathStateUpdate contains optional updates for path state.
type PathStateUpdate struct {
	SendingAllowed    *bool
	CongestionLimited *bool
	BytesInFlight     *ByteCount
	CongestionWindow  *ByteCount
	SmoothedRTT       *time.Duration
	RTTVar            *time.Duration
	PotentiallyFailed *bool
}

// PathStatistics contains statistics for a path.
type PathStatistics struct {
	PathID               PathID
	PacketsSent          uint64
	BytesSent            ByteCount
	PacketsLost          uint64
	PacketsRetransmitted uint64
	SmoothedRTT          time.Duration
	RTTVar               time.Duration
	CongestionWindow     ByteCount
	BytesInFlight        ByteCount
	LastPacketTime       time.Time
}

// applyPathCongestion sets the congestion state of the paths, using the PathCongestion callback of the context.
// A path whose congestion window is full is not allowed to send.
func applyPathCongestion(paths []SchedulerPathInfo, ctx PathSelectionContext) {
	if ctx.PathCongestion == nil {
		return
	}
	for i := range paths {
		cwnd, bytesInFlight, ok := ctx.PathCongestion(paths[i].PathID)
		if !ok {
			continue
		}
		paths[i].CongestionWindow = cwnd
		paths[i].BytesInFlight = bytesInFlight
		if bytesInFlight >= cwnd {
			paths[i].CongestionLimited = true
			paths[i].SendingAllowed = false
		}
	}
}
