package quic

import (
	"net"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// DefaultMultipathController is a complete implementation of MultipathController
// with integrated scheduling and path management.
type DefaultMultipathController struct {
	mu         sync.RWMutex
	scheduler  PathScheduler
	paths      map[PathID]*pathState
	nextPathID PathID

	// Configuration
	enableDuplication   bool
	duplicationUnprobed bool   // Duplicate on unprobed paths only
	duplicationQuota    uint64 // Max quota difference for duplication
}

// pathState tracks the state of a path for scheduling decisions.
type pathState struct {
	info                 PathInfo
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
	validated            bool
	lastPacketTime       time.Time
}

// NewDefaultMultipathController creates a new multipath controller with the specified scheduler.
// If scheduler is nil, it defaults to LowLatencyScheduler.
func NewDefaultMultipathController(scheduler PathScheduler) *DefaultMultipathController {
	if scheduler == nil {
		scheduler = NewLowLatencyScheduler()
	}
	return &DefaultMultipathController{
		scheduler:           scheduler,
		paths:               make(map[PathID]*pathState),
		nextPathID:          1,
		enableDuplication:   false,
		duplicationUnprobed: true,
		duplicationQuota:    10,
	}
}

// EnablePacketDuplication enables packet duplication on unprobed paths.
func (c *DefaultMultipathController) EnablePacketDuplication(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enableDuplication = enable
}

// SetDuplicationParameters configures packet duplication behavior.
func (c *DefaultMultipathController) SetDuplicationParameters(unprobedOnly bool, maxQuotaDiff uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.duplicationUnprobed = unprobedOnly
	c.duplicationQuota = maxQuotaDiff
}

// RegisterPath registers a new path with the controller.
func (c *DefaultMultipathController) RegisterPath(info PathInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.paths[info.ID]; exists {
		return
	}

	if info.ID >= c.nextPathID {
		c.nextPathID = info.ID + 1
	}
	c.paths[info.ID] = &pathState{
		info:           info,
		sendingAllowed: true,
		validated:      info.ID == 0,
	}
}

// HandleAddAddressFrame registers a new remote address as a path.
func (c *DefaultMultipathController) HandleAddAddressFrame(frame *wire.AddAddressFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()

	primary, ok := c.paths[0]
	if !ok || primary.info.LocalAddr == nil {
		return
	}
	remoteAddr := frame.GetUDPAddr()
	for _, state := range c.paths {
		if addrsEqual(state.info.RemoteAddr, remoteAddr) {
			return
		}
	}
	pathID := c.nextPathID
	c.nextPathID++
	c.paths[pathID] = &pathState{
		info: PathInfo{
			ID:         pathID,
			LocalAddr:  primary.info.LocalAddr,
			RemoteAddr: remoteAddr,
		},
		sendingAllowed: true,
		validated:      false,
	}
}

// AddPath adds a new path and returns the assigned path ID.
func (c *DefaultMultipathController) AddPath(info PathInfo) (PathID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pathID := info.ID
	if pathID == InvalidPathID {
		pathID = c.nextPathID
		c.nextPathID++
	}
	if _, exists := c.paths[pathID]; exists {
		return pathID, false
	}
	info.ID = pathID
	c.paths[pathID] = &pathState{
		info:           info,
		sendingAllowed: true,
		validated:      pathID == 0,
	}
	return pathID, true
}

// ValidatePath marks a path as validated.
func (c *DefaultMultipathController) ValidatePath(pathID PathID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state, exists := c.paths[pathID]
	if !exists {
		return
	}
	state.validated = true
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
	if update.Validated != nil {
		state.validated = *update.Validated
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

// RemovePath removes a path from the controller.
func (c *DefaultMultipathController) RemovePath(pathID PathID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.paths, pathID)
}

// SelectPath selects the best path for sending a packet.
func (c *DefaultMultipathController) SelectPath(ctx PathSelectionContext) (PathInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.scheduler == nil {
		return PathInfo{}, false
	}

	// Convert path states to scheduler format
	schedulerPaths := make([]SchedulerPathInfo, 0, len(c.paths))
	for pathID, state := range c.paths {
		remoteAddr := ""
		if state.info.RemoteAddr != nil {
			remoteAddr = state.info.RemoteAddr.String()
		}
		schedulerPaths = append(schedulerPaths, SchedulerPathInfo{
			PathID:               pathID,
			RemoteAddr:           remoteAddr,
			SendingAllowed:       state.sendingAllowed,
			CongestionLimited:    state.congestionLimited,
			BytesInFlight:        state.bytesInFlight,
			CongestionWindow:     state.congestionWindow,
			SmoothedRTT:          state.smoothedRTT,
			RTTVar:               state.rttVar,
			PotentiallyFailed:    state.potentiallyFailed,
			PacketsSent:          state.packetsSent,
			BytesSent:            state.bytesSent,
			PacketsLost:          state.packetsLost,
			PacketsRetransmitted: state.packetsRetransmitted,
		})
	}

	// Use scheduler to select path
	selected := c.scheduler.SelectPath(schedulerPaths, ctx.HasRetransmission)
	if selected == nil {
		return PathInfo{}, false
	}

	// Return the full PathInfo
	state, exists := c.paths[selected.PathID]
	if !exists {
		return PathInfo{}, false
	}

	return state.info, true
}

// PathIDForPacket maps a received packet to a path ID.
func (c *DefaultMultipathController) PathIDForPacket(remoteAddr, localAddr net.Addr) (PathID, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Find path matching the addresses
	for pathID, state := range c.paths {
		if addrsEqual(state.info.RemoteAddr, remoteAddr) &&
			matchLocalAddr(state.info.LocalAddr, localAddr) {
			return pathID, true
		}
	}

	return InvalidPathID, false
}

// GetScheduler returns the underlying PathScheduler.
func (c *DefaultMultipathController) GetScheduler() PathScheduler {
	return c.scheduler
}

// ShouldDuplicatePacket returns whether a packet should be duplicated and on which path.
func (c *DefaultMultipathController) ShouldDuplicatePacket(sentOnPath PathID) (PathID, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.enableDuplication {
		return InvalidPathID, false
	}

	_, exists := c.paths[sentOnPath]
	if !exists {
		return InvalidPathID, false
	}

	// Get scheduler quotas
	var schedulerWithStats interface{}
	schedulerWithStats = c.scheduler
	stats, hasStats := schedulerWithStats.(interface {
		GetStatistics() map[PathID]SchedulerStats
	})

	var sentQuota uint64
	if hasStats {
		if s, ok := stats.GetStatistics()[sentOnPath]; ok {
			sentQuota = s.Quota
		}
	}

	// Find a suitable path for duplication
	for pathID, state := range c.paths {
		if pathID == sentOnPath {
			continue
		}

		// Skip if sending not allowed
		if !state.sendingAllowed {
			continue
		}

		// If duplicationUnprobed, only duplicate on unprobed paths
		if c.duplicationUnprobed && state.smoothedRTT > 0 {
			continue
		}

		// Check quota difference
		var pathQuota uint64
		if hasStats {
			if s, ok := stats.GetStatistics()[pathID]; ok {
				pathQuota = s.Quota
			}
		}

		if sentQuota > pathQuota && (sentQuota-pathQuota) <= c.duplicationQuota {
			return pathID, true
		}
	}

	return InvalidPathID, false
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

// PathInfoForID returns path info by ID.
func (c *DefaultMultipathController) PathInfoForID(pathID PathID) (PathInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	state, ok := c.paths[pathID]
	if !ok {
		return PathInfo{}, false
	}
	return state.info, true
}

// GetAvailablePaths returns paths that are eligible for sending.
func (c *DefaultMultipathController) GetAvailablePaths() []PathInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths := make([]PathInfo, 0, len(c.paths))
	for _, state := range c.paths {
		if !state.sendingAllowed {
			continue
		}
		if state.potentiallyFailed {
			continue
		}
		if state.info.RemoteAddr == nil {
			continue
		}
		paths = append(paths, state.info)
	}
	return paths
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
	Validated         *bool
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

// addrsEqual compares two network addresses.
func addrsEqual(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Network() == b.Network() && a.String() == b.String()
}

func matchLocalAddr(stored, actual net.Addr) bool {
	if addrsEqual(stored, actual) {
		return true
	}
	storedUDP, okStored := stored.(*net.UDPAddr)
	actualUDP, okActual := actual.(*net.UDPAddr)
	if okStored && okActual {
		if storedUDP.IP == nil || storedUDP.IP.IsUnspecified() {
			return storedUDP.Port == actualUDP.Port
		}
		return false
	}
	storedIP, okStoredIP := stored.(*net.IPAddr)
	_, okActualIP := actual.(*net.IPAddr)
	if okStoredIP && okActualIP {
		if storedIP.IP == nil || storedIP.IP.IsUnspecified() {
			return true
		}
		return false
	}
	return false
}
