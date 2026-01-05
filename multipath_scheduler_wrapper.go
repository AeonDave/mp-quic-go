package quic

import (
	"net"
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// SchedulingPolicy defines the scheduling algorithm to use
type SchedulingPolicy int

const (
	SchedulingPolicyRoundRobin SchedulingPolicy = iota
	SchedulingPolicyMinRTT
	SchedulingPolicyLowLatency
)

// PathSchedulerWrapper integrates the path manager with scheduling algorithms
type PathSchedulerWrapper struct {
	mu               sync.RWMutex
	pathManager      *MultipathPathManager
	scheduler        PathScheduler
	multipathEnabled bool
}

// NewMultipathScheduler creates a new multipath scheduler
func NewMultipathScheduler(pm *MultipathPathManager, policy SchedulingPolicy) *PathSchedulerWrapper {
	var scheduler PathScheduler

	switch policy {
	case SchedulingPolicyRoundRobin:
		scheduler = NewRoundRobinScheduler()
	case SchedulingPolicyMinRTT, SchedulingPolicyLowLatency:
		scheduler = NewLowLatencyScheduler()
	default:
		scheduler = NewRoundRobinScheduler()
	}

	return &PathSchedulerWrapper{
		pathManager: pm,
		scheduler:   scheduler,
	}
}

// EnableMultipath enables multipath support
func (s *PathSchedulerWrapper) EnableMultipath() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.multipathEnabled = true
}

// DisableMultipath disables multipath support
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

// selectPathInternal selects the best path for sending the next packet (internal)
func (s *PathSchedulerWrapper) selectPathInternal(hasRetransmission bool) protocol.PathID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.multipathEnabled || s.pathManager == nil {
		return protocol.InvalidPathID
	}

	// Get active paths from path manager
	activePaths := s.pathManager.GetActivePaths()
	if len(activePaths) == 0 {
		return protocol.InvalidPathID
	}

	// Convert to scheduler path info
	pathInfos := make([]SchedulerPathInfo, 0, len(activePaths))
	for _, path := range activePaths {
		if path.State != MultipathPathStateActive {
			continue
		}

		pathInfo := SchedulerPathInfo{
			PathID:         protocol.PathID(path.PathID),
			SendingAllowed: true,
			SmoothedRTT:    path.RTT,
			BytesSent:      ByteCount(path.BytesSent),
			PacketsSent:    0, // Field not available in MultipathPath
		}
		pathInfos = append(pathInfos, pathInfo)
	}

	if len(pathInfos) == 0 {
		return protocol.InvalidPathID
	}

	// Use scheduler to select path
	selected := s.scheduler.SelectPath(pathInfos, hasRetransmission)
	if selected == nil {
		return protocol.InvalidPathID
	}

	return selected.PathID
}

// RecordSent updates scheduler state after sending a packet
func (s *PathSchedulerWrapper) RecordSent(pathID protocol.PathID, packetSize uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.multipathEnabled {
		return
	}

	s.scheduler.UpdateQuota(PathID(pathID), ByteCount(packetSize))
}

// SelectPath implements MultipathController interface
func (s *PathSchedulerWrapper) SelectPath(ctx PathSelectionContext) (PathInfo, bool) {
	pathID := s.selectPathInternal(ctx.HasRetransmission)
	if pathID == protocol.InvalidPathID {
		return PathInfo{}, false
	}

	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()
	if !enabled || pm == nil {
		return PathInfo{}, false
	}

	path := pm.GetPath(pathID)
	if path == nil || path.RemoteAddr == nil {
		return PathInfo{}, false
	}

	return PathInfo{
		ID:         PathID(path.PathID),
		LocalAddr:  path.LocalAddr,
		RemoteAddr: path.RemoteAddr,
	}, true
}

// PathIDForPacket implements MultipathController interface
func (s *PathSchedulerWrapper) PathIDForPacket(remoteAddr, localAddr net.Addr) (PathID, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.multipathEnabled || s.pathManager == nil {
		return 0, false
	}

	paths := s.pathManager.GetAllPaths()
	for _, path := range paths {
		if addrsEqual(path.RemoteAddr, remoteAddr) && matchLocalAddr(path.LocalAddr, localAddr) {
			return PathID(path.PathID), true
		}
	}

	return 0, false
}

// RegisterPath registers the primary path for scheduling.
func (s *PathSchedulerWrapper) RegisterPath(info PathInfo) {
	s.mu.RLock()
	pm := s.pathManager
	s.mu.RUnlock()

	if pm == nil {
		return
	}
	if info.ID == 0 {
		pm.SetPrimaryPath(info.LocalAddr, info.RemoteAddr)
		s.EnableMultipath()
		return
	}
	pm.AddPath(info.LocalAddr, info.RemoteAddr)
}

// AddPath adds a new path and returns the assigned path ID.
func (s *PathSchedulerWrapper) AddPath(info PathInfo) (PathID, bool) {
	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()

	if !enabled || pm == nil || info.RemoteAddr == nil {
		return InvalidPathID, false
	}
	pathID := pm.AddPath(info.LocalAddr, info.RemoteAddr)
	if pathID == protocol.InvalidPathID {
		return InvalidPathID, false
	}
	return PathID(pathID), true
}

// GetAvailablePaths returns active paths suitable for scheduling.
func (s *PathSchedulerWrapper) GetAvailablePaths() []PathInfo {
	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()

	if !enabled || pm == nil {
		return nil
	}

	active := pm.GetActivePaths()
	paths := make([]PathInfo, 0, len(active))
	for _, path := range active {
		if path.RemoteAddr == nil {
			continue
		}
		paths = append(paths, PathInfo{
			ID:         PathID(path.PathID),
			LocalAddr:  path.LocalAddr,
			RemoteAddr: path.RemoteAddr,
		})
	}
	return paths
}

// PathInfoForID returns path information for a given ID.
func (s *PathSchedulerWrapper) PathInfoForID(pathID PathID) (PathInfo, bool) {
	s.mu.RLock()
	pm := s.pathManager
	s.mu.RUnlock()

	if pm == nil {
		return PathInfo{}, false
	}
	path := pm.GetPath(protocol.PathID(pathID))
	if path == nil || path.RemoteAddr == nil {
		return PathInfo{}, false
	}
	return PathInfo{
		ID:         PathID(path.PathID),
		LocalAddr:  path.LocalAddr,
		RemoteAddr: path.RemoteAddr,
	}, true
}

// ValidatePath marks a path as validated and active.
func (s *PathSchedulerWrapper) ValidatePath(pathID PathID) {
	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()

	if !enabled || pm == nil {
		return
	}
	pm.ValidatePath(protocol.PathID(pathID))
}

// HandleAddAddressFrame forwards ADD_ADDRESS frames to the path manager.
func (s *PathSchedulerWrapper) HandleAddAddressFrame(frame *wire.AddAddressFrame) {
	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()

	if !enabled || pm == nil {
		return
	}
	pm.HandleAddAddressFrame(frame)
}

// HandlePathsFrame forwards PATHS frames to the path manager.
func (s *PathSchedulerWrapper) HandlePathsFrame(frame *wire.PathsFrame) {
	_ = frame
}

// HandleClosePathFrame forwards CLOSE_PATH frames to the path manager.
func (s *PathSchedulerWrapper) HandleClosePathFrame(frame *wire.ClosePathFrame) {
	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()

	if !enabled || pm == nil {
		return
	}
	pm.HandleClosePathFrame(frame)
}

// OnPacketSent updates scheduler and path statistics.
func (s *PathSchedulerWrapper) OnPacketSent(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.IsPathProbe || ev.IsPathMTUProbe || !ev.AckEliciting {
		return
	}
	s.RecordSent(protocol.PathID(ev.PathID), uint64(ev.PacketSize))

	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()
	if !enabled || pm == nil {
		return
	}
	pm.RecordPathUsage(protocol.PathID(ev.PathID), uint64(ev.PacketSize))
}

// OnPacketAcked updates RTT statistics for a path.
func (s *PathSchedulerWrapper) OnPacketAcked(ev PathEvent) {
	if ev.PathID == InvalidPathID || ev.SmoothedRTT == 0 {
		return
	}
	s.mu.RLock()
	pm := s.pathManager
	enabled := s.multipathEnabled
	s.mu.RUnlock()
	if !enabled || pm == nil {
		return
	}
	pm.UpdatePathRTT(protocol.PathID(ev.PathID), ev.SmoothedRTT)
}

// OnPacketLost is a no-op for scheduler wrapper.
func (s *PathSchedulerWrapper) OnPacketLost(ev PathEvent) {
	_ = ev
}
