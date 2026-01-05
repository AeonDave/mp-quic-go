package quic

import (
	"net"
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// MultipathPathState represents the current state of a path in multipath mode
type MultipathPathState int

const (
	// MultipathPathStateUnknown indicates path state is not yet determined
	MultipathPathStateUnknown MultipathPathState = iota
	// MultipathPathStateValidating indicates path is being validated
	MultipathPathStateValidating
	// MultipathPathStateActive indicates path is active and can send data
	MultipathPathStateActive
	// MultipathPathStateStandby indicates path is available but not actively used
	MultipathPathStateStandby
	// MultipathPathStateClosing indicates path is being closed
	MultipathPathStateClosing
	// MultipathPathStateClosed indicates path is closed
	MultipathPathStateClosed
)

// MultipathPath represents a single path in a multipath connection
type MultipathPath struct {
	// PathID uniquely identifies this path
	PathID protocol.PathID

	// LocalAddr is the local address for this path
	LocalAddr net.Addr

	// RemoteAddr is the remote address for this path
	RemoteAddr net.Addr

	// State is the current path state
	State MultipathPathState

	// CreatedAt is when the path was created
	CreatedAt time.Time

	// LastUsed is when the path was last used to send data
	LastUsed time.Time

	// BytesSent tracks total bytes sent on this path
	BytesSent uint64

	// BytesReceived tracks total bytes received on this path
	BytesReceived uint64

	// RTT is the current round-trip time (populated from RTT stats)
	RTT time.Duration

	// Validated indicates if the path has been validated
	Validated bool
}

// MultipathPathManager manages multiple paths in a multipath connection
type MultipathPathManager struct {
	mutex sync.RWMutex

	// paths stores all paths indexed by PathID
	paths map[protocol.PathID]*MultipathPath

	// nextPathID is the next available PathID to assign
	nextPathID protocol.PathID

	// primaryPath is the initial/primary path
	primaryPath protocol.PathID

	// activePaths tracks which paths are currently active
	activePaths map[protocol.PathID]bool

	// perspective indicates if this is client or server
	perspective protocol.Perspective

	// enabled indicates if multipath is enabled for this connection
	enabled bool
}

// NewMultipathPathManager creates a new multipath path manager
func NewMultipathPathManager(perspective protocol.Perspective) *MultipathPathManager {
	pm := &MultipathPathManager{
		paths:       make(map[protocol.PathID]*MultipathPath),
		activePaths: make(map[protocol.PathID]bool),
		perspective: perspective,
		enabled:     false,
		nextPathID:  1, // Start from 1, 0 is reserved for primary
	}
	return pm
}

// EnableMultipath enables multipath support
func (pm *MultipathPathManager) EnableMultipath() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.enabled = true
}

// IsMultipathEnabled returns whether multipath is enabled
func (pm *MultipathPathManager) IsMultipathEnabled() bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.enabled
}

// AddPath adds a new path to the manager
func (pm *MultipathPathManager) AddPath(localAddr, remoteAddr net.Addr) protocol.PathID {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.enabled {
		// If multipath not enabled, return invalid path ID
		return protocol.InvalidPathID
	}

	pathID := pm.nextPathID
	pm.nextPathID++

	path := &MultipathPath{
		PathID:     pathID,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		State:      MultipathPathStateValidating,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		Validated:  false,
	}

	pm.paths[pathID] = path

	return pathID
}

// SetPrimaryPath sets the primary path (usually path 0)
func (pm *MultipathPathManager) SetPrimaryPath(localAddr, remoteAddr net.Addr) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Primary path always uses PathID 0
	path := &MultipathPath{
		PathID:     0,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		State:      MultipathPathStateActive,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		Validated:  true, // Primary path is pre-validated
	}

	pm.paths[0] = path
	pm.primaryPath = 0
	pm.activePaths[0] = true
}

// GetPath returns a path by ID
func (pm *MultipathPathManager) GetPath(pathID protocol.PathID) *MultipathPath {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.paths[pathID]
}

// GetActivePaths returns a slice of all active paths
func (pm *MultipathPathManager) GetActivePaths() []*MultipathPath {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	var active []*MultipathPath
	for pathID := range pm.activePaths {
		if path, ok := pm.paths[pathID]; ok && path.State == MultipathPathStateActive {
			active = append(active, path)
		}
	}
	return active
}

// GetAllPaths returns all paths
func (pm *MultipathPathManager) GetAllPaths() []*MultipathPath {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	paths := make([]*MultipathPath, 0, len(pm.paths))
	for _, path := range pm.paths {
		paths = append(paths, path)
	}
	return paths
}

// ActivatePath marks a path as active
func (pm *MultipathPathManager) ActivatePath(pathID protocol.PathID) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	path, ok := pm.paths[pathID]
	if !ok {
		return false
	}

	if !path.Validated {
		return false // Cannot activate unvalidated path
	}

	path.State = MultipathPathStateActive
	pm.activePaths[pathID] = true
	return true
}

// ValidatePath marks a path as validated
func (pm *MultipathPathManager) ValidatePath(pathID protocol.PathID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if path, ok := pm.paths[pathID]; ok {
		path.Validated = true
		// Auto-activate validated paths
		if pm.enabled {
			path.State = MultipathPathStateActive
			pm.activePaths[pathID] = true
		}
	}
}

// ClosePath closes a path
func (pm *MultipathPathManager) ClosePath(pathID protocol.PathID) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if path, ok := pm.paths[pathID]; ok {
		path.State = MultipathPathStateClosed
		delete(pm.activePaths, pathID)
	}
}

// HandleAddAddressFrame processes an ADD_ADDRESS frame
func (pm *MultipathPathManager) HandleAddAddressFrame(frame *wire.AddAddressFrame) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.enabled {
		return // Ignore if multipath not enabled
	}

	primary, ok := pm.paths[pm.primaryPath]
	if !ok || primary.LocalAddr == nil {
		return
	}

	pathID := pm.nextPathID
	pm.nextPathID++

	pm.paths[pathID] = &MultipathPath{
		PathID:     pathID,
		LocalAddr:  primary.LocalAddr,
		RemoteAddr: frame.GetUDPAddr(),
		State:      MultipathPathStateValidating,
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		Validated:  false,
	}
}

// HandleClosePathFrame processes a CLOSE_PATH frame
func (pm *MultipathPathManager) HandleClosePathFrame(frame *wire.ClosePathFrame) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if path, ok := pm.paths[protocol.PathID(frame.PathID)]; ok {
		path.State = MultipathPathStateClosed
		delete(pm.activePaths, protocol.PathID(frame.PathID))
	}
}

// UpdatePathRTT updates the RTT for a path
func (pm *MultipathPathManager) UpdatePathRTT(pathID protocol.PathID, rtt time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if path, ok := pm.paths[pathID]; ok {
		path.RTT = rtt
	}
}

// RecordPathUsage updates usage statistics for a path
func (pm *MultipathPathManager) RecordPathUsage(pathID protocol.PathID, bytesSent uint64) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if path, ok := pm.paths[pathID]; ok {
		path.LastUsed = time.Now()
		path.BytesSent += bytesSent
	}
}

// GetPathCount returns the total number of paths
func (pm *MultipathPathManager) GetPathCount() int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return len(pm.paths)
}

// GetActivePathCount returns the number of active paths
func (pm *MultipathPathManager) GetActivePathCount() int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return len(pm.activePaths)
}

// GetPrimaryPathID returns the primary path ID
func (pm *MultipathPathManager) GetPrimaryPathID() protocol.PathID {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.primaryPath
}
