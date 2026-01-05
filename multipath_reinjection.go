package quic

import (
	"sync"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// MultipathReinjectionPolicy defines when and how to reinject lost packets on alternate paths
type MultipathReinjectionPolicy struct {
	mu sync.RWMutex

	// Enabled indicates if reinjection is active
	enabled bool

	// ReinjectionDelay is how long to wait before reinjecting a lost packet
	reinjectionDelay time.Duration

	// MaxReinjections is the maximum number of times a packet can be reinjected
	maxReinjections int

	// PreferredPathsForReinjection limits which paths to use for reinjection (nil = all)
	preferredPathsForReinjection map[protocol.PathID]bool

	// maxQueuePerPath limits how many pending reinjections can target a single path (0 = unlimited)
	maxQueuePerPath int

	// minReinjectionInterval adds a minimum interval between reinjections on the same path (0 = disabled)
	minReinjectionInterval time.Duration

	// reinjectCryptoFrames indicates whether to reinject crypto frames
	reinjectCryptoFrames bool

	// reinjectControlFrames indicates whether to reinject control frames
	reinjectControlFrames bool
}

// PacketReinjectionInfo tracks information about a packet pending reinjection
type PacketReinjectionInfo struct {
	OriginalPathID   protocol.PathID
	PacketNumber     protocol.PacketNumber
	EncryptionLevel  protocol.EncryptionLevel
	Frames           []ackhandler.Frame
	LostTime         time.Time
	NextAttemptAt    time.Time
	ReinjectionCount int
	LastReinjectedAt time.Time
	TargetPathID     protocol.PathID
}

// MultipathReinjectionManager manages packet reinjection across paths
type MultipathReinjectionManager struct {
	mu sync.RWMutex

	policy *MultipathReinjectionPolicy

	// pendingReinjections tracks packets waiting to be reinjected
	pendingReinjections map[protocol.PacketNumber]*PacketReinjectionInfo

	// reinjectedPackets tracks packets that have been reinjected
	reinjectedPackets map[protocol.PacketNumber]int

	// lastReinjectionAt tracks the last reinjection attempt per path
	lastReinjectionAt map[protocol.PathID]time.Time
}

// NewMultipathReinjectionPolicy creates a new reinjection policy with defaults
func NewMultipathReinjectionPolicy() *MultipathReinjectionPolicy {
	return &MultipathReinjectionPolicy{
		enabled:                      false,
		reinjectionDelay:             50 * time.Millisecond, // 50ms default
		maxReinjections:              2,                     // Max 2 reinjections per packet
		preferredPathsForReinjection: nil,                   // Use all paths
		maxQueuePerPath:              0,                     // Unlimited by default
		minReinjectionInterval:       0,                     // Disabled by default
		reinjectCryptoFrames:         true,                  // Crypto is critical
		reinjectControlFrames:        true,                  // Control frames are critical
	}
}

// NewMultipathReinjectionManager creates a new reinjection manager
func NewMultipathReinjectionManager(policy *MultipathReinjectionPolicy) *MultipathReinjectionManager {
	if policy == nil {
		policy = NewMultipathReinjectionPolicy()
	}
	return &MultipathReinjectionManager{
		policy:              policy,
		pendingReinjections: make(map[protocol.PacketNumber]*PacketReinjectionInfo),
		reinjectedPackets:   make(map[protocol.PacketNumber]int),
		lastReinjectionAt:   make(map[protocol.PathID]time.Time),
	}
}

// Enable enables packet reinjection
func (p *MultipathReinjectionPolicy) Enable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = true
}

// Disable disables packet reinjection
func (p *MultipathReinjectionPolicy) Disable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = false
}

// IsEnabled returns whether reinjection is enabled
func (p *MultipathReinjectionPolicy) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// SetReinjectionDelay sets the delay before reinjecting a lost packet
func (p *MultipathReinjectionPolicy) SetReinjectionDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reinjectionDelay = delay
}

// GetReinjectionDelay returns the current reinjection delay
func (p *MultipathReinjectionPolicy) GetReinjectionDelay() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.reinjectionDelay
}

// SetMaxReinjections sets the maximum number of reinjections per packet
func (p *MultipathReinjectionPolicy) SetMaxReinjections(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if max < 0 {
		max = 0
	}
	p.maxReinjections = max
}

// GetMaxReinjections returns the maximum number of reinjections
func (p *MultipathReinjectionPolicy) GetMaxReinjections() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxReinjections
}

// SetMaxReinjectionQueuePerPath sets the maximum queue size per target path (0 = unlimited)
func (p *MultipathReinjectionPolicy) SetMaxReinjectionQueuePerPath(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if max < 0 {
		max = 0
	}
	p.maxQueuePerPath = max
}

// GetMaxReinjectionQueuePerPath returns the maximum queue size per target path
func (p *MultipathReinjectionPolicy) GetMaxReinjectionQueuePerPath() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxQueuePerPath
}

// SetMinReinjectionInterval sets a minimum interval between reinjections on the same path
func (p *MultipathReinjectionPolicy) SetMinReinjectionInterval(interval time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if interval < 0 {
		interval = 0
	}
	p.minReinjectionInterval = interval
}

// GetMinReinjectionInterval returns the minimum reinjection interval
func (p *MultipathReinjectionPolicy) GetMinReinjectionInterval() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.minReinjectionInterval
}

// AddPreferredPathForReinjection adds a path to the preferred list
func (p *MultipathReinjectionPolicy) AddPreferredPathForReinjection(pathID protocol.PathID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.preferredPathsForReinjection == nil {
		p.preferredPathsForReinjection = make(map[protocol.PathID]bool)
	}
	p.preferredPathsForReinjection[pathID] = true
}

// RemovePreferredPathForReinjection removes a path from the preferred list
func (p *MultipathReinjectionPolicy) RemovePreferredPathForReinjection(pathID protocol.PathID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.preferredPathsForReinjection, pathID)
}

// IsPreferredPathForReinjection checks if a path is preferred for reinjection
func (p *MultipathReinjectionPolicy) IsPreferredPathForReinjection(pathID protocol.PathID) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.preferredPathsForReinjection == nil {
		return true // All paths allowed if no preference set
	}
	return p.preferredPathsForReinjection[pathID]
}

// ShouldReinjectFrame determines if a frame should be reinjected
func (p *MultipathReinjectionPolicy) ShouldReinjectFrame(frame wire.Frame) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.enabled {
		return false
	}

	switch frame.(type) {
	case *wire.CryptoFrame:
		return p.reinjectCryptoFrames
	case *wire.StreamFrame:
		return true // Always reinject stream data
	case *wire.MaxDataFrame, *wire.MaxStreamDataFrame,
		*wire.MaxStreamsFrame, *wire.DataBlockedFrame,
		*wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
		return p.reinjectControlFrames
	default:
		return false
	}
}

// OnPacketLost is called when a packet is lost and should be considered for reinjection
func (m *MultipathReinjectionManager) OnPacketLost(
	pathID protocol.PathID,
	pn protocol.PacketNumber,
	encLevel protocol.EncryptionLevel,
	frames []ackhandler.Frame,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.policy.IsEnabled() {
		return
	}

	// Check if already reinjected too many times
	if count, exists := m.reinjectedPackets[pn]; exists {
		if count >= m.policy.GetMaxReinjections() {
			return // Exceeded max reinjections
		}
	}

	// Check if any frame should be reinjected
	shouldReinject := false
	for _, f := range frames {
		if m.policy.ShouldReinjectFrame(f.Frame) {
			shouldReinject = true
			break
		}
	}

	if !shouldReinject {
		return
	}

	// Add to pending reinjections
	info := &PacketReinjectionInfo{
		OriginalPathID:   pathID,
		PacketNumber:     pn,
		EncryptionLevel:  encLevel,
		Frames:           frames,
		LostTime:         time.Now(),
		ReinjectionCount: m.reinjectedPackets[pn],
		TargetPathID:     protocol.InvalidPathID, // Will be determined by scheduler
	}
	info.NextAttemptAt = info.LostTime.Add(m.policy.GetReinjectionDelay())

	m.pendingReinjections[pn] = info
}

// GetPendingReinjections returns packets ready for reinjection
func (m *MultipathReinjectionManager) GetPendingReinjections(now time.Time) []*PacketReinjectionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ready []*PacketReinjectionInfo

	for pn, info := range m.pendingReinjections {
		if info.NextAttemptAt.IsZero() {
			info.NextAttemptAt = info.LostTime.Add(m.policy.GetReinjectionDelay())
		}
		if !now.Before(info.NextAttemptAt) {
			ready = append(ready, info)
			delete(m.pendingReinjections, pn)
		}
	}

	return ready
}

// MarkReinjected marks a packet as having been reinjected
func (m *MultipathReinjectionManager) MarkReinjected(pn protocol.PacketNumber, targetPath protocol.PathID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reinjectedPackets[pn]++
	if targetPath != protocol.InvalidPathID {
		m.lastReinjectionAt[targetPath] = time.Now()
	}

	// Update info if still in pending (for stats)
	if info, exists := m.pendingReinjections[pn]; exists {
		info.LastReinjectedAt = time.Now()
		info.TargetPathID = targetPath
		info.ReinjectionCount++
	}
}

// OnPacketAcked is called when a packet is acknowledged, removing it from tracking
func (m *MultipathReinjectionManager) OnPacketAcked(pn protocol.PacketNumber) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pendingReinjections, pn)
	delete(m.reinjectedPackets, pn)
}

// GetStatistics returns reinjection statistics
func (m *MultipathReinjectionManager) GetStatistics() (pending, reinjected int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pending = len(m.pendingReinjections)
	for _, count := range m.reinjectedPackets {
		reinjected += count
	}
	return
}

// Reset clears all reinjection state
func (m *MultipathReinjectionManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pendingReinjections = make(map[protocol.PacketNumber]*PacketReinjectionInfo)
	m.reinjectedPackets = make(map[protocol.PacketNumber]int)
	m.lastReinjectionAt = make(map[protocol.PathID]time.Time)
}

func (m *MultipathReinjectionManager) canReinjectOnPath(pathID protocol.PathID, now time.Time) (bool, time.Time) {
	if pathID == protocol.InvalidPathID {
		return true, time.Time{}
	}
	interval := m.policy.GetMinReinjectionInterval()
	if interval <= 0 {
		return true, time.Time{}
	}
	m.mu.RLock()
	last := m.lastReinjectionAt[pathID]
	m.mu.RUnlock()
	if last.IsZero() {
		return true, time.Time{}
	}
	next := last.Add(interval)
	if now.Before(next) {
		return false, next
	}
	return true, time.Time{}
}

func (m *MultipathReinjectionManager) deferReinjection(info *PacketReinjectionInfo, nextAttempt time.Time) {
	if info == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	info.NextAttemptAt = nextAttempt
	m.pendingReinjections[info.PacketNumber] = info
}
