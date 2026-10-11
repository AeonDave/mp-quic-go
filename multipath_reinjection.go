package quic

import (
	"cmp"
	"slices"
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

	// reinjectOnPTO indicates whether the frames of the packets outstanding on a path are sent on another path
	// when the path's probe timeout expires
	reinjectOnPTO bool
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

// A reinjectionKey identifies a packet.
// With IETF Multipath QUIC, every path has its own packet number space.
type reinjectionKey struct {
	pathID protocol.PathID
	pn     protocol.PacketNumber
}

// MultipathReinjectionManager manages packet reinjection across paths
type MultipathReinjectionManager struct {
	mu sync.RWMutex

	policy *MultipathReinjectionPolicy

	// pendingReinjections tracks packets waiting to be reinjected
	pendingReinjections map[reinjectionKey]*PacketReinjectionInfo

	// reinjectedPackets tracks packets that have been reinjected
	reinjectedPackets map[reinjectionKey]int
	// totalReinjections counts all reinjections (for statistics)
	totalReinjections int

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
		pendingReinjections: make(map[reinjectionKey]*PacketReinjectionInfo),
		reinjectedPackets:   make(map[reinjectionKey]int),
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

// SetReinjectOnPTO sets whether the frames of the packets outstanding on a path are sent on another path
// when the probe timeout (PTO) of the path expires (section 5.7 of draft-ietf-quic-multipath-21).
// This only applies to IETF Multipath QUIC. The frames are sent in addition to the probe packets on the path,
// if the congestion window of the other path allows. The packets are not declared lost:
// if one of them is lost later, its frames are retransmitted as usual.
// Like all reinjections, it requires the policy to be enabled.
func (p *MultipathReinjectionPolicy) SetReinjectOnPTO(enable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reinjectOnPTO = enable
}

// ReinjectsOnPTO returns whether frames are reinjected when the probe timeout of a path expires.
func (p *MultipathReinjectionPolicy) ReinjectsOnPTO() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled && p.reinjectOnPTO
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

	key := reinjectionKey{pathID: pathID, pn: pn}
	// Packet numbers are never reused: the packet won't be reported again.
	count := m.reinjectedPackets[key]
	delete(m.reinjectedPackets, key)

	if !m.policy.IsEnabled() {
		return
	}
	// Check if already reinjected too many times
	if count >= m.policy.GetMaxReinjections() {
		return
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
		ReinjectionCount: count,
		TargetPathID:     protocol.InvalidPathID, // Will be determined by scheduler
	}
	info.NextAttemptAt = info.LostTime.Add(m.policy.GetReinjectionDelay())

	m.pendingReinjections[key] = info
}

// GetPendingReinjections returns packets ready for reinjection,
// in ascending order of their path IDs and packet numbers.
func (m *MultipathReinjectionManager) GetPendingReinjections(now time.Time) []*PacketReinjectionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ready []*PacketReinjectionInfo

	for key, info := range m.pendingReinjections {
		if info.NextAttemptAt.IsZero() {
			info.NextAttemptAt = info.LostTime.Add(m.policy.GetReinjectionDelay())
		}
		if !now.Before(info.NextAttemptAt) {
			ready = append(ready, info)
			delete(m.pendingReinjections, key)
		}
	}
	slices.SortFunc(ready, func(a, b *PacketReinjectionInfo) int {
		if c := cmp.Compare(a.OriginalPathID, b.OriginalPathID); c != 0 {
			return c
		}
		return cmp.Compare(a.PacketNumber, b.PacketNumber)
	})
	return ready
}

// MarkReinjected marks a packet sent on a path as having been reinjected
func (m *MultipathReinjectionManager) MarkReinjected(pathID protocol.PathID, pn protocol.PacketNumber, targetPath protocol.PathID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.markReinjectedLocked(reinjectionKey{pathID: pathID, pn: pn}, targetPath)
}

func (m *MultipathReinjectionManager) markReinjectedLocked(key reinjectionKey, targetPath protocol.PathID) {
	m.reinjectedPackets[key]++
	m.totalReinjections++
	if targetPath != protocol.InvalidPathID {
		m.lastReinjectionAt[targetPath] = time.Now()
	}

	// Update info if still in pending (for stats)
	if info, exists := m.pendingReinjections[key]; exists {
		info.LastReinjectedAt = time.Now()
		info.TargetPathID = targetPath
		info.ReinjectionCount++
	}
}

// reinjectOnPTO is called when the frames of a packet that is outstanding on a path whose probe timeout expired
// are sent on another path. It returns false if the packet was reinjected too often already.
func (m *MultipathReinjectionManager) reinjectOnPTO(pathID protocol.PathID, pn protocol.PacketNumber, targetPath protocol.PathID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := reinjectionKey{pathID: pathID, pn: pn}
	if m.reinjectedPackets[key] >= m.policy.GetMaxReinjections() {
		return false
	}
	m.markReinjectedLocked(key, targetPath)
	return true
}

// OnPacketAcked is called when a packet sent on a path is acknowledged, removing it from tracking
func (m *MultipathReinjectionManager) OnPacketAcked(pathID protocol.PathID, pn protocol.PacketNumber) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := reinjectionKey{pathID: pathID, pn: pn}
	delete(m.pendingReinjections, key)
	delete(m.reinjectedPackets, key)
}

// GetStatistics returns reinjection statistics
func (m *MultipathReinjectionManager) GetStatistics() (pending, reinjected int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.pendingReinjections), m.totalReinjections
}

// forgetPacket removes the reinjection count of a packet.
func (m *MultipathReinjectionManager) forgetPacket(pathID protocol.PathID, pn protocol.PacketNumber) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.reinjectedPackets, reinjectionKey{pathID: pathID, pn: pn})
}

// forgetPacketsExcept removes the reinjection counts of the packets sent on a path, except for the given packets
// (in ascending order). It is called with the packets that are still outstanding on the path: the counts of other
// packets are not needed anymore. Packets whose frames are sent in a PTO probe packet are removed from the
// history without being acknowledged or reported lost.
func (m *MultipathReinjectionManager) forgetPacketsExcept(pathID protocol.PathID, outstanding []protocol.PacketNumber) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.reinjectedPackets {
		if key.pathID != pathID {
			continue
		}
		if _, ok := slices.BinarySearch(outstanding, key.pn); !ok {
			delete(m.reinjectedPackets, key)
		}
	}
}

// forgetPath removes the state kept for the packets sent on a path.
// It is called when a path is abandoned: its packets are neither acknowledged nor reported lost anymore.
func (m *MultipathReinjectionManager) forgetPath(pathID protocol.PathID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.reinjectedPackets {
		if key.pathID == pathID {
			delete(m.reinjectedPackets, key)
		}
	}
	for key := range m.pendingReinjections {
		if key.pathID == pathID {
			delete(m.pendingReinjections, key)
		}
	}
}

// Reset clears all reinjection state
func (m *MultipathReinjectionManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pendingReinjections = make(map[reinjectionKey]*PacketReinjectionInfo)
	m.reinjectedPackets = make(map[reinjectionKey]int)
	m.totalReinjections = 0
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
	m.pendingReinjections[reinjectionKey{pathID: info.OriginalPathID, pn: info.PacketNumber}] = info
}
