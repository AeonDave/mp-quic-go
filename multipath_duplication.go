package quic

import (
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// MultipathDuplicationPolicy defines when and how to duplicate packets across paths
type MultipathDuplicationPolicy struct {
	mu sync.RWMutex

	// Enabled indicates if duplication is active
	enabled bool

	// DuplicateStreams is a set of stream IDs to always duplicate
	duplicateStreams map[protocol.StreamID]bool

	// DuplicateCryptoFrames indicates whether to duplicate crypto handshake frames
	duplicateCryptoFrames bool

	// DuplicateResets indicates whether to duplicate RST_STREAM frames
	duplicateResets bool

	// MaxDuplicates is the maximum number of path copies (including original)
	maxDuplicates int

	// DuplicatePathCount is how many paths to send duplicates on (0 = all available)
	duplicatePathCount int
}

// NewMultipathDuplicationPolicy creates a new duplication policy with defaults
func NewMultipathDuplicationPolicy() *MultipathDuplicationPolicy {
	return &MultipathDuplicationPolicy{
		enabled:               false,
		duplicateStreams:      make(map[protocol.StreamID]bool),
		duplicateCryptoFrames: true, // Crypto frames are critical
		duplicateResets:       true, // Connection control is critical
		maxDuplicates:         3,    // Original + 2 duplicates max
		duplicatePathCount:    2,    // Send on 2 paths total (including original)
	}
}

// Enable enables packet duplication
func (p *MultipathDuplicationPolicy) Enable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = true
}

// Disable disables packet duplication
func (p *MultipathDuplicationPolicy) Disable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = false
}

// IsEnabled returns whether duplication is enabled
func (p *MultipathDuplicationPolicy) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// AddStreamForDuplication marks a stream for packet duplication
func (p *MultipathDuplicationPolicy) AddStreamForDuplication(streamID protocol.StreamID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.duplicateStreams[streamID] = true
}

// RemoveStreamForDuplication removes a stream from duplication
func (p *MultipathDuplicationPolicy) RemoveStreamForDuplication(streamID protocol.StreamID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.duplicateStreams, streamID)
}

// ShouldDuplicateStream returns whether frames for this stream should be duplicated
func (p *MultipathDuplicationPolicy) ShouldDuplicateStream(streamID protocol.StreamID) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled && p.duplicateStreams[streamID]
}

// ShouldDuplicateCrypto returns whether crypto frames should be duplicated
func (p *MultipathDuplicationPolicy) ShouldDuplicateCrypto() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled && p.duplicateCryptoFrames
}

// ShouldDuplicateReset returns whether RST_STREAM frames should be duplicated
func (p *MultipathDuplicationPolicy) ShouldDuplicateReset() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled && p.duplicateResets
}

// GetDuplicatePathCount returns how many paths to use for duplication
func (p *MultipathDuplicationPolicy) GetDuplicatePathCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.duplicatePathCount
}

// SetDuplicatePathCount sets how many paths to use for duplication
func (p *MultipathDuplicationPolicy) SetDuplicatePathCount(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if count < 1 {
		count = 1
	}
	if count > p.maxDuplicates {
		count = p.maxDuplicates
	}
	p.duplicatePathCount = count
}

// SetDuplicateCryptoFrames sets whether to duplicate crypto frames
func (p *MultipathDuplicationPolicy) SetDuplicateCryptoFrames(enable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.duplicateCryptoFrames = enable
}

// SetDuplicateResets sets whether to duplicate reset frames
func (p *MultipathDuplicationPolicy) SetDuplicateResets(enable bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.duplicateResets = enable
}
