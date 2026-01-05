package ackhandler

import (
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// PathPacketNumberManager manages packet numbers independently for each path.
// This is essential for multipath QUIC where each path needs its own packet
// number sequence to avoid ambiguity in ACKs.
type PathPacketNumberManager struct {
	mu sync.RWMutex

	// Per-path packet number generators for each encryption level
	pathGenerators map[protocol.PathID]map[protocol.EncryptionLevel]*perPathPacketNumberGen

	// Fallback for packets without PathID (single-path mode)
	defaultGenerator map[protocol.EncryptionLevel]*perPathPacketNumberGen
}

type perPathPacketNumberGen struct {
	highestAcked protocol.PacketNumber
	highestSent  protocol.PacketNumber
	pns          packetNumberGenerator
}

// NewPathPacketNumberManager creates a new per-path packet number manager.
func NewPathPacketNumberManager() *PathPacketNumberManager {
	return &PathPacketNumberManager{
		pathGenerators:   make(map[protocol.PathID]map[protocol.EncryptionLevel]*perPathPacketNumberGen),
		defaultGenerator: make(map[protocol.EncryptionLevel]*perPathPacketNumberGen),
	}
}

// PeekPacketNumber returns the next packet number for a path without incrementing.
func (m *PathPacketNumberManager) PeekPacketNumber(
	pathID protocol.PathID,
	encLevel protocol.EncryptionLevel,
) (protocol.PacketNumber, protocol.PacketNumberLen) {
	encLevel = normalizePacketNumberEncLevel(encLevel)
	m.mu.Lock()
	defer m.mu.Unlock()

	gen := m.getOrCreateGenerator(pathID, encLevel)
	pn := gen.pns.Peek()
	return pn, protocol.PacketNumberLengthForHeader(pn, gen.highestAcked)
}

// PopPacketNumber consumes and returns the next packet number for a path.
func (m *PathPacketNumberManager) PopPacketNumber(
	pathID protocol.PathID,
	encLevel protocol.EncryptionLevel,
) protocol.PacketNumber {
	encLevel = normalizePacketNumberEncLevel(encLevel)
	_, pn := m.PopPacketNumberWithSkip(pathID, encLevel)
	return pn
}

// PopPacketNumberWithSkip consumes and returns the next packet number for a path.
// It also reports whether an internal skip occurred.
func (m *PathPacketNumberManager) PopPacketNumberWithSkip(
	pathID protocol.PathID,
	encLevel protocol.EncryptionLevel,
) (bool, protocol.PacketNumber) {
	encLevel = normalizePacketNumberEncLevel(encLevel)
	m.mu.Lock()
	defer m.mu.Unlock()

	gen := m.getOrCreateGenerator(pathID, encLevel)
	skipped, pn := gen.pns.Pop()
	gen.highestSent = pn
	return skipped, pn
}

// SetHighestAcked updates the highest acked packet number for a path.
func (m *PathPacketNumberManager) SetHighestAcked(
	pathID protocol.PathID,
	encLevel protocol.EncryptionLevel,
	pn protocol.PacketNumber,
) {
	encLevel = normalizePacketNumberEncLevel(encLevel)
	m.mu.Lock()
	defer m.mu.Unlock()

	gen := m.getOrCreateGenerator(pathID, encLevel)
	if pn > gen.highestAcked {
		gen.highestAcked = pn
	}
}

// getOrCreateGenerator returns or creates a packet number generator for a path.
// Must be called with lock held.
func (m *PathPacketNumberManager) getOrCreateGenerator(
	pathID protocol.PathID,
	encLevel protocol.EncryptionLevel,
) *perPathPacketNumberGen {
	encLevel = normalizePacketNumberEncLevel(encLevel)
	// Use default generator for invalid path (single-path mode)
	if pathID == protocol.InvalidPathID {
		if gen, ok := m.defaultGenerator[encLevel]; ok {
			return gen
		}
		gen := &perPathPacketNumberGen{
			highestAcked: protocol.InvalidPacketNumber,
			highestSent:  protocol.InvalidPacketNumber,
			pns:          newPacketNumberGeneratorForEncryption(encLevel),
		}
		m.defaultGenerator[encLevel] = gen
		return gen
	}

	// Get or create per-path generator
	encLevelMap, ok := m.pathGenerators[pathID]
	if !ok {
		encLevelMap = make(map[protocol.EncryptionLevel]*perPathPacketNumberGen)
		m.pathGenerators[pathID] = encLevelMap
	}

	gen, ok := encLevelMap[encLevel]
	if !ok {
		gen = &perPathPacketNumberGen{
			highestAcked: protocol.InvalidPacketNumber,
			highestSent:  protocol.InvalidPacketNumber,
			pns:          newPacketNumberGeneratorForEncryption(encLevel),
		}
		encLevelMap[encLevel] = gen
	}

	return gen
}

// RemovePath removes all packet number generators for a path.
// Called when a path is closed or removed.
func (m *PathPacketNumberManager) RemovePath(pathID protocol.PathID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pathGenerators, pathID)
}

// GetHighestSent returns the highest sent packet number for a path.
func (m *PathPacketNumberManager) GetHighestSent(
	pathID protocol.PathID,
	encLevel protocol.EncryptionLevel,
) protocol.PacketNumber {
	encLevel = normalizePacketNumberEncLevel(encLevel)
	m.mu.Lock()
	defer m.mu.Unlock()
	gen := m.getOrCreateGenerator(pathID, encLevel)
	return gen.highestSent
}

func newPacketNumberGeneratorForEncryption(encLevel protocol.EncryptionLevel) packetNumberGenerator {
	if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
		return newSkippingPacketNumberGenerator(0, protocol.SkipPacketInitialPeriod, protocol.SkipPacketMaxPeriod)
	}
	return newSequentialPacketNumberGenerator(0)
}

func normalizePacketNumberEncLevel(encLevel protocol.EncryptionLevel) protocol.EncryptionLevel {
	if encLevel == protocol.Encryption0RTT {
		return protocol.Encryption1RTT
	}
	return encLevel
}
