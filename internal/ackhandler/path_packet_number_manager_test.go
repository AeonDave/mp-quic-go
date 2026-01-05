package ackhandler

import (
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestPathPacketNumberManager_BasicFunctionality(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	// First packet should be 0
	pn1, pnLen := m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(0), pn1)
	require.Equal(t, protocol.PacketNumberLen2, pnLen)

	// Pop should return same number
	pn2 := m.PopPacketNumber(pathID, protocol.Encryption1RTT)
	require.Equal(t, pn1, pn2)

	// Next peek should return incremented
	pn3, _ := m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	require.Greater(t, pn3, pn2)
}

func TestPathPacketNumberManager_IndependentPaths(t *testing.T) {
	m := NewPathPacketNumberManager()
	path1 := protocol.PathID(1)
	path2 := protocol.PathID(2)

	// Pop from path 1
	pn1 := m.PopPacketNumber(path1, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(0), pn1)

	// Pop from path 2 should also start at 0
	pn2 := m.PopPacketNumber(path2, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(0), pn2)

	// Paths should maintain independent sequences
	for i := 0; i < 10; i++ {
		m.PopPacketNumber(path1, protocol.Encryption1RTT)
	}

	pn2Next, _ := m.PeekPacketNumber(path2, protocol.Encryption1RTT)
	require.Less(t, pn2Next, protocol.PacketNumber(5), "Path 2 should not be affected by path 1")
}

func TestPathPacketNumberManager_IndependentEncryptionLevels(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	// Each encryption level has independent sequence
	pnInitial := m.PopPacketNumber(pathID, protocol.EncryptionInitial)
	pnHandshake := m.PopPacketNumber(pathID, protocol.EncryptionHandshake)
	pn1RTT := m.PopPacketNumber(pathID, protocol.Encryption1RTT)

	require.Equal(t, protocol.PacketNumber(0), pnInitial)
	require.Equal(t, protocol.PacketNumber(0), pnHandshake)
	require.Equal(t, protocol.PacketNumber(0), pn1RTT)

	// Advance one level
	m.PopPacketNumber(pathID, protocol.EncryptionHandshake)
	m.PopPacketNumber(pathID, protocol.EncryptionHandshake)

	// Others should be unaffected
	pn1RTTNext, _ := m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	require.Less(t, pn1RTTNext, protocol.PacketNumber(5))
}

func TestPathPacketNumberManager_PacketNumberLength(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	tests := []struct {
		highestAcked protocol.PacketNumber
		next         protocol.PacketNumber
	}{
		{0, 10},
		{0, 255},
		{0, 256},
		{0, 1000},
		{0, 65535},
		{0, 65536},
		{0, 100000},
		{0, 16777216},
	}

	for _, tt := range tests {
		m.SetHighestAcked(pathID, protocol.Encryption1RTT, tt.highestAcked)

		// Set next manually by popping until we reach it
		for {
			current, _ := m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
			if current >= tt.next {
				break
			}
			m.PopPacketNumber(pathID, protocol.Encryption1RTT)
		}

		_, pnLen := m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
		expectedLen := protocol.PacketNumberLengthForHeader(tt.next, tt.highestAcked)
		require.Equal(t, expectedLen, pnLen,
			"highestAcked=%d, next=%d, diff=%d", tt.highestAcked, tt.next, tt.next-tt.highestAcked)
	}
}

func TestPathPacketNumberManager_HighestAckedUpdates(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	// Send several packets
	for i := 0; i < 10; i++ {
		m.PopPacketNumber(pathID, protocol.Encryption1RTT)
	}

	// ACK packet 5
	m.SetHighestAcked(pathID, protocol.Encryption1RTT, 5)

	// Packet number length should be based on new highest acked
	_, pnLen := m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumberLen2, pnLen)

	// ACK out of order (packet 3) should not update highest
	m.SetHighestAcked(pathID, protocol.Encryption1RTT, 3)

	// Should still be based on packet 5
	_, pnLen = m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumberLen2, pnLen)
}

func TestPathPacketNumberManager_SkipPacketNumbers(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	var lastPN protocol.PacketNumber
	skippedCount := 0

	// Generate enough packet numbers to guarantee at least one skip.
	for i := 0; i < 600; i++ {
		pn := m.PopPacketNumber(pathID, protocol.Encryption1RTT)
		if i > 0 && pn != lastPN+1 {
			skippedCount++
			require.Equal(t, lastPN+2, pn, "Should skip exactly one packet number")
		}
		lastPN = pn
	}

	// Should have skipped some packets for anti-correlation
	require.Greater(t, skippedCount, 0, "Should skip some packet numbers")
	require.Less(t, skippedCount, 10, "Should not skip too many packets")
}

func TestPathPacketNumberManager_RemovePath(t *testing.T) {
	m := NewPathPacketNumberManager()
	path1 := protocol.PathID(1)
	path2 := protocol.PathID(2)

	// Create sequences on both paths
	for i := 0; i < 5; i++ {
		m.PopPacketNumber(path1, protocol.Encryption1RTT)
		m.PopPacketNumber(path2, protocol.Encryption1RTT)
	}

	// Remove path 1
	m.RemovePath(path1)

	// Path 1 should restart from 0
	pn1, _ := m.PeekPacketNumber(path1, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(0), pn1)

	// Path 2 should be unaffected
	pn2, _ := m.PeekPacketNumber(path2, protocol.Encryption1RTT)
	require.Greater(t, pn2, protocol.PacketNumber(4))
}

func TestPathPacketNumberManager_DefaultPath(t *testing.T) {
	m := NewPathPacketNumberManager()

	// InvalidPathID should use default generator (single-path mode)
	pn1 := m.PopPacketNumber(protocol.InvalidPathID, protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(0), pn1)

	pn2 := m.PopPacketNumber(protocol.InvalidPathID, protocol.Encryption1RTT)
	require.Greater(t, pn2, pn1)

	// Should be independent from other paths
	pn3 := m.PopPacketNumber(protocol.PathID(1), protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(0), pn3)
}

func TestPathPacketNumberManager_ConcurrentAccess(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	done := make(chan bool, 10)

	// Spawn 10 goroutines that generate packet numbers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				m.PeekPacketNumber(pathID, protocol.Encryption1RTT)
				m.PopPacketNumber(pathID, protocol.Encryption1RTT)
				m.SetHighestAcked(pathID, protocol.Encryption1RTT, protocol.PacketNumber(j))
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have generated many unique packet numbers
	highestSent := m.GetHighestSent(pathID, protocol.Encryption1RTT)
	require.Greater(t, highestSent, protocol.PacketNumber(500))
}

func TestPathPacketNumberManager_GetHighestSent(t *testing.T) {
	m := NewPathPacketNumberManager()
	pathID := protocol.PathID(1)

	// Initially invalid
	highest := m.GetHighestSent(pathID, protocol.Encryption1RTT)
	require.Equal(t, protocol.InvalidPacketNumber, highest)

	// Pop some packets
	for i := 0; i < 10; i++ {
		pn := m.PopPacketNumber(pathID, protocol.Encryption1RTT)
		highest = m.GetHighestSent(pathID, protocol.Encryption1RTT)
		require.Equal(t, pn, highest)
	}
}
