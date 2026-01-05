package quic

import (
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestMultipathReinjectionPolicy_Creation(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	require.NotNil(t, policy)
	require.False(t, policy.IsEnabled())
	require.Equal(t, 50*time.Millisecond, policy.GetReinjectionDelay())
	require.Equal(t, 2, policy.GetMaxReinjections())
	require.Equal(t, 0, policy.GetMaxReinjectionQueuePerPath())
	require.Zero(t, policy.GetMinReinjectionInterval())
}

func TestMultipathReinjectionPolicy_EnableDisable(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()

	require.False(t, policy.IsEnabled())

	policy.Enable()
	require.True(t, policy.IsEnabled())

	policy.Disable()
	require.False(t, policy.IsEnabled())
}

func TestMultipathReinjectionPolicy_ReinjectionDelay(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()

	// Default is 50ms
	require.Equal(t, 50*time.Millisecond, policy.GetReinjectionDelay())

	// Set to 100ms
	policy.SetReinjectionDelay(100 * time.Millisecond)
	require.Equal(t, 100*time.Millisecond, policy.GetReinjectionDelay())

	// Set to 1 second
	policy.SetReinjectionDelay(time.Second)
	require.Equal(t, time.Second, policy.GetReinjectionDelay())
}

func TestMultipathReinjectionPolicy_MaxReinjections(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()

	// Default is 2
	require.Equal(t, 2, policy.GetMaxReinjections())

	// Set to 5
	policy.SetMaxReinjections(5)
	require.Equal(t, 5, policy.GetMaxReinjections())

	// Cannot go negative
	policy.SetMaxReinjections(-1)
	require.Equal(t, 0, policy.GetMaxReinjections())
}

func TestMultipathReinjectionPolicy_MaxQueuePerPath(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()

	require.Equal(t, 0, policy.GetMaxReinjectionQueuePerPath())

	policy.SetMaxReinjectionQueuePerPath(3)
	require.Equal(t, 3, policy.GetMaxReinjectionQueuePerPath())

	policy.SetMaxReinjectionQueuePerPath(-1)
	require.Equal(t, 0, policy.GetMaxReinjectionQueuePerPath())
}

func TestMultipathReinjectionPolicy_MinInterval(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()

	require.Zero(t, policy.GetMinReinjectionInterval())

	policy.SetMinReinjectionInterval(25 * time.Millisecond)
	require.Equal(t, 25*time.Millisecond, policy.GetMinReinjectionInterval())

	policy.SetMinReinjectionInterval(-time.Millisecond)
	require.Zero(t, policy.GetMinReinjectionInterval())
}

func TestMultipathReinjectionManager_PathBackoff(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetMinReinjectionInterval(50 * time.Millisecond)
	manager := NewMultipathReinjectionManager(policy)

	pathID := protocol.PathID(1)
	now := time.Now()

	ok, _ := manager.canReinjectOnPath(pathID, now)
	require.True(t, ok)

	manager.MarkReinjected(1, pathID)
	ok, next := manager.canReinjectOnPath(pathID, now)
	require.False(t, ok)
	require.True(t, next.After(now))

	ok, _ = manager.canReinjectOnPath(pathID, next)
	require.True(t, ok)
}

func TestMultipathReinjectionPolicy_PreferredPaths(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()

	path1 := protocol.PathID(1)
	path2 := protocol.PathID(2)
	path3 := protocol.PathID(3)

	// Initially all paths are allowed
	require.True(t, policy.IsPreferredPathForReinjection(path1))
	require.True(t, policy.IsPreferredPathForReinjection(path2))
	require.True(t, policy.IsPreferredPathForReinjection(path3))

	// Add path1 and path2 as preferred
	policy.AddPreferredPathForReinjection(path1)
	policy.AddPreferredPathForReinjection(path2)

	// Now only path1 and path2 are allowed
	require.True(t, policy.IsPreferredPathForReinjection(path1))
	require.True(t, policy.IsPreferredPathForReinjection(path2))
	require.False(t, policy.IsPreferredPathForReinjection(path3))

	// Remove path1
	policy.RemovePreferredPathForReinjection(path1)
	require.False(t, policy.IsPreferredPathForReinjection(path1))
	require.True(t, policy.IsPreferredPathForReinjection(path2))
}

func TestMultipathReinjectionPolicy_ShouldReinjectFrame(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()

	// Crypto frames should be reinjected (default)
	cryptoFrame := &wire.CryptoFrame{}
	require.True(t, policy.ShouldReinjectFrame(cryptoFrame))

	// Stream frames should always be reinjected
	streamFrame := &wire.StreamFrame{}
	require.True(t, policy.ShouldReinjectFrame(streamFrame))

	// Control frames should be reinjected (default)
	maxDataFrame := &wire.MaxDataFrame{}
	require.True(t, policy.ShouldReinjectFrame(maxDataFrame))

	// Ping frames should not be reinjected
	pingFrame := &wire.PingFrame{}
	require.False(t, policy.ShouldReinjectFrame(pingFrame))

	// When disabled, nothing should be reinjected
	policy.Disable()
	require.False(t, policy.ShouldReinjectFrame(cryptoFrame))
	require.False(t, policy.ShouldReinjectFrame(streamFrame))
	require.False(t, policy.ShouldReinjectFrame(maxDataFrame))
}

func TestMultipathReinjectionManager_OnPacketLost(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	manager := NewMultipathReinjectionManager(policy)

	pathID := protocol.PathID(1)
	pn := protocol.PacketNumber(42)
	encLevel := protocol.Encryption1RTT

	frames := []ackhandler.Frame{
		{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
	}

	// Report packet loss
	manager.OnPacketLost(pathID, pn, encLevel, frames)

	// Should be in pending
	pending, _ := manager.GetStatistics()
	require.Equal(t, 1, pending)
}

func TestMultipathReinjectionManager_GetPendingReinjections(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(10 * time.Millisecond)
	manager := NewMultipathReinjectionManager(policy)

	pathID := protocol.PathID(1)
	pn := protocol.PacketNumber(42)
	encLevel := protocol.Encryption1RTT

	frames := []ackhandler.Frame{
		{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
	}

	now := time.Now()
	manager.OnPacketLost(pathID, pn, encLevel, frames)

	// Immediately - should not be ready
	ready := manager.GetPendingReinjections(now)
	require.Empty(t, ready)

	// After delay - should be ready
	ready = manager.GetPendingReinjections(now.Add(20 * time.Millisecond))
	require.Len(t, ready, 1)
	require.Equal(t, pn, ready[0].PacketNumber)
	require.Equal(t, pathID, ready[0].OriginalPathID)
}

func TestMultipathReinjectionManager_MaxReinjections(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetMaxReinjections(2)
	policy.SetReinjectionDelay(1 * time.Millisecond)
	manager := NewMultipathReinjectionManager(policy)

	pathID := protocol.PathID(1)
	pn := protocol.PacketNumber(42)
	encLevel := protocol.Encryption1RTT

	frames := []ackhandler.Frame{
		{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
	}

	// First loss
	manager.OnPacketLost(pathID, pn, encLevel, frames)
	time.Sleep(5 * time.Millisecond)
	ready := manager.GetPendingReinjections(time.Now())
	require.Len(t, ready, 1)
	manager.MarkReinjected(pn, protocol.PathID(2))

	// Second loss
	manager.OnPacketLost(pathID, pn, encLevel, frames)
	time.Sleep(5 * time.Millisecond)
	ready = manager.GetPendingReinjections(time.Now())
	require.Len(t, ready, 1)
	manager.MarkReinjected(pn, protocol.PathID(3))

	// Third loss - should be rejected (exceeded max)
	manager.OnPacketLost(pathID, pn, encLevel, frames)
	time.Sleep(5 * time.Millisecond)
	ready = manager.GetPendingReinjections(time.Now())
	require.Empty(t, ready) // Exceeded max reinjections
}

func TestMultipathReinjectionManager_OnPacketAcked(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	manager := NewMultipathReinjectionManager(policy)

	pathID := protocol.PathID(1)
	pn := protocol.PacketNumber(42)
	encLevel := protocol.Encryption1RTT

	frames := []ackhandler.Frame{
		{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
	}

	manager.OnPacketLost(pathID, pn, encLevel, frames)

	// Should be in pending
	pending, _ := manager.GetStatistics()
	require.Equal(t, 1, pending)

	// ACK the packet
	manager.OnPacketAcked(pn)

	// Should be removed from pending
	pending, _ = manager.GetStatistics()
	require.Equal(t, 0, pending)
}

func TestMultipathReinjectionManager_Statistics(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(1 * time.Millisecond)
	manager := NewMultipathReinjectionManager(policy)

	// Add 3 lost packets
	for i := 0; i < 3; i++ {
		frames := []ackhandler.Frame{
			{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
		}
		manager.OnPacketLost(protocol.PathID(1), protocol.PacketNumber(i), protocol.Encryption1RTT, frames)
	}

	pending, reinjected := manager.GetStatistics()
	require.Equal(t, 3, pending)
	require.Equal(t, 0, reinjected)

	// Reinject them
	time.Sleep(5 * time.Millisecond)
	ready := manager.GetPendingReinjections(time.Now())
	for _, info := range ready {
		manager.MarkReinjected(info.PacketNumber, protocol.PathID(2))
	}

	pending, reinjected = manager.GetStatistics()
	require.Equal(t, 0, pending)
	require.Equal(t, 3, reinjected)
}

func TestMultipathReinjectionManager_Reset(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	manager := NewMultipathReinjectionManager(policy)

	// Add some packets
	for i := 0; i < 3; i++ {
		frames := []ackhandler.Frame{
			{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
		}
		manager.OnPacketLost(protocol.PathID(1), protocol.PacketNumber(i), protocol.Encryption1RTT, frames)
	}

	pending, _ := manager.GetStatistics()
	require.Greater(t, pending, 0)

	// Reset
	manager.Reset()

	pending, reinjected := manager.GetStatistics()
	require.Equal(t, 0, pending)
	require.Equal(t, 0, reinjected)
}
