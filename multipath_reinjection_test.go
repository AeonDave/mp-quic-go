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

	manager.MarkReinjected(2, 1, pathID)
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

// Every packet is reinjected at most GetMaxReinjections times:
// when its frames are sent on another path because the PTO expired, and when it is lost.
// A packet is only reported lost once, so its reinjection count is removed when it is lost.
func TestMultipathReinjectionManager_MaxReinjections(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetMaxReinjections(2)
	policy.SetReinjectionDelay(1 * time.Millisecond)
	manager := NewMultipathReinjectionManager(policy)

	pathID := protocol.PathID(1)
	encLevel := protocol.Encryption1RTT
	frames := []ackhandler.Frame{
		{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}},
	}

	// packet 42 is reinjected when the PTO expires, and then lost
	require.True(t, manager.reinjectOnPTO(pathID, 42, 2))
	manager.OnPacketLost(pathID, 42, encLevel, frames)
	require.Empty(t, manager.reinjectedPackets)
	ready := manager.GetPendingReinjections(time.Now().Add(time.Second))
	require.Len(t, ready, 1)
	require.Equal(t, protocol.PacketNumber(42), ready[0].PacketNumber)
	require.Equal(t, 1, ready[0].ReinjectionCount)

	// packet 43 is reinjected twice when the PTO expires: it's not reinjected again when it is lost
	require.True(t, manager.reinjectOnPTO(pathID, 43, 2))
	require.True(t, manager.reinjectOnPTO(pathID, 43, 3))
	require.False(t, manager.reinjectOnPTO(pathID, 43, 2))
	manager.OnPacketLost(pathID, 43, encLevel, frames)
	require.Empty(t, manager.GetPendingReinjections(time.Now().Add(time.Second)))
	require.Empty(t, manager.reinjectedPackets)

	// packet 44 is reinjected when the PTO expires, and then lost while reinjection is disabled
	require.True(t, manager.reinjectOnPTO(pathID, 44, 2))
	policy.Disable()
	manager.OnPacketLost(pathID, 44, encLevel, frames)
	require.Empty(t, manager.reinjectedPackets)
}

// The reinjection counts of packets that are not outstanding anymore are removed.
func TestMultipathReinjectionManagerForgetPacketsExcept(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	manager := NewMultipathReinjectionManager(policy)
	for pn := range protocol.PacketNumber(5) {
		require.True(t, manager.reinjectOnPTO(1, pn, 2))
	}
	require.True(t, manager.reinjectOnPTO(2, 1, 1))

	manager.forgetPacketsExcept(1, []protocol.PacketNumber{1, 3, 7})
	require.Equal(t, map[reinjectionKey]int{{pathID: 1, pn: 1}: 1, {pathID: 1, pn: 3}: 1, {pathID: 2, pn: 1}: 1}, manager.reinjectedPackets)
	manager.forgetPacketsExcept(1, nil)
	require.Equal(t, map[reinjectionKey]int{{pathID: 2, pn: 1}: 1}, manager.reinjectedPackets)
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
	manager.OnPacketAcked(pathID, pn)

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
	for i := range 3 {
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
		manager.MarkReinjected(info.OriginalPathID, info.PacketNumber, protocol.PathID(2))
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
	for i := range 3 {
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

// With IETF Multipath QUIC, every path has its own packet number space.
// Packets with the same packet number that were sent on different paths are tracked separately.
func TestMultipathReinjectionManager_PacketNumbersOfDifferentPaths(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(0)
	policy.SetMaxReinjections(1)
	manager := NewMultipathReinjectionManager(policy)
	frames := func() []ackhandler.Frame {
		return []ackhandler.Frame{{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}}}
	}

	manager.OnPacketLost(1, 5, protocol.Encryption1RTT, frames())
	manager.OnPacketLost(2, 5, protocol.Encryption1RTT, frames())
	pending, _ := manager.GetStatistics()
	require.Equal(t, 2, pending)
	// acknowledging the packet sent on path 1 doesn't affect the packet sent on path 2
	manager.OnPacketAcked(1, 5)
	ready := manager.GetPendingReinjections(time.Now())
	require.Len(t, ready, 1)
	require.Equal(t, protocol.PathID(2), ready[0].OriginalPathID)
	require.Equal(t, protocol.PacketNumber(5), ready[0].PacketNumber)
	manager.MarkReinjected(2, 5, 0)

	// The packet sent on path 2 was reinjected as often as allowed.
	manager.OnPacketLost(2, 5, protocol.Encryption1RTT, frames())
	pending, _ = manager.GetStatistics()
	require.Zero(t, pending)
	// The packet with the same packet number sent on path 1 can still be reinjected.
	manager.OnPacketLost(1, 5, protocol.Encryption1RTT, frames())
	pending, _ = manager.GetStatistics()
	require.Equal(t, 1, pending)
	// the state kept for path 1 is removed when it is abandoned
	manager.forgetPath(1)
	pending, _ = manager.GetStatistics()
	require.Zero(t, pending)
}

// The packets ready for reinjection are returned in ascending order of their path IDs and packet numbers.
func TestMultipathReinjectionManager_PendingReinjectionsOrder(t *testing.T) {
	policy := NewMultipathReinjectionPolicy()
	policy.Enable()
	policy.SetReinjectionDelay(0)
	manager := NewMultipathReinjectionManager(policy)
	type packet struct {
		pathID protocol.PathID
		pn     protocol.PacketNumber
	}
	for _, p := range []packet{{3, 1}, {1, 7}, {0, 9}, {1, 2}, {3, 0}} {
		manager.OnPacketLost(p.pathID, p.pn, protocol.Encryption1RTT, []ackhandler.Frame{{Frame: &wire.StreamFrame{StreamID: 1, Data: []byte("test")}}})
	}
	var order []packet
	for _, info := range manager.GetPendingReinjections(time.Now()) {
		order = append(order, packet{info.OriginalPathID, info.PacketNumber})
	}
	require.Equal(t, []packet{{0, 9}, {1, 2}, {1, 7}, {3, 0}, {3, 1}}, order)
}
