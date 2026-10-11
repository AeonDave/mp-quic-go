package ackhandler

import (
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// These tests cover IETF Multipath QUIC (draft-ietf-quic-multipath):
// every path has its own packet number space, and its packets are acknowledged using PATH_ACK frames.

func newMultipathReceivedPacketHandler() *ReceivedPacketHandler {
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.EnableMultipath()
	return h
}

func TestReceivedPacketHandlerMultipathPerPathTrackers(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()

	// Every path uses its own packet numbers, starting at 0.
	for pn := range protocol.PacketNumber(10) {
		require.False(t, handler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT, 1))
		require.NoError(t, handler.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
		require.True(t, handler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT, 1))
		// The same packet number on another path is not a duplicate.
		require.False(t, handler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT, 2))
		require.False(t, handler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT, 0))
	}
	for _, pn := range []protocol.PacketNumber{0, 1, 2, 5} {
		require.NoError(t, handler.ReceivedPacket(pn, protocol.ECT1, protocol.Encryption1RTT, now, true, 2))
	}
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 0))
	require.True(t, handler.IsPotentiallyDuplicate(0, protocol.Encryption1RTT, 0))
	require.Equal(t, []protocol.PathID{1, 2}, handler.pathIDs)

	// PATH_ACK frames acknowledge the packets received on one path.
	ack := handler.GetAckFrame(protocol.Encryption1RTT, now, false, 2)
	require.NotNil(t, ack)
	require.True(t, ack.HasPathID)
	require.Equal(t, protocol.PathID(2), ack.PathID)
	require.Equal(t, protocol.PacketNumber(5), ack.LargestAcked())
	require.True(t, ack.AcksPacket(2))
	require.False(t, ack.AcksPacket(3))
	require.False(t, ack.AcksPacket(9))
	require.Equal(t, uint64(4), ack.ECT1)

	ack = handler.GetAckFrame(protocol.Encryption1RTT, now, false, 1)
	require.NotNil(t, ack)
	require.True(t, ack.HasPathID)
	require.Equal(t, protocol.PathID(1), ack.PathID)
	require.Equal(t, protocol.PacketNumber(9), ack.LargestAcked())
	require.False(t, ack.HasMissingRanges())
	require.Zero(t, ack.ECT1)

	// path 0 also uses PATH_ACK frames
	ack = handler.GetAckFrame(protocol.Encryption1RTT, now, false, 0)
	require.NotNil(t, ack)
	require.True(t, ack.HasPathID)
	require.Zero(t, ack.PathID)
	require.Equal(t, protocol.PacketNumber(0), ack.LargestAcked())

	// no ACK for a path that didn't receive any packets
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false, 3))
	require.NotContains(t, handler.paths, protocol.PathID(3))
}

func TestReceivedPacketHandlerMultipathNoFallback(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	// two packets: an ACK is queued for path 2
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 2))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now, true, 2))
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	// the ACK for path 2 is not returned for path 1
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 1))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 0))
	ack := handler.GetAckFrame(protocol.Encryption1RTT, now, true, 2)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PathID(2), ack.PathID)
}

func TestReceivedPacketHandlerMultipathMissingPackets(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	// Packets 0 and 1 are acknowledged.
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 1))
	// Packet 2 is missing. Every path has its own packet number space, so a gap means that packets were lost,
	// and an ACK is sent immediately.
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	ack := handler.GetAckFrame(protocol.Encryption1RTT, now, true, 1)
	require.NotNil(t, ack)
	require.True(t, ack.HasMissingRanges())
}

func TestReceivedPacketHandlerMultipathAckDuePaths(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	require.Empty(t, handler.AckDuePaths(now))

	// A single ack-eliciting packet arms the ACK timer.
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 4))
	// Two ack-eliciting packets queue an ACK.
	for _, pathID := range []protocol.PathID{3, 1, 0} {
		require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, pathID))
		require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now, true, pathID))
	}
	// A non-ack-eliciting packet doesn't need to be acknowledged.
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, false, 2))
	require.Equal(t, []protocol.PathID{0, 1, 3}, handler.AckDuePaths(now))
	require.Equal(t, now.Add(protocol.MaxAckDelay), handler.GetAlarmTimeout())

	// After max_ack_delay, the ACK for path 4 is due as well.
	require.Equal(t, []protocol.PathID{0, 1, 3, 4}, handler.AckDuePaths(now.Add(protocol.MaxAckDelay)))
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 1))
	require.Equal(t, []protocol.PathID{0, 3, 4}, handler.AckDuePaths(now.Add(protocol.MaxAckDelay)))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 4))
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now.Add(protocol.MaxAckDelay), true, 4))
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 0))
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 3))
	require.Empty(t, handler.AckDuePaths(now.Add(time.Hour)))
	require.Zero(t, handler.GetAlarmTimeout())
}

func TestReceivedPacketHandlerMultipathAbandonPath(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 2))
	require.Empty(t, handler.AckDuePaths(now))

	// Abandoning the path queues an ACK immediately.
	handler.AbandonPath(1)
	require.Equal(t, []protocol.PathID{1}, handler.AckDuePaths(now))
	ack := handler.GetAckFrame(protocol.Encryption1RTT, now, true, 1)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PathID(1), ack.PathID)
	require.Empty(t, handler.AckDuePaths(now))

	// Every ack-eliciting packet received on the abandoned path is acknowledged immediately.
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.Equal(t, []protocol.PathID{1}, handler.AckDuePaths(now))
	ack = handler.GetAckFrame(protocol.Encryption1RTT, now, true, 1)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PacketNumber(2), ack.LargestAcked())
	// but not non-ack-eliciting packets
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, now, false, 1))
	require.Empty(t, handler.AckDuePaths(now))

	// path 0 can be abandoned as well
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 0))
	handler.AbandonPath(0)
	require.Equal(t, []protocol.PathID{0}, handler.AckDuePaths(now))
	ack = handler.GetAckFrame(protocol.Encryption1RTT, now, true, 0)
	require.NotNil(t, ack)
	require.Zero(t, ack.PathID)
	require.True(t, ack.HasPathID)

	// Abandoning a path without packets to acknowledge doesn't queue an ACK.
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false, 2))
	handler.AbandonPath(2)
	require.Empty(t, handler.AckDuePaths(now))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, true, 2))
	require.Zero(t, handler.GetAlarmTimeout())
	handler.AbandonPath(5) // unknown path
	require.Empty(t, handler.AckDuePaths(now))
	require.NotContains(t, handler.paths, protocol.PathID(5))
}

func TestReceivedPacketHandlerMultipathRemovePath(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.Equal(t, []protocol.PathID{1}, handler.AckDuePaths(now))

	handler.RemovePath(1)
	require.NotContains(t, handler.paths, protocol.PathID(1))
	require.Empty(t, handler.pathIDs)
	require.Empty(t, handler.AckDuePaths(now))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false, 1))
	// packets received on the path are ignored
	require.True(t, handler.IsPotentiallyDuplicate(5, protocol.Encryption1RTT, 1))
	require.NoError(t, handler.ReceivedPacket(5, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NotContains(t, handler.paths, protocol.PathID(1))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false, 1))

	// path 0 can be removed as well
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 0))
	handler.RemovePath(0)
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false, 0))
	require.True(t, handler.IsPotentiallyDuplicate(1, protocol.Encryption1RTT, 0))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, now, true, 0))
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption0RTT, now, true, 0))
	require.Empty(t, handler.AckDuePaths(now))
	require.Nil(t, handler.GetAckFrame(protocol.Encryption1RTT, now, false, 0))
	require.NotContains(t, handler.paths, protocol.PathID(0))
	require.Zero(t, handler.GetAlarmTimeout())
}

func TestReceivedPacketHandlerMultipathIgnorePacketsBelow(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	for _, pathID := range []protocol.PathID{0, 1, 2} {
		for pn := range protocol.PacketNumber(10) {
			require.NoError(t, handler.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true, pathID))
		}
	}
	handler.IgnorePacketsBelowForPath(1, 5)
	handler.IgnorePacketsBelowForPath(3, 5) // unknown path
	// An ACK frame acknowledged packets of path 0.
	handler.IgnorePacketsBelow(3)
	for _, tc := range []struct {
		pathID protocol.PathID
		lowest protocol.PacketNumber
	}{{0, 3}, {1, 5}, {2, 0}} {
		ack := handler.GetAckFrame(protocol.Encryption1RTT, now, false, tc.pathID)
		require.NotNil(t, ack)
		require.Equal(t, tc.lowest, ack.LowestAcked(), "path %d", tc.pathID)
		require.Equal(t, protocol.PacketNumber(9), ack.LargestAcked())
	}
	require.True(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT, 1))
	require.False(t, handler.IsPotentiallyDuplicate(10, protocol.Encryption1RTT, 1))
}

func TestReceivedPacketHandlerMultipath0RTT(t *testing.T) {
	handler := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	// 1-RTT packets on other paths don't affect the check that 0-RTT packets have lower packet numbers
	require.NoError(t, handler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption0RTT, now, true, 0))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, now, true, 0))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption0RTT, now, true, 0))
	require.Error(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption0RTT, now, true, 0))
	// 0-RTT and 1-RTT packets share the packet number space of path 0
	require.True(t, handler.IsPotentiallyDuplicate(2, protocol.Encryption1RTT, 0))
	require.True(t, handler.IsPotentiallyDuplicate(3, protocol.Encryption0RTT, 0))
	require.False(t, handler.IsPotentiallyDuplicate(2, protocol.Encryption1RTT, 1))
	ack := handler.GetAckFrame(protocol.Encryption1RTT, now, false, 0)
	require.NotNil(t, ack)
	require.True(t, ack.AcksPacket(1))
	require.True(t, ack.AcksPacket(2))
	require.True(t, ack.AcksPacket(3))
}

// A reordered packet received on a path after a PATH_ACK frame that acknowledged later packets of that path.
// Once the peer acknowledges the packet containing the PATH_ACK frame, there's nothing left to acknowledge
// on the path, and no PATH_ACK frame without ACK ranges is sent. Other paths are not affected.
func TestReceivedPacketHandlerMultipathIgnoreBelowReorderedPacket(t *testing.T) {
	h := newMultipathReceivedPacketHandler()
	now := monotime.Now()
	for _, pathID := range []protocol.PathID{0, 1} {
		require.NoError(t, h.ReceivedPacket(10, protocol.ECNNon, protocol.Encryption1RTT, now, true, pathID))
		require.NoError(t, h.ReceivedPacket(11, protocol.ECNNon, protocol.Encryption1RTT, now, true, pathID))
		ack := h.GetAckFrame(protocol.Encryption1RTT, now, false, pathID)
		require.NotNil(t, ack)
		require.Equal(t, []wire.AckRange{{Smallest: 10, Largest: 11}}, ack.AckRanges)
	}

	// the reordered packet was reported missing, so a PATH_ACK is queued
	require.NoError(t, h.ReceivedPacket(9, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.Equal(t, []protocol.PathID{1}, h.AckDuePaths(now))
	// the peer acknowledges the packet that contained the PATH_ACK frame
	h.IgnorePacketsBelowForPath(1, 12)
	require.Empty(t, h.AckDuePaths(now))
	require.Nil(t, h.GetAckFrame(protocol.Encryption1RTT, now, true, 1))
	require.Nil(t, h.GetAckFrame(protocol.Encryption1RTT, now.Add(time.Hour), false, 1))
	require.Zero(t, h.GetAlarmTimeout())

	// newly received packets are acknowledged
	require.NoError(t, h.ReceivedPacket(12, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	require.NoError(t, h.ReceivedPacket(13, protocol.ECNNon, protocol.Encryption1RTT, now, true, 1))
	ack := h.GetAckFrame(protocol.Encryption1RTT, now, true, 1)
	require.NotNil(t, ack)
	require.True(t, ack.HasPathID)
	require.Equal(t, protocol.PathID(1), ack.PathID)
	require.Equal(t, []wire.AckRange{{Smallest: 12, Largest: 13}}, ack.AckRanges)
	require.NotZero(t, ack.Length(protocol.Version1))
}
