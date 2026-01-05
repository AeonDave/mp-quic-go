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

func TestGenerateACKsForPacketNumberSpaces(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	now := monotime.Now()
	sendTime := now.Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT0, protocol.EncryptionInitial, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(5, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECT0, protocol.EncryptionInitial, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))

	// Initial
	initialAck := handler.GetAckFrame(protocol.EncryptionInitial, now, true, protocol.InvalidPathID)
	require.NotNil(t, initialAck)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 3}}, initialAck.AckRanges)
	require.Zero(t, initialAck.DelayTime)
	require.EqualValues(t, 2, initialAck.ECT0)
	require.Zero(t, initialAck.ECT1)
	require.Zero(t, initialAck.ECNCE)

	// Handshake
	handshakeAck := handler.GetAckFrame(protocol.EncryptionHandshake, now, true, protocol.InvalidPathID)
	require.NotNil(t, handshakeAck)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, handshakeAck.AckRanges)
	require.Zero(t, handshakeAck.DelayTime)
	require.Zero(t, handshakeAck.ECT0)
	require.EqualValues(t, 2, handshakeAck.ECT1)
	require.Zero(t, handshakeAck.ECNCE)

	// 1-RTT
	oneRTTAck := handler.GetAckFrame(protocol.Encryption1RTT, now, true, protocol.InvalidPathID)
	require.NotNil(t, oneRTTAck)
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 5}}, oneRTTAck.AckRanges)
	require.Equal(t, time.Second, oneRTTAck.DelayTime)
	require.Zero(t, oneRTTAck.ECT0)
	require.Zero(t, oneRTTAck.ECT1)
	require.EqualValues(t, 2, oneRTTAck.ECNCE)
}

func TestReceive0RTTAnd1RTT(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	sendTime := monotime.Now().Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))

	ack := handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true, protocol.InvalidPathID)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 3}}, ack.AckRanges)

	// 0-RTT packets with higher packet numbers than 1-RTT packets are rejected...
	require.Error(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true, protocol.InvalidPathID))
	// ... but reordered 0-RTT packets are allowed
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true, protocol.InvalidPathID))
}

func TestDropPackets(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	sendTime := monotime.Now().Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.EncryptionInitial, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.EncryptionHandshake, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))

	// Initial
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionInitial, monotime.Now(), true, protocol.InvalidPathID))
	handler.DropPackets(protocol.EncryptionInitial)
	require.Nil(t, handler.GetAckFrame(protocol.EncryptionInitial, monotime.Now(), true, protocol.InvalidPathID))

	// Handshake
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionHandshake, monotime.Now(), true, protocol.InvalidPathID))
	handler.DropPackets(protocol.EncryptionHandshake)
	require.Nil(t, handler.GetAckFrame(protocol.EncryptionHandshake, monotime.Now(), true, protocol.InvalidPathID))

	// 1-RTT
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true, protocol.InvalidPathID))

	// 0-RTT is a no-op
	handler.DropPackets(protocol.Encryption0RTT)
}

func TestAckRangePruning(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	sendTime := monotime.Now()
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))

	ack := handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true, protocol.InvalidPathID)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ack.AckRanges)

	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))
	handler.IgnorePacketsBelow(2)
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))

	ack = handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true, protocol.InvalidPathID)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 4}}, ack.AckRanges)
}

func TestPacketDuplicateDetection(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)
	sendTime := monotime.Now()

	// 1-RTT is tested separately at the end
	encLevels := []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
	}

	for _, encLevel := range encLevels {
		// first, packet 3 is not a duplicate
		require.False(t, handler.IsPotentiallyDuplicate(3, encLevel, protocol.InvalidPathID))
		require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, encLevel, sendTime, true, protocol.InvalidPathID))
		// now packet 3 is considered a duplicate
		require.True(t, handler.IsPotentiallyDuplicate(3, encLevel, protocol.InvalidPathID))
	}

	// 1-RTT
	require.True(t, handler.IsPotentiallyDuplicate(3, protocol.Encryption1RTT, protocol.InvalidPathID))
	require.False(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT, protocol.InvalidPathID))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true, protocol.InvalidPathID))
	require.True(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT, protocol.InvalidPathID))
}
