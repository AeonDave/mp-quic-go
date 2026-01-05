package ackhandler

import (
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrames []StreamFrame, frames []Frame, encLevel protocol.EncryptionLevel, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket, isPathProbePacket bool, pathID protocol.PathID)
	// ReceivedAck processes an ACK frame.
	// It does not store a copy of the frame.
	ReceivedAck(f *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time, pathID protocol.PathID) (bool /* 1-RTT packet acked */, error)
	ReceivedPacket(protocol.EncryptionLevel, monotime.Time)
	ReceivedBytes(_ protocol.ByteCount, rcvTime monotime.Time)
	DropPackets(_ protocol.EncryptionLevel, rcvTime monotime.Time)
	ResetForRetry(rcvTime monotime.Time)

	// The SendMode determines if and what kind of packets can be sent.
	SendMode(now monotime.Time) SendMode
	// TimeUntilSend is the time when the next packet should be sent.
	// It is used for pacing packets.
	TimeUntilSend() monotime.Time
	SetMaxDatagramSize(count protocol.ByteCount)

	// only to be called once the handshake is complete
	QueueProbePacket(protocol.EncryptionLevel) bool /* was a packet queued */

	ECNMode(isShortHeaderPacket bool) protocol.ECN // isShortHeaderPacket should only be true for non-coalesced 1-RTT packets
	PeekPacketNumber(protocol.PathID, protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.PathID, protocol.EncryptionLevel) protocol.PacketNumber

	GetLossDetectionTimeout() monotime.Time
	OnLossDetectionTimeout(now monotime.Time) error

	MigratedPath(now monotime.Time, initialMaxPacketSize protocol.ByteCount)
}
