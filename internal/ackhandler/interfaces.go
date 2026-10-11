package ackhandler

import (
	"iter"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	// pathAcks are the PATH_ACK frames contained in the packet (IETF Multipath QUIC),
	// largestAcked refers to the ACK frame.
	SentPacket(t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrames []StreamFrame, frames []Frame, encLevel protocol.EncryptionLevel, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket, isPathProbePacket bool, pathID protocol.PathID, pathAcks ...PathAck)
	// ReceivedAck processes an ACK frame.
	// It does not store a copy of the frame.
	ReceivedAck(f *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* 1-RTT packet acked */, error)
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
	// SetECNEnabled is called when the connection switched to a sendConn that can or can't set the ECN bits
	// (RFC 9000 connection migration by the client).
	SetECNEnabled(enabled bool)

	// BytesInFlight returns the bytes in flight of all paths.
	BytesInFlight() protocol.ByteCount
	SetPacketObserver(PacketObserver)
	SetCongestionControlFactory(func(protocol.PathID, *utils.RTTStats, protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos)
	AddPath(_ protocol.PathID, addressValidated bool)
	// AbandonPath declares all packets sent on a path lost.
	AbandonPath(protocol.PathID, monotime.Time)
	RemovePath(protocol.PathID, monotime.Time)
	PathCongestionState(protocol.PathID) (cwnd, bytesInFlight protocol.ByteCount, ok bool)
	GetPathRTTStats(protocol.PathID) *utils.RTTStats
	ECNModeForPath(protocol.PathID) protocol.ECN

	// EnableMultipath enables IETF Multipath QUIC.
	EnableMultipath(ignorePacketsBelow func(protocol.PathID, protocol.PacketNumber))
	SetPathAddressValidated(protocol.PathID, monotime.Time)
	// AmplificationBudgetForPath returns the number of bytes that can be sent on a path
	// before the anti-amplification limit of the path is reached.
	// For path 0, this is the anti-amplification limit of the handshake.
	AmplificationBudgetForPath(protocol.PathID) protocol.ByteCount
	ReceivedBytesForPath(_ protocol.PathID, _ protocol.ByteCount, rcvTime monotime.Time)
	SendModeForPath(_ protocol.PathID, now monotime.Time) SendMode
	TimeUntilSendForPath(protocol.PathID) monotime.Time
	QueueProbePacketForPath(protocol.PathID) bool /* was a packet queued */
	NextProbePath() (protocol.PathID, bool)
	SetMaxDatagramSizeForPath(protocol.PathID, protocol.ByteCount)
	MigratedPathForPath(_ protocol.PathID, now monotime.Time, initialMaxPacketSize protocol.ByteCount)
	// MaxPTO returns the largest PTO of all paths that were not removed.
	MaxPTO(includeMaxAckDelay bool) time.Duration
	// OutstandingPackets iterates over the outstanding packets sent on a path (IETF Multipath QUIC).
	OutstandingPackets(protocol.PathID) iter.Seq[PacketEvent]
	// DeclareOutstandingLost declares the outstanding packets sent on a path lost (IETF Multipath QUIC).
	DeclareOutstandingLost(protocol.PathID, monotime.Time)
}
