package congestion

import (
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount)
	// OnPersistentCongestion is called when persistent congestion is established (section 7.6 of RFC 9002).
	// It is called after OnCongestionEvent was called for the lost packets.
	OnPersistentCongestion()
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(protocol.ByteCount)
}

// A SendAlgorithmWithDebugInfos is a SendAlgorithm that exposes some debug infos
type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() protocol.ByteCount
}

// State is the state of a congestion controller that another controller can continue with,
// such that the response to the losses detected so far is kept (section 7.3.2 of RFC 9002).
type State struct {
	CongestionWindow   protocol.ByteCount
	SlowStartThreshold protocol.ByteCount

	LargestSentPacketNumber  protocol.PacketNumber
	LargestAckedPacketNumber protocol.PacketNumber
	// The largest packet number sent when the congestion window was last reduced.
	// The recovery period ends when a packet sent after it is acknowledged.
	LargestSentAtLastCutback protocol.PacketNumber
}

// A StateExporter is a congestion controller that another controller can take over from.
type StateExporter interface {
	State() State
}

// A StateImporter is a congestion controller that can continue with the state of another controller.
type StateImporter interface {
	TakeOverState(State)
}
