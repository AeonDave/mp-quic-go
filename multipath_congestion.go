package quic

import (
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
)

// oliaCongestionAdapter adapts OLIACongestionControl to the SendAlgorithmWithDebugInfos interface.
type oliaCongestionAdapter struct {
	*OLIACongestionControl
}

// Ensure oliaCongestionAdapter implements SendAlgorithmWithDebugInfos
var _ congestion.SendAlgorithmWithDebugInfos = &oliaCongestionAdapter{}

// InSlowStart returns whether the connection is in slow start.
func (a *oliaCongestionAdapter) InSlowStart() bool {
	return a.OLIACongestionControl.InSlowStart()
}

// InRecovery returns whether the connection is in recovery.
func (a *oliaCongestionAdapter) InRecovery() bool {
	return a.OLIACongestionControl.InRecovery()
}

// GetCongestionWindow returns the congestion window in bytes.
func (a *oliaCongestionAdapter) GetCongestionWindow() protocol.ByteCount {
	return a.OLIACongestionControl.GetCongestionWindow()
}

// OnPacketSent is called when a packet is sent.
func (a *oliaCongestionAdapter) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	a.OLIACongestionControl.OnPacketSent(sentTime.ToTime(), packetNumber, bytes, isRetransmittable)
}

// CanSend returns whether a packet can be sent.
func (a *oliaCongestionAdapter) CanSend(bytesInFlight protocol.ByteCount) bool {
	return a.OLIACongestionControl.CanSend(bytesInFlight)
}

// MaybeExitSlowStart is called when a packet is acked.
func (a *oliaCongestionAdapter) MaybeExitSlowStart() {
	// OLIA handles this internally in OnPacketAcked
}

// OnPacketAcked is called when a packet is acked.
func (a *oliaCongestionAdapter) OnPacketAcked(
	packetNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	a.OLIACongestionControl.OnPacketAcked(packetNumber, ackedBytes, priorInFlight, eventTime.ToTime())
}

// OnCongestionEvent is called when a loss or ECN-CE event occurs.
func (a *oliaCongestionAdapter) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	a.OLIACongestionControl.OnPacketLost(packetNumber, lostBytes, priorInFlight)
}

// OnRetransmissionTimeout is called on an retransmission timeout.
func (a *oliaCongestionAdapter) OnRetransmissionTimeout(packetsRetransmitted bool) {
	a.OLIACongestionControl.OnRetransmissionTimeout(packetsRetransmitted)
}

// SetMaxDatagramSize sets the max datagram size.
func (a *oliaCongestionAdapter) SetMaxDatagramSize(size protocol.ByteCount) {
	a.OLIACongestionControl.SetMaxDatagramSize(size)
}

// HasPacingBudget returns whether there is pacing budget available.
func (a *oliaCongestionAdapter) HasPacingBudget(now monotime.Time) bool {
	// OLIA doesn't implement pacing
	return true
}

// TimeUntilSend returns when the next packet should be sent.
func (a *oliaCongestionAdapter) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	// OLIA doesn't implement pacing
	if a.CanSend(bytesInFlight) {
		return monotime.Now()
	}
	// Return far future (1 hour from now)
	return monotime.Now().Add(time.Hour)
}

// NewOLIACongestionControlFactory creates a factory function for OLIA congestion controllers.
// This factory is used by sent_packet_handler to create per-path OLIA instances.
func NewOLIACongestionControlFactory(sharedState *oliaSharedState) func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
	return func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		olia := NewOLIACongestionControl(pathID, sharedState, initialMaxDatagramSize)
		return &oliaCongestionAdapter{OLIACongestionControl: olia}
	}
}
