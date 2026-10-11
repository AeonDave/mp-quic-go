package quic

import (
	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
)

// oliaCongestionAdapter adapts OLIACongestionControl to the SendAlgorithmWithDebugInfos interface.
// CanSend, MaybeExitSlowStart, OnCongestionEvent, OnPersistentCongestion, OnRetransmissionTimeout,
// SetMaxDatagramSize, InSlowStart, InRecovery and GetCongestionWindow are promoted from OLIACongestionControl.
type oliaCongestionAdapter struct {
	*OLIACongestionControl
}

var (
	_ congestion.SendAlgorithmWithDebugInfos = &oliaCongestionAdapter{}
	_ congestion.StateImporter               = &oliaCongestionAdapter{}
)

// OnPacketSent is called when a packet is sent.
func (a *oliaCongestionAdapter) OnPacketSent(
	sentTime monotime.Time,
	_ protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	a.OLIACongestionControl.OnPacketSent(sentTime.ToTime(), packetNumber, bytes, isRetransmittable)
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

// TakeOverState continues with the state of the congestion controller that this controller replaces.
func (a *oliaCongestionAdapter) TakeOverState(s congestion.State) {
	a.takeOverState(s)
}

// HasPacingBudget returns whether there is pacing budget available.
func (a *oliaCongestionAdapter) HasPacingBudget(monotime.Time) bool {
	// OLIA doesn't implement pacing
	return true
}

// TimeUntilSend returns when the next packet should be sent.
// OLIA doesn't implement pacing: sending is only limited by the congestion window (CanSend),
// so there is never a pacing delay.
func (a *oliaCongestionAdapter) TimeUntilSend(protocol.ByteCount) monotime.Time {
	return 0
}

// NewOLIACongestionControlFactory creates a factory function for OLIA congestion controllers.
// This factory is used by sent_packet_handler to create per-path OLIA instances.
// The controllers take their RTT from the RTT stats passed to the factory.
// All controllers created by the factory are coupled through sharedState,
// so a factory (and a shared state) must only be used for a single connection.
// Closed paths should be removed from the shared state with Unregister.
func NewOLIACongestionControlFactory(sharedState *oliaSharedState) func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
	if sharedState == nil {
		sharedState = NewOLIASharedState()
	}
	return func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		olia := newOLIACongestionControl(pathID, sharedState, initialMaxDatagramSize, rttStats)
		return &oliaCongestionAdapter{OLIACongestionControl: olia}
	}
}
