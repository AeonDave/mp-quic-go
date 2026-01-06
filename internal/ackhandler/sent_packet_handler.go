package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/congestion"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// Specified as an RTT multiplier.
	timeThreshold = 9.0 / 8
	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
	packetThreshold = 3
	// Before validating the client's address, the server won't send more than 3x bytes than it received.
	amplificationFactor = 3
	// We use Retry packets to derive an RTT estimate. Make sure we don't set the RTT to a super low value yet.
	minRTTAfterRetry = 5 * time.Millisecond
	// The PTO duration uses exponential backoff, but is truncated to a maximum value, as allowed by RFC 8961, section 4.4.
	maxPTODuration = 60 * time.Second
)

// Path probe packets are declared lost after this time.
const pathProbePacketLossTimeout = time.Second

type packetNumberSpace struct {
	history sentPacketHistory
	pns     packetNumberGenerator

	lossTime                   monotime.Time
	lastAckElicitingPacketTime monotime.Time

	largestAcked protocol.PacketNumber
	largestSent  protocol.PacketNumber
}

func newPacketNumberSpace(initialPN protocol.PacketNumber, isAppData bool) *packetNumberSpace {
	var pns packetNumberGenerator
	if isAppData {
		pns = newSkippingPacketNumberGenerator(initialPN, protocol.SkipPacketInitialPeriod, protocol.SkipPacketMaxPeriod)
	} else {
		pns = newSequentialPacketNumberGenerator(initialPN)
	}
	return &packetNumberSpace{
		history:      *newSentPacketHistory(isAppData),
		pns:          pns,
		largestSent:  protocol.InvalidPacketNumber,
		largestAcked: protocol.InvalidPacketNumber,
	}
}

type alarmTimer struct {
	Time            monotime.Time
	TimerType       qlog.TimerType
	EncryptionLevel protocol.EncryptionLevel
}

type sentPacketHandler struct {
	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	appDataPackets   map[protocol.PathID]*packetNumberSpace
	lostPackets      map[protocol.PathID]*lostPacketTracker // only for application-data packet number space
	// send time of the largest acknowledged packet, across all packet number spaces
	largestAckedTime monotime.Time

	// Do we know that the peer completed address validation yet?
	// Always true for the server.
	peerCompletedAddressValidation bool
	bytesReceived                  protocol.ByteCount
	bytesSent                      protocol.ByteCount
	// Have we validated the peer's address yet?
	// Always true for the client.
	peerAddressValidated bool

	handshakeConfirmed bool

	ignorePacketsBelow func(protocol.PacketNumber)

	ackedPackets []packetWithPacketNumber // to avoid allocations in detectAndRemoveAckedPackets

	bytesInFlight protocol.ByteCount

	congestion congestion.SendAlgorithmWithDebugInfos
	rttStats   *utils.RTTStats
	connStats  *utils.ConnectionStats

	// Per-path congestion control and RTT tracking for multipath
	pathCongestionControllers map[protocol.PathID]congestion.SendAlgorithmWithDebugInfos
	pathRTTStats              map[protocol.PathID]*utils.RTTStats
	pathPacketNumberManager   *PathPacketNumberManager

	// Factory for creating per-path congestion controllers
	// If nil, creates Cubic controllers by default
	ccFactory func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos

	// The number of times a PTO has been sent without receiving an ack.
	ptoCount uint32
	ptoMode  SendMode
	// The number of PTO probe packets that should be sent.
	// Only applies to the application-data packet number space.
	numProbesToSend int

	// The alarm timeout
	alarm alarmTimer

	enableECN  bool
	ecnTracker ecnHandler

	perspective protocol.Perspective

	qlogger     qlogwriter.Recorder
	lastMetrics qlog.MetricsUpdated
	logger      utils.Logger

	packetObserver PacketObserver
}

var _ SentPacketHandler = &sentPacketHandler{}

func (h *sentPacketHandler) BytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

// clientAddressValidated indicates whether the address was validated beforehand by an address validation token.
// If the address was validated, the amplification limit doesn't apply. It has no effect for a client.
func NewSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
) SentPacketHandler {
	cc := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		connStats,
		initialMaxDatagramSize,
		true, // use Reno
		qlogger,
	)

	h := &sentPacketHandler{
		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
		peerAddressValidated:           pers == protocol.PerspectiveClient || clientAddressValidated,
		initialPackets:                 newPacketNumberSpace(initialPN, false),
		handshakePackets:               newPacketNumberSpace(0, false),
		appDataPackets: map[protocol.PathID]*packetNumberSpace{
			protocol.InvalidPathID: newPacketNumberSpace(0, true),
		},
		lostPackets: map[protocol.PathID]*lostPacketTracker{
			protocol.InvalidPathID: newLostPacketTracker(64),
		},
		rttStats:                  rttStats,
		connStats:                 connStats,
		congestion:                cc,
		pathCongestionControllers: make(map[protocol.PathID]congestion.SendAlgorithmWithDebugInfos),
		pathRTTStats:              make(map[protocol.PathID]*utils.RTTStats),
		pathPacketNumberManager:   NewPathPacketNumberManager(),
		ignorePacketsBelow:        ignorePacketsBelow,
		perspective:               pers,
		qlogger:                   qlogger,
		logger:                    logger,
	}
	if enableECN {
		h.enableECN = true
		h.ecnTracker = newECNTracker(logger, qlogger)
	}
	return h
}

func (h *sentPacketHandler) SetPacketObserver(o PacketObserver) {
	h.packetObserver = o
}

// SetCongestionControlFactory sets a custom factory for creating per-path congestion controllers.
// This allows using OLIA or other multipath-aware congestion control algorithms.
// The factory function receives the pathID, RTT stats, and initial max datagram size.
func (h *sentPacketHandler) SetCongestionControlFactory(
	factory func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos,
) {
	h.ccFactory = factory
}

// getOrCreatePathCongestionControl returns the congestion controller for a path.
// If pathID is invalid, returns the default controller (single-path mode).
func (h *sentPacketHandler) getOrCreatePathCongestionControl(pathID protocol.PathID) congestion.SendAlgorithmWithDebugInfos {
	if pathID == protocol.InvalidPathID {
		return h.congestion
	}

	if cc, ok := h.pathCongestionControllers[pathID]; ok {
		return cc
	}

	// Create new congestion controller for this path
	var cc congestion.SendAlgorithmWithDebugInfos
	rttStats := h.getOrCreatePathRTTStats(pathID)

	if h.ccFactory != nil {
		// Use custom factory (e.g., for OLIA)
		cc = h.ccFactory(pathID, rttStats, protocol.InitialPacketSize)
	} else {
		// Default to Cubic
		cc = congestion.NewCubicSender(
			congestion.DefaultClock{},
			rttStats,
			h.connStats,
			protocol.InitialPacketSize,
			true, // use Reno
			h.qlogger,
		)
	}

	h.pathCongestionControllers[pathID] = cc
	return cc
}

// getOrCreatePathRTTStats returns the RTT stats for a path.
// If pathID is invalid, returns the default stats (single-path mode).
func (h *sentPacketHandler) getOrCreatePathRTTStats(pathID protocol.PathID) *utils.RTTStats {
	if pathID == protocol.InvalidPathID {
		return h.rttStats
	}

	if stats, ok := h.pathRTTStats[pathID]; ok {
		return stats
	}

	// Create new RTT stats for this path, inheriting MaxAckDelay from global stats
	stats := utils.NewRTTStats()
	stats.SetMaxAckDelay(h.rttStats.MaxAckDelay())
	h.pathRTTStats[pathID] = stats
	return stats
}

func (h *sentPacketHandler) GetPathRTTStats(pathID protocol.PathID) *utils.RTTStats {
	return h.getOrCreatePathRTTStats(pathID)
}

func (h *sentPacketHandler) getAppDataPacketNumberSpace(pathID protocol.PathID) *packetNumberSpace {
	if pnSpace, ok := h.appDataPackets[pathID]; ok {
		return pnSpace
	}
	// If pathID is InvalidPathID and we have sent packets on other paths,
	// fall back to the first path with sent packets to avoid ACK mismatch.
	if pathID == protocol.InvalidPathID {
		for pid, pnSpace := range h.appDataPackets {
			if pid != protocol.InvalidPathID && pnSpace.largestSent != protocol.InvalidPacketNumber {
				return pnSpace
			}
		}
	}
	pnSpace := newPacketNumberSpace(0, true)
	h.appDataPackets[pathID] = pnSpace
	return pnSpace
}

func (h *sentPacketHandler) getLostPacketTracker(pathID protocol.PathID) *lostPacketTracker {
	if tracker, ok := h.lostPackets[pathID]; ok {
		return tracker
	}
	tracker := newLostPacketTracker(64)
	h.lostPackets[pathID] = tracker
	return tracker
}

func (h *sentPacketHandler) forEachAppDataSpace(fn func(pathID protocol.PathID, pnSpace *packetNumberSpace)) {
	for pathID, pnSpace := range h.appDataPackets {
		fn(pathID, pnSpace)
	}
}

func (h *sentPacketHandler) hasOutstandingAppDataPackets() bool {
	for _, pnSpace := range h.appDataPackets {
		if pnSpace.history.HasOutstandingPackets() {
			return true
		}
	}
	return false
}

func (h *sentPacketHandler) hasOutstandingAppDataPathProbes() bool {
	for _, pnSpace := range h.appDataPackets {
		if pnSpace.history.HasOutstandingPathProbes() {
			return true
		}
	}
	return false
}

func (h *sentPacketHandler) SetPacketPathID(encLevel protocol.EncryptionLevel, pn protocol.PacketNumber, pathID protocol.PathID) {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	if pnSpace == nil {
		return
	}
	p, ok := pnSpace.history.SetPathID(pn, pathID)
	if !ok || p == nil {
		return
	}
	if h.packetObserver != nil && !p.sentNotified {
		p.sentNotified = true
		h.packetObserver.OnPacketSent(newPacketEvent(pn, p, p.SendTime))
	}
}

func (h *sentPacketHandler) removeFromBytesInFlight(p *packet) {
	if p.includedInBytesInFlight {
		if p.Length > h.bytesInFlight {
			panic("negative bytes_in_flight")
		}
		h.bytesInFlight -= p.Length
		p.includedInBytesInFlight = false
	}
}

func (h *sentPacketHandler) DropPackets(encLevel protocol.EncryptionLevel, now monotime.Time) {
	// The server won't await address validation after the handshake is confirmed.
	// This applies even if we didn't receive an ACK for a Handshake packet.
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionHandshake {
		h.peerCompletedAddressValidation = true
	}
	// remove outstanding packets from bytes_in_flight
	if encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake {
		pnSpace := h.getPacketNumberSpace(encLevel, protocol.InvalidPathID)
		// We might already have dropped this packet number space.
		if pnSpace == nil {
			return
		}
		for _, p := range pnSpace.history.Packets() {
			h.removeFromBytesInFlight(p)
		}
	}
	// drop the packet history
	//nolint:exhaustive // Not every packet number space can be dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		// Dropping the handshake packet number space means that the handshake is confirmed,
		// see section 4.9.2 of RFC 9001.
		h.handshakeConfirmed = true
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// This function is only called when 0-RTT is rejected,
		// and not when the client drops 0-RTT keys when the handshake completes.
		// When 0-RTT is rejected, all application data sent so far becomes invalid.
		// Delete the packets from the history and remove them from bytes_in_flight.
		h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
			for pn, p := range pnSpace.history.Packets() {
				if p.EncryptionLevel != protocol.Encryption0RTT {
					break
				}
				h.removeFromBytesInFlight(p)
				_ = pnSpace.history.Remove(pn)
			}
		})
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	if h.qlogger != nil && h.ptoCount != 0 {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
	}
	h.ptoCount = 0
	h.numProbesToSend = 0
	h.ptoMode = SendNone
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) ReceivedBytes(n protocol.ByteCount, t monotime.Time) {
	h.connStats.BytesReceived.Add(uint64(n))
	wasAmplificationLimit := h.isAmplificationLimited()
	h.bytesReceived += n
	if wasAmplificationLimit && !h.isAmplificationLimited() {
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) ReceivedPacket(l protocol.EncryptionLevel, t monotime.Time) {
	h.connStats.PacketsReceived.Add(1)
	if h.perspective == protocol.PerspectiveServer && l == protocol.EncryptionHandshake && !h.peerAddressValidated {
		h.peerAddressValidated = true
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) packetsInFlight() int {
	packetsInFlight := 0
	h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
		packetsInFlight += pnSpace.history.Len()
	})
	if h.handshakePackets != nil {
		packetsInFlight += h.handshakePackets.history.Len()
	}
	if h.initialPackets != nil {
		packetsInFlight += h.initialPackets.history.Len()
	}
	return packetsInFlight
}

func (h *sentPacketHandler) SentPacket(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	streamFrames []StreamFrame,
	frames []Frame,
	encLevel protocol.EncryptionLevel,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
	isPathProbePacket bool,
	pathID protocol.PathID,
) {
	h.bytesSent += size
	h.connStats.BytesSent.Add(uint64(size))
	h.connStats.PacketsSent.Add(1)

	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	if h.logger.Debug() && (pnSpace.history.HasOutstandingPackets() || pnSpace.history.HasOutstandingPathProbes()) {
		for p := max(0, pnSpace.largestSent+1); p < pn; p++ {
			h.logger.Debugf("Skipping packet number %d", p)
		}
	}

	pnSpace.largestSent = pn

	p := getPacket()
	p.SendTime = t
	p.EncryptionLevel = encLevel
	p.Length = size
	p.Frames = frames
	p.LargestAcked = largestAcked
	p.StreamFrames = streamFrames
	p.IsPathMTUProbePacket = isPathMTUProbePacket
	p.isPathProbePacket = isPathProbePacket
	p.PathID = pathID
	isAckEliciting := p.IsAckEliciting()

	if isPathProbePacket {
		pnSpace.history.SentPathProbePacket(pn, p)
		h.setLossDetectionTimer(t)
		return
	}
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		h.bytesInFlight += size
		p.includedInBytesInFlight = true
		if h.numProbesToSend > 0 {
			h.numProbesToSend--
		}
	}

	// Use per-path congestion controller when available
	cc := h.getOrCreatePathCongestionControl(pathID)
	cc.OnPacketSent(t, h.bytesInFlight, pn, size, isAckEliciting)

	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
		h.ecnTracker.SentPacket(pn, ecn)
	}

	pnSpace.history.SentPacket(pn, p)
	if !isAckEliciting {
		if !h.peerCompletedAddressValidation {
			h.setLossDetectionTimer(t)
		}
		return
	}
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	h.setLossDetectionTimer(t)
}

func (h *sentPacketHandler) qlogMetricsUpdated() {
	var metricsUpdatedEvent qlog.MetricsUpdated
	var updated bool
	if h.rttStats.HasMeasurement() {
		if h.lastMetrics.MinRTT != h.rttStats.MinRTT() {
			metricsUpdatedEvent.MinRTT = h.rttStats.MinRTT()
			h.lastMetrics.MinRTT = metricsUpdatedEvent.MinRTT
			updated = true
		}
		if h.lastMetrics.SmoothedRTT != h.rttStats.SmoothedRTT() {
			metricsUpdatedEvent.SmoothedRTT = h.rttStats.SmoothedRTT()
			h.lastMetrics.SmoothedRTT = metricsUpdatedEvent.SmoothedRTT
			updated = true
		}
		if h.lastMetrics.LatestRTT != h.rttStats.LatestRTT() {
			metricsUpdatedEvent.LatestRTT = h.rttStats.LatestRTT()
			h.lastMetrics.LatestRTT = metricsUpdatedEvent.LatestRTT
			updated = true
		}
		if h.lastMetrics.RTTVariance != h.rttStats.MeanDeviation() {
			metricsUpdatedEvent.RTTVariance = h.rttStats.MeanDeviation()
			h.lastMetrics.RTTVariance = metricsUpdatedEvent.RTTVariance
			updated = true
		}
	}
	if cwnd := h.congestion.GetCongestionWindow(); h.lastMetrics.CongestionWindow != int(cwnd) {
		metricsUpdatedEvent.CongestionWindow = int(cwnd)
		h.lastMetrics.CongestionWindow = metricsUpdatedEvent.CongestionWindow
		updated = true
	}
	if h.lastMetrics.BytesInFlight != int(h.bytesInFlight) {
		metricsUpdatedEvent.BytesInFlight = int(h.bytesInFlight)
		h.lastMetrics.BytesInFlight = metricsUpdatedEvent.BytesInFlight
		updated = true
	}
	if h.lastMetrics.PacketsInFlight != h.packetsInFlight() {
		metricsUpdatedEvent.PacketsInFlight = h.packetsInFlight()
		h.lastMetrics.PacketsInFlight = metricsUpdatedEvent.PacketsInFlight
		updated = true
	}
	if updated {
		h.qlogger.RecordEvent(metricsUpdatedEvent)
	}
}

func (h *sentPacketHandler) getPacketNumberSpace(encLevel protocol.EncryptionLevel, pathID protocol.PathID) *packetNumberSpace {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets
	case protocol.EncryptionHandshake:
		return h.handshakePackets
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.getAppDataPacketNumberSpace(pathID)
	default:
		panic("invalid packet number space")
	}
}

func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time, pathID protocol.PathID) (bool /* contained 1-RTT packet */, error) {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)

	largestAcked := ack.LargestAcked()
	if largestAcked > pnSpace.largestSent {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received ACK for an unsent packet",
		}
	}

	// Servers complete address validation when a protected packet is received.
	if h.perspective == protocol.PerspectiveClient && !h.peerCompletedAddressValidation &&
		(encLevel == protocol.EncryptionHandshake || encLevel == protocol.Encryption1RTT) {
		h.peerCompletedAddressValidation = true
		h.logger.Debugf("Peer doesn't await address validation any longer.")
		// Make sure that the timer is reset, even if this ACK doesn't acknowledge any (ack-eliciting) packets.
		h.setLossDetectionTimer(rcvTime)
	}

	priorInFlight := h.bytesInFlight
	ackedPackets, hasAckEliciting, err := h.detectAndRemoveAckedPackets(ack, encLevel, pathID)
	if err != nil || len(ackedPackets) == 0 {
		return false, err
	}
	// update the RTT, if:
	// * the largest acked is newly acknowledged, AND
	// * at least one new ack-eliciting packet was acknowledged
	if len(ackedPackets) > 0 {
		if p := ackedPackets[len(ackedPackets)-1]; p.PacketNumber == ack.LargestAcked() && !p.isPathProbePacket && hasAckEliciting {
			// don't use the ack delay for Initial and Handshake packets
			var ackDelay time.Duration
			if encLevel == protocol.Encryption1RTT {
				ackDelay = min(ack.DelayTime, h.rttStats.MaxAckDelay())
			}
			if h.largestAckedTime.IsZero() || !p.SendTime.Before(h.largestAckedTime) {
				rtt := rcvTime.Sub(p.SendTime)

				// Update per-path RTT stats
				pathRTT := h.getOrCreatePathRTTStats(p.PathID)
				pathRTT.UpdateRTT(rtt, ackDelay)

				// Update global RTT only if it's a different instance
				if pathRTT != h.rttStats {
					h.rttStats.UpdateRTT(rtt, ackDelay)
				}

				if h.logger.Debug() {
					h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
				}
				h.largestAckedTime = p.SendTime
			}

			// Call MaybeExitSlowStart on per-path CC
			cc := h.getOrCreatePathCongestionControl(p.PathID)
			cc.MaybeExitSlowStart()
		}
	}

	// Only inform the ECN tracker about new 1-RTT ACKs if the ACK increases the largest acked.
	if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil && largestAcked > pnSpace.largestAcked {
		congested := h.ecnTracker.HandleNewlyAcked(ackedPackets, int64(ack.ECT0), int64(ack.ECT1), int64(ack.ECNCE))
		if congested {
			// Group packets by path for congestion events
			pathPackets := make(map[protocol.PathID][]packetWithPacketNumber)
			for _, p := range ackedPackets {
				pathPackets[p.PathID] = append(pathPackets[p.PathID], p)
			}

			// Send congestion event to each path's CC
			for pathID := range pathPackets {
				cc := h.getOrCreatePathCongestionControl(pathID)
				cc.OnCongestionEvent(largestAcked, 0, priorInFlight)
			}
		}
	}

	pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)
	if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
		h.pathPacketNumberManager.SetHighestAcked(pathID, encLevel, pnSpace.largestAcked)
	}

	h.detectLostPackets(rcvTime, encLevel, pathID)
	if encLevel == protocol.Encryption1RTT {
		h.detectLostPathProbes(rcvTime)
	}
	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if h.packetObserver != nil {
			h.packetObserver.OnPacketAcked(newPacketEvent(p.PacketNumber, p.packet, rcvTime))
		}
		if p.includedInBytesInFlight && !p.declaredLost {
			// Route OnPacketAcked to per-path CC
			cc := h.getOrCreatePathCongestionControl(p.PathID)
			cc.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
		}
		if p.EncryptionLevel == protocol.Encryption1RTT {
			acked1RTTPacket = true
		}
		h.removeFromBytesInFlight(p.packet)
		if !p.isPathProbePacket {
			putPacket(p.packet)
		}
	}

	// detect spurious losses for application data packets, if the ACK was not reordered
	if encLevel == protocol.Encryption1RTT && largestAcked == pnSpace.largestAcked {
		h.detectSpuriousLosses(
			ack,
			rcvTime.Add(-min(ack.DelayTime, h.rttStats.MaxAckDelay())),
			pathID,
		)
		// clean up lost packet history
		h.getLostPacketTracker(pathID).DeleteBefore(rcvTime.Add(-3 * h.rttStats.PTO(false)))
	}

	// After this point, we must not use ackedPackets any longer!
	// We've already returned the buffers.
	ackedPackets = nil    //nolint:ineffassign // This is just to be on the safe side.
	clear(h.ackedPackets) // make sure the memory is released
	h.ackedPackets = h.ackedPackets[:0]

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	if h.peerCompletedAddressValidation {
		if h.qlogger != nil && h.ptoCount != 0 {
			h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		}
		h.ptoCount = 0
	}
	h.numProbesToSend = 0

	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}

	h.setLossDetectionTimer(rcvTime)
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time, pathID protocol.PathID) {
	var maxPacketReordering protocol.PacketNumber
	var maxTimeReordering time.Duration
	ackRangeIdx := len(ack.AckRanges) - 1
	var spuriousLosses []protocol.PacketNumber
	lostPackets := h.getLostPacketTracker(pathID)
	pnSpace := h.getAppDataPacketNumberSpace(pathID)
	for pn, sendTime := range lostPackets.All() {
		ackRange := ack.AckRanges[ackRangeIdx]
		for pn > ackRange.Largest {
			// this should never happen, since detectSpuriousLosses is only called for ACKs that increase the largest acked
			if ackRangeIdx == 0 {
				break
			}
			ackRangeIdx--
			ackRange = ack.AckRanges[ackRangeIdx]
		}
		if pn < ackRange.Smallest {
			continue
		}
		if pn <= ackRange.Largest {
			packetReordering := pnSpace.history.Difference(ack.LargestAcked(), pn)
			timeReordering := ackTime.Sub(sendTime)
			maxPacketReordering = max(maxPacketReordering, packetReordering)
			maxTimeReordering = max(maxTimeReordering, timeReordering)

			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.SpuriousLoss{
					EncryptionLevel:  protocol.Encryption1RTT,
					PacketNumber:     pn,
					PacketReordering: uint64(packetReordering),
					TimeReordering:   timeReordering,
				})
			}
			spuriousLosses = append(spuriousLosses, pn)
		}
	}
	for _, pn := range spuriousLosses {
		lostPackets.Delete(pn)
	}
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(
	ack *wire.AckFrame,
	encLevel protocol.EncryptionLevel,
	pathID protocol.PathID,
) (_ []packetWithPacketNumber, hasAckEliciting bool, _ error) {
	if len(h.ackedPackets) > 0 {
		return nil, false, errors.New("ackhandler BUG: ackedPackets slice not empty")
	}

	pnSpace := h.getPacketNumberSpace(encLevel, pathID)

	if encLevel == protocol.Encryption1RTT {
		for p := range pnSpace.history.SkippedPackets() {
			if ack.AcksPacket(p) {
				return nil, false, &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received an ACK for skipped packet number: %d (%s)", p, encLevel),
				}
			}
		}
	}

	var ackRangeIndex int
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	for pn, p := range pnSpace.history.Packets() {
		// ignore packets below the lowest acked
		if pn < lowestAcked {
			continue
		}
		if pn > largestAcked {
			break
		}

		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]

			for pn > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}

			if pn < ackRange.Smallest { // packet not contained in ACK range
				continue
			}
			if pn > ackRange.Largest {
				return nil, false, fmt.Errorf("BUG: ackhandler would have acked wrong packet %d, while evaluating range %d -> %d", pn, ackRange.Smallest, ackRange.Largest)
			}
		}
		if p.isPathProbePacket {
			probePacket := pnSpace.history.RemovePathProbe(pn)
			// the probe packet might already have been declared lost
			if probePacket != nil {
				h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: probePacket})
			}
			continue
		}
		if p.IsAckEliciting() {
			hasAckEliciting = true
		}
		h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: p})
	}
	if h.logger.Debug() && len(h.ackedPackets) > 0 {
		pns := make([]protocol.PacketNumber, len(h.ackedPackets))
		for i, p := range h.ackedPackets {
			pns[i] = p.PacketNumber
		}
		h.logger.Debugf("\tnewly acked packets (%d): %d", len(pns), pns)
	}

	for _, p := range h.ackedPackets {
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT && h.ignorePacketsBelow != nil {
			h.ignorePacketsBelow(p.LargestAcked + 1)
		}

		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		for _, f := range p.StreamFrames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		if err := pnSpace.history.Remove(p.PacketNumber); err != nil {
			return nil, false, err
		}
	}
	// TODO: add support for the transport:packets_acked qlog event
	return h.ackedPackets, hasAckEliciting, nil
}

func (h *sentPacketHandler) getLossTimeAndSpace() (monotime.Time, protocol.EncryptionLevel, protocol.PathID) {
	var encLevel protocol.EncryptionLevel
	var lossTime monotime.Time
	var pathID protocol.PathID

	if h.initialPackets != nil {
		lossTime = h.initialPackets.lossTime
		encLevel = protocol.EncryptionInitial
		pathID = protocol.InvalidPathID
	}
	if h.handshakePackets != nil && (lossTime.IsZero() || (!h.handshakePackets.lossTime.IsZero() && h.handshakePackets.lossTime.Before(lossTime))) {
		lossTime = h.handshakePackets.lossTime
		encLevel = protocol.EncryptionHandshake
		pathID = protocol.InvalidPathID
	}
	h.forEachAppDataSpace(func(appPathID protocol.PathID, pnSpace *packetNumberSpace) {
		if pnSpace.lossTime.IsZero() {
			return
		}
		if lossTime.IsZero() || pnSpace.lossTime.Before(lossTime) {
			lossTime = pnSpace.lossTime
			encLevel = protocol.Encryption1RTT
			pathID = appPathID
		}
	})
	return lossTime, encLevel, pathID
}

func (h *sentPacketHandler) getScaledPTO(includeMaxAckDelay bool) time.Duration {
	pto := h.rttStats.PTO(includeMaxAckDelay) << h.ptoCount
	if pto > maxPTODuration || pto <= 0 {
		return maxPTODuration
	}
	return pto
}

// same logic as getLossTimeAndSpace, but for lastAckElicitingPacketTime instead of lossTime
func (h *sentPacketHandler) getPTOTimeAndSpace(now monotime.Time) (pto monotime.Time, encLevel protocol.EncryptionLevel, pathID protocol.PathID) {
	// We only send application data probe packets once the handshake is confirmed,
	// because before that, we don't have the keys to decrypt ACKs sent in 1-RTT packets.
	if !h.handshakeConfirmed && !h.hasOutstandingCryptoPackets() {
		if h.peerCompletedAddressValidation {
			return
		}
		t := now.Add(h.getScaledPTO(false))
		if h.initialPackets != nil {
			return t, protocol.EncryptionInitial, protocol.InvalidPathID
		}
		return t, protocol.EncryptionHandshake, protocol.InvalidPathID
	}

	if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() &&
		!h.initialPackets.lastAckElicitingPacketTime.IsZero() {
		encLevel = protocol.EncryptionInitial
		pathID = protocol.InvalidPathID
		if t := h.initialPackets.lastAckElicitingPacketTime; !t.IsZero() {
			pto = t.Add(h.getScaledPTO(false))
		}
	}
	if h.handshakePackets != nil && h.handshakePackets.history.HasOutstandingPackets() &&
		!h.handshakePackets.lastAckElicitingPacketTime.IsZero() {
		t := h.handshakePackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(false))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.EncryptionHandshake
			pathID = protocol.InvalidPathID
		}
	}
	if h.handshakeConfirmed {
		h.forEachAppDataSpace(func(appPathID protocol.PathID, pnSpace *packetNumberSpace) {
			if !pnSpace.history.HasOutstandingPackets() || pnSpace.lastAckElicitingPacketTime.IsZero() {
				return
			}
			t := pnSpace.lastAckElicitingPacketTime.Add(h.getScaledPTO(true))
			if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
				pto = t
				encLevel = protocol.Encryption1RTT
				pathID = appPathID
			}
		})
	}
	return pto, encLevel, pathID
}

func (h *sentPacketHandler) hasOutstandingCryptoPackets() bool {
	if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() {
		return true
	}
	if h.handshakePackets != nil && h.handshakePackets.history.HasOutstandingPackets() {
		return true
	}
	return false
}

func (h *sentPacketHandler) setLossDetectionTimer(now monotime.Time) {
	oldAlarm := h.alarm // only needed in case tracing is enabled
	newAlarm := h.lossDetectionTime(now)
	h.alarm = newAlarm

	hasAlarm := !newAlarm.Time.IsZero()
	if !hasAlarm && !oldAlarm.Time.IsZero() {
		h.logger.Debugf("Canceling loss detection timer.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}

	if h.qlogger != nil && hasAlarm && newAlarm != oldAlarm {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeSet,
			TimerType: newAlarm.TimerType,
			EncLevel:  newAlarm.EncryptionLevel,
			Time:      newAlarm.Time.ToTime(),
		})
	}
}

func (h *sentPacketHandler) lossDetectionTime(now monotime.Time) alarmTimer {
	// cancel the alarm if no packets are outstanding
	if h.peerCompletedAddressValidation && !h.hasOutstandingCryptoPackets() &&
		!h.hasOutstandingAppDataPackets() && !h.hasOutstandingAppDataPathProbes() {
		return alarmTimer{}
	}

	// cancel the alarm if amplification limited
	if h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var pathProbeLossTime monotime.Time
	h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
		if _, p := pnSpace.history.FirstOutstandingPathProbe(); p != nil {
			lossTime := p.SendTime.Add(pathProbePacketLossTimeout)
			if pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime) {
				pathProbeLossTime = lossTime
			}
		}
	})

	// early retransmit timer or time loss detection
	lossTime, encLevel, _ := h.getLossTimeAndSpace()
	if !lossTime.IsZero() && (pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            lossTime,
			TimerType:       qlog.TimerTypeACK,
			EncryptionLevel: encLevel,
		}
	}
	ptoTime, encLevel, _ := h.getPTOTimeAndSpace(now)
	if !ptoTime.IsZero() && (pathProbeLossTime.IsZero() || ptoTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            ptoTime,
			TimerType:       qlog.TimerTypePTO,
			EncryptionLevel: encLevel,
		}
	}
	if !pathProbeLossTime.IsZero() {
		return alarmTimer{
			Time:            pathProbeLossTime,
			TimerType:       qlog.TimerTypePathProbe,
			EncryptionLevel: protocol.Encryption1RTT,
		}
	}
	return alarmTimer{}
}

func (h *sentPacketHandler) detectLostPathProbes(now monotime.Time) {
	lossTime := now.Add(-pathProbePacketLossTimeout)
	h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
		if !pnSpace.history.HasOutstandingPathProbes() {
			return
		}
		// RemovePathProbe cannot be called while iterating.
		var lostPathProbes []packetWithPacketNumber
		for pn, p := range pnSpace.history.PathProbes() {
			if !p.SendTime.After(lossTime) {
				lostPathProbes = append(lostPathProbes, packetWithPacketNumber{PacketNumber: pn, packet: p})
			}
		}
		for _, p := range lostPathProbes {
			if h.packetObserver != nil {
				h.packetObserver.OnPacketLost(newPacketEvent(p.PacketNumber, p.packet, now))
			}
			for _, f := range p.Frames {
				f.Handler.OnLost(f.Frame)
			}
			pnSpace.history.RemovePathProbe(p.PacketNumber)
		}
	})
}

func (h *sentPacketHandler) detectLostPackets(now monotime.Time, encLevel protocol.EncryptionLevel, pathID protocol.PathID) {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	pnSpace.lossTime = 0

	maxRTT := float64(max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	lossDelay := time.Duration(timeThreshold * maxRTT)

	// Minimum time of granularity before packets are deemed lost.
	lossDelay = max(lossDelay, protocol.TimerGranularity)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	priorInFlight := h.bytesInFlight
	for pn, p := range pnSpace.history.Packets() {
		if pn > pnSpace.largestAcked {
			break
		}

		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (time threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossTimeThreshold,
					})
				}
			}
		} else if pnSpace.history.Difference(pnSpace.largestAcked, pn) >= packetThreshold {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (reordering threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossReorderingThreshold,
					})
				}
			}
		} else if pnSpace.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", pn, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost {
			if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
				h.getLostPacketTracker(p.PathID).Add(pn, p.SendTime)
			}
			pnSpace.history.DeclareLost(pn)
			if h.packetObserver != nil {
				h.packetObserver.OnPacketLost(newPacketEvent(pn, p, now))
			}

			if !p.isPathProbePacket && p.IsAckEliciting() {
				// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
				h.removeFromBytesInFlight(p)
				h.queueFramesForRetransmission(p)
				if !p.IsPathMTUProbePacket {
					// Route congestion event to per-path CC
					cc := h.getOrCreatePathCongestionControl(p.PathID)
					cc.OnCongestionEvent(pn, p.Length, priorInFlight)
				}
				if encLevel == protocol.Encryption1RTT && h.ecnTracker != nil {
					h.ecnTracker.LostPacket(pn)
				}
			}
		}
	}
}

func (h *sentPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	defer h.setLossDetectionTimer(now)

	if h.handshakeConfirmed {
		h.detectLostPathProbes(now)
	}

	earliestLossTime, encLevel, lossPathID := h.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypeACK,
				EncLevel:  encLevel,
			})
		}
		// Early retransmit or time loss detection
		h.detectLostPackets(now, encLevel, lossPathID)
		return nil
	}

	// PTO
	// When all outstanding are acknowledged, the alarm is canceled in setLossDetectionTimer.
	// However, there's no way to reset the timer in the connection.
	// When OnLossDetectionTimeout is called, we therefore need to make sure that there are
	// actually packets outstanding.
	if h.bytesInFlight == 0 && !h.peerCompletedAddressValidation {
		h.ptoCount++
		h.numProbesToSend++
		if h.initialPackets != nil {
			h.ptoMode = SendPTOInitial
		} else if h.handshakePackets != nil {
			h.ptoMode = SendPTOHandshake
		} else {
			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
		}
		return nil
	}

	ptoTime, encLevel, ptoPathID := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() {
		return nil
	}
	ps := h.getPacketNumberSpace(encLevel, ptoPathID)
	if !ps.history.HasOutstandingPackets() && !ps.history.HasOutstandingPathProbes() && !h.peerCompletedAddressValidation {
		return nil
	}
	h.ptoCount++
	if h.logger.Debug() {
		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, h.ptoCount)
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeExpired,
			TimerType: qlog.TimerTypePTO,
			EncLevel:  encLevel,
		})
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: h.ptoCount})
	}
	h.numProbesToSend += 2
	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.ptoMode = SendPTOInitial
	case protocol.EncryptionHandshake:
		h.ptoMode = SendPTOHandshake
	case protocol.Encryption1RTT:
		// Skip a packet number in order to elicit an immediate ACK when sending the PTO probe.
		pn := h.PopPacketNumber(ptoPathID, protocol.Encryption1RTT)
		ps.history.SkippedPacket(pn)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d", pn)
		}
		h.ptoMode = SendPTOAppData
	default:
		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
	}
	return nil
}

func (h *sentPacketHandler) GetLossDetectionTimeout() monotime.Time {
	return h.alarm.Time
}

func (h *sentPacketHandler) ECNMode(isShortHeaderPacket bool) protocol.ECN {
	if !h.enableECN {
		return protocol.ECNUnsupported
	}
	if !isShortHeaderPacket {
		return protocol.ECNNon
	}
	return h.ecnTracker.Mode()
}

func (h *sentPacketHandler) PeekPacketNumber(pathID protocol.PathID, encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	if encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake {
		pn := pnSpace.pns.Peek()
		// See section 17.1 of RFC 9000.
		return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
	}
	pn, _ := h.pathPacketNumberManager.PeekPacketNumber(pathID, encLevel)
	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

func (h *sentPacketHandler) PopPacketNumber(pathID protocol.PathID, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	if encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake {
		skipped, pn := pnSpace.pns.Pop()
		if skipped {
			h.markSkippedPacket(pnSpace, pn-1)
		}
		return pn
	}

	skipped, pn := h.pathPacketNumberManager.PopPacketNumberWithSkip(pathID, encLevel)
	if skipped {
		h.markSkippedPacket(pnSpace, pn-1)
	}
	return pn
}

func (h *sentPacketHandler) markSkippedPacket(pnSpace *packetNumberSpace, pn protocol.PacketNumber) {
	pnSpace.history.SkippedPacket(pn)
	if h.logger.Debug() {
		h.logger.Debugf("Skipping packet number %d", pn)
	}
}

func (h *sentPacketHandler) SendMode(now monotime.Time) SendMode {
	numTrackedPackets := 0
	h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
		numTrackedPackets += pnSpace.history.Len()
	})
	if h.initialPackets != nil {
		numTrackedPackets += h.initialPackets.history.Len()
	}
	if h.handshakePackets != nil {
		numTrackedPackets += h.handshakePackets.history.Len()
	}

	if h.isAmplificationLimited() {
		h.logger.Debugf("Amplification window limited. Received %d bytes, already sent out %d bytes", h.bytesReceived, h.bytesSent)
		return SendNone
	}
	// Don't send any packets if we're keeping track of the maximum number of packets.
	// Note that since MaxOutstandingSentPackets is smaller than MaxTrackedSentPackets,
	// we will stop sending out new data when reaching MaxOutstandingSentPackets,
	// but still allow sending of retransmissions and ACKs.
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Limited by the number of tracked packets: tracking %d packets, maximum %d", numTrackedPackets, protocol.MaxTrackedSentPackets)
		}
		return SendNone
	}
	if h.numProbesToSend > 0 {
		return h.ptoMode
	}
	// Only send ACKs if we're congestion limited.
	if !h.congestion.CanSend(h.bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, h.congestion.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	if !h.congestion.HasPacingBudget(now) {
		return SendPacingLimited
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() monotime.Time {
	return h.congestion.TimeUntilSend(h.bytesInFlight)
}

func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.congestion.SetMaxDatagramSize(s)
}

func (h *sentPacketHandler) isAmplificationLimited() bool {
	if h.peerAddressValidated {
		return false
	}
	return h.bytesSent >= amplificationFactor*h.bytesReceived
}

func (h *sentPacketHandler) QueueProbePacket(encLevel protocol.EncryptionLevel) bool {
	if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
		var selectedSpace *packetNumberSpace
		var selectedPacket *packet
		var selectedPN protocol.PacketNumber
		h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
			pn, p := pnSpace.history.FirstOutstanding()
			if p == nil {
				return
			}
			if selectedPacket == nil || p.SendTime.Before(selectedPacket.SendTime) {
				selectedSpace = pnSpace
				selectedPacket = p
				selectedPN = pn
			}
		})
		if selectedPacket == nil {
			return false
		}
		h.queueFramesForRetransmission(selectedPacket)
		// TODO: don't declare the packet lost here.
		// Keep track of acknowledged frames instead.
		h.removeFromBytesInFlight(selectedPacket)
		selectedSpace.history.DeclareLost(selectedPN)
		return true
	}

	pnSpace := h.getPacketNumberSpace(encLevel, protocol.InvalidPathID)
	pn, p := pnSpace.history.FirstOutstanding()
	if p == nil {
		return false
	}
	h.queueFramesForRetransmission(p)
	// TODO: don't declare the packet lost here.
	// Keep track of acknowledged frames instead.
	h.removeFromBytesInFlight(p)
	pnSpace.history.DeclareLost(pn)
	return true
}

func (h *sentPacketHandler) queueFramesForRetransmission(p *packet) {
	if len(p.Frames) == 0 && len(p.StreamFrames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	for _, f := range p.StreamFrames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	p.StreamFrames = nil
	p.Frames = nil
}

func (h *sentPacketHandler) ResetForRetry(now monotime.Time) {
	h.bytesInFlight = 0
	var firstPacketSendTime monotime.Time
	for _, p := range h.initialPackets.history.Packets() {
		if firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if !p.declaredLost && p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}
	// All application data packets sent at this point are 0-RTT packets.
	// In the case of a Retry, we can assume that the server dropped all of them.
	h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
		for _, p := range pnSpace.history.Packets() {
			if !p.declaredLost && p.IsAckEliciting() {
				h.queueFramesForRetransmission(p)
			}
		}
	})

	// Only use the Retry to estimate the RTT if we didn't send any retransmission for the Initial.
	// Otherwise, we don't know which Initial the Retry was sent in response to.
	if h.ptoCount == 0 {
		// Don't set the RTT to a value lower than 5ms here.
		h.rttStats.UpdateRTT(max(minRTTAfterRetry, now.Sub(firstPacketSendTime)), 0)
		if h.logger.Debug() {
			h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
		}
		if h.qlogger != nil {
			h.qlogMetricsUpdated()
		}
	}
	h.initialPackets = newPacketNumberSpace(h.initialPackets.pns.Peek(), false)
	h.appDataPackets = map[protocol.PathID]*packetNumberSpace{
		protocol.InvalidPathID: newPacketNumberSpace(0, true),
	}
	h.lostPackets = map[protocol.PathID]*lostPacketTracker{
		protocol.InvalidPathID: newLostPacketTracker(64),
	}
	oldAlarm := h.alarm
	h.alarm = alarmTimer{}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		if !oldAlarm.Time.IsZero() {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}
	h.ptoCount = 0
}

func (h *sentPacketHandler) MigratedPath(now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	h.rttStats.ResetForPathMigration()
	h.forEachAppDataSpace(func(_ protocol.PathID, pnSpace *packetNumberSpace) {
		for pn, p := range pnSpace.history.Packets() {
			pnSpace.history.DeclareLost(pn)
			if !p.isPathProbePacket {
				h.removeFromBytesInFlight(p)
				if p.IsAckEliciting() {
					h.queueFramesForRetransmission(p)
				}
			}
		}
		for pn := range pnSpace.history.PathProbes() {
			pnSpace.history.RemovePathProbe(pn)
		}
	})
	h.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
	)
	h.setLossDetectionTimer(now)
}
