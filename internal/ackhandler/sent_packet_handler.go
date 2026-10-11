package ackhandler

import (
	"errors"
	"fmt"
	"iter"
	"slices"
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
	// The persistent congestion duration, as a multiple of the PTO including max_ack_delay (RFC 9002, section 7.6.1).
	persistentCongestionThreshold = 3
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

// A pathRecovery holds the application data packet number space of a path,
// and the loss recovery and congestion control state that belongs to it.
//
// The sentPacketHandler's appData is path 0, the path that the handshake is performed on.
// Without IETF Multipath QUIC, it is the only path.
// With IETF Multipath QUIC (see EnableMultipath), every path is recovered independently (RFC 9002 applied per path).
type pathRecovery struct {
	id    protocol.PathID
	space *packetNumberSpace

	lostPackets lostPacketTracker

	rttStats   *utils.RTTStats // for path 0, the RTT stats passed to NewSentPacketHandler
	congestion congestion.SendAlgorithmWithDebugInfos
	ecnTracker ecnHandler // nil if ECN is disabled

	// The time when the first RTT sample was taken on this path, zero before.
	// Only packets sent after it can establish persistent congestion (section 7.6.2 of RFC 9002).
	firstRTTSampleTime monotime.Time

	// The bytes in flight of the packets sent on this path.
	// For path 0, this includes Initial and Handshake packets.
	bytesInFlight protocol.ByteCount
	// send time of the largest acknowledged packet.
	// Not used for path 0, see sentPacketHandler.largestAckedTime.
	largestAckedTime monotime.Time

	// The number of times a PTO has been sent without receiving an ack.
	// The values of path 0 also apply to the Initial and Handshake packet number space.
	ptoCount uint32
	ptoMode  SendMode
	// The number of PTO probe packets that should be sent.
	numProbesToSend int

	// The anti-amplification limit of paths other than path 0 (IETF Multipath QUIC).
	addressValidated         bool
	bytesSent, bytesReceived protocol.ByteCount

	abandoned bool
	// Path 0 of an IETF Multipath QUIC connection was removed. Other paths are deleted when they are removed.
	removed bool
}

type alarmTimer struct {
	Time            monotime.Time
	TimerType       qlog.TimerType
	EncryptionLevel protocol.EncryptionLevel
}

type sentPacketHandler struct {
	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	// The application data state of path 0.
	// Without IETF Multipath QUIC, this is the state of the connection.
	appData pathRecovery
	// All other paths (IETF Multipath QUIC), and their path IDs in ascending order.
	paths   map[protocol.PathID]*pathRecovery
	pathIDs []protocol.PathID
	// Paths that were removed. Path IDs are never reused.
	removedPaths utils.PathIDSet
	// Is IETF Multipath QUIC used?
	multipath bool

	// send time of the largest acknowledged packet, across Initial, Handshake and appData
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

	ignorePacketsBelow        func(protocol.PacketNumber)
	ignorePacketsBelowForPath func(protocol.PathID, protocol.PacketNumber)

	ackedPackets []packetWithPacketNumber // to avoid allocations in detectAndRemoveAckedPackets

	// the bytes in flight of all paths
	bytesInFlight protocol.ByteCount

	maxDatagramSize        protocol.ByteCount
	initialMaxDatagramSize protocol.ByteCount
	rttStats               *utils.RTTStats // the RTT stats of appData
	connStats              *utils.ConnectionStats

	// Factory for creating per-path congestion controllers
	// If nil, creates Cubic controllers by default
	ccFactory func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos

	// The alarm timeout
	alarm alarmTimer
	// With IETF Multipath QUIC, the path that the alarm is set for.
	// The timers of the Initial and Handshake packet number spaces belong to path 0.
	alarmPathID protocol.PathID

	enableECN bool

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
	congestion := congestion.NewCubicSender(
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
		appData: pathRecovery{
			id:          0,
			space:       newPacketNumberSpace(0, true),
			lostPackets: *newLostPacketTracker(64),
			rttStats:    rttStats,
			congestion:  congestion,
		},
		rttStats:               rttStats,
		connStats:              connStats,
		maxDatagramSize:        initialMaxDatagramSize,
		initialMaxDatagramSize: initialMaxDatagramSize,
		ignorePacketsBelow:     ignorePacketsBelow,
		perspective:            pers,
		qlogger:                qlogger,
		logger:                 logger,
	}
	if enableECN {
		h.enableECN = true
		h.appData.ecnTracker = newECNTracker(logger, qlogger)
	}
	return h
}

// EnableMultipath enables IETF Multipath QUIC (draft-ietf-quic-multipath).
// Every path gets its own packet number space, RTT estimate, congestion controller, ECN validation and PTO state.
// When a packet containing a PATH_ACK frame for a path (or an ACK frame, for path 0) is acknowledged,
// ignorePacketsBelow is called for that path.
// If it is nil, the callback passed to NewSentPacketHandler is used for path 0.
// It must be called before any path other than path 0 is used.
// If a congestion control factory is set, path 0 gets a controller created by the factory,
// which continues with the state of the controller used so far.
func (h *sentPacketHandler) EnableMultipath(ignorePacketsBelow func(protocol.PathID, protocol.PacketNumber)) {
	if h.multipath {
		return
	}
	h.multipath = true
	h.ignorePacketsBelowForPath = ignorePacketsBelow
	if h.ccFactory != nil {
		h.replacePath0CongestionController()
	}
}

// replacePath0CongestionController replaces the congestion controller of path 0 by a controller created by the
// congestion control factory. Path 0 was used before, and the response to losses must not be undone
// (section 7.3.2 of RFC 9002): the new controller continues with the state of the old one.
// If that's not possible, path 0 keeps its controller.
func (h *sentPacketHandler) replacePath0CongestionController() {
	from, ok := h.appData.congestion.(congestion.StateExporter)
	if !ok {
		return
	}
	cc := h.ccFactory(0, h.rttStats, h.maxDatagramSize)
	to, ok := cc.(congestion.StateImporter)
	if !ok {
		unregisterCongestionController(cc)
		return
	}
	to.TakeOverState(from.State())
	h.appData.congestion = cc
}

func (h *sentPacketHandler) SetPacketObserver(o PacketObserver) {
	h.packetObserver = o
}

// SetCongestionControlFactory sets a custom factory for creating per-path congestion controllers.
// This allows using OLIA or other multipath-aware congestion control algorithms.
// The factory function receives the pathID, RTT stats, and initial max datagram size.
// It is used for congestion controllers created after this call.
func (h *sentPacketHandler) SetCongestionControlFactory(
	factory func(pathID protocol.PathID, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos,
) {
	h.ccFactory = factory
}

// path returns the state of a path, or nil if the path doesn't exist.
func (h *sentPacketHandler) path(pathID protocol.PathID) *pathRecovery {
	if pathID == 0 {
		return &h.appData
	}
	return h.paths[pathID]
}

// getOrCreatePath returns the state of a path, creating it if it doesn't exist yet.
// Paths other than path 0 can only be created with IETF Multipath QUIC.
func (h *sentPacketHandler) getOrCreatePath(pathID protocol.PathID) *pathRecovery {
	if r := h.path(pathID); r != nil {
		return r
	}
	if !h.multipath {
		panic(fmt.Sprintf("ackhandler BUG: path %d used without multipath", pathID))
	}
	if h.removedPaths.Contains(pathID) {
		// Recreating the path would reuse its packet numbers.
		panic(fmt.Sprintf("ackhandler BUG: path %d was removed", pathID))
	}
	r := &pathRecovery{
		id:          pathID,
		space:       newPacketNumberSpace(0, true),
		lostPackets: *newLostPacketTracker(64),
		rttStats:    h.newPathRTTStats(),
		// Only the server needs to validate the client's address.
		addressValidated: h.perspective == protocol.PerspectiveClient,
	}
	// Congestion control and ECN events don't name a path in qlog.
	// Only those of path 0 are logged.
	r.congestion = h.newPathCongestionController(pathID, r.rttStats, h.initialMaxDatagramSize, nil)
	if h.enableECN {
		r.ecnTracker = newECNTracker(h.logger, nil)
	}
	if h.paths == nil {
		h.paths = make(map[protocol.PathID]*pathRecovery)
	}
	h.paths[pathID] = r
	idx, _ := slices.BinarySearch(h.pathIDs, pathID)
	h.pathIDs = slices.Insert(h.pathIDs, idx, pathID)
	return r
}

// allPaths iterates over all paths, in ascending order of their path IDs.
func (h *sentPacketHandler) allPaths() iter.Seq[*pathRecovery] {
	return func(yield func(*pathRecovery) bool) {
		if !yield(&h.appData) {
			return
		}
		for _, pathID := range h.pathIDs {
			if !yield(h.paths[pathID]) {
				return
			}
		}
	}
}

func (h *sentPacketHandler) newPathRTTStats() *utils.RTTStats {
	// The peer's max_ack_delay applies to all paths.
	stats := utils.NewRTTStats()
	stats.SetMaxAckDelay(h.rttStats.MaxAckDelay())
	return stats
}

func (h *sentPacketHandler) newPathCongestionController(
	pathID protocol.PathID,
	rttStats *utils.RTTStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) congestion.SendAlgorithmWithDebugInfos {
	if h.ccFactory != nil {
		// Use custom factory (e.g., for OLIA)
		return h.ccFactory(pathID, rttStats, initialMaxDatagramSize)
	}
	return congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		qlogger,
	)
}

// AddPath creates the state of a path (IETF Multipath QUIC).
// addressValidated says if the peer's address on this path was validated.
// Until it is, the server doesn't send more than 3 times the bytes received on the path.
func (h *sentPacketHandler) AddPath(pathID protocol.PathID, addressValidated bool) {
	if !h.multipath || h.removedPaths.Contains(pathID) {
		return
	}
	if r := h.getOrCreatePath(pathID); addressValidated && r != &h.appData {
		r.addressValidated = true
	}
}

// SetPathAddressValidated is called when the peer's address on a path was validated (IETF Multipath QUIC).
func (h *sentPacketHandler) SetPathAddressValidated(pathID protocol.PathID, now monotime.Time) {
	r := h.path(pathID)
	if !h.multipath || r == nil || r == &h.appData || r.addressValidated {
		return
	}
	wasAmplificationLimited := h.isPathAmplificationLimited(r)
	r.addressValidated = true
	if wasAmplificationLimited {
		h.setLossDetectionTimer(now)
	}
}

// PathCongestionState returns the congestion window and the bytes in flight of a path.
// ok is false if the path doesn't exist.
func (h *sentPacketHandler) PathCongestionState(pathID protocol.PathID) (cwnd, bytesInFlight protocol.ByteCount, ok bool) {
	r := h.path(pathID)
	if r == nil {
		return 0, 0, false
	}
	return r.congestion.GetCongestionWindow(), r.bytesInFlight, true
}

// AbandonPath declares all packets sent on a path lost, and queues their frames for retransmission
// (IETF Multipath QUIC). This is not a congestion event.
// No packets must be sent on the path afterwards, and acknowledgments for the path are ignored.
func (h *sentPacketHandler) AbandonPath(pathID protocol.PathID, now monotime.Time) {
	r := h.path(pathID)
	if !h.multipath || r == nil {
		return
	}
	h.abandonPath(r)
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) abandonPath(r *pathRecovery) {
	r.abandoned = true
	for pn, p := range r.space.history.Packets() {
		r.space.history.DeclareLost(pn)
		if p.isPathProbePacket {
			continue
		}
		h.removeFromBytesInFlight(p)
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}
	for _, p := range removePathProbes(r.space) {
		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnLost(f.Frame)
			}
		}
	}
	r.space.lossTime = 0
	r.numProbesToSend = 0
	r.ptoCount = 0
	r.ptoMode = SendNone
	// No packets are sent on the path anymore.
	// A coupled congestion controller (e.g. OLIA) stops taking it into account.
	unregisterCongestionController(r.congestion)
}

// unregisterCongestionController removes the congestion controller of a path from the state it shares with
// the controllers of the other paths, if it is a coupled congestion controller.
func unregisterCongestionController(cc congestion.SendAlgorithmWithDebugInfos) {
	if u, ok := cc.(interface{ Unregister() }); ok {
		u.Unregister()
	}
}

// removePathProbes removes all path probe packets from the history of a packet number space, and returns them.
func removePathProbes(pnSpace *packetNumberSpace) []packetWithPacketNumber {
	// RemovePathProbe cannot be called while iterating.
	var pathProbes []packetWithPacketNumber
	for pn, p := range pnSpace.history.PathProbes() {
		pathProbes = append(pathProbes, packetWithPacketNumber{PacketNumber: pn, packet: p})
	}
	for _, p := range pathProbes {
		pnSpace.history.RemovePathProbe(p.PacketNumber)
	}
	return pathProbes
}

// RemovePath removes all state kept for a path (IETF Multipath QUIC).
// Outstanding packets sent on the path are declared lost, and their frames are queued for retransmission.
// Path 0 can't be removed, it is abandoned instead.
// The path ID of a removed path must not be used again.
func (h *sentPacketHandler) RemovePath(pathID protocol.PathID, now monotime.Time) {
	if !h.multipath {
		return
	}
	if pathID == 0 {
		h.AbandonPath(pathID, now)
		h.appData.removed = true
		return
	}
	if r, ok := h.paths[pathID]; ok {
		h.abandonPath(r)
		unregisterCongestionController(r.congestion)
		delete(h.paths, pathID)
		if idx, found := slices.BinarySearch(h.pathIDs, pathID); found {
			h.pathIDs = slices.Delete(h.pathIDs, idx, idx+1)
		}
	}
	h.removedPaths.Add(pathID)
	h.setLossDetectionTimer(now)
}

// ECNModeForPath returns the ECN marking to use for a 1-RTT packet sent on the given path.
func (h *sentPacketHandler) ECNModeForPath(pathID protocol.PathID) protocol.ECN {
	if !h.enableECN {
		return protocol.ECNUnsupported
	}
	r := h.path(pathID)
	if r == nil || r.ecnTracker == nil {
		return protocol.ECNNon
	}
	return r.ecnTracker.Mode()
}

// GetPathRTTStats returns the RTT stats of a path, or nil if the path doesn't exist.
func (h *sentPacketHandler) GetPathRTTStats(pathID protocol.PathID) *utils.RTTStats {
	if r := h.path(pathID); r != nil {
		return r.rttStats
	}
	return nil
}

func (h *sentPacketHandler) getAppDataPacketNumberSpace(pathID protocol.PathID) *packetNumberSpace {
	return h.getOrCreatePath(pathID).space
}

func (h *sentPacketHandler) removeFromBytesInFlight(p *packet) {
	if p.includedInBytesInFlight {
		if p.Length > h.bytesInFlight {
			panic("negative bytes_in_flight")
		}
		h.bytesInFlight -= p.Length
		p.includedInBytesInFlight = false
		if r := h.path(p.PathID); r != nil {
			r.bytesInFlight -= min(r.bytesInFlight, p.Length)
		}
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
		pnSpace := h.getPacketNumberSpace(encLevel, 0)
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
		for r := range h.allPaths() {
			for pn, p := range r.space.history.Packets() {
				if p.EncryptionLevel != protocol.Encryption0RTT {
					break
				}
				h.removeFromBytesInFlight(p)
				_ = r.space.history.Remove(pn)
			}
		}
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	if h.qlogger != nil && h.appData.ptoCount != 0 {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
	}
	h.appData.ptoCount = 0
	h.appData.numProbesToSend = 0
	h.appData.ptoMode = SendNone
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

// ReceivedBytesForPath is called for every datagram received on a path.
// With IETF Multipath QUIC, the bytes received on a path other than path 0
// increase the anti-amplification limit of that path.
// Without IETF Multipath QUIC, and for path 0, it is equivalent to ReceivedBytes.
func (h *sentPacketHandler) ReceivedBytesForPath(pathID protocol.PathID, n protocol.ByteCount, t monotime.Time) {
	if !h.multipath || pathID == 0 {
		h.ReceivedBytes(n, t)
		return
	}
	h.connStats.BytesReceived.Add(uint64(n))
	if h.removedPaths.Contains(pathID) {
		return
	}
	r := h.getOrCreatePath(pathID)
	wasAmplificationLimit := h.isPathAmplificationLimited(r)
	r.bytesReceived += n
	if wasAmplificationLimit && !h.isPathAmplificationLimited(r) {
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

// packetsInFlight returns the number of outstanding packets, for the qlog metrics.
// With IETF Multipath QUIC, the metrics are those of path 0, so only its packets are counted.
func (h *sentPacketHandler) packetsInFlight() int {
	packetsInFlight := h.appData.space.history.NumOutstanding()
	if h.handshakePackets != nil {
		packetsInFlight += h.handshakePackets.history.NumOutstanding()
	}
	if h.initialPackets != nil {
		packetsInFlight += h.initialPackets.history.NumOutstanding()
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
	pathAcks ...PathAck,
) {
	h.connStats.BytesSent.Add(uint64(size))
	h.connStats.PacketsSent.Add(1)

	r := &h.appData
	var pnSpace *packetNumberSpace
	//nolint:exhaustive // Initial, Handshake and application data are the only packet number spaces.
	switch encLevel {
	case protocol.EncryptionInitial:
		pnSpace = h.initialPackets
	case protocol.EncryptionHandshake:
		pnSpace = h.handshakePackets
	default:
		r = h.getOrCreatePath(pathID)
		pnSpace = r.space
	}
	if h.multipath && r != &h.appData {
		r.bytesSent += size
	} else {
		h.bytesSent += size
	}

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
	if len(pathAcks) > 0 {
		p.setPathAcks(pathAcks)
	}
	p.StreamFrames = streamFrames
	p.IsPathMTUProbePacket = isPathMTUProbePacket
	p.isPathProbePacket = isPathProbePacket
	p.PathID = r.id
	isAckEliciting := p.IsAckEliciting()
	if h.packetObserver != nil {
		h.packetObserver.OnPacketSent(newPacketEvent(pn, p, t))
	}

	if isPathProbePacket {
		pnSpace.history.SentPathProbePacket(pn, p)
		h.setLossDetectionTimer(t)
		return
	}
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		h.bytesInFlight += size
		r.bytesInFlight += size
		p.includedInBytesInFlight = true
		if r.numProbesToSend > 0 {
			r.numProbesToSend--
		}
	}

	r.congestion.OnPacketSent(t, r.bytesInFlight, pn, size, isAckEliciting)

	if encLevel == protocol.Encryption1RTT && r.ecnTracker != nil {
		r.ecnTracker.SentPacket(pn, ecn)
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
	if cwnd := h.appData.congestion.GetCongestionWindow(); h.lastMetrics.CongestionWindow != int(cwnd) {
		metricsUpdatedEvent.CongestionWindow = int(cwnd)
		h.lastMetrics.CongestionWindow = metricsUpdatedEvent.CongestionWindow
		updated = true
	}
	// With IETF Multipath QUIC, the metrics are those of path 0.
	if h.lastMetrics.BytesInFlight != int(h.appData.bytesInFlight) {
		metricsUpdatedEvent.BytesInFlight = int(h.appData.bytesInFlight)
		h.lastMetrics.BytesInFlight = metricsUpdatedEvent.BytesInFlight
		updated = true
	}
	packetsInFlight := h.packetsInFlight()
	if h.lastMetrics.PacketsInFlight != packetsInFlight {
		metricsUpdatedEvent.PacketsInFlight = packetsInFlight
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

// ReceivedAck processes an ACK frame.
// With IETF Multipath QUIC, a PATH_ACK frame acknowledges packets sent on the path it names,
// and an ACK frame acknowledges packets sent on path 0.
// The path the frame was received on doesn't matter.
func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	r := &h.appData
	var pnSpace *packetNumberSpace
	//nolint:exhaustive // 0-RTT packets can't contain ACK frames.
	switch encLevel {
	case protocol.EncryptionInitial:
		pnSpace = h.initialPackets
	case protocol.EncryptionHandshake:
		pnSpace = h.handshakePackets
	default:
		if h.multipath {
			r = h.path(ack.PathID)
			if r == nil {
				// PATH_ACK frames for removed paths are ignored (draft-ietf-quic-multipath, section 3.4.3).
				if h.removedPaths.Contains(ack.PathID) {
					return false, nil
				}
				return false, &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received ACK for path %d, which didn't send any packets", ack.PathID),
				}
			}
			// So are PATH_ACK frames for abandoned paths.
			// Packets sent on these paths were already declared lost.
			if r.abandoned {
				return false, nil
			}
		}
		pnSpace = r.space
	}

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

	priorInFlight := r.bytesInFlight
	ackedPackets, hasAckEliciting, err := h.detectAndRemoveAckedPackets(ack, encLevel, pnSpace)
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
				ackDelay = min(ack.DelayTime, r.rttStats.MaxAckDelay())
			}
			// With IETF Multipath QUIC, paths other than path 0 track the largest acknowledged packet themselves.
			largestAckedTime := &h.largestAckedTime
			if r != &h.appData {
				largestAckedTime = &r.largestAckedTime
			}
			if largestAckedTime.IsZero() || !p.SendTime.Before(*largestAckedTime) {
				r.rttStats.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay)
				if r.firstRTTSampleTime.IsZero() && r.rttStats.HasMeasurement() {
					r.firstRTTSampleTime = rcvTime
				}
				if h.logger.Debug() {
					h.logger.Debugf("\tupdated RTT: %s (σ: %s)", r.rttStats.SmoothedRTT(), r.rttStats.MeanDeviation())
				}
				*largestAckedTime = p.SendTime
			}
			r.congestion.MaybeExitSlowStart()
		}
	}

	// Only inform the ECN tracker about new 1-RTT ACKs if the ACK increases the largest acked.
	if encLevel == protocol.Encryption1RTT && r.ecnTracker != nil && largestAcked > pnSpace.largestAcked {
		congested := r.ecnTracker.HandleNewlyAcked(ackedPackets, int64(ack.ECT0), int64(ack.ECT1), int64(ack.ECNCE))
		if congested {
			r.congestion.OnCongestionEvent(largestAcked, 0, priorInFlight)
		}
	}

	pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)

	h.detectLostPackets(rcvTime, encLevel, r.id)
	if encLevel == protocol.Encryption1RTT {
		h.detectLostPathProbes(rcvTime)
	}
	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if h.packetObserver != nil {
			h.packetObserver.OnPacketAcked(newPacketEvent(p.PacketNumber, p.packet, rcvTime))
		}
		if p.includedInBytesInFlight {
			r.congestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
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
			rcvTime.Add(-min(ack.DelayTime, r.rttStats.MaxAckDelay())),
			r,
		)
		// clean up lost packet history
		r.lostPackets.DeleteBefore(rcvTime.Add(-3 * r.rttStats.PTO(false)))
	}

	// After this point, we must not use ackedPackets any longer!
	// We've already returned the buffers.
	ackedPackets = nil    //nolint:ineffassign // This is just to be on the safe side.
	clear(h.ackedPackets) // make sure the memory is released
	h.ackedPackets = h.ackedPackets[:0]

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	if h.peerCompletedAddressValidation {
		// The event doesn't name a path. With IETF Multipath QUIC, only the PTO count of path 0 is logged.
		if h.qlogger != nil && r == &h.appData && r.ptoCount != 0 {
			h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		}
		r.ptoCount = 0
	}
	r.numProbesToSend = 0

	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}

	h.setLossDetectionTimer(rcvTime)
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time, r *pathRecovery) {
	var maxPacketReordering protocol.PacketNumber
	var maxTimeReordering time.Duration
	ackRangeIdx := len(ack.AckRanges) - 1
	var spuriousLosses []protocol.PacketNumber
	for pn, sendTime := range r.lostPackets.All() {
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
			packetReordering := r.space.history.Difference(ack.LargestAcked(), pn)
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
		r.lostPackets.Delete(pn)
	}
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(
	ack *wire.AckFrame,
	encLevel protocol.EncryptionLevel,
	pnSpace *packetNumberSpace,
) (_ []packetWithPacketNumber, hasAckEliciting bool, _ error) {
	if len(h.ackedPackets) > 0 {
		return nil, false, errors.New("ackhandler BUG: ackedPackets slice not empty")
	}

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
		// The frames of probed packets were already retransmitted.
		// The packet is only kept to establish persistent congestion.
		if p.probed {
			if err := pnSpace.history.Remove(pn); err != nil {
				return nil, false, err
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
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT {
			h.ackOfAckReceived(p.AckPathID, p.LargestAcked)
			for _, a := range p.extraAcks {
				h.ackOfAckReceived(a.PathID, a.LargestAcked)
			}
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

// ackOfAckReceived is called when a packet containing an ACK or a PATH_ACK frame was acknowledged.
// pathID is the path acknowledged by the frame: an ACK frame acknowledges packets received on path 0.
func (h *sentPacketHandler) ackOfAckReceived(pathID protocol.PathID, largestAcked protocol.PacketNumber) {
	if h.ignorePacketsBelowForPath != nil {
		h.ignorePacketsBelowForPath(pathID, largestAcked+1)
	} else if pathID == 0 && h.ignorePacketsBelow != nil {
		h.ignorePacketsBelow(largestAcked + 1)
	}
}

// canArmTimers says if the loss detection timer is armed for packets sent on a path.
// For appData, the anti-amplification limit is checked in lossDetectionTime and pathLossDetectionTime.
func (h *sentPacketHandler) canArmTimers(r *pathRecovery) bool {
	return !r.abandoned && (r == &h.appData || !h.isPathAmplificationLimited(r))
}

// pathLossTime returns the loss time of the application data packets sent on a path,
// or zero if the loss detection timer is not armed for them.
func (h *sentPacketHandler) pathLossTime(r *pathRecovery) monotime.Time {
	if !h.canArmTimers(r) {
		return 0
	}
	return r.space.lossTime
}

// getLossTimeAndSpace returns the earliest loss time of the packet number spaces recovered together with path r.
// Every path is recovered on its own (RFC 9002 applied per path).
// The Initial and Handshake packet number spaces are recovered together with path 0.
func (h *sentPacketHandler) getLossTimeAndSpace(r *pathRecovery) (monotime.Time, protocol.EncryptionLevel, protocol.PathID) {
	var encLevel protocol.EncryptionLevel
	var lossTime monotime.Time
	var pathID protocol.PathID

	if r == &h.appData {
		if h.initialPackets != nil {
			lossTime = h.initialPackets.lossTime
			encLevel = protocol.EncryptionInitial
			pathID = h.appData.id
		}
		if h.handshakePackets != nil && (lossTime.IsZero() || (!h.handshakePackets.lossTime.IsZero() && h.handshakePackets.lossTime.Before(lossTime))) {
			lossTime = h.handshakePackets.lossTime
			encLevel = protocol.EncryptionHandshake
			pathID = h.appData.id
		}
	}
	if t := h.pathLossTime(r); !t.IsZero() && (lossTime.IsZero() || t.Before(lossTime)) {
		return t, protocol.Encryption1RTT, r.id
	}
	return lossTime, encLevel, pathID
}

func (h *sentPacketHandler) getScaledPTO(includeMaxAckDelay bool) time.Duration {
	return scalePTO(h.rttStats.PTO(includeMaxAckDelay), h.appData.ptoCount)
}

// getScaledPathPTO returns the PTO for application data packets sent on a path.
// Paths can have very different RTTs, so the connection's RTT can't be used.
func (h *sentPacketHandler) getScaledPathPTO(r *pathRecovery) time.Duration {
	return scalePTO(r.rttStats.PTO(true), r.ptoCount)
}

func scalePTO(pto time.Duration, ptoCount uint32) time.Duration {
	pto <<= ptoCount
	if pto > maxPTODuration || pto <= 0 {
		return maxPTODuration
	}
	return pto
}

// same logic as getLossTimeAndSpace, but for lastAckElicitingPacketTime instead of lossTime
func (h *sentPacketHandler) getPTOTimeAndSpace(now monotime.Time, r *pathRecovery) (pto monotime.Time, encLevel protocol.EncryptionLevel, pathID protocol.PathID) {
	if r == &h.appData {
		// We only send application data probe packets once the handshake is confirmed,
		// because before that, we don't have the keys to decrypt ACKs sent in 1-RTT packets.
		if !h.handshakeConfirmed && !h.hasOutstandingCryptoPackets() {
			if h.peerCompletedAddressValidation {
				return
			}
			t := now.Add(h.getScaledPTO(false))
			if h.initialPackets != nil {
				return t, protocol.EncryptionInitial, h.appData.id
			}
			return t, protocol.EncryptionHandshake, h.appData.id
		}

		if h.initialPackets != nil && h.initialPackets.history.HasOutstandingPackets() &&
			!h.initialPackets.lastAckElicitingPacketTime.IsZero() {
			encLevel = protocol.EncryptionInitial
			pathID = h.appData.id
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
				pathID = h.appData.id
			}
		}
	}
	if !h.handshakeConfirmed {
		return pto, encLevel, pathID
	}
	if t := h.pathPTOTime(r); !t.IsZero() && (pto.IsZero() || t.Before(pto)) {
		return t, protocol.Encryption1RTT, r.id
	}
	return pto, encLevel, pathID
}

// pathPTOTime returns the PTO time of the application data packets sent on a path,
// or zero if the PTO timer is not armed for them.
func (h *sentPacketHandler) pathPTOTime(r *pathRecovery) monotime.Time {
	if !r.space.history.HasOutstandingPackets() || r.space.lastAckElicitingPacketTime.IsZero() || !h.canArmTimers(r) {
		return 0
	}
	return r.space.lastAckElicitingPacketTime.Add(h.getScaledPathPTO(r))
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
	var newAlarm alarmTimer
	if h.multipath {
		newAlarm, h.alarmPathID = h.multipathLossDetectionTime(now)
	} else {
		newAlarm = h.lossDetectionTime(now)
	}
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

// lossDetectionTime returns the loss detection timer of a connection that doesn't use IETF Multipath QUIC.
func (h *sentPacketHandler) lossDetectionTime(now monotime.Time) alarmTimer {
	// cancel the alarm if no packets are outstanding
	if h.peerCompletedAddressValidation && !h.hasOutstandingCryptoPackets() &&
		!h.appData.space.history.HasOutstandingPackets() && !h.appData.space.history.HasOutstandingPathProbes() {
		return alarmTimer{}
	}

	// cancel the alarm if amplification limited
	if h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var pathProbeLossTime monotime.Time
	if h.appData.space.history.HasOutstandingPathProbes() {
		if _, p := h.appData.space.history.FirstOutstandingPathProbe(); p != nil {
			pathProbeLossTime = p.SendTime.Add(pathProbePacketLossTimeout)
		}
	}

	// early retransmit timer or time loss detection
	lossTime, encLevel, _ := h.getLossTimeAndSpace(&h.appData)
	if !lossTime.IsZero() && (pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            lossTime,
			TimerType:       qlog.TimerTypeACK,
			EncryptionLevel: encLevel,
		}
	}
	ptoTime, encLevel, _ := h.getPTOTimeAndSpace(now, &h.appData)
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

// multipathLossDetectionTime is lossDetectionTime for a connection using IETF Multipath QUIC.
// Every path runs its own loss recovery (draft-ietf-quic-multipath, sections 1 and 5.7),
// and has its own timer (see pathLossDetectionTime).
// The alarm is set for the earliest of them. If timers are equal, the path with the lowest path ID is selected.
func (h *sentPacketHandler) multipathLossDetectionTime(now monotime.Time) (alarmTimer, protocol.PathID) {
	var alarm alarmTimer
	var pathID protocol.PathID
	for r := range h.allPaths() {
		if t := h.pathLossDetectionTime(now, r); !t.Time.IsZero() && (alarm.Time.IsZero() || t.Time.Before(alarm.Time)) {
			alarm = t
			pathID = r.id
		}
	}
	return alarm, pathID
}

// pathLossDetectionTime returns the timer of a path of a connection using IETF Multipath QUIC.
// As in Appendix A.8 of RFC 9002, this is the path's loss time if one is set, and its PTO time otherwise.
// The timer of path 0 also covers the Initial and Handshake packet number spaces.
// If the first outstanding path probe packet sent on the path is declared lost earlier, the timer is set for that.
func (h *sentPacketHandler) pathLossDetectionTime(now monotime.Time, r *pathRecovery) alarmTimer {
	// cancel the timer if amplification limited
	if r == &h.appData && h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var alarm alarmTimer
	// If no packets are outstanding, there's nothing to detect lost.
	// However, the client needs to arm the timer if the server might be blocked by the anti-amplification limit.
	hasOutstanding := r.space.history.HasOutstandingPackets()
	if r == &h.appData {
		hasOutstanding = hasOutstanding || h.hasOutstandingCryptoPackets() || !h.peerCompletedAddressValidation
	}
	if hasOutstanding {
		if lossTime, encLevel, _ := h.getLossTimeAndSpace(r); !lossTime.IsZero() {
			alarm = alarmTimer{
				Time:            lossTime,
				TimerType:       qlog.TimerTypeACK,
				EncryptionLevel: encLevel,
			}
		} else if ptoTime, encLevel, _ := h.getPTOTimeAndSpace(now, r); !ptoTime.IsZero() {
			alarm = alarmTimer{
				Time:            ptoTime,
				TimerType:       qlog.TimerTypePTO,
				EncryptionLevel: encLevel,
			}
		}
	}
	if _, p := r.space.history.FirstOutstandingPathProbe(); p != nil {
		if lossTime := p.SendTime.Add(pathProbePacketLossTimeout); alarm.Time.IsZero() || lossTime.Before(alarm.Time) {
			alarm = alarmTimer{
				Time:            lossTime,
				TimerType:       qlog.TimerTypePathProbe,
				EncryptionLevel: protocol.Encryption1RTT,
			}
		}
	}
	return alarm
}

func (h *sentPacketHandler) detectLostPathProbes(now monotime.Time) {
	lossTime := now.Add(-pathProbePacketLossTimeout)
	for r := range h.allPaths() {
		if !r.space.history.HasOutstandingPathProbes() {
			continue
		}
		// RemovePathProbe cannot be called while iterating.
		var lostPathProbes []packetWithPacketNumber
		for pn, p := range r.space.history.PathProbes() {
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
			r.space.history.RemovePathProbe(p.PacketNumber)
		}
	}
}

func (h *sentPacketHandler) detectLostPackets(now monotime.Time, encLevel protocol.EncryptionLevel, pathID protocol.PathID) {
	r := &h.appData
	if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
		r = h.path(pathID)
	}
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	pnSpace.lossTime = 0

	maxRTT := float64(max(r.rttStats.LatestRTT(), r.rttStats.SmoothedRTT()))
	lossDelay := time.Duration(timeThreshold * maxRTT)

	// Minimum time of granularity before packets are deemed lost.
	lossDelay = max(lossDelay, protocol.TimerGranularity)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	// Persistent congestion (section 7.6 of RFC 9002) is established if two ack-eliciting packets declared lost here
	// were sent more than the persistent congestion duration apart, and no packet sent between them was acknowledged.
	// Only packets sent after the first RTT sample on the path, and only those of this packet number space,
	// are taken into account.
	pcDuration := persistentCongestionThreshold * r.rttStats.PTO(true)
	var pcStart monotime.Time // send time of the first lost packet since the last acknowledged packet
	var persistentCongestion bool
	prevPN := protocol.InvalidPacketNumber

	priorInFlight := r.bytesInFlight
	for pn, p := range pnSpace.history.Packets() {
		if pn > pnSpace.largestAcked {
			break
		}
		// A packet sent between the previous packet and this packet was acknowledged.
		if p.precedingAcked > prevPN {
			pcStart = 0
		}
		prevPN = pn

		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (time threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header:  h.qlogPacketHeader(p, pn),
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
						Header:  h.qlogPacketHeader(p, pn),
						Trigger: qlog.PacketLossReorderingThreshold,
					})
				}
			}
		} else if pnSpace.lossTime.IsZero() && !p.probed {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", pn, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost && p.probed {
			// The frames of this packet were already retransmitted in a PTO probe packet,
			// and it was removed from bytes in flight.
			// Its loss doesn't change the congestion window, but it can establish persistent congestion.
			pnSpace.history.DeclareLost(pn)
			persistentCongestion = h.updatePersistentCongestion(r, p, &pcStart, pcDuration) || persistentCongestion
		} else if packetLost {
			if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
				r.lostPackets.Add(pn, p.SendTime)
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
					r.congestion.OnCongestionEvent(pn, p.Length, priorInFlight)
					persistentCongestion = h.updatePersistentCongestion(r, p, &pcStart, pcDuration) || persistentCongestion
				}
				if encLevel == protocol.Encryption1RTT && r.ecnTracker != nil {
					r.ecnTracker.LostPacket(pn)
				}
			}
		}
	}
	if persistentCongestion {
		if h.logger.Debug() {
			h.logger.Debugf("\tpersistent congestion (%s)", encLevel)
		}
		r.congestion.OnPersistentCongestion()
	}
}

// updatePersistentCongestion is called for every ack-eliciting packet declared lost in detectLostPackets,
// except for Path MTU probe packets, whose loss is not a congestion signal.
// pcStart is the send time of the first such packet since the last acknowledged packet, or zero.
// It returns true if the loss of p establishes persistent congestion.
func (h *sentPacketHandler) updatePersistentCongestion(r *pathRecovery, p *packet, pcStart *monotime.Time, pcDuration time.Duration) bool {
	// Persistent congestion can only be established after an RTT sample (section 7.6.2 of RFC 9002).
	if r.firstRTTSampleTime.IsZero() || !p.SendTime.After(r.firstRTTSampleTime) {
		return false
	}
	if pcStart.IsZero() {
		*pcStart = p.SendTime
		return false
	}
	return p.SendTime.Sub(*pcStart) > pcDuration
}

// qlogPacketHeader returns the header logged for a lost packet.
// With IETF Multipath QUIC, the header of a 1-RTT packet contains the path ID.
func (h *sentPacketHandler) qlogPacketHeader(p *packet, pn protocol.PacketNumber) qlog.PacketHeader {
	hdr := qlog.PacketHeader{
		PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
		PacketNumber: pn,
	}
	if h.multipath && p.EncryptionLevel == protocol.Encryption1RTT {
		hdr.PathID = p.PathID
		hdr.HasPathID = true
	}
	return hdr
}

func (h *sentPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	defer h.setLossDetectionTimer(now)

	if h.handshakeConfirmed {
		h.detectLostPathProbes(now)
	}

	// With IETF Multipath QUIC, every path has its own timer (see multipathLossDetectionTime).
	// Only the timer that the alarm was set for is handled.
	// If the timers of other paths expired as well, the alarm is set for the next one,
	// and it fires right away.
	r := &h.appData
	if h.multipath {
		// Path probe packets were already declared lost above.
		if h.alarm.TimerType == qlog.TimerTypePathProbe {
			return nil
		}
		if r = h.path(h.alarmPathID); r == nil {
			return nil
		}
	}

	earliestLossTime, encLevel, lossPathID := h.getLossTimeAndSpace(r)
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
	// The bytes in flight of path 0 include the Initial and Handshake packets.
	if r == &h.appData && r.bytesInFlight == 0 && !h.peerCompletedAddressValidation {
		h.appData.ptoCount++
		h.appData.numProbesToSend++
		if h.initialPackets != nil {
			h.appData.ptoMode = SendPTOInitial
		} else if h.handshakePackets != nil {
			h.appData.ptoMode = SendPTOHandshake
		} else {
			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
		}
		return nil
	}

	ptoTime, encLevel, ptoPathID := h.getPTOTimeAndSpace(now, r)
	if ptoTime.IsZero() {
		return nil
	}
	ps := h.getPacketNumberSpace(encLevel, ptoPathID)
	if !ps.history.HasOutstandingPackets() && !ps.history.HasOutstandingPathProbes() && !h.peerCompletedAddressValidation {
		return nil
	}
	pto := &h.appData
	if encLevel == protocol.Encryption1RTT {
		pto = h.path(ptoPathID)
	}
	pto.ptoCount++
	if h.logger.Debug() {
		if h.multipath && encLevel == protocol.Encryption1RTT {
			h.logger.Debugf("Loss detection alarm for %s on path %d fired in PTO mode. PTO count: %d", encLevel, ptoPathID, pto.ptoCount)
		} else {
			h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, pto.ptoCount)
		}
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeExpired,
			TimerType: qlog.TimerTypePTO,
			EncLevel:  encLevel,
		})
		// The event doesn't name a path. With IETF Multipath QUIC, only the PTO count of path 0 is logged.
		if pto == &h.appData {
			h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: pto.ptoCount})
		}
	}
	pto.numProbesToSend += 2
	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		pto.ptoMode = SendPTOInitial
	case protocol.EncryptionHandshake:
		pto.ptoMode = SendPTOHandshake
	case protocol.Encryption1RTT:
		// skip a packet number in order to elicit an immediate ACK
		pn := h.PopPacketNumber(ptoPathID, protocol.Encryption1RTT)
		h.getPacketNumberSpace(protocol.Encryption1RTT, ptoPathID).history.SkippedPacket(pn)
		pto.ptoMode = SendPTOAppData
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
	return h.appData.ecnTracker.Mode()
}

func (h *sentPacketHandler) PeekPacketNumber(pathID protocol.PathID, encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	pn := pnSpace.pns.Peek()
	// See section 17.1 of RFC 9000.
	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

func (h *sentPacketHandler) PopPacketNumber(pathID protocol.PathID, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	pnSpace := h.getPacketNumberSpace(encLevel, pathID)
	skipped, pn := pnSpace.pns.Pop()
	if skipped {
		skippedPN := pn - 1
		pnSpace.history.SkippedPacket(skippedPN)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d", skippedPN)
		}
	}
	return pn
}

func (h *sentPacketHandler) SendMode(now monotime.Time) SendMode {
	if h.multipath {
		return h.multipathSendMode(now)
	}
	numTrackedPackets := h.appData.space.history.Len()
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
	if h.appData.numProbesToSend > 0 {
		return h.appData.ptoMode
	}
	// Only send ACKs if we're congestion limited.
	if !h.appData.congestion.CanSend(h.bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, h.appData.congestion.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	if !h.appData.congestion.HasPacingBudget(now) {
		return SendPacingLimited
	}
	return SendAny
}

// multipathSendMode is the SendMode of an IETF Multipath QUIC connection.
// It summarizes the send modes of all paths:
// a probe packet is due if a path needs to send one (the path with the lowest path ID is preferred),
// otherwise the connection can send if any path can send.
func (h *sentPacketHandler) multipathSendMode(now monotime.Time) SendMode {
	mode := SendNone
	for r := range h.allPaths() {
		switch m := h.pathSendMode(r, now); m {
		case SendPTOInitial, SendPTOHandshake, SendPTOAppData:
			return m
		case SendAny:
			mode = SendAny
		case SendPacingLimited:
			if mode != SendAny {
				mode = SendPacingLimited
			}
		case SendAck:
			if mode == SendNone {
				mode = SendAck
			}
		case SendNone:
		}
	}
	return mode
}

// SendModeForPath returns the send mode of a path.
// The anti-amplification limit, the number of tracked packets, PTO probes, the congestion window
// and pacing apply per path.
// Without IETF Multipath QUIC, it returns the SendMode of the connection.
func (h *sentPacketHandler) SendModeForPath(pathID protocol.PathID, now monotime.Time) SendMode {
	if !h.multipath {
		return h.SendMode(now)
	}
	r := h.path(pathID)
	if r == nil {
		return SendNone
	}
	return h.pathSendMode(r, now)
}

func (h *sentPacketHandler) pathSendMode(r *pathRecovery, now monotime.Time) SendMode {
	if r.abandoned {
		return SendNone
	}
	numTrackedPackets := r.space.history.Len()
	if r == &h.appData {
		if h.initialPackets != nil {
			numTrackedPackets += h.initialPackets.history.Len()
		}
		if h.handshakePackets != nil {
			numTrackedPackets += h.handshakePackets.history.Len()
		}
	}
	if h.isPathAmplificationLimited(r) {
		if h.logger.Debug() {
			h.logger.Debugf("Path %d: amplification window limited", r.id)
		}
		return SendNone
	}
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Path %d: limited by the number of tracked packets: tracking %d packets, maximum %d", r.id, numTrackedPackets, protocol.MaxTrackedSentPackets)
		}
		return SendNone
	}
	if r.numProbesToSend > 0 {
		return r.ptoMode
	}
	if !r.congestion.CanSend(r.bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Path %d: congestion limited: bytes in flight %d, window %d", r.id, r.bytesInFlight, r.congestion.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Path %d: max outstanding limited: tracking %d packets, maximum: %d", r.id, numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	if !r.congestion.HasPacingBudget(now) {
		return SendPacingLimited
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() monotime.Time {
	if !h.multipath {
		return h.appData.congestion.TimeUntilSend(h.bytesInFlight)
	}
	// the earliest time at which a path that is not congestion limited can send
	var t monotime.Time
	var found bool
	for r := range h.allPaths() {
		if r.abandoned || !r.congestion.CanSend(r.bytesInFlight) {
			continue
		}
		pt := r.congestion.TimeUntilSend(r.bytesInFlight)
		if pt.IsZero() {
			return 0
		}
		if !found || pt.Before(t) {
			t = pt
			found = true
		}
	}
	if !found {
		return h.appData.congestion.TimeUntilSend(h.appData.bytesInFlight)
	}
	return t
}

// TimeUntilSendForPath is the time when the next packet should be sent on a path.
// Without IETF Multipath QUIC, it returns TimeUntilSend.
func (h *sentPacketHandler) TimeUntilSendForPath(pathID protocol.PathID) monotime.Time {
	if !h.multipath {
		return h.TimeUntilSend()
	}
	r := h.path(pathID)
	if r == nil {
		return 0
	}
	return r.congestion.TimeUntilSend(r.bytesInFlight)
}

// SetMaxDatagramSize sets the maximum datagram size of path 0.
// With IETF Multipath QUIC, every path has its own maximum datagram size (see SetMaxDatagramSizeForPath).
func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.maxDatagramSize = s
	h.appData.congestion.SetMaxDatagramSize(s)
}

// SetMaxDatagramSizeForPath sets the maximum datagram size of a path.
// Without IETF Multipath QUIC, it is equivalent to SetMaxDatagramSize.
func (h *sentPacketHandler) SetMaxDatagramSizeForPath(pathID protocol.PathID, s protocol.ByteCount) {
	if !h.multipath || pathID == 0 {
		h.SetMaxDatagramSize(s)
		return
	}
	if r := h.path(pathID); r != nil {
		r.congestion.SetMaxDatagramSize(s)
	}
}

// MaxPTO returns the largest PTO (without exponential backoff) of all paths that were not removed.
// This includes abandoned paths: packets sent by the peer on these paths might still arrive
// (section 3.4 of draft-ietf-quic-multipath-21).
// Without IETF Multipath QUIC, it is the PTO of the connection.
func (h *sentPacketHandler) MaxPTO(includeMaxAckDelay bool) time.Duration {
	if !h.multipath {
		return h.rttStats.PTO(includeMaxAckDelay)
	}
	var pto time.Duration
	var found bool
	for r := range h.allPaths() {
		if r.removed {
			continue
		}
		pto = max(pto, r.rttStats.PTO(includeMaxAckDelay))
		found = true
	}
	if !found {
		return h.rttStats.PTO(includeMaxAckDelay)
	}
	return pto
}

// OutstandingPackets iterates over the outstanding packets sent on a path, in ascending order of their packet numbers:
// the ack-eliciting packets that were neither acknowledged nor declared lost.
// Path probe packets and Path MTU probe packets are not included, and neither are packets sent on abandoned paths.
// It is only used with IETF Multipath QUIC. The frames of the packets must not be modified.
func (h *sentPacketHandler) OutstandingPackets(pathID protocol.PathID) iter.Seq[PacketEvent] {
	return func(yield func(PacketEvent) bool) {
		if !h.multipath {
			return
		}
		r := h.path(pathID)
		if r == nil || r.abandoned {
			return
		}
		for pn, p := range r.space.history.Packets() {
			if !p.Outstanding() {
				continue
			}
			if !yield(newPacketEvent(pn, p, p.SendTime)) {
				return
			}
		}
	}
}

// DeclareOutstandingLost declares the outstanding packets sent on a path lost, and queues their frames for
// retransmission. Like for any other lost packet, the congestion controller of the path reduces the congestion
// window (section 7.3.2 of RFC 9002). The PTO state of the path is kept.
// It is used when a path potentially failed (IETF Multipath QUIC): without acknowledgments for the path,
// its packets would only be declared lost by the path's probe timeouts (section 5.7 of draft-ietf-quic-multipath-21).
// Acknowledgments received for these packets later are ignored.
func (h *sentPacketHandler) DeclareOutstandingLost(pathID protocol.PathID, now monotime.Time) {
	if !h.multipath {
		return
	}
	r := h.path(pathID)
	if r == nil || r.abandoned {
		return
	}
	priorInFlight := r.bytesInFlight
	var declaredLost bool
	for pn, p := range r.space.history.Packets() {
		if !p.Outstanding() {
			continue
		}
		declaredLost = true
		if h.logger.Debug() {
			h.logger.Debugf("\tlost packet %d (path %d potentially failed)", pn, pathID)
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.PacketLost{Header: h.qlogPacketHeader(p, pn)})
		}
		r.lostPackets.Add(pn, p.SendTime)
		r.space.history.DeclareLost(pn)
		if h.packetObserver != nil {
			h.packetObserver.OnPacketLost(newPacketEvent(pn, p, now))
		}
		h.removeFromBytesInFlight(p)
		h.queueFramesForRetransmission(p)
		r.congestion.OnCongestionEvent(pn, p.Length, priorInFlight)
		if r.ecnTracker != nil {
			r.ecnTracker.LostPacket(pn)
		}
	}
	r.space.lossTime = 0
	h.setLossDetectionTimer(now)
	if declaredLost && h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
}

func (h *sentPacketHandler) isAmplificationLimited() bool {
	if h.peerAddressValidated {
		return false
	}
	return h.bytesSent >= amplificationFactor*h.bytesReceived
}

// isPathAmplificationLimited says if sending on a path is limited by the anti-amplification limit.
// For path 0, this is the anti-amplification limit of the handshake.
func (h *sentPacketHandler) isPathAmplificationLimited(r *pathRecovery) bool {
	if r == &h.appData {
		return h.isAmplificationLimited()
	}
	if !h.multipath || r.addressValidated {
		return false
	}
	return r.bytesSent >= amplificationFactor*r.bytesReceived
}

// AmplificationBudgetForPath returns the number of bytes that can be sent on a path
// before the anti-amplification limit of the path is reached.
// For path 0, this is the anti-amplification limit of the handshake. The other paths are paths of IETF Multipath QUIC.
// It returns protocol.MaxByteCount if the limit doesn't apply to the path.
func (h *sentPacketHandler) AmplificationBudgetForPath(pathID protocol.PathID) protocol.ByteCount {
	if pathID == 0 {
		if h.peerAddressValidated {
			return protocol.MaxByteCount
		}
		if limit := amplificationFactor * h.bytesReceived; limit > h.bytesSent {
			return limit - h.bytesSent
		}
		return 0
	}
	r := h.path(pathID)
	if !h.multipath || r == nil || r.addressValidated {
		return protocol.MaxByteCount
	}
	if limit := amplificationFactor * r.bytesReceived; limit > r.bytesSent {
		return limit - r.bytesSent
	}
	return 0
}

func (h *sentPacketHandler) QueueProbePacket(encLevel protocol.EncryptionLevel) bool {
	// With IETF Multipath QUIC, the probe packet is sent on the path whose PTO expired.
	if h.multipath && (encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT) {
		pathID, ok := h.NextProbePath()
		if !ok {
			pathID = 0
		}
		return h.QueueProbePacketForPath(pathID)
	}
	return h.queueProbePacket(h.getPacketNumberSpace(encLevel, 0))
}

// QueueProbePacketForPath queues the frames of the oldest outstanding 1-RTT packet sent on a path for retransmission.
// Without IETF Multipath QUIC, it is equivalent to QueueProbePacket for 1-RTT packets.
func (h *sentPacketHandler) QueueProbePacketForPath(pathID protocol.PathID) bool {
	if !h.multipath {
		return h.QueueProbePacket(protocol.Encryption1RTT)
	}
	r := h.path(pathID)
	if r == nil {
		return false
	}
	return h.queueProbePacket(r.space)
}

func (h *sentPacketHandler) queueProbePacket(pnSpace *packetNumberSpace) bool {
	pn, p := pnSpace.history.FirstOutstanding()
	if p == nil {
		return false
	}
	// TODO: don't remove the packet from bytes in flight here.
	// Keep track of acknowledged frames instead.
	// Call DeclareProbed before queueFramesForRetransmission, which clears the packet's frames.
	pnSpace.history.DeclareProbed(pn)
	h.removeFromBytesInFlight(p)
	h.queueFramesForRetransmission(p)
	return true
}

// NextProbePath returns the path with the lowest path ID that needs to send PTO probe packets.
// Without IETF Multipath QUIC, this is path 0.
func (h *sentPacketHandler) NextProbePath() (protocol.PathID, bool) {
	if !h.multipath {
		return 0, h.appData.numProbesToSend > 0
	}
	for r := range h.allPaths() {
		if !r.abandoned && r.numProbesToSend > 0 {
			return r.id, true
		}
	}
	return protocol.InvalidPathID, false
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

// ResetForRetry is called when the client receives a Retry packet.
// IETF Multipath QUIC is only used once the handshake completes, so all packets were sent on path 0.
func (h *sentPacketHandler) ResetForRetry(now monotime.Time) {
	h.bytesInFlight = 0
	h.appData.bytesInFlight = 0
	var firstPacketSendTime monotime.Time
	for _, p := range h.initialPackets.history.Packets() {
		if firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}
	// All application data packets sent at this point are 0-RTT packets.
	// In the case of a Retry, we can assume that the server dropped all of them.
	for _, p := range h.appData.space.history.Packets() {
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}

	// Only use the Retry to estimate the RTT if we didn't send any retransmission for the Initial.
	// Otherwise, we don't know which Initial the Retry was sent in response to.
	if h.appData.ptoCount == 0 {
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
	h.appData.space = newPacketNumberSpace(h.appData.space.pns.Peek(), true)
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
	h.appData.ptoCount = 0
}

func (h *sentPacketHandler) MigratedPath(now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	if h.multipath {
		h.MigratedPathForPath(0, now, initialMaxDatagramSize)
		return
	}
	h.rttStats.ResetForPathMigration()
	h.appData.firstRTTSampleTime = 0
	h.declareAllLostForMigration(&h.appData)
	h.appData.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
	)
	// The new path might not have the same ECN capability (sections 9.2 and 13.4.2 of RFC 9000).
	// ECN validation starts again.
	if h.appData.ecnTracker != nil {
		h.appData.ecnTracker.Restart()
	}
	h.setLossDetectionTimer(now)
}

// SetECNEnabled enables or disables sending of ECN-marked packets, without IETF Multipath QUIC.
// It is called when the client switched to a path whose connection can or can't set the ECN bits.
// Enabling ECN starts ECN validation (section 13.4.2 of RFC 9000).
// With IETF Multipath QUIC, the ECN marking is chosen for every path, see ECNModeForPath.
func (h *sentPacketHandler) SetECNEnabled(enabled bool) {
	if h.multipath || enabled == h.enableECN {
		return
	}
	h.enableECN = enabled
	if enabled {
		h.appData.ecnTracker = newECNTracker(h.logger, h.qlogger)
	} else {
		h.appData.ecnTracker = nil
	}
}

// MigratedPathForPath resets the RTT estimate and the congestion controller of a path
// after the path's peer address changed, and declares all packets sent on the path lost.
// Without IETF Multipath QUIC, it is equivalent to MigratedPath.
func (h *sentPacketHandler) MigratedPathForPath(pathID protocol.PathID, now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	if !h.multipath {
		h.MigratedPath(now, initialMaxDatagramSize)
		return
	}
	r := h.path(pathID)
	if r == nil {
		return
	}
	r.rttStats.ResetForPathMigration()
	r.firstRTTSampleTime = 0
	h.declareAllLostForMigration(r)
	unregisterCongestionController(r.congestion)
	var qlogger qlogwriter.Recorder
	if r == &h.appData {
		qlogger = h.qlogger
	}
	r.congestion = h.newPathCongestionController(r.id, r.rttStats, initialMaxDatagramSize, qlogger)
	// The new path might not have the same ECN capability (section 9.2 of RFC 9000).
	// ECN validation starts again.
	if r.ecnTracker != nil {
		r.ecnTracker.Restart()
	}
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) declareAllLostForMigration(r *pathRecovery) {
	for pn, p := range r.space.history.Packets() {
		r.space.history.DeclareLost(pn)
		if !p.isPathProbePacket {
			h.removeFromBytesInFlight(p)
			if p.IsAckEliciting() {
				h.queueFramesForRetransmission(p)
			}
		}
	}
	removePathProbes(r.space)
}
