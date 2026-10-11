package ackhandler

import (
	"fmt"
	"iter"
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

type ReceivedPacketHandler struct {
	initialPackets   *receivedPacketTracker
	handshakePackets *receivedPacketTracker
	// The application data packets received on path 0.
	appDataPackets appDataReceivedPacketTracker
	// IETF Multipath QUIC: the trackers of all other paths, and their path IDs in ascending order.
	// Every path has its own packet number space.
	paths   map[protocol.PathID]*appDataReceivedPacketTracker
	pathIDs []protocol.PathID
	// IETF Multipath QUIC: paths that were removed
	closedPaths utils.PathIDSet
	// Is IETF Multipath QUIC used?
	multipath bool

	ackDuePaths []protocol.PathID // returned by AckDuePaths

	lowest1RTTPacket protocol.PacketNumber
	logger           utils.Logger
}

func NewReceivedPacketHandler(logger utils.Logger) *ReceivedPacketHandler {
	return &ReceivedPacketHandler{
		initialPackets:   newReceivedPacketTracker(),
		handshakePackets: newReceivedPacketTracker(),
		appDataPackets:   *newAppDataReceivedPacketTracker(logger),
		lowest1RTTPacket: protocol.InvalidPacketNumber,
		logger:           logger,
	}
}

// EnableMultipath enables IETF Multipath QUIC (draft-ietf-quic-multipath).
// Every path has its own packet number space, and 1-RTT packets are acknowledged using PATH_ACK frames.
// The tracker used so far becomes the tracker of path 0.
func (h *ReceivedPacketHandler) EnableMultipath() {
	h.multipath = true
}

// tracker returns the tracker of a path, or nil if there's no tracker for the path.
func (h *ReceivedPacketHandler) tracker(pathID protocol.PathID) *appDataReceivedPacketTracker {
	if h.closedPaths.Contains(pathID) {
		return nil
	}
	if pathID == 0 {
		return &h.appDataPackets
	}
	return h.paths[pathID]
}

// getOrCreateTracker returns the tracker of a path, and creates it if it doesn't exist yet.
// Trackers for paths other than path 0 are only created with IETF Multipath QUIC.
// It returns nil if the path was removed.
func (h *ReceivedPacketHandler) getOrCreateTracker(pathID protocol.PathID) *appDataReceivedPacketTracker {
	if tracker := h.tracker(pathID); tracker != nil {
		return tracker
	}
	if !h.multipath || h.closedPaths.Contains(pathID) {
		return nil
	}
	tracker := newAppDataReceivedPacketTracker(h.logger)
	if h.paths == nil {
		h.paths = make(map[protocol.PathID]*appDataReceivedPacketTracker)
	}
	h.paths[pathID] = tracker
	idx, _ := slices.BinarySearch(h.pathIDs, pathID)
	h.pathIDs = slices.Insert(h.pathIDs, idx, pathID)
	return tracker
}

func (h *ReceivedPacketHandler) deleteTracker(pathID protocol.PathID) {
	delete(h.paths, pathID)
	if idx, found := slices.BinarySearch(h.pathIDs, pathID); found {
		h.pathIDs = slices.Delete(h.pathIDs, idx, idx+1)
	}
}

// allTrackers iterates over the trackers of all paths, in ascending order of their path IDs.
func (h *ReceivedPacketHandler) allTrackers() iter.Seq2[protocol.PathID, *appDataReceivedPacketTracker] {
	return func(yield func(protocol.PathID, *appDataReceivedPacketTracker) bool) {
		if !h.closedPaths.Contains(0) && !yield(0, &h.appDataPackets) {
			return
		}
		for _, pathID := range h.pathIDs {
			if !yield(pathID, h.paths[pathID]) {
				return
			}
		}
	}
}

func (h *ReceivedPacketHandler) ReceivedPacket(
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	encLevel protocol.EncryptionLevel,
	rcvTime monotime.Time,
	ackEliciting bool,
	pathID protocol.PathID,
) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.EncryptionHandshake:
		// The Handshake packet number space might already have been dropped as a result
		// of processing the CRYPTO frame that was contained in this packet.
		if h.handshakePackets == nil {
			return nil
		}
		return h.handshakePackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.Encryption0RTT:
		if h.lowest1RTTPacket != protocol.InvalidPacketNumber && pn > h.lowest1RTTPacket {
			return fmt.Errorf("received packet number %d on a 0-RTT packet after receiving %d on a 1-RTT packet", pn, h.lowest1RTTPacket)
		}
		// 0-RTT packets are sent on path 0.
		tracker := h.tracker(0)
		if tracker == nil {
			return nil
		}
		return tracker.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	case protocol.Encryption1RTT:
		tracker := h.getOrCreateTracker(pathID)
		if tracker == nil {
			return nil
		}
		// 0-RTT and 1-RTT packets share the packet number space of path 0.
		if pathID == 0 && (h.lowest1RTTPacket == protocol.InvalidPacketNumber || pn < h.lowest1RTTPacket) {
			h.lowest1RTTPacket = pn
		}
		return tracker.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	default:
		panic(fmt.Sprintf("received packet with unknown encryption level: %s", encLevel))
	}
}

// IgnorePacketsBelow is called when an ACK frame that acknowledged packets up to pn-1 was acknowledged by the peer.
// ACK frames acknowledge packets received on path 0.
func (h *ReceivedPacketHandler) IgnorePacketsBelow(pn protocol.PacketNumber) {
	h.appDataPackets.IgnoreBelow(pn)
}

// IgnorePacketsBelowForPath is called when a PATH_ACK frame (or an ACK frame, for path 0)
// that acknowledged packets of a path up to pn-1 was acknowledged by the peer (IETF Multipath QUIC).
func (h *ReceivedPacketHandler) IgnorePacketsBelowForPath(pathID protocol.PathID, pn protocol.PacketNumber) {
	if tracker := h.tracker(pathID); tracker != nil {
		tracker.IgnoreBelow(pn)
	}
}

func (h *ReceivedPacketHandler) DropPackets(encLevel protocol.EncryptionLevel) {
	//nolint:exhaustive // 1-RTT packet number space is never dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// Nothing to do here.
		// If we are rejecting 0-RTT, no 0-RTT packets will have been decrypted.
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) GetAlarmTimeout() monotime.Time {
	var alarm monotime.Time
	for _, tracker := range h.allTrackers() {
		t := tracker.GetAlarmTimeout()
		if alarm.IsZero() || (!t.IsZero() && t.Before(alarm)) {
			alarm = t
		}
	}
	return alarm
}

// AckDuePaths returns the paths for which an ACK frame should be sent now,
// in ascending order of their path IDs.
// The returned slice is only valid until the next call.
func (h *ReceivedPacketHandler) AckDuePaths(now monotime.Time) []protocol.PathID {
	h.ackDuePaths = h.ackDuePaths[:0]
	for pathID, tracker := range h.allTrackers() {
		if tracker.ackDue(now) {
			h.ackDuePaths = append(h.ackDuePaths, pathID)
		}
	}
	return h.ackDuePaths
}

// GetAckFrame returns the ACK frame for the packets received on a path.
// With IETF Multipath QUIC, 1-RTT packets are acknowledged using PATH_ACK frames.
func (h *ReceivedPacketHandler) GetAckFrame(encLevel protocol.EncryptionLevel, now monotime.Time, onlyIfQueued bool, pathID protocol.PathID) *wire.AckFrame {
	//nolint:exhaustive // 0-RTT packets can't contain ACK frames.
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialPackets != nil {
			return h.initialPackets.GetAckFrame()
		}
		return nil
	case protocol.EncryptionHandshake:
		if h.handshakePackets != nil {
			return h.handshakePackets.GetAckFrame()
		}
		return nil
	case protocol.Encryption1RTT:
		tracker := h.tracker(pathID)
		if tracker == nil {
			return nil
		}
		ack := tracker.GetAckFrame(now, onlyIfQueued)
		if ack != nil && h.multipath {
			ack.PathID = pathID
			ack.HasPathID = true
		}
		return ack
	default:
		// 0-RTT packets can't contain ACK frames
		return nil
	}
}

// AbandonPath is called when a path is abandoned (IETF Multipath QUIC).
// The packets received on the path, and on the path until it is removed, are acknowledged immediately.
func (h *ReceivedPacketHandler) AbandonPath(pathID protocol.PathID) {
	if tracker := h.tracker(pathID); tracker != nil {
		tracker.Abandon()
	}
}

// RemovePath removes the tracker for a path (IETF Multipath QUIC).
// Packets received on the path afterwards are ignored, and no ACK is sent for the path.
func (h *ReceivedPacketHandler) RemovePath(pathID protocol.PathID) {
	if !h.multipath {
		return
	}
	h.closedPaths.Add(pathID)
	if pathID == 0 {
		h.appDataPackets = *newAppDataReceivedPacketTracker(h.logger)
		return
	}
	h.deleteTracker(pathID)
}

// IsPotentiallyDuplicate says if a packet might be a duplicate.
// With IETF Multipath QUIC, packets received on a removed path are reported as duplicates.
func (h *ReceivedPacketHandler) IsPotentiallyDuplicate(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel, pathID protocol.PathID) bool {
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialPackets != nil {
			return h.initialPackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.EncryptionHandshake:
		if h.handshakePackets != nil {
			return h.handshakePackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		// 0-RTT packets are sent on path 0.
		if encLevel == protocol.Encryption0RTT {
			pathID = 0
		}
		if h.closedPaths.Contains(pathID) {
			return true
		}
		if tracker := h.tracker(pathID); tracker != nil {
			return tracker.IsPotentiallyDuplicate(pn)
		}
		return false
	}
	panic("unexpected encryption level")
}
