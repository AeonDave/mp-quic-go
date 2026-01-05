package ackhandler

import (
	"fmt"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

type ReceivedPacketHandler struct {
	initialPackets   *receivedPacketTracker
	handshakePackets *receivedPacketTracker
	appDataPackets   map[protocol.PathID]*appDataReceivedPacketTracker

	lowest1RTTPacket map[protocol.PathID]protocol.PacketNumber
	logger           utils.Logger
}

func NewReceivedPacketHandler(logger utils.Logger) *ReceivedPacketHandler {
	return &ReceivedPacketHandler{
		initialPackets:   newReceivedPacketTracker(),
		handshakePackets: newReceivedPacketTracker(),
		appDataPackets: map[protocol.PathID]*appDataReceivedPacketTracker{
			protocol.InvalidPathID: newAppDataReceivedPacketTracker(logger),
		},
		lowest1RTTPacket: map[protocol.PathID]protocol.PacketNumber{
			protocol.InvalidPathID: protocol.InvalidPacketNumber,
		},
		logger: logger,
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
		lowest1RTTPacket := h.getLowest1RTTPacket(pathID)
		if lowest1RTTPacket != protocol.InvalidPacketNumber && pn > lowest1RTTPacket {
			return fmt.Errorf("received packet number %d on a 0-RTT packet after receiving %d on a 1-RTT packet", pn, lowest1RTTPacket)
		}
		return h.getAppDataTracker(pathID).ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	case protocol.Encryption1RTT:
		lowest1RTTPacket := h.getLowest1RTTPacket(pathID)
		if lowest1RTTPacket == protocol.InvalidPacketNumber || pn < lowest1RTTPacket {
			h.lowest1RTTPacket[pathID] = pn
		}
		return h.getAppDataTracker(pathID).ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	default:
		panic(fmt.Sprintf("received packet with unknown encryption level: %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) IgnorePacketsBelow(pn protocol.PacketNumber) {
	for _, tracker := range h.appDataPackets {
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
	for _, tracker := range h.appDataPackets {
		t := tracker.GetAlarmTimeout()
		if alarm.IsZero() || (!t.IsZero() && t.Before(alarm)) {
			alarm = t
		}
	}
	return alarm
}

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
		return h.getAppDataTracker(pathID).GetAckFrame(now, onlyIfQueued)
	default:
		// 0-RTT packets can't contain ACK frames
		return nil
	}
}

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
		return h.getAppDataTracker(pathID).IsPotentiallyDuplicate(pn)
	}
	panic("unexpected encryption level")
}

func (h *ReceivedPacketHandler) getAppDataTracker(pathID protocol.PathID) *appDataReceivedPacketTracker {
	if tracker, ok := h.appDataPackets[pathID]; ok {
		return tracker
	}
	tracker := newAppDataReceivedPacketTracker(h.logger)
	h.appDataPackets[pathID] = tracker
	h.lowest1RTTPacket[pathID] = protocol.InvalidPacketNumber
	return tracker
}

func (h *ReceivedPacketHandler) getLowest1RTTPacket(pathID protocol.PathID) protocol.PacketNumber {
	if pn, ok := h.lowest1RTTPacket[pathID]; ok {
		return pn
	}
	h.lowest1RTTPacket[pathID] = protocol.InvalidPacketNumber
	return protocol.InvalidPacketNumber
}
