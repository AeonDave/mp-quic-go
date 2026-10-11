package ackhandler

import (
	"slices"
	"sync"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// PacketEvent describes a sent packet with its path association.
type PacketEvent struct {
	PacketNumber         protocol.PacketNumber
	Length               protocol.ByteCount
	EncryptionLevel      protocol.EncryptionLevel
	PathID               protocol.PathID
	IsAckEliciting       bool
	IsPathProbePacket    bool
	IsPathMTUProbePacket bool
	SendTime             monotime.Time
	EventTime            monotime.Time
	Frames               []Frame
	StreamFrames         []StreamFrame
}

// PacketObserver receives packet lifecycle events.
type PacketObserver interface {
	OnPacketSent(PacketEvent)
	OnPacketAcked(PacketEvent)
	OnPacketLost(PacketEvent)
}

func newPacketEvent(pn protocol.PacketNumber, p *packet, eventTime monotime.Time) PacketEvent {
	return PacketEvent{
		PacketNumber:         pn,
		Length:               p.Length,
		EncryptionLevel:      p.EncryptionLevel,
		PathID:               p.PathID,
		IsAckEliciting:       p.IsAckEliciting(),
		IsPathProbePacket:    p.isPathProbePacket,
		IsPathMTUProbePacket: p.IsPathMTUProbePacket,
		SendTime:             p.SendTime,
		EventTime:            eventTime,
		Frames:               p.Frames,
		StreamFrames:         p.StreamFrames,
	}
}

// A PathAck describes a PATH_ACK frame (IETF Multipath QUIC) contained in a sent packet.
type PathAck struct {
	PathID       protocol.PathID
	LargestAcked protocol.PacketNumber
}

type packetWithPacketNumber struct {
	PacketNumber protocol.PacketNumber
	*packet
}

// A Packet is a packet
type packet struct {
	SendTime     monotime.Time
	StreamFrames []StreamFrame
	Frames       []Frame
	LargestAcked protocol.PacketNumber // InvalidPacketNumber if the packet doesn't contain an ACK
	// The path acknowledged by the frame of LargestAcked (IETF Multipath QUIC):
	// the path ID of a PATH_ACK frame, path 0 for an ACK frame.
	AckPathID protocol.PathID
	// PATH_ACK frames contained in the packet in addition to the frame of LargestAcked.
	// Packets rarely contain more than one ACK or PATH_ACK frame.
	extraAcks       []PathAck
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel
	PathID          protocol.PathID

	IsPathMTUProbePacket bool // We don't report the loss of Path MTU probe packets to the congestion controller.

	// The largest packet number of the acknowledged packets sent between the preceding packet in the
	// sent packet history and this packet, or InvalidPacketNumber. It is set by the sentPacketHistory,
	// and used to establish persistent congestion (section 7.6 of RFC 9002).
	precedingAcked protocol.PacketNumber

	includedInBytesInFlight bool
	isPathProbePacket       bool
	// The frames of the packet were retransmitted in a PTO probe packet.
	// The packet is no longer outstanding, but it stays in the sent packet history until it is acknowledged
	// or declared lost: its loss can establish persistent congestion (section 7.6 of RFC 9002).
	probed bool
}

// setPathAcks records the PATH_ACK frames contained in the packet.
// The first ACK or PATH_ACK frame is stored inline.
func (p *packet) setPathAcks(acks []PathAck) {
	if p.LargestAcked == protocol.InvalidPacketNumber {
		p.LargestAcked = acks[0].LargestAcked
		p.AckPathID = acks[0].PathID
		acks = acks[1:]
	}
	if len(acks) > 0 {
		p.extraAcks = slices.Clone(acks)
	}
}

func (p *packet) Outstanding() bool {
	return !p.IsPathMTUProbePacket && !p.isPathProbePacket && !p.probed && p.IsAckEliciting()
}

func (p *packet) IsAckEliciting() bool {
	return len(p.StreamFrames) > 0 || len(p.Frames) > 0
}

var packetPool = sync.Pool{New: func() any { return &packet{} }}

func getPacket() *packet {
	p := packetPool.Get().(*packet)
	p.StreamFrames = nil
	p.Frames = nil
	p.LargestAcked = 0
	p.AckPathID = 0
	p.extraAcks = nil
	p.Length = 0
	p.EncryptionLevel = protocol.EncryptionLevel(0)
	p.PathID = 0
	p.SendTime = 0
	p.IsPathMTUProbePacket = false
	p.includedInBytesInFlight = false
	p.isPathProbePacket = false
	p.probed = false
	return p
}

// We currently only return Packets back into the pool when they're acknowledged (not when they're lost).
// This simplifies the code, and gives the vast majority of the performance benefit we can gain from using the pool.
func putPacket(p *packet) {
	p.Frames = nil
	p.StreamFrames = nil
	p.extraAcks = nil
	packetPool.Put(p)
}
