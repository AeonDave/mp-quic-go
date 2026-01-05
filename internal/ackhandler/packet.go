package ackhandler

import (
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

type packetWithPacketNumber struct {
	PacketNumber protocol.PacketNumber
	*packet
}

// A Packet is a packet
type packet struct {
	SendTime        monotime.Time
	StreamFrames    []StreamFrame
	Frames          []Frame
	LargestAcked    protocol.PacketNumber // InvalidPacketNumber if the packet doesn't contain an ACK
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel
	PathID          protocol.PathID

	IsPathMTUProbePacket bool // We don't report the loss of Path MTU probe packets to the congestion controller.

	includedInBytesInFlight bool
	declaredLost            bool
	isPathProbePacket       bool
	sentNotified            bool
}

func (p *packet) Outstanding() bool {
	return !p.declaredLost && !p.IsPathMTUProbePacket && !p.isPathProbePacket && p.IsAckEliciting()
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
	p.Length = 0
	p.EncryptionLevel = protocol.EncryptionLevel(0)
	p.PathID = protocol.InvalidPathID
	p.SendTime = 0
	p.IsPathMTUProbePacket = false
	p.includedInBytesInFlight = false
	p.declaredLost = false
	p.isPathProbePacket = false
	p.sentNotified = false
	return p
}

// We currently only return Packets back into the pool when they're acknowledged (not when they're lost).
// This simplifies the code, and gives the vast majority of the performance benefit we can gain from using the pool.
func putPacket(p *packet) {
	p.Frames = nil
	p.StreamFrames = nil
	p.PathID = protocol.InvalidPathID
	p.sentNotified = false
	packetPool.Put(p)
}
