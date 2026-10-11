package quic

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
)

var errNothingToPack = errors.New("nothing to pack")

// errPacketNumbersExhausted is returned when the next packet number reaches the largest packet number.
// The connection is then closed without sending any further packets (section 12.3 of RFC 9000).
var errPacketNumbersExhausted = &qerr.TransportError{
	ErrorCode:    qerr.InternalError,
	ErrorMessage: "packet numbers exhausted",
}

type packer interface {
	PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (*coalescedPacket, error)
	PackAckOnlyPacket(maxPacketSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, *packetBuffer, error)
	AppendPacket(_ *packetBuffer, maxPacketSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, error)
	PackPTOProbePacket(_ protocol.EncryptionLevel, _ protocol.ByteCount, addPingIfEmpty bool, now monotime.Time, v protocol.Version, pathID protocol.PathID) (*coalescedPacket, error)
	PackConnectionClose(*qerr.TransportError, protocol.ByteCount, protocol.Version, protocol.PathID) (*coalescedPacket, error)
	PackApplicationClose(*qerr.ApplicationError, protocol.ByteCount, protocol.Version, protocol.PathID) (*coalescedPacket, error)
	// PackPathProbePacket packs a packet containing PATH_CHALLENGE and PATH_RESPONSE frames, sent to connID.
	// The datagram is expanded to 1200 bytes, unless maxPacketSize is smaller.
	PackPathProbePacket(_ protocol.ConnectionID, _ []ackhandler.Frame, maxPacketSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error)
	PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, *packetBuffer, error)
	// PackMultipathProbePacket packs a packet that carries frames bound to a path of IETF Multipath QUIC
	// (PATH_CHALLENGE and PATH_RESPONSE frames), and the PATH_ACK frame for the path, if one is available.
	// It is sent to connID, a connection ID of the path.
	PackMultipathProbePacket(pathID protocol.PathID, connID protocol.ConnectionID, frames []ackhandler.Frame, maxPacketSize, padTo protocol.ByteCount, now monotime.Time, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)
	// PackPathPacket packs a packet that only carries the given frames, on a path of IETF Multipath QUIC.
	PackPathPacket(pathID protocol.PathID, frames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame, maxPacketSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)

	SetToken([]byte)
	// EnableMultipath enables IETF Multipath QUIC.
	// From now on, the path ID of 1-RTT packets selects the destination connection ID, the packet number space
	// and the nonce, and the packets carry PATH_ACK frames.
	// getDestConnID returns false if the peer didn't provide a connection ID for a path.
	EnableMultipath(getDestConnID func(protocol.PathID) (protocol.ConnectionID, bool), pathFrames mpFrameSource)
	// EnableAddressDiscovery enables sending of the OBSERVED_ADDRESS frames of QUIC Address Discovery.
	EnableAddressDiscovery(observedAddressSource)
	// EnableQUICBitGreasing sets the QUIC Bit of all packets packed from now on to a random value (RFC 9287).
	EnableQUICBitGreasing()
}

type sealer interface {
	handshake.LongHeaderSealer
}

type payload struct {
	streamFrames []ackhandler.StreamFrame
	frames       []ackhandler.Frame
	ack          *wire.AckFrame
	// IETF Multipath QUIC: PATH_ACK frames for other paths than the path the packet is sent on
	extraAcks []*wire.AckFrame
	length    protocol.ByteCount
}

type longHeaderPacket struct {
	header       *wire.ExtendedHeader
	ack          *wire.AckFrame
	frames       []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame // only used for 0-RTT packets

	length protocol.ByteCount

	// Multipath support
	PathID uint64
}

type shortHeaderPacket struct {
	PacketNumber protocol.PacketNumber
	Frames       []ackhandler.Frame
	StreamFrames []ackhandler.StreamFrame
	Ack          *wire.AckFrame
	// IETF Multipath QUIC: PATH_ACK frames for other paths than the path the packet is sent on
	ExtraAcks            []*wire.AckFrame
	Length               protocol.ByteCount
	IsPathMTUProbePacket bool
	IsPathProbePacket    bool

	// Multipath support
	PathID uint64

	// used for logging
	DestConnID      protocol.ConnectionID
	PacketNumberLen protocol.PacketNumberLen
	KeyPhase        protocol.KeyPhaseBit
}

func (p *shortHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.Frames) }

type coalescedPacket struct {
	buffer         *packetBuffer
	longHdrPackets []*longHeaderPacket
	shortHdrPacket *shortHeaderPacket
}

// IsOnlyShortHeaderPacket says if this packet only contains a short header packet (and no long header packets).
func (p *coalescedPacket) IsOnlyShortHeaderPacket() bool {
	return len(p.longHdrPackets) == 0 && p.shortHdrPacket != nil
}

func (p *longHeaderPacket) EncryptionLevel() protocol.EncryptionLevel {
	//nolint:exhaustive // Will never be called for Retry packets (and they don't have encrypted data).
	switch p.header.Type {
	case protocol.PacketTypeInitial:
		return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		return protocol.EncryptionHandshake
	case protocol.PacketType0RTT:
		return protocol.Encryption0RTT
	default:
		panic("can't determine encryption level")
	}
}

func (p *longHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.frames) }

type packetNumberManager interface {
	PeekPacketNumber(protocol.PathID, protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.PathID, protocol.EncryptionLevel) protocol.PacketNumber
}

type sealingManager interface {
	GetInitialSealer() (handshake.LongHeaderSealer, error)
	GetHandshakeSealer() (handshake.LongHeaderSealer, error)
	Get0RTTSealer() (handshake.LongHeaderSealer, error)
	Get1RTTSealer() (handshake.ShortHeaderSealer, error)
}

type frameSource interface {
	HasData() bool
	Append([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount, monotime.Time, protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount)
}

type ackFrameSource interface {
	GetAckFrame(_ protocol.EncryptionLevel, now monotime.Time, onlyIfQueued bool, pathID protocol.PathID) *wire.AckFrame
	AckDuePaths(now monotime.Time) []protocol.PathID
}

// An mpFrameSource provides frames that need to be sent on a specific path of IETF Multipath QUIC,
// e.g. PATH_RESPONSE frames.
type mpFrameSource interface {
	HasPathFrames(protocol.PathID) bool
	AppendPathFrames(_ []ackhandler.Frame, _ protocol.PathID, maxLen protocol.ByteCount, _ protocol.Version) ([]ackhandler.Frame, protocol.ByteCount)
}

// An observedAddressSource provides the OBSERVED_ADDRESS frames of QUIC Address Discovery
// (draft-ietf-quic-address-discovery-01), which need to be sent on a specific path.
type observedAddressSource interface {
	HasObservedAddress(protocol.PathID) bool
	AppendObservedAddress(_ []ackhandler.Frame, _ protocol.PathID, maxLen protocol.ByteCount, _ protocol.Version) ([]ackhandler.Frame, protocol.ByteCount)
}

type packetPacker struct {
	srcConnID     protocol.ConnectionID
	getDestConnID func() protocol.ConnectionID

	perspective protocol.Perspective
	cryptoSetup sealingManager
	// If set, 0-RTT packets use this version, and not the version in use for the connection.
	// The client sets it to its Chosen Version (section 4.1 of RFC 9369).
	zeroRTTVersion protocol.Version

	initialStream   *initialCryptoStream
	handshakeStream *cryptoStream

	token []byte

	pnManager           packetNumberManager
	framer              frameSource
	acks                ackFrameSource
	datagramQueue       *datagramQueue
	retransmissionQueue *retransmissionQueue
	rand                rand.Rand

	numNonAckElicitingAcks int

	// IETF Multipath QUIC
	multipath bool
	// returns the destination connection ID of paths other than path 0
	getPathDestConnID func(protocol.PathID) (protocol.ConnectionID, bool)
	pathFrames        mpFrameSource

	// QUIC Address Discovery
	observedAddrs observedAddressSource

	// Set once the peer sent the grease_quic_bit transport parameter (RFC 9287), if greasing is enabled locally.
	greaseQUICBit bool

	// Returns the number of bytes that can be sent on a path before its anti-amplification limit is reached.
	// If nil, the limit doesn't apply.
	amplificationBudget func(protocol.PathID) protocol.ByteCount
}

var _ packer = &packetPacker{}

func newPacketPacker(
	srcConnID protocol.ConnectionID,
	getDestConnID func() protocol.ConnectionID,
	initialStream *initialCryptoStream,
	handshakeStream *cryptoStream,
	packetNumberManager packetNumberManager,
	retransmissionQueue *retransmissionQueue,
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	datagramQueue *datagramQueue,
	perspective protocol.Perspective,
) *packetPacker {
	var b [16]byte
	_, _ = crand.Read(b[:])

	return &packetPacker{
		cryptoSetup:         cryptoSetup,
		getDestConnID:       getDestConnID,
		srcConnID:           srcConnID,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		retransmissionQueue: retransmissionQueue,
		datagramQueue:       datagramQueue,
		perspective:         perspective,
		framer:              framer,
		acks:                acks,
		rand:                *rand.New(rand.NewPCG(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:]))),
		pnManager:           packetNumberManager,
	}
}

// EnableMultipath enables IETF Multipath QUIC.
func (p *packetPacker) EnableMultipath(getDestConnID func(protocol.PathID) (protocol.ConnectionID, bool), pathFrames mpFrameSource) {
	p.multipath = true
	p.getPathDestConnID = getDestConnID
	p.pathFrames = pathFrames
}

// EnableAddressDiscovery enables sending of OBSERVED_ADDRESS frames.
// They are only sent in 1-RTT packets.
func (p *packetPacker) EnableAddressDiscovery(s observedAddressSource) {
	p.observedAddrs = s
}

// EnableQUICBitGreasing sets the QUIC Bit of all packets packed from now on to a random value.
// It must only be called once the peer's transport parameters were processed,
// and if the peer sent the grease_quic_bit transport parameter (section 3.1 of RFC 9287).
func (p *packetPacker) EnableQUICBitGreasing() {
	p.greaseQUICBit = true
}

// maybeGreaseQUICBit sets the QUIC Bit of the first byte of the header to a random value, if enabled.
// The first byte is protected by the AEAD, so this needs to happen before the packet is sealed.
func (p *packetPacker) maybeGreaseQUICBit(firstByte *byte) {
	if p.greaseQUICBit && p.rand.Uint32()&1 == 0 {
		*firstByte &^= 0x40
	}
}

// destConnID returns the destination connection ID for a 1-RTT packet sent on a path.
// Without IETF Multipath QUIC, the same connection ID is used on all paths.
// With IETF Multipath QUIC, packets are only sent on a path once the peer provided a connection ID for it
// (section 3.1 of draft-ietf-quic-multipath-21). Packets are never sent with an empty connection ID instead.
func (p *packetPacker) destConnID(pathID protocol.PathID) (protocol.ConnectionID, error) {
	if p.multipath && pathID != 0 {
		connID, ok := p.getPathDestConnID(pathID)
		if !ok {
			return protocol.ConnectionID{}, fmt.Errorf("no connection ID available for path %d", pathID)
		}
		return connID, nil
	}
	return p.getDestConnID(), nil
}

// PackConnectionClose packs a packet that closes the connection with a transport error.
func (p *packetPacker) PackConnectionClose(e *qerr.TransportError, maxPacketSize protocol.ByteCount, v protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
	var reason string
	// don't send details of crypto errors
	if !e.ErrorCode.IsCryptoError() {
		reason = e.ErrorMessage
	}
	return p.packConnectionClose(false, uint64(e.ErrorCode), e.FrameType, reason, maxPacketSize, v, pathID)
}

// PackApplicationClose packs a packet that closes the connection with an application error.
func (p *packetPacker) PackApplicationClose(e *qerr.ApplicationError, maxPacketSize protocol.ByteCount, v protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
	return p.packConnectionClose(true, uint64(e.ErrorCode), 0, e.ErrorMessage, maxPacketSize, v, pathID)
}

func (p *packetPacker) packConnectionClose(
	isApplicationError bool,
	errorCode uint64,
	frameType uint64,
	reason string,
	maxPacketSize protocol.ByteCount,
	v protocol.Version,
	pathID protocol.PathID,
) (*coalescedPacket, error) {
	var sealers [4]sealer
	var hdrs [3]*wire.ExtendedHeader
	var payloads [4]payload
	var size protocol.ByteCount
	var connID protocol.ConnectionID
	var oneRTTPacketNumber protocol.PacketNumber
	var oneRTTPacketNumberLen protocol.PacketNumberLen
	var keyPhase protocol.KeyPhaseBit // only set for 1-RTT
	var numLongHdrPackets uint8
	encLevels := [4]protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT}
	for i, encLevel := range encLevels {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.Encryption0RTT {
			continue
		}
		ccf := &wire.ConnectionCloseFrame{
			IsApplicationError: isApplicationError,
			ErrorCode:          errorCode,
			FrameType:          frameType,
			ReasonPhrase:       reason,
		}
		// don't send application errors in Initial or Handshake packets
		if isApplicationError && (encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake) {
			ccf.IsApplicationError = false
			ccf.ErrorCode = uint64(qerr.ApplicationErrorErrorCode)
			ccf.ReasonPhrase = ""
		}
		pl := payload{
			frames: []ackhandler.Frame{{Frame: ccf}},
			length: ccf.Length(v),
		}

		var sealer sealer
		var err error
		switch encLevel {
		case protocol.EncryptionInitial:
			sealer, err = p.cryptoSetup.GetInitialSealer()
		case protocol.EncryptionHandshake:
			sealer, err = p.cryptoSetup.GetHandshakeSealer()
		case protocol.Encryption0RTT:
			sealer, err = p.cryptoSetup.Get0RTTSealer()
		case protocol.Encryption1RTT:
			var s handshake.ShortHeaderSealer
			s, err = p.cryptoSetup.Get1RTTSealer()
			if err == nil {
				keyPhase = s.KeyPhase()
			}
			sealer = s
		}
		if err == handshake.ErrKeysNotYetAvailable || err == handshake.ErrKeysDropped {
			continue
		}
		if err != nil {
			return nil, err
		}
		sealers[i] = sealer
		var hdr *wire.ExtendedHeader
		if encLevel == protocol.Encryption1RTT {
			connID, err = p.destConnID(pathID)
			if err != nil {
				return nil, err
			}
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
			size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, pl) + protocol.ByteCount(sealer.Overhead())
		} else {
			hdr = p.getLongHeader(encLevel, v)
			hdrs[i] = hdr
			size += p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
			numLongHdrPackets++
		}
		payloads[i] = pl
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, numLongHdrPackets),
	}
	for i, encLevel := range encLevels {
		if sealers[i] == nil {
			continue
		}
		if encLevel == protocol.Encryption1RTT {
			shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, keyPhase, payloads[i], 0, maxPacketSize, sealers[i].(handshake.ShortHeaderSealer), false, v, pathID)
			if err != nil {
				return nil, err
			}
			packet.shortHdrPacket = &shp
		} else {
			var paddingLen protocol.ByteCount
			if encLevel == protocol.EncryptionInitial {
				paddingLen = p.initialPaddingLen(payloads[i].frames, size, maxPacketSize)
			}
			longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdrs[i], payloads[i], paddingLen, encLevel, sealers[i], v)
			if err != nil {
				return nil, err
			}
			packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
		}
	}
	return packet, nil
}

// longHeaderPacketLength calculates the length of a serialized long header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) longHeaderPacketLength(hdr *wire.ExtendedHeader, pl payload, v protocol.Version) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(hdr.PacketNumberLen)
	if pl.length < 4-pnLen {
		paddingLen = 4 - pnLen - pl.length
	}
	return hdr.GetLength(v) + pl.length + paddingLen
}

// shortHeaderPacketLength calculates the length of a serialized short header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) shortHeaderPacketLength(connID protocol.ConnectionID, pnLen protocol.PacketNumberLen, pl payload) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
	}
	return wire.ShortHeaderLen(connID, pnLen) + pl.length + paddingLen
}

// size is the expected size of the packet, if no padding was applied.
func (p *packetPacker) initialPaddingLen(frames []ackhandler.Frame, currentSize, maxPacketSize protocol.ByteCount) protocol.ByteCount {
	// For the server, only ack-eliciting Initial packets need to be padded.
	if p.perspective == protocol.PerspectiveServer && !ackhandler.HasAckElicitingFrames(frames) {
		return 0
	}
	if currentSize >= maxPacketSize {
		return 0
	}
	return maxPacketSize - currentSize
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *packetPacker) PackCoalescedPacket(onlyAck bool, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
	var (
		initialHdr, handshakeHdr, zeroRTTHdr                            *wire.ExtendedHeader
		initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
		oneRTTPacketNumber                                              protocol.PacketNumber
		oneRTTPacketNumberLen                                           protocol.PacketNumberLen
	)
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var size protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload = p.maybeGetCryptoPacket(
			maxSize-protocol.ByteCount(initialSealer.Overhead()),
			protocol.EncryptionInitial,
			now,
			false,
			onlyAck,
			v,
		)
		if initialPayload.length > 0 {
			size += p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead())
		}
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(
				maxSize-size-protocol.ByteCount(handshakeSealer.Overhead()),
				protocol.EncryptionHandshake,
				now,
				false,
				onlyAck,
				v,
			)
			if handshakePayload.length > 0 {
				s := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead())
				size += s
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var zeroRTTSealer sealer
	var oneRTTSealer handshake.ShortHeaderSealer
	var connID protocol.ConnectionID
	var kp protocol.KeyPhaseBit
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		oneRTTSealer, err = p.cryptoSetup.Get1RTTSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if err == nil { // 1-RTT
			kp = oneRTTSealer.KeyPhase()
			connID, err = p.destConnID(pathID)
			if err != nil {
				return nil, err
			}
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
			hdrLen := wire.ShortHeaderLen(connID, oneRTTPacketNumberLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxSize-size, onlyAck, now, v, pathID)
			if oneRTTPayload.length > 0 {
				size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead())
			}
		} else if p.perspective == protocol.PerspectiveClient && !onlyAck { // 0-RTT packets can't contain ACK frames
			var err error
			zeroRTTSealer, err = p.cryptoSetup.Get0RTTSealer()
			if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
				return nil, err
			}
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxSize-size, now, p.get0RTTVersion(v))
				if zeroRTTPayload.length > 0 {
					size += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, p.get0RTTVersion(v)) + protocol.ByteCount(zeroRTTSealer.Overhead())
				}
			}
		}
	}

	if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 && oneRTTPayload.length == 0 {
		return nil, nil
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, 3),
	}
	var initialPadding protocol.ByteCount
	if initialPayload.length > 0 {
		initialPadding = p.initialPaddingLen(initialPayload.frames, size, maxSize)
		cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, initialPadding, protocol.EncryptionInitial, initialSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if handshakePayload.length > 0 {
		cont, err := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 {
		longHdrPacket, err := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, p.get0RTTVersion(v))
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		padding := p.pathValidationPadding(oneRTTPayload, size+initialPadding, maxSize, pathID)
		shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, padding, maxSize, oneRTTSealer, false, v, pathID)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
	}
	return packet, nil
}

// PackAckOnlyPacket packs a packet containing only an ACK in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) PackAckOnlyPacket(maxSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
	buf := getPacketBuffer()
	packet, err := p.appendPacket(buf, true, maxSize, now, v, pathID)
	return packet, buf, err
}

// AppendPacket packs a packet in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) AppendPacket(buf *packetBuffer, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, error) {
	return p.appendPacket(buf, false, maxSize, now, v, pathID)
}

func (p *packetPacker) appendPacket(
	buf *packetBuffer,
	onlyAck bool,
	maxPacketSize protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
	pathID protocol.PathID,
) (shortHeaderPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	connID, err := p.destConnID(pathID)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	hdrLen := wire.ShortHeaderLen(connID, pnLen)
	pl := p.maybeGetShortHeaderPacket(sealer, hdrLen, maxPacketSize, onlyAck, now, v, pathID)
	if pl.length == 0 {
		return shortHeaderPacket{}, errNothingToPack
	}
	kp := sealer.KeyPhase()

	size := p.shortHeaderPacketLength(connID, pnLen, pl) + protocol.ByteCount(sealer.Overhead())
	padding := p.pathValidationPadding(pl, size, maxPacketSize, pathID)
	packet, err := p.appendShortHeaderPacket(buf, connID, pn, pnLen, kp, pl, padding, maxPacketSize, sealer, false, v, pathID)
	return packet, err
}

// pathValidationPadding returns the padding that expands a datagram containing a PATH_CHALLENGE or PATH_RESPONSE
// frame to 1200 bytes (sections 8.2.1 and 8.2.2 of RFC 9000). size is the size of the datagram without padding,
// and pl the payload of its 1-RTT packet. The datagram is not expanded beyond maxSize, and not at all if the
// anti-amplification limit doesn't allow sending a datagram of 1200 bytes.
func (p *packetPacker) pathValidationPadding(pl payload, size, maxSize protocol.ByteCount, pathID protocol.PathID) protocol.ByteCount {
	padTo := min(protocol.ByteCount(protocol.MinInitialPacketSize), maxSize)
	if size >= padTo || !slices.ContainsFunc(pl.frames, isPathValidationFrame) {
		return 0
	}
	if p.amplificationBudget != nil && p.amplificationBudget(pathID) < protocol.MinInitialPacketSize {
		return 0
	}
	return padTo - size
}

func isPathValidationFrame(f ackhandler.Frame) bool {
	switch f.Frame.(type) {
	case *wire.PathChallengeFrame, *wire.PathResponseFrame:
		return true
	default:
		return false
	}
}

func (p *packetPacker) maybeGetCryptoPacket(
	maxPacketSize protocol.ByteCount,
	encLevel protocol.EncryptionLevel,
	now monotime.Time,
	addPingIfEmpty bool,
	onlyAck bool,
	v protocol.Version,
) (*wire.ExtendedHeader, payload) {
	if onlyAck {
		if ack := p.acks.GetAckFrame(encLevel, now, true, 0); ack != nil {
			hdr := p.getLongHeader(encLevel, v)
			maxPacketSize -= hdr.GetLength(v)
			ack.Truncate(maxPacketSize, v)
			return hdr, payload{ack: ack, length: ack.Length(v)}
		}
		return nil, payload{length: 0}
	}

	var hasCryptoData func() bool
	var popCryptoFrame func(maxLen protocol.ByteCount) *wire.CryptoFrame
	//nolint:exhaustive // Initial and Handshake are the only two encryption levels here.
	switch encLevel {
	case protocol.EncryptionInitial:
		hasCryptoData = p.initialStream.HasData
		popCryptoFrame = p.initialStream.PopCryptoFrame
	case protocol.EncryptionHandshake:
		hasCryptoData = p.handshakeStream.HasData
		popCryptoFrame = p.handshakeStream.PopCryptoFrame
	}
	handler := p.retransmissionQueue.AckHandler(encLevel)
	hasRetransmission := p.retransmissionQueue.HasData(encLevel)

	ack := p.acks.GetAckFrame(encLevel, now, !hasRetransmission && !hasCryptoData(), 0)
	var pl payload
	if !hasCryptoData() && !hasRetransmission && ack == nil {
		if !addPingIfEmpty {
			// nothing to send
			return nil, payload{}
		}
		ping := &wire.PingFrame{}
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}})
		pl.length += ping.Length(v)
	}

	hdr := p.getLongHeader(encLevel, v)
	maxPacketSize -= hdr.GetLength(v)

	if ack != nil {
		ack.Truncate(maxPacketSize, v)
		pl.ack = ack
		pl.length = ack.Length(v)
		maxPacketSize -= pl.length
	}
	if hasRetransmission {
		for {
			frame := p.retransmissionQueue.GetFrame(encLevel, maxPacketSize, v)
			if frame == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{
				Frame:   frame,
				Handler: p.retransmissionQueue.AckHandler(encLevel),
			})
			frameLen := frame.Length(v)
			pl.length += frameLen
			maxPacketSize -= frameLen
		}
		return hdr, pl
	} else {
		for hasCryptoData() {
			cf := popCryptoFrame(maxPacketSize)
			if cf == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: cf, Handler: handler})
			pl.length += cf.Length(v)
			maxPacketSize -= cf.Length(v)
		}
	}
	return hdr, pl
}

func (p *packetPacker) get0RTTVersion(v protocol.Version) protocol.Version {
	if p.zeroRTTVersion != 0 {
		return p.zeroRTTVersion
	}
	return v
}

func (p *packetPacker) maybeGetAppDataPacketFor0RTT(sealer sealer, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version) (*wire.ExtendedHeader, payload) {
	if p.perspective != protocol.PerspectiveClient {
		return nil, payload{}
	}

	hdr := p.getLongHeader(protocol.Encryption0RTT, v)
	maxPayloadSize := maxSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead())
	return hdr, p.maybeGetAppDataPacket(maxPayloadSize, false, false, now, v, 0)
}

func (p *packetPacker) maybeGetShortHeaderPacket(
	sealer handshake.ShortHeaderSealer,
	hdrLen, maxPacketSize protocol.ByteCount,
	onlyAck bool,
	now monotime.Time,
	v protocol.Version,
	pathID protocol.PathID,
) payload {
	maxPayloadSize := maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead())
	return p.maybeGetAppDataPacket(maxPayloadSize, onlyAck, true, now, v, pathID)
}

func (p *packetPacker) maybeGetAppDataPacket(
	maxPayloadSize protocol.ByteCount,
	onlyAck, ackAllowed bool,
	now monotime.Time,
	v protocol.Version,
	pathID protocol.PathID,
) payload {
	pl := p.composeNextPacket(maxPayloadSize, onlyAck, ackAllowed, now, v, pathID)

	// check if we have anything to send
	if len(pl.frames) == 0 && len(pl.streamFrames) == 0 {
		if pl.ack == nil && len(pl.extraAcks) == 0 {
			return payload{}
		}
		// the packet only contains an ACK
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping})
			pl.length += ping.Length(v)
			p.numNonAckElicitingAcks = 0
		} else {
			p.numNonAckElicitingAcks++
		}
	} else {
		p.numNonAckElicitingAcks = 0
	}
	return pl
}

func (p *packetPacker) composeNextPacket(
	maxPayloadSize protocol.ByteCount,
	onlyAck, ackAllowed bool,
	now monotime.Time,
	v protocol.Version,
	pathID protocol.PathID,
) payload {
	if onlyAck {
		var pl payload
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, true, pathID); ack != nil {
			ack.Truncate(maxPayloadSize, v)
			pl.ack = ack
			pl.length = ack.Length(v)
		}
		if p.multipath {
			p.appendExtraAcks(&pl, maxPayloadSize, now, v, pathID)
		}
		return pl
	}

	hasData := p.framer.HasData()
	hasRetransmission := p.retransmissionQueue.HasData(protocol.Encryption1RTT)
	hasPathFrames := p.multipath && p.pathFrames.HasPathFrames(pathID)
	// OBSERVED_ADDRESS frames are only sent in 1-RTT packets, never in 0-RTT packets (which don't allow ACKs).
	hasObservedAddr := ackAllowed && p.observedAddrs != nil && p.observedAddrs.HasObservedAddress(pathID)

	var pl payload
	if ackAllowed {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, !hasRetransmission && !hasData && !hasPathFrames && !hasObservedAddr, pathID); ack != nil {
			ack.Truncate(maxPayloadSize, v)
			pl.ack = ack
			pl.length += ack.Length(v)
		}
		if p.multipath {
			p.appendExtraAcks(&pl, maxPayloadSize, now, v, pathID)
		}
	}

	if hasPathFrames {
		var lengthAdded protocol.ByteCount
		pl.frames, lengthAdded = p.pathFrames.AppendPathFrames(pl.frames, pathID, maxPayloadSize-pl.length, v)
		pl.length += lengthAdded
	}
	if hasObservedAddr {
		var lengthAdded protocol.ByteCount
		pl.frames, lengthAdded = p.observedAddrs.AppendObservedAddress(pl.frames, pathID, maxPayloadSize-pl.length, v)
		pl.length += lengthAdded
	}

	if p.datagramQueue != nil {
		if f := p.datagramQueue.Peek(); f != nil {
			size := f.Length(v)
			if size <= maxPayloadSize-pl.length { // DATAGRAM frame fits
				pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
				pl.length += size
				p.datagramQueue.Pop()
			} else if pl.ack == nil && len(pl.extraAcks) == 0 {
				// The DATAGRAM frame doesn't fit, and the packet doesn't contain an ACK.
				// Discard this frame. There's no point in retrying this in the next packet,
				// as it's unlikely that the available packet size will increase.
				p.datagramQueue.Pop()
			}
			// If the DATAGRAM frame was too large and the packet contained an ACK, we'll try to send it out later.
		}
	}

	if (pl.ack != nil || len(pl.extraAcks) > 0) && !hasData && !hasRetransmission {
		return pl
	}

	if hasRetransmission {
		for {
			remainingLen := maxPayloadSize - pl.length
			if remainingLen < protocol.MinStreamFrameSize {
				break
			}
			f := p.retransmissionQueue.GetFrame(protocol.Encryption1RTT, remainingLen, v)
			if f == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: f, Handler: p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)})
			pl.length += f.Length(v)
		}
	}

	if hasData {
		var lengthAdded protocol.ByteCount
		startLen := len(pl.frames)
		pl.frames, pl.streamFrames, lengthAdded = p.framer.Append(pl.frames, pl.streamFrames, maxPayloadSize-pl.length, now, v)
		pl.length += lengthAdded
		// add handlers for the control frames that were added
		for i := startLen; i < len(pl.frames); i++ {
			if pl.frames[i].Handler != nil {
				continue
			}
			switch pl.frames[i].Frame.(type) {
			case *wire.PathChallengeFrame, *wire.PathResponseFrame:
				// Path probing is currently not supported, therefore we don't need to set the OnAcked callback yet.
				// PATH_CHALLENGE and PATH_RESPONSE are never retransmitted.
			default:
				// we might be packing a 0-RTT packet, but we need to use the 1-RTT ack handler anyway
				pl.frames[i].Handler = p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)
			}
		}
	}
	return pl
}

func (p *packetPacker) PackPTOProbePacket(
	encLevel protocol.EncryptionLevel,
	maxPacketSize protocol.ByteCount,
	addPingIfEmpty bool,
	now monotime.Time,
	v protocol.Version,
	pathID protocol.PathID,
) (*coalescedPacket, error) {
	if encLevel == protocol.Encryption1RTT {
		return p.packPTOProbePacket1RTT(maxPacketSize, addPingIfEmpty, now, v, pathID)
	}

	var sealer handshake.LongHeaderSealer
	//nolint:exhaustive // Probe packets are never sent for 0-RTT.
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
	default:
		panic("unknown encryption level")
	}
	hdr, pl := p.maybeGetCryptoPacket(
		maxPacketSize-protocol.ByteCount(sealer.Overhead()),
		encLevel,
		now,
		addPingIfEmpty,
		false,
		v,
	)
	if pl.length == 0 {
		return nil, nil
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	size := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		padding = p.initialPaddingLen(pl.frames, size, maxPacketSize)
	}

	longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v)
	if err != nil {
		return nil, err
	}
	packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}
	return packet, nil
}

func (p *packetPacker) packPTOProbePacket1RTT(maxPacketSize protocol.ByteCount, addPingIfEmpty bool, now monotime.Time, v protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return nil, err
	}
	kp := s.KeyPhase()
	connID, err := p.destConnID(pathID)
	if err != nil {
		return nil, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	hdrLen := wire.ShortHeaderLen(connID, pnLen)
	pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, now, v, pathID)
	if pl.length == 0 {
		if !addPingIfEmpty {
			return nil, nil
		}
		ping := &wire.PingFrame{}
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}})
		pl.length += ping.Length(v)
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	shp, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, 0, maxPacketSize, s, false, v, pathID)
	if err != nil {
		return nil, err
	}
	packet.shortHdrPacket = &shp
	return packet, nil
}

func (p *packetPacker) PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
	pl := payload{
		frames: []ackhandler.Frame{ping},
		length: ping.Frame.Length(v),
	}
	buffer := getPacketBuffer()
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	connID, err := p.destConnID(pathID)
	if err != nil {
		buffer.Release()
		return shortHeaderPacket{}, nil, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	padding := size - p.shortHeaderPacketLength(connID, pnLen, pl) - protocol.ByteCount(s.Overhead())
	kp := s.KeyPhase()
	packet, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, padding, size, s, true, v, pathID)
	return packet, buffer, err
}

// PackPathProbePacket packs a packet that only contains the given frames (PATH_CHALLENGE, PATH_RESPONSE and
// OBSERVED_ADDRESS frames), sent to connID.
// The datagram is expanded to 1200 bytes (sections 8.2.1 and 8.2.2 of RFC 9000). If the anti-amplification limit
// doesn't allow sending 1200 bytes, maxPacketSize is smaller, and the datagram is only expanded to maxPacketSize.
// It returns errNothingToPack if the frames don't fit into maxPacketSize.
func (p *packetPacker) PackPathProbePacket(
	connID protocol.ConnectionID,
	frames []ackhandler.Frame,
	maxPacketSize protocol.ByteCount,
	v protocol.Version,
	pathID protocol.PathID,
) (shortHeaderPacket, *packetBuffer, error) {
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	var l protocol.ByteCount
	for _, f := range frames {
		l += f.Frame.Length(v)
	}
	payload := payload{
		frames: frames,
		length: l,
	}
	size := p.shortHeaderPacketLength(connID, pnLen, payload) + protocol.ByteCount(s.Overhead())
	if size > maxPacketSize {
		return shortHeaderPacket{}, nil, errNothingToPack
	}
	var padding protocol.ByteCount
	if padTo := min(protocol.ByteCount(protocol.MinInitialPacketSize), maxPacketSize); size < padTo {
		padding = padTo - size
	}
	buf := getPacketBuffer()
	packet, err := p.appendShortHeaderPacket(buf, connID, pn, pnLen, s.KeyPhase(), payload, padding, maxPacketSize, s, false, v, pathID)
	if err != nil {
		buf.Release()
		return shortHeaderPacket{}, nil, err
	}
	packet.IsPathProbePacket = true
	return packet, buf, nil
}

// PackMultipathProbePacket packs a packet that carries frames bound to a path of IETF Multipath QUIC,
// i.e. PATH_CHALLENGE and PATH_RESPONSE frames, and the PATH_ACK frame for the path, if one is available
// (section 3.1 of draft-ietf-quic-multipath-21).
// The packet is sent to connID, which must be a connection ID of the path. A PATH_RESPONSE sent to another
// 4-tuple than the one the path uses needs a connection ID that isn't used on any other 4-tuple
// (section 9.5 of RFC 9000).
// The packet is padded to padTo bytes, and is never larger than maxPacketSize.
// It returns errNothingToPack if the frames don't fit.
// Like the path probe packets of RFC 9000, the packet is not congestion controlled.
func (p *packetPacker) PackMultipathProbePacket(
	pathID protocol.PathID,
	connID protocol.ConnectionID,
	frames []ackhandler.Frame,
	maxPacketSize, padTo protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) (shortHeaderPacket, *packetBuffer, error) {
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	maxPayloadSize := maxPacketSize - wire.ShortHeaderLen(connID, pnLen) - protocol.ByteCount(s.Overhead())
	var pl payload
	for _, f := range frames {
		// These frames are never retransmitted, but the sent packet handler expects a handler.
		if f.Handler == nil {
			f.Handler = emptyHandler{}
		}
		pl.frames = append(pl.frames, f)
		pl.length += f.Frame.Length(v)
	}
	if pl.length > maxPayloadSize {
		return shortHeaderPacket{}, nil, errNothingToPack
	}
	if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, false, pathID); ack != nil {
		// Truncation keeps at least one ACK range, so the frame might still not fit.
		ack.Truncate(maxPayloadSize-pl.length, v)
		if l := ack.Length(v); pl.length+l <= maxPayloadSize {
			pl.ack = ack
			pl.length += l
		}
	}
	var padding protocol.ByteCount
	if size := p.shortHeaderPacketLength(connID, pnLen, pl) + protocol.ByteCount(s.Overhead()); size < padTo {
		padding = min(padTo, maxPacketSize) - size
	}
	buf := getPacketBuffer()
	packet, err := p.appendShortHeaderPacket(buf, connID, pn, pnLen, s.KeyPhase(), pl, padding, maxPacketSize, s, false, v, pathID)
	if err != nil {
		buf.Release()
		return shortHeaderPacket{}, nil, err
	}
	packet.IsPathProbePacket = true
	return packet, buf, nil
}

// PackPathPacket packs a 1-RTT packet that only carries the given frames, on a path of IETF Multipath QUIC.
// It is used for copies of frames sent on other paths (frame-level duplication and reinjection),
// and for PING frames sent on a path that potentially failed.
// Frames without a handler are never retransmitted. The frames must fit into a packet of maxPacketSize bytes.
// Unlike the probe packets used for path validation, the packet is congestion controlled.
func (p *packetPacker) PackPathPacket(
	pathID protocol.PathID,
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	maxPacketSize protocol.ByteCount,
	v protocol.Version,
) (shortHeaderPacket, *packetBuffer, error) {
	if len(frames) == 0 && len(streamFrames) == 0 {
		return shortHeaderPacket{}, nil, errNothingToPack
	}
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	connID, err := p.destConnID(pathID)
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	pl := payload{frames: frames, streamFrames: streamFrames}
	for _, f := range frames {
		pl.length += f.Frame.Length(v)
	}
	for _, f := range streamFrames {
		pl.length += f.Frame.Length(v)
	}
	buf := getPacketBuffer()
	packet, err := p.appendShortHeaderPacket(buf, connID, pn, pnLen, s.KeyPhase(), pl, 0, maxPacketSize, s, false, v, pathID)
	if err != nil {
		buf.Release()
		return shortHeaderPacket{}, nil, err
	}
	return packet, buf, nil
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel, v protocol.Version) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(0, encLevel)
	hdr := &wire.ExtendedHeader{
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
	}
	hdr.Version = v
	hdr.SrcConnectionID = p.srcConnID
	hdr.DestConnectionID = p.getDestConnID()

	//nolint:exhaustive // 1-RTT packets are not long header packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		hdr.Type = protocol.PacketTypeInitial
		hdr.Token = p.token
	case protocol.EncryptionHandshake:
		hdr.Type = protocol.PacketTypeHandshake
	case protocol.Encryption0RTT:
		hdr.Type = protocol.PacketType0RTT
	}
	return hdr
}

func (p *packetPacker) appendLongHeaderPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, padding protocol.ByteCount, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) {
	if header.PacketNumber >= protocol.MaxPacketNumber {
		return nil, errPacketNumbersExhausted
	}
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(header.PacketNumberLen)
	if pl.length < 4-pnLen {
		paddingLen = 4 - pnLen - pl.length
	}
	paddingLen += padding
	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + pl.length + paddingLen

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := header.Append(raw, v)
	if err != nil {
		return nil, err
	}
	p.maybeGreaseQUICBit(&raw[0])
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return nil, err
	}
	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen)
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if pn := p.pnManager.PopPacketNumber(0, encLevel); pn != header.PacketNumber {
		return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, header.PacketNumber)
	}
	return &longHeaderPacket{
		header:       header,
		ack:          pl.ack,
		frames:       pl.frames,
		streamFrames: pl.streamFrames,
		length:       protocol.ByteCount(len(raw)),
	}, nil
}

func (p *packetPacker) appendShortHeaderPacket(
	buffer *packetBuffer,
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	kp protocol.KeyPhaseBit,
	pl payload,
	padding, maxPacketSize protocol.ByteCount,
	sealer handshake.ShortHeaderSealer,
	isMTUProbePacket bool,
	v protocol.Version,
	pathID protocol.PathID,
) (shortHeaderPacket, error) {
	if pn >= protocol.MaxPacketNumber {
		return shortHeaderPacket{}, errPacketNumbersExhausted
	}
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
	}
	paddingLen += padding

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := wire.AppendShortHeader(raw, connID, pn, pnLen, kp)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	p.maybeGreaseQUICBit(&raw[0])
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	if !isMTUProbePacket {
		if size := protocol.ByteCount(len(raw) + sealer.Overhead()); size > maxPacketSize {
			return shortHeaderPacket{}, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, maxPacketSize)
		}
	}
	if p.multipath && pathID != 0 {
		// The nonce of IETF Multipath QUIC contains the path ID (section 2.4 of draft-ietf-quic-multipath-21).
		// For path 0, it is the nonce of RFC 9001.
		_ = sealer.SealForPath(raw[payloadOffset:payloadOffset], raw[payloadOffset:], pathID, pn, raw[:payloadOffset])
		raw = p.protectHeader(raw[:len(raw)+sealer.Overhead()], sealer, payloadOffset, protocol.ByteCount(pnLen))
	} else {
		raw = p.encryptPacket(raw, sealer, pn, payloadOffset, protocol.ByteCount(pnLen))
	}
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if newPN := p.pnManager.PopPacketNumber(pathID, protocol.Encryption1RTT); newPN != pn {
		return shortHeaderPacket{}, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, newPN)
	}
	return shortHeaderPacket{
		PacketNumber:         pn,
		PacketNumberLen:      pnLen,
		KeyPhase:             kp,
		StreamFrames:         pl.streamFrames,
		Frames:               pl.frames,
		Ack:                  pl.ack,
		ExtraAcks:            pl.extraAcks,
		Length:               protocol.ByteCount(len(raw)),
		DestConnID:           connID,
		IsPathMTUProbePacket: isMTUProbePacket,
		PathID:               uint64(pathID),
	}, nil
}

// appendPacketPayload serializes the payload of a packet into the raw byte slice.
// It modifies the order of payload.frames.
func (p *packetPacker) appendPacketPayload(raw []byte, pl payload, paddingLen protocol.ByteCount, v protocol.Version) ([]byte, error) {
	payloadOffset := len(raw)
	if pl.ack != nil {
		var err error
		raw, err = pl.ack.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	for _, ack := range pl.extraAcks {
		var err error
		raw, err = ack.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	if paddingLen > 0 {
		raw = append(raw, make([]byte, paddingLen)...)
	}
	// Randomize the order of the control frames.
	// This makes sure that the receiver doesn't rely on the order in which frames are packed.
	if len(pl.frames) > 1 {
		p.rand.Shuffle(len(pl.frames), func(i, j int) { pl.frames[i], pl.frames[j] = pl.frames[j], pl.frames[i] })
	}
	for _, f := range pl.frames {
		var err error
		raw, err = f.Frame.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	for _, f := range pl.streamFrames {
		var err error
		raw, err = f.Frame.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}

	if payloadSize := protocol.ByteCount(len(raw)-payloadOffset) - paddingLen; payloadSize != pl.length {
		return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", pl.length, payloadSize)
	}
	return raw, nil
}

func (p *packetPacker) encryptPacket(raw []byte, sealer sealer, pn protocol.PacketNumber, payloadOffset, pnLen protocol.ByteCount) []byte {
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], pn, raw[:payloadOffset])
	return p.protectHeader(raw[:len(raw)+sealer.Overhead()], sealer, payloadOffset, pnLen)
}

// protectHeader applies header protection to a sealed packet.
func (p *packetPacker) protectHeader(raw []byte, sealer sealer, payloadOffset, pnLen protocol.ByteCount) []byte {
	pnOffset := payloadOffset - pnLen
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[0], raw[pnOffset:payloadOffset])
	return raw
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}

// maxTruncatedPathAckSize is the largest possible size of a PATH_ACK frame that was truncated to a single ACK range:
// type (1 byte), path ID, largest acknowledged, ACK delay (8 bytes each), range count (1 byte),
// first ACK range and three ECN counts (8 bytes each).
// An additional PATH_ACK frame is only added to a packet if this many bytes are left.
const maxTruncatedPathAckSize protocol.ByteCount = 1 + 3*8 + 1 + 4*8

// appendExtraAcks adds the PATH_ACK frames that are due for other paths than the path the packet is sent on,
// in ascending order of their path IDs, as long as they fit into the packet (IETF Multipath QUIC).
// This way, acknowledgments for paths that are not used for sending (at the moment) are sent as well.
func (p *packetPacker) appendExtraAcks(pl *payload, maxPayloadSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) {
	for _, id := range p.acks.AckDuePaths(now) {
		if id == pathID {
			continue
		}
		if maxPayloadSize-pl.length < maxTruncatedPathAckSize {
			return
		}
		ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, true, id)
		if ack == nil {
			continue
		}
		ack.Truncate(maxPayloadSize-pl.length, v)
		pl.extraAcks = append(pl.extraAcks, ack)
		pl.length += ack.Length(v)
	}
}

type emptyHandler struct{}

var _ ackhandler.FrameHandler = emptyHandler{}

func (emptyHandler) OnAcked(wire.Frame) {}
func (emptyHandler) OnLost(wire.Frame)  {}
