package wire

import "github.com/AeonDave/mp-quic-go/internal/protocol"

type FrameType uint64

// These constants correspond to those defined in RFC 9000.
// Stream frame types are not listed explicitly here; use FrameType.IsStreamFrameType() to identify them.
const (
	FrameTypePing        FrameType = 0x1
	FrameTypeAck         FrameType = 0x2
	FrameTypeAckECN      FrameType = 0x3
	FrameTypeResetStream FrameType = 0x4
	FrameTypeStopSending FrameType = 0x5
	FrameTypeCrypto      FrameType = 0x6
	FrameTypeNewToken    FrameType = 0x7

	FrameTypeMaxData            FrameType = 0x10
	FrameTypeMaxStreamData      FrameType = 0x11
	FrameTypeBidiMaxStreams     FrameType = 0x12
	FrameTypeUniMaxStreams      FrameType = 0x13
	FrameTypeDataBlocked        FrameType = 0x14
	FrameTypeStreamDataBlocked  FrameType = 0x15
	FrameTypeBidiStreamBlocked  FrameType = 0x16
	FrameTypeUniStreamBlocked   FrameType = 0x17
	FrameTypeNewConnectionID    FrameType = 0x18
	FrameTypeRetireConnectionID FrameType = 0x19
	FrameTypePathChallenge      FrameType = 0x1a
	FrameTypePathResponse       FrameType = 0x1b
	FrameTypeConnectionClose    FrameType = 0x1c
	FrameTypeApplicationClose   FrameType = 0x1d
	FrameTypeHandshakeDone      FrameType = 0x1e
	// https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/11/
	FrameTypeResetStreamAt FrameType = 0x24
	// https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/11/
	FrameTypeAckFrequency FrameType = 0xaf
	FrameTypeImmediateAck FrameType = 0x1f

	FrameTypeDatagramNoLength   FrameType = 0x30
	FrameTypeDatagramWithLength FrameType = 0x31

	// https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/
	FrameTypePathAck                FrameType = 0x3e
	FrameTypePathAckECN             FrameType = 0x3f
	FrameTypePathAbandon            FrameType = 0x3e75
	FrameTypePathStatusBackup       FrameType = 0x3e76
	FrameTypePathStatusAvailable    FrameType = 0x3e77
	FrameTypePathNewConnectionID    FrameType = 0x3e78
	FrameTypePathRetireConnectionID FrameType = 0x3e79
	FrameTypeMaxPathID              FrameType = 0x3e7a
	FrameTypePathsBlocked           FrameType = 0x3e7b
	FrameTypePathCIDsBlocked        FrameType = 0x3e7c

	// ADD_ADDRESS of the address advertisement extension of this module (a private frame type,
	// not part of IETF Multipath QUIC). The extension is negotiated using the add_address transport parameter,
	// and only used together with IETF Multipath QUIC.
	// A large value, so that it doesn't collide with registered frame types or custom extension frames.
	FrameTypeAddAddress FrameType = 0x1f0f9c0d40

	// https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/01/
	FrameTypeObservedAddressIPv4 FrameType = 0x9f81a6
	FrameTypeObservedAddressIPv6 FrameType = 0x9f81a7
)

// IsReservedFrameType says if a frame type is used by this QUIC implementation,
// including the frames of extensions that might not be negotiated on a connection.
// Such frame types can't be used for custom frames.
func IsReservedFrameType(t uint64) bool {
	switch ft := FrameType(t); {
	case ft.isValidRFC9000(), ft.IsDatagramFrameType():
		return true
	case ft == FrameTypeResetStreamAt, ft == FrameTypeAckFrequency, ft == FrameTypeImmediateAck:
		return true
	case ft.IsMultipathFrameType(), ft == FrameTypeAddAddress, ft.IsObservedAddressFrameType():
		return true
	default:
		return false
	}
}

func (t FrameType) IsStreamFrameType() bool {
	return t >= 0x8 && t <= 0xf
}

func (t FrameType) isValidRFC9000() bool {
	return t <= 0x1e
}

func (t FrameType) IsAckFrameType() bool {
	return t == FrameTypeAck || t == FrameTypeAckECN
}

func (t FrameType) IsDatagramFrameType() bool {
	return t == FrameTypeDatagramNoLength || t == FrameTypeDatagramWithLength
}

// IsPathAckFrameType says if the frame type is a PATH_ACK frame of the multipath extension.
// PATH_ACK frames are parsed into an AckFrame, like ACK frames.
func (t FrameType) IsPathAckFrameType() bool {
	return t == FrameTypePathAck || t == FrameTypePathAckECN
}

// IsMultipathFrameType says if the frame type is defined by the multipath extension (draft-ietf-quic-multipath).
func (t FrameType) IsMultipathFrameType() bool {
	return t.IsPathAckFrameType() || (t >= FrameTypePathAbandon && t <= FrameTypePathCIDsBlocked)
}

// IsObservedAddressFrameType says if the frame type is an OBSERVED_ADDRESS frame of QUIC Address Discovery
// (draft-ietf-quic-address-discovery).
func (t FrameType) IsObservedAddressFrameType() bool {
	return t == FrameTypeObservedAddressIPv4 || t == FrameTypeObservedAddressIPv6
}

func (t FrameType) isAllowedAtEncLevel(encLevel protocol.EncryptionLevel) bool {
	//nolint:exhaustive
	switch encLevel {
	case protocol.EncryptionInitial, protocol.EncryptionHandshake:
		switch t {
		case FrameTypeCrypto, FrameTypeAck, FrameTypeAckECN, FrameTypeConnectionClose, FrameTypePing:
			return true
		default:
			return false
		}
	case protocol.Encryption0RTT:
		// The frames of the multipath extension are only allowed in 1-RTT packets
		// (section 4 of draft-ietf-quic-multipath), and so is the ADD_ADDRESS frame:
		// 0-RTT packets can be replayed.
		if t.IsMultipathFrameType() || t == FrameTypeAddAddress {
			return false
		}
		switch t {
		case FrameTypeCrypto, FrameTypeAck, FrameTypeAckECN, FrameTypeConnectionClose, FrameTypeNewToken, FrameTypePathResponse, FrameTypeRetireConnectionID:
			return false
		default:
			return true
		}
	case protocol.Encryption1RTT:
		return true
	default:
		panic("unknown encryption level")
	}
}
