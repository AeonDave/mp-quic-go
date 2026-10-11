package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

var errUnknownFrameType = errors.New("unknown frame type")

// The FrameParser parses QUIC frames, one by one.
type FrameParser struct {
	ackDelayExponent        uint8
	supportsDatagrams       bool
	supportsResetStreamAt   bool
	supportsAckFrequency    bool
	supportsMultipath       bool
	supportsAddAddress      bool
	supportsObservedAddress bool

	// To avoid allocating when parsing, keep a single ACK frame struct.
	// It is used over and over again.
	ackFrame *AckFrame

	allowUnknownFrameTypes bool
}

// NewFrameParser creates a new frame parser.
func NewFrameParser(supportsDatagrams, supportsResetStreamAt, supportsAckFrequency bool) *FrameParser {
	return &FrameParser{
		supportsDatagrams:     supportsDatagrams,
		supportsResetStreamAt: supportsResetStreamAt,
		supportsAckFrequency:  supportsAckFrequency,
		ackFrame:              &AckFrame{},
	}
}

// ParseType parses the frame type of the next frame.
// It skips over PADDING frames.
func (p *FrameParser) ParseType(b []byte, encLevel protocol.EncryptionLevel) (FrameType, int, error) {
	var parsed int
	for len(b) != 0 {
		typ, l, err := quicvarint.Parse(b)
		parsed += l
		if err != nil {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.FrameEncodingError,
				ErrorMessage: err.Error(),
			}
		}
		b = b[l:]
		if typ == 0x0 { // skip PADDING frames
			continue
		}
		ft := FrameType(typ)
		valid := p.IsKnownFrameType(ft)
		// DATAGRAM frames received without having advertised support are a PROTOCOL_VIOLATION
		// (section 3 of RFC 9221).
		if !valid && ft.IsDatagramFrameType() {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    typ,
				ErrorMessage: "received a DATAGRAM frame, but datagram support was not advertised",
			}
		}
		if !valid {
			// Unknown frame types are only handed to the extension frame handler for 0-RTT and 1-RTT packets.
			// Initial and Handshake packets are not authenticated against on-path attackers.
			if p.allowUnknownFrameTypes && (encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT) {
				return ft, parsed, nil
			}
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.FrameEncodingError,
				FrameType:    typ,
				ErrorMessage: errUnknownFrameType.Error(),
			}
		}
		if !ft.isAllowedAtEncLevel(encLevel) {
			// Receiving a frame in a packet type that doesn't permit it is a PROTOCOL_VIOLATION
			// (section 12.4 of RFC 9000). This includes the frames of IETF Multipath QUIC and the ADD_ADDRESS frame
			// in packets other than 1-RTT packets (section 4 of draft-ietf-quic-multipath), and the OBSERVED_ADDRESS
			// frames outside of the application data packet number space (section 4.1 of
			// draft-ietf-quic-address-discovery-01).
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				FrameType:    typ,
				ErrorMessage: fmt.Sprintf("%d not allowed at encryption level %s", ft, encLevel),
			}
		}
		return ft, parsed, nil
	}
	return 0, parsed, io.EOF
}

// AllowUnknownFrameTypes enables parsing of frame types not known to quic-go.
func (p *FrameParser) AllowUnknownFrameTypes() {
	p.allowUnknownFrameTypes = true
}

// EnableMultipath enables parsing of the frames of the multipath extension (draft-ietf-quic-multipath).
// It needs to be called when advertising the initial_max_path_id transport parameter, before the peer's
// transport parameters are known, so that these frames are a PROTOCOL_VIOLATION in all packets other than
// 1-RTT packets (section 4 of the draft).
// In 1-RTT packets, they are accepted even if the peer didn't advertise the extension.
func (p *FrameParser) EnableMultipath() {
	p.supportsMultipath = true
}

// EnableAddAddress enables parsing of the ADD_ADDRESS frame.
// It is called once both endpoints advertised the address advertisement extension and IETF Multipath QUIC.
// The frame is only accepted in 1-RTT packets.
func (p *FrameParser) EnableAddAddress() {
	p.supportsAddAddress = true
}

// EnableObservedAddress enables parsing of the OBSERVED_ADDRESS frames of QUIC Address Discovery
// (draft-ietf-quic-address-discovery-01).
// It needs to be called when sending the address_discovery transport parameter, before the peer's transport
// parameters are known, so that these frames are a PROTOCOL_VIOLATION in Initial and Handshake packets.
// The frames are accepted in 0-RTT and 1-RTT packets.
func (p *FrameParser) EnableObservedAddress() {
	p.supportsObservedAddress = true
}

// IsKnownFrameType reports if the frame type is supported by the parser.
func (p *FrameParser) IsKnownFrameType(frameType FrameType) bool {
	return frameType.isValidRFC9000() ||
		(p.supportsDatagrams && frameType.IsDatagramFrameType()) ||
		(p.supportsResetStreamAt && frameType == FrameTypeResetStreamAt) ||
		(p.supportsAckFrequency && (frameType == FrameTypeAckFrequency || frameType == FrameTypeImmediateAck)) ||
		(p.supportsMultipath && frameType.IsMultipathFrameType()) ||
		(p.supportsAddAddress && frameType == FrameTypeAddAddress) ||
		(p.supportsObservedAddress && frameType.IsObservedAddressFrameType())
}

func (p *FrameParser) ParseStreamFrame(frameType FrameType, data []byte, v protocol.Version) (*StreamFrame, int, error) {
	frame, n, err := ParseStreamFrame(data, frameType, v)
	if err != nil {
		return nil, n, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}
	return frame, n, nil
}

// ParseAckFrame parses an ACK or a PATH_ACK frame.
// The returned frame is only valid until the next call to ParseAckFrame.
func (p *FrameParser) ParseAckFrame(frameType FrameType, data []byte, encLevel protocol.EncryptionLevel, v protocol.Version) (*AckFrame, int, error) {
	ackDelayExponent := p.ackDelayExponent
	if encLevel != protocol.Encryption1RTT {
		ackDelayExponent = protocol.DefaultAckDelayExponent
	}
	p.ackFrame.Reset()
	l, err := parseAckFrame(p.ackFrame, data, frameType, ackDelayExponent, v)
	if err != nil {
		return nil, l, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}

	return p.ackFrame, l, nil
}

func (p *FrameParser) ParseDatagramFrame(frameType FrameType, data []byte, v protocol.Version) (*DatagramFrame, int, error) {
	f, l, err := parseDatagramFrame(data, frameType, v)
	if err != nil {
		return nil, 0, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}
	return f, l, nil
}

// ParseLessCommonFrame parses everything except STREAM, ACK, PATH_ACK or DATAGRAM.
// These cases should be handled separately for performance reasons.
func (p *FrameParser) ParseLessCommonFrame(frameType FrameType, data []byte, v protocol.Version) (Frame, int, error) {
	var frame Frame
	var l int
	var err error
	//nolint:exhaustive // Common frames should already be handled.
	switch frameType {
	case FrameTypePing:
		frame = &PingFrame{}
	case FrameTypeResetStream:
		frame, l, err = parseResetStreamFrame(data, false, v)
	case FrameTypeStopSending:
		frame, l, err = parseStopSendingFrame(data, v)
	case FrameTypeCrypto:
		frame, l, err = parseCryptoFrame(data, v)
	case FrameTypeNewToken:
		frame, l, err = parseNewTokenFrame(data, v)
	case FrameTypeMaxData:
		frame, l, err = parseMaxDataFrame(data, v)
	case FrameTypeMaxStreamData:
		frame, l, err = parseMaxStreamDataFrame(data, v)
	case FrameTypeBidiMaxStreams, FrameTypeUniMaxStreams:
		frame, l, err = parseMaxStreamsFrame(data, frameType, v)
	case FrameTypeDataBlocked:
		frame, l, err = parseDataBlockedFrame(data, v)
	case FrameTypeStreamDataBlocked:
		frame, l, err = parseStreamDataBlockedFrame(data, v)
	case FrameTypeBidiStreamBlocked, FrameTypeUniStreamBlocked:
		frame, l, err = parseStreamsBlockedFrame(data, frameType, v)
	case FrameTypeNewConnectionID:
		frame, l, err = parseNewConnectionIDFrame(data, v)
	case FrameTypeRetireConnectionID:
		frame, l, err = parseRetireConnectionIDFrame(data, v)
	case FrameTypePathChallenge:
		frame, l, err = parsePathChallengeFrame(data, v)
	case FrameTypePathResponse:
		frame, l, err = parsePathResponseFrame(data, v)
	case FrameTypeConnectionClose, FrameTypeApplicationClose:
		frame, l, err = parseConnectionCloseFrame(data, frameType, v)
	case FrameTypeHandshakeDone:
		frame = &HandshakeDoneFrame{}
	case FrameTypeResetStreamAt:
		frame, l, err = parseResetStreamFrame(data, true, v)
	case FrameTypeAckFrequency:
		frame, l, err = parseAckFrequencyFrame(data, v)
	case FrameTypeImmediateAck:
		frame = &ImmediateAckFrame{}
	case FrameTypePathAbandon:
		frame, l, err = parsePathAbandonFrame(data, v)
	case FrameTypePathStatusBackup, FrameTypePathStatusAvailable:
		frame, l, err = parsePathStatusFrame(data, frameType, v)
	case FrameTypePathNewConnectionID:
		frame, l, err = parsePathNewConnectionIDFrame(data, v)
	case FrameTypePathRetireConnectionID:
		frame, l, err = parsePathRetireConnectionIDFrame(data, v)
	case FrameTypeMaxPathID:
		frame, l, err = parseMaxPathIDFrame(data, v)
	case FrameTypePathsBlocked:
		frame, l, err = parsePathsBlockedFrame(data, v)
	case FrameTypePathCIDsBlocked:
		frame, l, err = parsePathCIDsBlockedFrame(data, v)
	case FrameTypeAddAddress:
		frame, l, err = parseAddAddressFrame(data, v)
	case FrameTypeObservedAddressIPv4, FrameTypeObservedAddressIPv6:
		frame, l, err = parseObservedAddressFrame(data, frameType, v)
	default:
		err = errUnknownFrameType
	}
	if err != nil {
		return frame, l, &qerr.TransportError{
			ErrorCode:    qerr.FrameEncodingError,
			FrameType:    uint64(frameType),
			ErrorMessage: err.Error(),
		}
	}
	return frame, l, err
}

// SetAckDelayExponent sets the acknowledgment delay exponent (sent in the transport parameters).
// This value is used to scale the ACK Delay field in the ACK frame.
func (p *FrameParser) SetAckDelayExponent(exp uint8) {
	p.ackDelayExponent = exp
}

func replaceUnexpectedEOF(e error) error {
	if e == io.ErrUnexpectedEOF {
		return io.EOF
	}
	return e
}
