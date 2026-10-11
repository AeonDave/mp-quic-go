package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// AdditionalTransportParametersClient are additional transport parameters that will be added
// to the client's transport parameters.
// This is not intended for production use, but _only_ to increase the size of the ClientHello beyond
// the usual size of less than 1 MTU.
var AdditionalTransportParametersClient map[uint64][]byte

const transportParameterMarshalingVersion = 1

type transportParameterID uint64

const (
	originalDestinationConnectionIDParameterID transportParameterID = 0x0
	maxIdleTimeoutParameterID                  transportParameterID = 0x1
	statelessResetTokenParameterID             transportParameterID = 0x2
	maxUDPPayloadSizeParameterID               transportParameterID = 0x3
	initialMaxDataParameterID                  transportParameterID = 0x4
	initialMaxStreamDataBidiLocalParameterID   transportParameterID = 0x5
	initialMaxStreamDataBidiRemoteParameterID  transportParameterID = 0x6
	initialMaxStreamDataUniParameterID         transportParameterID = 0x7
	initialMaxStreamsBidiParameterID           transportParameterID = 0x8
	initialMaxStreamsUniParameterID            transportParameterID = 0x9
	ackDelayExponentParameterID                transportParameterID = 0xa
	maxAckDelayParameterID                     transportParameterID = 0xb
	disableActiveMigrationParameterID          transportParameterID = 0xc
	preferredAddressParameterID                transportParameterID = 0xd
	activeConnectionIDLimitParameterID         transportParameterID = 0xe
	initialSourceConnectionIDParameterID       transportParameterID = 0xf
	retrySourceConnectionIDParameterID         transportParameterID = 0x10
	// RFC 9368
	versionInformationParameterID transportParameterID = 0x11
	// RFC 9221
	maxDatagramFrameSizeParameterID transportParameterID = 0x20
	// RFC 9287
	greaseQUICBitParameterID transportParameterID = 0x2ab2
	// https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/
	initialMaxPathIDParameterID transportParameterID = 0x3e
	// https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/11/
	// The value is registered permanently by IANA. It is used since draft-09.
	resetStreamAtParameterID transportParameterID = 0x1d
	// https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/07/
	// The provisional value used up to draft-08. The RESET_STREAM_AT frame (0x24) is the same in all drafts.
	// When removing support for this codepoint, increment transportParameterMarshalingVersion
	// to prevent 0-RTT resumption with tickets that remember it.
	legacyResetStreamAtParameterID transportParameterID = 0x17f7586d2cb571
	// https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/11/
	minAckDelayParameterID transportParameterID = 0xff04de1b
	// The add_address transport parameter of the address advertisement extension of this module (ADD_ADDRESS).
	// It is not registered with IANA. The value is outside of the ranges of registered transport parameters,
	// and not a reserved value (31 * N + 27). It is the same value as the frame type of the ADD_ADDRESS frame.
	addAddressParameterID transportParameterID = 0x1f0f9c0d40
	// https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/01/
	addressDiscoveryParameterID transportParameterID = 0x9f81a176
)

// AddressDiscoveryMode is the value of the address_discovery transport parameter of QUIC Address Discovery
// (draft-ietf-quic-address-discovery-01).
type AddressDiscoveryMode uint8

const (
	// AddressDiscoveryUnsupported means that the transport parameter is not sent.
	AddressDiscoveryUnsupported AddressDiscoveryMode = iota
	// AddressDiscoveryProvide (value 0): the endpoint provides address observations to the peer,
	// but doesn't want to receive any.
	AddressDiscoveryProvide
	// AddressDiscoveryReceive (value 1): the endpoint wants to receive address observations,
	// but doesn't provide any.
	AddressDiscoveryReceive
	// AddressDiscoveryProvideAndReceive (value 2): the endpoint wants to receive address observations,
	// and provides them to the peer.
	AddressDiscoveryProvideAndReceive
)

// Provides says if the endpoint is willing to provide address observations.
func (m AddressDiscoveryMode) Provides() bool {
	return m == AddressDiscoveryProvide || m == AddressDiscoveryProvideAndReceive
}

// Receives says if the endpoint wants to receive address observations.
func (m AddressDiscoveryMode) Receives() bool {
	return m == AddressDiscoveryReceive || m == AddressDiscoveryProvideAndReceive
}

func (m AddressDiscoveryMode) String() string {
	switch m {
	case AddressDiscoveryUnsupported:
		return "unsupported"
	case AddressDiscoveryProvide:
		return "provide"
	case AddressDiscoveryReceive:
		return "receive"
	case AddressDiscoveryProvideAndReceive:
		return "provide and receive"
	default:
		return fmt.Sprintf("AddressDiscoveryMode(%d)", uint8(m))
	}
}

// VersionInformation is the value of the version_information transport parameter,
// see section 3 of RFC 9368.
type VersionInformation struct {
	ChosenVersion protocol.Version
	// AvailableVersions are the versions that the client's first flight is compatible with (when sent by the client),
	// or the Fully Deployed Versions of the server (when sent by the server).
	AvailableVersions []protocol.Version
}

func (v *VersionInformation) String() string {
	return fmt.Sprintf("{ChosenVersion: %s, AvailableVersions: %s}", v.ChosenVersion, v.AvailableVersions)
}

// PreferredAddress is the value encoding in the preferred_address transport parameter
type PreferredAddress struct {
	IPv4, IPv6          netip.AddrPort
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

// TransportParameters are parameters sent to the peer during the handshake
type TransportParameters struct {
	InitialMaxStreamDataBidiLocal  protocol.ByteCount
	InitialMaxStreamDataBidiRemote protocol.ByteCount
	InitialMaxStreamDataUni        protocol.ByteCount
	InitialMaxData                 protocol.ByteCount

	MaxAckDelay      time.Duration
	AckDelayExponent uint8

	DisableActiveMigration bool

	MaxUDPPayloadSize protocol.ByteCount

	MaxUniStreamNum  protocol.StreamNum
	MaxBidiStreamNum protocol.StreamNum

	MaxIdleTimeout time.Duration

	PreferredAddress *PreferredAddress

	OriginalDestinationConnectionID protocol.ConnectionID
	InitialSourceConnectionID       protocol.ConnectionID
	RetrySourceConnectionID         *protocol.ConnectionID // use a pointer here to distinguish zero-length connection IDs from missing transport parameters

	StatelessResetToken     *protocol.StatelessResetToken
	ActiveConnectionIDLimit uint64

	MaxDatagramFrameSize protocol.ByteCount // RFC 9221
	EnableResetStreamAt  bool               // https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/11/
	MinAckDelay          *time.Duration

	// The initial_max_path_id of the multipath extension (draft-ietf-quic-multipath).
	// It is only sent if HasInitialMaxPathID is set.
	// The received value is not validated: values larger than protocol.MaxPathID are invalid.
	InitialMaxPathID    protocol.PathID
	HasInitialMaxPathID bool

	// EnableAddAddress is the add_address transport parameter of the address advertisement extension (ADD_ADDRESS).
	// The extension is only used if IETF Multipath QUIC is used as well.
	EnableAddAddress bool

	// AddressDiscovery is the address_discovery transport parameter of QUIC Address Discovery
	// (draft-ietf-quic-address-discovery-01). It is not sent if it is AddressDiscoveryUnsupported.
	AddressDiscovery AddressDiscoveryMode

	// VersionInformation is the version_information transport parameter (RFC 9368).
	// It is not sent if it is nil.
	VersionInformation *VersionInformation

	// GreaseQUICBit is the grease_quic_bit transport parameter (RFC 9287).
	// The sender accepts packets with the QUIC Bit set to 0.
	GreaseQUICBit bool
}

// Unmarshal the transport parameters
func (p *TransportParameters) Unmarshal(data []byte, sentBy protocol.Perspective) error {
	if err := p.unmarshal(data, sentBy, false); err != nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: err.Error(),
		}
	}
	return nil
}

func (p *TransportParameters) unmarshal(b []byte, sentBy protocol.Perspective, fromSessionTicket bool) error {
	// needed to check that every parameter is only sent at most once
	parameterIDs := make([]transportParameterID, 0, 32)

	var (
		readOriginalDestinationConnectionID bool
		readInitialSourceConnectionID       bool
	)

	p.AckDelayExponent = protocol.DefaultAckDelayExponent
	p.MaxAckDelay = protocol.DefaultMaxAckDelay
	p.MaxDatagramFrameSize = protocol.InvalidByteCount
	p.ActiveConnectionIDLimit = protocol.DefaultActiveConnectionIDLimit

	for len(b) > 0 {
		paramIDInt, l, err := quicvarint.Parse(b)
		if err != nil {
			return err
		}
		paramID := transportParameterID(paramIDInt)
		b = b[l:]
		paramLen, l, err := quicvarint.Parse(b)
		if err != nil {
			return err
		}
		b = b[l:]
		if uint64(len(b)) < paramLen {
			return fmt.Errorf("remaining length (%d) smaller than parameter length (%d)", len(b), paramLen)
		}
		parameterIDs = append(parameterIDs, paramID)
		switch paramID {
		case maxIdleTimeoutParameterID,
			maxUDPPayloadSizeParameterID,
			initialMaxDataParameterID,
			initialMaxStreamDataBidiLocalParameterID,
			initialMaxStreamDataBidiRemoteParameterID,
			initialMaxStreamDataUniParameterID,
			initialMaxStreamsBidiParameterID,
			initialMaxStreamsUniParameterID,
			maxAckDelayParameterID,
			maxDatagramFrameSizeParameterID,
			ackDelayExponentParameterID,
			activeConnectionIDLimitParameterID,
			minAckDelayParameterID,
			addressDiscoveryParameterID:
			if err := p.readNumericTransportParameter(b, paramID, int(paramLen)); err != nil {
				return err
			}
			b = b[paramLen:]
		case preferredAddressParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent a preferred_address")
			}
			if err := p.readPreferredAddress(b, int(paramLen)); err != nil {
				return err
			}
			b = b[paramLen:]
		case disableActiveMigrationParameterID:
			if paramLen != 0 {
				return fmt.Errorf("wrong length for disable_active_migration: %d (expected empty)", paramLen)
			}
			p.DisableActiveMigration = true
		case statelessResetTokenParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent a stateless_reset_token")
			}
			if paramLen != 16 {
				return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", paramLen)
			}
			var token protocol.StatelessResetToken
			if len(b) < len(token) {
				return io.EOF
			}
			copy(token[:], b)
			b = b[len(token):]
			p.StatelessResetToken = &token
		case originalDestinationConnectionIDParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent an original_destination_connection_id")
			}
			if paramLen > protocol.MaxConnIDLen {
				return protocol.ErrInvalidConnectionIDLen
			}
			p.OriginalDestinationConnectionID = protocol.ParseConnectionID(b[:paramLen])
			b = b[paramLen:]
			readOriginalDestinationConnectionID = true
		case initialSourceConnectionIDParameterID:
			if paramLen > protocol.MaxConnIDLen {
				return protocol.ErrInvalidConnectionIDLen
			}
			p.InitialSourceConnectionID = protocol.ParseConnectionID(b[:paramLen])
			b = b[paramLen:]
			readInitialSourceConnectionID = true
		case retrySourceConnectionIDParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent a retry_source_connection_id")
			}
			if paramLen > protocol.MaxConnIDLen {
				return protocol.ErrInvalidConnectionIDLen
			}
			connID := protocol.ParseConnectionID(b[:paramLen])
			b = b[paramLen:]
			p.RetrySourceConnectionID = &connID
		case resetStreamAtParameterID, legacyResetStreamAtParameterID:
			if paramLen != 0 {
				return fmt.Errorf("wrong length for reset_stream_at: %d (expected empty)", paramLen)
			}
			p.EnableResetStreamAt = true
		case greaseQUICBitParameterID:
			// The extension only applies to the current connection, so it is never saved in a session ticket.
			if fromSessionTicket {
				return errors.New("grease_quic_bit in session ticket")
			}
			if paramLen != 0 {
				return fmt.Errorf("wrong length for grease_quic_bit: %d (expected empty)", paramLen)
			}
			p.GreaseQUICBit = true
		case initialMaxPathIDParameterID:
			// This parameter must not be remembered for 0-RTT (section 2.1 of draft-ietf-quic-multipath),
			// so it is never saved in a session ticket.
			if fromSessionTicket {
				return errors.New("initial_max_path_id in session ticket")
			}
			if err := p.readNumericTransportParameter(b, paramID, int(paramLen)); err != nil {
				return err
			}
			b = b[paramLen:]
		case versionInformationParameterID:
			// The Version Information is specific to a connection, and never saved in a session ticket.
			if fromSessionTicket {
				return errors.New("version_information in session ticket")
			}
			if err := p.readVersionInformation(b[:paramLen], sentBy); err != nil {
				return err
			}
			b = b[paramLen:]
		case addAddressParameterID:
			// Like initial_max_path_id, this parameter is never saved in a session ticket:
			// the extension is only used together with IETF Multipath QUIC.
			if fromSessionTicket {
				return errors.New("add_address in session ticket")
			}
			if paramLen != 0 {
				return fmt.Errorf("wrong length for add_address: %d (expected empty)", paramLen)
			}
			p.EnableAddAddress = true
		default:
			if fromSessionTicket {
				// A ticket might contain a parameter for an extension supported by an older
				// version of this endpoint. If we can't parse it, don't resume with it.
				return fmt.Errorf("unknown transport parameter %#x in session ticket", paramID)
			}
			b = b[paramLen:]
		}
	}

	// min_ack_delay must be less or equal to max_ack_delay
	if p.MinAckDelay != nil && *p.MinAckDelay > p.MaxAckDelay {
		return fmt.Errorf("min_ack_delay (%s) is greater than max_ack_delay (%s)", *p.MinAckDelay, p.MaxAckDelay)
	}
	if !fromSessionTicket {
		if sentBy == protocol.PerspectiveServer && !readOriginalDestinationConnectionID {
			return errors.New("missing original_destination_connection_id")
		}
		if p.MaxUDPPayloadSize == 0 {
			p.MaxUDPPayloadSize = protocol.MaxByteCount
		}
		if !readInitialSourceConnectionID {
			return errors.New("missing initial_source_connection_id")
		}
	}

	// check that every transport parameter was sent at most once
	slices.Sort(parameterIDs)
	for i := range len(parameterIDs) - 1 {
		if parameterIDs[i] == parameterIDs[i+1] {
			return fmt.Errorf("received duplicate transport parameter %#x", parameterIDs[i])
		}
	}

	return nil
}

func (p *TransportParameters) readPreferredAddress(b []byte, expectedLen int) error {
	remainingLen := len(b)
	pa := &PreferredAddress{}
	if len(b) < 4+2+16+2+1 {
		return io.EOF
	}
	var ipv4 [4]byte
	copy(ipv4[:], b[:4])
	port4 := binary.BigEndian.Uint16(b[4:])
	b = b[4+2:]
	if port4 != 0 && ipv4 != [4]byte{} {
		pa.IPv4 = netip.AddrPortFrom(netip.AddrFrom4(ipv4), port4)
	}
	var ipv6 [16]byte
	copy(ipv6[:], b[:16])
	port6 := binary.BigEndian.Uint16(b[16:])
	if port6 != 0 && ipv6 != [16]byte{} {
		pa.IPv6 = netip.AddrPortFrom(netip.AddrFrom16(ipv6), port6)
	}
	b = b[16+2:]
	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen == 0 || connIDLen > protocol.MaxConnIDLen {
		return fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	if len(b) < connIDLen+len(pa.StatelessResetToken) {
		return io.EOF
	}
	pa.ConnectionID = protocol.ParseConnectionID(b[:connIDLen])
	b = b[connIDLen:]
	copy(pa.StatelessResetToken[:], b)
	b = b[len(pa.StatelessResetToken):]
	if bytesRead := remainingLen - len(b); bytesRead != expectedLen {
		return fmt.Errorf("expected preferred_address to be %d long, read %d bytes", expectedLen, bytesRead)
	}
	p.PreferredAddress = pa
	return nil
}

// readVersionInformation reads the version_information transport parameter.
// Section 4 of RFC 9368 defines which values are parsing failures.
func (p *TransportParameters) readVersionInformation(b []byte, sentBy protocol.Perspective) error {
	if len(b) < 4 || len(b)%4 != 0 {
		return fmt.Errorf("invalid length for version_information: %d", len(b))
	}
	vi := &VersionInformation{ChosenVersion: protocol.Version(binary.BigEndian.Uint32(b))}
	if vi.ChosenVersion == 0 {
		return errors.New("version_information: Chosen Version is 0")
	}
	b = b[4:]
	vi.AvailableVersions = make([]protocol.Version, 0, len(b)/4)
	for len(b) > 0 {
		v := protocol.Version(binary.BigEndian.Uint32(b))
		if v == 0 {
			return errors.New("version_information: Available Version is 0")
		}
		vi.AvailableVersions = append(vi.AvailableVersions, v)
		b = b[4:]
	}
	if sentBy == protocol.PerspectiveClient && !slices.Contains(vi.AvailableVersions, vi.ChosenVersion) {
		return fmt.Errorf("version_information: Chosen Version %s not contained in Available Versions %s", vi.ChosenVersion, vi.AvailableVersions)
	}
	p.VersionInformation = vi
	return nil
}

func (p *TransportParameters) readNumericTransportParameter(b []byte, paramID transportParameterID, expectedLen int) error {
	val, l, err := quicvarint.Parse(b)
	if err != nil {
		return fmt.Errorf("error while reading transport parameter %d: %s", paramID, err)
	}
	if l != expectedLen {
		return fmt.Errorf("inconsistent transport parameter length for transport parameter %#x", paramID)
	}
	//nolint:exhaustive // This only covers the numeric transport parameters.
	switch paramID {
	case initialMaxStreamDataBidiLocalParameterID:
		p.InitialMaxStreamDataBidiLocal = protocol.ByteCount(val)
	case initialMaxStreamDataBidiRemoteParameterID:
		p.InitialMaxStreamDataBidiRemote = protocol.ByteCount(val)
	case initialMaxStreamDataUniParameterID:
		p.InitialMaxStreamDataUni = protocol.ByteCount(val)
	case initialMaxDataParameterID:
		p.InitialMaxData = protocol.ByteCount(val)
	case initialMaxStreamsBidiParameterID:
		p.MaxBidiStreamNum = protocol.StreamNum(val)
		if p.MaxBidiStreamNum > protocol.MaxStreamCount {
			return fmt.Errorf("initial_max_streams_bidi too large: %d (maximum %d)", p.MaxBidiStreamNum, protocol.MaxStreamCount)
		}
	case initialMaxStreamsUniParameterID:
		p.MaxUniStreamNum = protocol.StreamNum(val)
		if p.MaxUniStreamNum > protocol.MaxStreamCount {
			return fmt.Errorf("initial_max_streams_uni too large: %d (maximum %d)", p.MaxUniStreamNum, protocol.MaxStreamCount)
		}
	case maxIdleTimeoutParameterID:
		p.MaxIdleTimeout = max(protocol.MinRemoteIdleTimeout, time.Duration(val)*time.Millisecond)
	case maxUDPPayloadSizeParameterID:
		if val < 1200 {
			return fmt.Errorf("invalid value for max_udp_payload_size: %d (minimum 1200)", val)
		}
		p.MaxUDPPayloadSize = protocol.ByteCount(val)
	case ackDelayExponentParameterID:
		if val > protocol.MaxAckDelayExponent {
			return fmt.Errorf("invalid value for ack_delay_exponent: %d (maximum %d)", val, protocol.MaxAckDelayExponent)
		}
		p.AckDelayExponent = uint8(val)
	case maxAckDelayParameterID:
		if val > uint64(protocol.MaxMaxAckDelay/time.Millisecond) {
			return fmt.Errorf("invalid value for max_ack_delay: %dms (maximum %dms)", val, protocol.MaxMaxAckDelay/time.Millisecond)
		}
		p.MaxAckDelay = time.Duration(val) * time.Millisecond
	case activeConnectionIDLimitParameterID:
		if val < 2 {
			return fmt.Errorf("invalid value for active_connection_id_limit: %d (minimum 2)", val)
		}
		p.ActiveConnectionIDLimit = val
	case maxDatagramFrameSizeParameterID:
		p.MaxDatagramFrameSize = protocol.ByteCount(val)
	case minAckDelayParameterID:
		mad := time.Duration(val) * time.Microsecond
		if mad < 0 {
			mad = math.MaxInt64
		}
		p.MinAckDelay = &mad
	case initialMaxPathIDParameterID:
		p.InitialMaxPathID = protocol.PathID(val)
		p.HasInitialMaxPathID = true
	case addressDiscoveryParameterID:
		// Section 3 of draft-ietf-quic-address-discovery-01:
		// Any other value than 0, 1 and 2 is a TRANSPORT_PARAMETER_ERROR.
		if val > 2 {
			return fmt.Errorf("invalid value for address_discovery: %d", val)
		}
		p.AddressDiscovery = AddressDiscoveryMode(val + 1)
	default:
		return fmt.Errorf("TransportParameter BUG: transport parameter %d not found", paramID)
	}
	return nil
}

// Marshal the transport parameters
func (p *TransportParameters) Marshal(pers protocol.Perspective) []byte {
	// Typical Transport Parameters consume around 110 bytes, depending on the exact values,
	// especially the lengths of the Connection IDs.
	// Allocate 256 bytes, so we won't have to grow the slice in any case.
	b := make([]byte, 0, 256)

	// add a greased value
	random := make([]byte, 18)
	rand.Read(random)
	b = quicvarint.Append(b, 27+31*uint64(random[0]))
	length := random[1] % 16
	b = quicvarint.Append(b, uint64(length))
	b = append(b, random[2:2+length]...)

	// initial_max_stream_data_bidi_local
	b = p.marshalVarintParam(b, initialMaxStreamDataBidiLocalParameterID, uint64(p.InitialMaxStreamDataBidiLocal))
	// initial_max_stream_data_bidi_remote
	b = p.marshalVarintParam(b, initialMaxStreamDataBidiRemoteParameterID, uint64(p.InitialMaxStreamDataBidiRemote))
	// initial_max_stream_data_uni
	b = p.marshalVarintParam(b, initialMaxStreamDataUniParameterID, uint64(p.InitialMaxStreamDataUni))
	// initial_max_data
	b = p.marshalVarintParam(b, initialMaxDataParameterID, uint64(p.InitialMaxData))
	// initial_max_bidi_streams
	b = p.marshalVarintParam(b, initialMaxStreamsBidiParameterID, uint64(p.MaxBidiStreamNum))
	// initial_max_uni_streams
	b = p.marshalVarintParam(b, initialMaxStreamsUniParameterID, uint64(p.MaxUniStreamNum))
	// idle_timeout
	b = p.marshalVarintParam(b, maxIdleTimeoutParameterID, uint64(p.MaxIdleTimeout/time.Millisecond))
	// max_udp_payload_size
	if p.MaxUDPPayloadSize > 0 {
		b = p.marshalVarintParam(b, maxUDPPayloadSizeParameterID, uint64(p.MaxUDPPayloadSize))
	}
	// max_ack_delay
	// Only send it if is different from the default value.
	if p.MaxAckDelay != protocol.DefaultMaxAckDelay {
		b = p.marshalVarintParam(b, maxAckDelayParameterID, uint64(p.MaxAckDelay/time.Millisecond))
	}
	// ack_delay_exponent
	// Only send it if is different from the default value.
	if p.AckDelayExponent != protocol.DefaultAckDelayExponent {
		b = p.marshalVarintParam(b, ackDelayExponentParameterID, uint64(p.AckDelayExponent))
	}
	// disable_active_migration
	if p.DisableActiveMigration {
		b = quicvarint.Append(b, uint64(disableActiveMigrationParameterID))
		b = quicvarint.Append(b, 0)
	}
	if pers == protocol.PerspectiveServer {
		// stateless_reset_token
		if p.StatelessResetToken != nil {
			b = quicvarint.Append(b, uint64(statelessResetTokenParameterID))
			b = quicvarint.Append(b, 16)
			b = append(b, p.StatelessResetToken[:]...)
		}
		// original_destination_connection_id
		b = quicvarint.Append(b, uint64(originalDestinationConnectionIDParameterID))
		b = quicvarint.Append(b, uint64(p.OriginalDestinationConnectionID.Len()))
		b = append(b, p.OriginalDestinationConnectionID.Bytes()...)
		// preferred_address
		if p.PreferredAddress != nil {
			b = quicvarint.Append(b, uint64(preferredAddressParameterID))
			b = quicvarint.Append(b, 4+2+16+2+1+uint64(p.PreferredAddress.ConnectionID.Len())+16)
			if p.PreferredAddress.IPv4.IsValid() {
				ipv4 := p.PreferredAddress.IPv4.Addr().As4()
				b = append(b, ipv4[:]...)
				b = binary.BigEndian.AppendUint16(b, p.PreferredAddress.IPv4.Port())
			} else {
				b = append(b, make([]byte, 6)...)
			}
			if p.PreferredAddress.IPv6.IsValid() {
				ipv6 := p.PreferredAddress.IPv6.Addr().As16()
				b = append(b, ipv6[:]...)
				b = binary.BigEndian.AppendUint16(b, p.PreferredAddress.IPv6.Port())
			} else {
				b = append(b, make([]byte, 18)...)
			}
			b = append(b, uint8(p.PreferredAddress.ConnectionID.Len()))
			b = append(b, p.PreferredAddress.ConnectionID.Bytes()...)
			b = append(b, p.PreferredAddress.StatelessResetToken[:]...)
		}
	}
	// active_connection_id_limit
	if p.ActiveConnectionIDLimit != protocol.DefaultActiveConnectionIDLimit {
		b = p.marshalVarintParam(b, activeConnectionIDLimitParameterID, p.ActiveConnectionIDLimit)
	}
	// initial_source_connection_id
	b = quicvarint.Append(b, uint64(initialSourceConnectionIDParameterID))
	b = quicvarint.Append(b, uint64(p.InitialSourceConnectionID.Len()))
	b = append(b, p.InitialSourceConnectionID.Bytes()...)
	// retry_source_connection_id
	if pers == protocol.PerspectiveServer && p.RetrySourceConnectionID != nil {
		b = quicvarint.Append(b, uint64(retrySourceConnectionIDParameterID))
		b = quicvarint.Append(b, uint64(p.RetrySourceConnectionID.Len()))
		b = append(b, p.RetrySourceConnectionID.Bytes()...)
	}
	// QUIC datagrams
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		b = p.marshalVarintParam(b, maxDatagramFrameSizeParameterID, uint64(p.MaxDatagramFrameSize))
	}
	// version_information
	if p.VersionInformation != nil {
		b = quicvarint.Append(b, uint64(versionInformationParameterID))
		b = quicvarint.Append(b, uint64(4*(1+len(p.VersionInformation.AvailableVersions))))
		b = binary.BigEndian.AppendUint32(b, uint32(p.VersionInformation.ChosenVersion))
		for _, v := range p.VersionInformation.AvailableVersions {
			b = binary.BigEndian.AppendUint32(b, uint32(v))
		}
	}
	// Multipath QUIC (draft-ietf-quic-multipath)
	if p.HasInitialMaxPathID {
		b = p.marshalVarintParam(b, initialMaxPathIDParameterID, uint64(p.InitialMaxPathID))
	}
	// address advertisement (ADD_ADDRESS)
	if p.EnableAddAddress {
		b = quicvarint.Append(b, uint64(addAddressParameterID))
		b = quicvarint.Append(b, 0)
	}
	// QUIC Address Discovery
	if p.AddressDiscovery != AddressDiscoveryUnsupported {
		b = p.marshalVarintParam(b, addressDiscoveryParameterID, uint64(p.AddressDiscovery-1))
	}
	// Greasing the QUIC Bit
	if p.GreaseQUICBit {
		b = quicvarint.Append(b, uint64(greaseQUICBitParameterID))
		b = quicvarint.Append(b, 0)
	}
	// QUIC Stream Resets with Partial Delivery.
	// Both code points are sent, the final one first, so that peers implementing an earlier draft enable the
	// extension as well. Receiving either one of them enables it.
	if p.EnableResetStreamAt {
		b = quicvarint.Append(b, uint64(resetStreamAtParameterID))
		b = quicvarint.Append(b, 0)
		b = quicvarint.Append(b, uint64(legacyResetStreamAtParameterID))
		b = quicvarint.Append(b, 0)
	}
	if p.MinAckDelay != nil {
		b = p.marshalVarintParam(b, minAckDelayParameterID, uint64(*p.MinAckDelay/time.Microsecond))
	}

	if pers == protocol.PerspectiveClient && len(AdditionalTransportParametersClient) > 0 {
		for k, v := range AdditionalTransportParametersClient {
			b = quicvarint.Append(b, k)
			b = quicvarint.Append(b, uint64(len(v)))
			b = append(b, v...)
		}
	}

	return b
}

func (p *TransportParameters) marshalVarintParam(b []byte, id transportParameterID, val uint64) []byte {
	b = quicvarint.Append(b, uint64(id))
	b = quicvarint.Append(b, uint64(quicvarint.Len(val)))
	return quicvarint.Append(b, val)
}

// MarshalForSessionTicket marshals the transport parameters we save in the session ticket.
// When sending a 0-RTT enabled TLS session tickets, we need to save the transport parameters.
// The client will remember the transport parameters used in the last session,
// and apply those to the 0-RTT data it sends.
// Saving the transport parameters in the ticket gives the server the option to reject 0-RTT
// if the transport parameters changed.
// Since the session ticket is encrypted, the serialization format is defined by the server.
// For convenience, we use the same format that we also use for sending the transport parameters.
func (p *TransportParameters) MarshalForSessionTicket(b []byte) []byte {
	b = quicvarint.Append(b, transportParameterMarshalingVersion)

	// initial_max_stream_data_bidi_local
	b = p.marshalVarintParam(b, initialMaxStreamDataBidiLocalParameterID, uint64(p.InitialMaxStreamDataBidiLocal))
	// initial_max_stream_data_bidi_remote
	b = p.marshalVarintParam(b, initialMaxStreamDataBidiRemoteParameterID, uint64(p.InitialMaxStreamDataBidiRemote))
	// initial_max_stream_data_uni
	b = p.marshalVarintParam(b, initialMaxStreamDataUniParameterID, uint64(p.InitialMaxStreamDataUni))
	// initial_max_data
	b = p.marshalVarintParam(b, initialMaxDataParameterID, uint64(p.InitialMaxData))
	// initial_max_bidi_streams
	b = p.marshalVarintParam(b, initialMaxStreamsBidiParameterID, uint64(p.MaxBidiStreamNum))
	// initial_max_uni_streams
	b = p.marshalVarintParam(b, initialMaxStreamsUniParameterID, uint64(p.MaxUniStreamNum))
	// active_connection_id_limit
	b = p.marshalVarintParam(b, activeConnectionIDLimitParameterID, p.ActiveConnectionIDLimit)
	// max_datagram_frame_size
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		b = p.marshalVarintParam(b, maxDatagramFrameSizeParameterID, uint64(p.MaxDatagramFrameSize))
	}
	// reset_stream_at
	if p.EnableResetStreamAt {
		b = quicvarint.Append(b, uint64(resetStreamAtParameterID))
		b = quicvarint.Append(b, 0)
	}
	// address_discovery is remembered (section 3 of draft-ietf-quic-address-discovery-01)
	if p.AddressDiscovery != AddressDiscoveryUnsupported {
		b = p.marshalVarintParam(b, addressDiscoveryParameterID, uint64(p.AddressDiscovery-1))
	}
	// initial_max_path_id must not be remembered (section 2.1 of draft-ietf-quic-multipath),
	// and neither are add_address, version_information and grease_quic_bit (a server must not set the QUIC Bit
	// to 0 based on a previous connection, section 3.1 of RFC 9287)
	return b
}

// UnmarshalFromSessionTicket unmarshals transport parameters from a session ticket.
func (p *TransportParameters) UnmarshalFromSessionTicket(b []byte) error {
	version, l, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}
	if version != transportParameterMarshalingVersion {
		return fmt.Errorf("unknown transport parameter marshaling version: %d", version)
	}
	return p.unmarshal(b[l:], protocol.PerspectiveServer, true)
}

// ValidFor0RTT checks if the transport parameters match those saved in the session ticket.
func (p *TransportParameters) ValidFor0RTT(saved *TransportParameters) bool {
	if saved.MaxDatagramFrameSize != protocol.InvalidByteCount && (p.MaxDatagramFrameSize == protocol.InvalidByteCount || p.MaxDatagramFrameSize < saved.MaxDatagramFrameSize) {
		return false
	}
	if saved.EnableResetStreamAt && !p.EnableResetStreamAt {
		return false
	}
	// Section 3 of draft-ietf-quic-address-discovery-01: if 0-RTT is accepted,
	// the server must not disable the extension or change the value.
	if p.AddressDiscovery != saved.AddressDiscovery {
		return false
	}
	return p.InitialMaxStreamDataBidiLocal >= saved.InitialMaxStreamDataBidiLocal &&
		p.InitialMaxStreamDataBidiRemote >= saved.InitialMaxStreamDataBidiRemote &&
		p.InitialMaxStreamDataUni >= saved.InitialMaxStreamDataUni &&
		p.InitialMaxData >= saved.InitialMaxData &&
		p.MaxBidiStreamNum >= saved.MaxBidiStreamNum &&
		p.MaxUniStreamNum >= saved.MaxUniStreamNum &&
		p.ActiveConnectionIDLimit == saved.ActiveConnectionIDLimit
}

// ValidForUpdate checks that the new transport parameters don't reduce limits after resuming a 0-RTT connection.
// It is only used on the client side.
func (p *TransportParameters) ValidForUpdate(saved *TransportParameters) bool {
	if saved.MaxDatagramFrameSize != protocol.InvalidByteCount && (p.MaxDatagramFrameSize == protocol.InvalidByteCount || p.MaxDatagramFrameSize < saved.MaxDatagramFrameSize) {
		return false
	}
	if saved.EnableResetStreamAt && !p.EnableResetStreamAt {
		return false
	}
	// section 3 of draft-ietf-quic-address-discovery-01
	if p.AddressDiscovery != saved.AddressDiscovery {
		return false
	}
	return p.ActiveConnectionIDLimit >= saved.ActiveConnectionIDLimit &&
		p.InitialMaxData >= saved.InitialMaxData &&
		p.InitialMaxStreamDataBidiLocal >= saved.InitialMaxStreamDataBidiLocal &&
		p.InitialMaxStreamDataBidiRemote >= saved.InitialMaxStreamDataBidiRemote &&
		p.InitialMaxStreamDataUni >= saved.InitialMaxStreamDataUni &&
		p.MaxBidiStreamNum >= saved.MaxBidiStreamNum &&
		p.MaxUniStreamNum >= saved.MaxUniStreamNum
}

// String returns a string representation, intended for logging.
func (p *TransportParameters) String() string {
	logString := "&wire.TransportParameters{OriginalDestinationConnectionID: %s, InitialSourceConnectionID: %s, "
	logParams := []any{p.OriginalDestinationConnectionID, p.InitialSourceConnectionID}
	if p.RetrySourceConnectionID != nil {
		logString += "RetrySourceConnectionID: %s, "
		logParams = append(logParams, p.RetrySourceConnectionID)
	}
	logString += "InitialMaxStreamDataBidiLocal: %d, InitialMaxStreamDataBidiRemote: %d, InitialMaxStreamDataUni: %d, InitialMaxData: %d, MaxBidiStreamNum: %d, MaxUniStreamNum: %d, MaxIdleTimeout: %s, AckDelayExponent: %d, MaxAckDelay: %s, ActiveConnectionIDLimit: %d"
	logParams = append(logParams, []any{p.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataUni, p.InitialMaxData, p.MaxBidiStreamNum, p.MaxUniStreamNum, p.MaxIdleTimeout, p.AckDelayExponent, p.MaxAckDelay, p.ActiveConnectionIDLimit}...)
	if p.StatelessResetToken != nil { // the client never sends a stateless reset token
		logString += ", StatelessResetToken: %#x"
		logParams = append(logParams, *p.StatelessResetToken)
	}
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		logString += ", MaxDatagramFrameSize: %d"
		logParams = append(logParams, p.MaxDatagramFrameSize)
	}
	logString += ", EnableResetStreamAt: %t"
	logParams = append(logParams, p.EnableResetStreamAt)
	if p.MinAckDelay != nil {
		logString += ", MinAckDelay: %s"
		logParams = append(logParams, *p.MinAckDelay)
	}
	if p.HasInitialMaxPathID {
		logString += ", InitialMaxPathID: %d"
		logParams = append(logParams, p.InitialMaxPathID)
	}
	if p.EnableAddAddress {
		logString += ", EnableAddAddress: true"
	}
	if p.AddressDiscovery != AddressDiscoveryUnsupported {
		logString += ", AddressDiscovery: %s"
		logParams = append(logParams, p.AddressDiscovery)
	}
	if p.VersionInformation != nil {
		logString += ", VersionInformation: %s"
		logParams = append(logParams, p.VersionInformation)
	}
	if p.GreaseQUICBit {
		logString += ", GreaseQUICBit: true"
	}
	logString += "}"
	return fmt.Sprintf(logString, logParams...)
}
