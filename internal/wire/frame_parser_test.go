package wire

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"

	"github.com/stretchr/testify/require"
)

func TestFrameTypeParsingReturnsNilWhenNothingToRead(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	frameType, l, err := parser.ParseType(nil, protocol.Encryption1RTT)
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, frameType)
	require.Zero(t, l)
}

func TestParseLessCommonFrameReturnsEOFWhenNothingToRead(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	l, f, err := parser.ParseLessCommonFrame(FrameTypeMaxStreamData, nil, protocol.Version1)
	require.IsType(t, &qerr.TransportError{}, err)
	require.Zero(t, l)
	require.Zero(t, f)
}

func TestFrameParsingSkipsPaddingFrames(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	b := []byte{0, 0} // 2 PADDING frames
	b, err := (&PingFrame{}).Append(b, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, 3, l)
	require.Equal(t, FrameTypePing, frameType)

	frame, l, err := parser.ParseLessCommonFrame(frameType, b[1:], protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, l)
	require.IsType(t, &PingFrame{}, frame)
}

func TestFrameParsingHandlesPaddingAtEnd(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	b := []byte{0, 0, 0}

	_, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 3, l)
}

func TestFrameParsingParsesSingleFrame(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	var b []byte
	for range 10 {
		var err error
		b, err = (&PingFrame{}).Append(b, protocol.Version1)
		require.NoError(t, err)
	}
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypePing, frameType)
	require.Equal(t, 1, l)

	frame, l, err := parser.ParseLessCommonFrame(frameType, b, protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, l)
	require.IsType(t, &PingFrame{}, frame)
}

func TestFrameParserACK(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	f := &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAck, frameType)
	require.Equal(t, 1, l)

	frame, l, err := parser.ParseAckFrame(frameType, b[l:], protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.Equal(t, protocol.PacketNumber(0x13), frame.LargestAcked())
	require.Equal(t, len(b)-1, l)
}

func TestFrameParserAckDelay(t *testing.T) {
	t.Run("1-RTT", func(t *testing.T) {
		testFrameParserAckDelay(t, protocol.Encryption1RTT)
	})
	t.Run("Handshake", func(t *testing.T) {
		testFrameParserAckDelay(t, protocol.EncryptionHandshake)
	})
}

func testFrameParserAckDelay(t *testing.T, encLevel protocol.EncryptionLevel) {
	parser := NewFrameParser(true, true, true)
	parser.SetAckDelayExponent(protocol.AckDelayExponent + 2)
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: time.Second,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, encLevel)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAck, frameType)
	require.Equal(t, 1, l)

	frame, l, err := parser.ParseAckFrame(frameType, b[l:], encLevel, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b)-1, l)
	if encLevel == protocol.Encryption1RTT {
		require.Equal(t, 4*time.Second, frame.DelayTime)
	} else {
		require.Equal(t, time.Second, frame.DelayTime)
	}
}

func checkFrameUnsupported(t *testing.T, err error, expectedFrameType uint64) {
	t.Helper()
	require.ErrorContains(t, err, errUnknownFrameType.Error())
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
	require.Equal(t, expectedFrameType, transportErr.FrameType)
	require.Equal(t, "unknown frame type", transportErr.ErrorMessage)
}

func TestFrameParserStreamFrames(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	f := &StreamFrame{
		StreamID: 0x42,
		Offset:   0x1337,
		Fin:      true,
		Data:     []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameType(0xd), frameType)
	require.True(t, frameType.IsStreamFrameType())
	require.Equal(t, 1, l)

	// ParseLessCommonFrame should not handle Stream Frames
	frame, l, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
	checkFrameUnsupported(t, err, 0xd)
	require.Nil(t, frame)
	require.Zero(t, l)
}

func TestParseStreamFrameWrapsError(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	f := &StreamFrame{
		StreamID:       0x1234,
		Offset:         0x1000,
		Data:           []byte("hello world"),
		DataLenPresent: true,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	// Corrupt the buffer to trigger a parse error
	b = b[:len(b)-2] // Remove last 2 bytes to cause an EOF

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)

	frame, n, err := parser.ParseStreamFrame(frameType, b[l:], protocol.Version1)
	require.Nil(t, frame)
	require.Zero(t, n)

	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
	require.Equal(t, uint64(frameType), transportErr.FrameType)
	require.ErrorContains(t, transportErr, "EOF")
}

func TestParseStreamFrameSuccess(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	original := &StreamFrame{
		StreamID:       0x1234,
		Offset:         0x1000,
		Fin:            true,
		Data:           []byte("hello world"),
		DataLenPresent: true,
	}
	b, err := original.Append(nil, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.True(t, frameType.IsStreamFrameType())
	require.Equal(t, FrameType(0x0f), frameType) // STREAM | OFF | LEN | FIN

	parsed, n, err := parser.ParseStreamFrame(frameType, b[l:], protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, len(b)-l, n)

	require.Equal(t, original.StreamID, parsed.StreamID)
	require.Equal(t, original.Offset, parsed.Offset)
	require.Equal(t, original.Fin, parsed.Fin)
	require.Equal(t, original.DataLenPresent, parsed.DataLenPresent)
	require.Equal(t, original.Data, parsed.Data)
}

func TestFrameParserFrames(t *testing.T) {
	tests := []struct {
		name      string
		frameType FrameType
		frame     Frame
	}{
		{
			name:      "MAX_DATA",
			frameType: FrameTypeMaxData,
			frame:     &MaxDataFrame{MaximumData: 0xcafe},
		},
		{
			name:      "MAX_STREAM_DATA",
			frameType: FrameTypeMaxStreamData,
			frame:     &MaxStreamDataFrame{StreamID: 0xdeadbeef, MaximumStreamData: 0xdecafbad},
		},
		{
			name:      "RESET_STREAM",
			frameType: FrameTypeResetStream,
			frame: &ResetStreamFrame{
				StreamID:  0xdeadbeef,
				FinalSize: 0xdecafbad1234,
				ErrorCode: 0x1337,
			},
		},
		{
			name:      "STOP_SENDING",
			frameType: FrameTypeStopSending,
			frame:     &StopSendingFrame{StreamID: 0x42},
		},
		{
			name:      "CRYPTO",
			frameType: FrameTypeCrypto,
			frame:     &CryptoFrame{Offset: 0x1337, Data: []byte("lorem ipsum")},
		},
		{
			name:      "NEW_TOKEN",
			frameType: FrameTypeNewToken,
			frame:     &NewTokenFrame{Token: []byte("foobar")},
		},
		{
			name:      "MAX_STREAMS",
			frameType: FrameTypeBidiMaxStreams,
			frame:     &MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 0x1337},
		},
		{
			name:      "DATA_BLOCKED",
			frameType: FrameTypeDataBlocked,
			frame:     &DataBlockedFrame{MaximumData: 0x1234},
		},
		{
			name:      "STREAM_DATA_BLOCKED",
			frameType: FrameTypeStreamDataBlocked,
			frame:     &StreamDataBlockedFrame{StreamID: 0xdeadbeef, MaximumStreamData: 0xdead},
		},
		{
			name:      "STREAMS_BLOCKED",
			frameType: FrameTypeBidiStreamBlocked,
			frame:     &StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 0x1234567},
		},
		{
			name:      "NEW_CONNECTION_ID",
			frameType: FrameTypeNewConnectionID,
			frame: &NewConnectionIDFrame{
				SequenceNumber:      0x1337,
				ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			},
		},
		{
			name:      "RETIRE_CONNECTION_ID",
			frameType: FrameTypeRetireConnectionID,
			frame:     &RetireConnectionIDFrame{SequenceNumber: 0x1337},
		},
		{
			name:      "PATH_CHALLENGE",
			frameType: FrameTypePathChallenge,
			frame:     &PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		{
			name:      "PATH_RESPONSE",
			frameType: FrameTypePathResponse,
			frame:     &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		{
			name:      "CONNECTION_CLOSE",
			frameType: FrameTypeConnectionClose,
			frame:     &ConnectionCloseFrame{IsApplicationError: false, ReasonPhrase: "foobar"},
		},
		{
			name:      "APPLICATION_CLOSE",
			frameType: FrameTypeApplicationClose,
			frame:     &ConnectionCloseFrame{IsApplicationError: true, ReasonPhrase: "foobar"},
		},
		{
			name:      "HANDSHAKE_DONE",
			frameType: FrameTypeHandshakeDone,
			frame:     &HandshakeDoneFrame{},
		},
		{
			name:      "RESET_STREAM_AT",
			frameType: FrameTypeResetStreamAt,
			frame:     &ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdeadbeef, IsResetStreamAt: true},
		},
		{
			name:      "ACK_FREQUENCY",
			frameType: FrameTypeAckFrequency,
			frame: &AckFrequencyFrame{
				SequenceNumber:        0x1337,
				AckElicitingThreshold: 0x42,
				RequestMaxAckDelay:    123 * time.Second,
				ReorderingThreshold:   0xcafe,
			},
		},
		{
			name:      "IMMEDIATE_ACK",
			frameType: FrameTypeImmediateAck,
			frame:     &ImmediateAckFrame{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parser := NewFrameParser(true, true, true)
			b, err := test.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)

			frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
			require.NoError(t, err)
			require.Equal(t, test.frameType, frameType)
			require.Equal(t, quicvarint.Len(uint64(test.frameType)), l)

			frame, l, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, test.frame, frame)
			require.Equal(t, len(b)-quicvarint.Len(uint64(test.frameType)), l)
		})
	}
}

func TestFrameAllowedAtEncLevel(t *testing.T) {
	type testCase struct {
		name             string
		frameType        FrameType
		frame            Frame
		allowedInitial   bool
		allowedHandshake bool
		allowedZeroRTT   bool
		allowedOneRTT    bool
	}

	for _, tc := range []testCase{
		{
			name:             "CRYPTO_FRAME",
			frameType:        FrameTypeCrypto,
			frame:            &CryptoFrame{Offset: 0, Data: []byte("foo")},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "ACK_FRAME",
			frameType:        FrameTypeAck,
			frame:            &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 1}}},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "CONNECTION_CLOSE_FRAME",
			frameType:        FrameTypeConnectionClose,
			frame:            &ConnectionCloseFrame{IsApplicationError: false, ReasonPhrase: "err"},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "PING_FRAME",
			frameType:        FrameTypePing,
			frame:            &PingFrame{},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
		{
			name:             "NEW_TOKEN_FRAME",
			frameType:        FrameTypeNewToken,
			frame:            &NewTokenFrame{Token: []byte("tok")},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "PATH_RESPONSE_FRAME",
			frameType:        FrameTypePathResponse,
			frame:            &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "RETIRE_CONNECTION_ID_FRAME",
			frameType:        FrameTypeRetireConnectionID,
			frame:            &RetireConnectionIDFrame{SequenceNumber: 1},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "MAX_DATA_FRAME",
			frameType:        FrameTypeMaxData,
			frame:            &MaxDataFrame{MaximumData: 1},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
		{
			name:             "STREAM_FRAME",
			frameType:        FrameType(0x8),
			frame:            &StreamFrame{StreamID: 1, Data: []byte("foobar")},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
		{
			name:             "RESET_STREAM_AT",
			frameType:        FrameTypeResetStreamAt,
			frame:            &ResetStreamFrame{StreamID: 1, FinalSize: 1, ReliableSize: 1},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
	} {
		for _, encLevel := range []protocol.EncryptionLevel{
			protocol.EncryptionInitial,
			protocol.EncryptionHandshake,
			protocol.Encryption0RTT,
			protocol.Encryption1RTT,
		} {
			t.Run(fmt.Sprintf("%s/%v", tc.name, encLevel), func(t *testing.T) {
				var allowed bool
				switch encLevel {
				case protocol.EncryptionInitial:
					allowed = tc.allowedInitial
				case protocol.EncryptionHandshake:
					allowed = tc.allowedHandshake
				case protocol.Encryption0RTT:
					allowed = tc.allowedZeroRTT
				case protocol.Encryption1RTT:
					allowed = tc.allowedOneRTT
				}

				parser := NewFrameParser(true, true, true)
				b, err := tc.frame.Append(nil, protocol.Version1)
				require.NoError(t, err)
				frameType, _, err := parser.ParseType(b, encLevel)
				if allowed {
					require.NoError(t, err)
					require.Equal(t, tc.frameType, frameType)
				} else {
					var transportErr *qerr.TransportError
					require.ErrorAs(t, err, &transportErr)
					require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
				}
			})
		}
	}
}

type multipathTestFrame struct {
	name      string
	frameType FrameType
	frame     Frame
}

// multipathTestFrames returns one frame of every frame type of the multipath extension.
func multipathTestFrames() []multipathTestFrame {
	return []multipathTestFrame{
		{
			name:      "PATH_ACK",
			frameType: FrameTypePathAck,
			frame:     &AckFrame{AckRanges: []AckRange{{Smallest: 10, Largest: 20}}, PathID: 3, HasPathID: true},
		},
		{
			name:      "PATH_ACK with ECN",
			frameType: FrameTypePathAckECN,
			frame:     &AckFrame{AckRanges: []AckRange{{Smallest: 10, Largest: 20}}, ECT0: 1, PathID: 3, HasPathID: true},
		},
		{
			name:      "PATH_ABANDON",
			frameType: FrameTypePathAbandon,
			frame:     &PathAbandonFrame{PathID: 1, ErrorCode: 0x3e},
		},
		{
			name:      "PATH_STATUS_BACKUP",
			frameType: FrameTypePathStatusBackup,
			frame:     &PathStatusFrame{PathID: 2, SequenceNumber: 3, Backup: true},
		},
		{
			name:      "PATH_STATUS_AVAILABLE",
			frameType: FrameTypePathStatusAvailable,
			frame:     &PathStatusFrame{PathID: 2, SequenceNumber: 4},
		},
		{
			name:      "PATH_NEW_CONNECTION_ID",
			frameType: FrameTypePathNewConnectionID,
			frame: &PathNewConnectionIDFrame{
				PathID:              1,
				SequenceNumber:      2,
				RetirePriorTo:       1,
				ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			},
		},
		{
			name:      "PATH_RETIRE_CONNECTION_ID",
			frameType: FrameTypePathRetireConnectionID,
			frame:     &PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 2},
		},
		{
			name:      "MAX_PATH_ID",
			frameType: FrameTypeMaxPathID,
			frame:     &MaxPathIDFrame{MaximumPathID: 7},
		},
		{
			name:      "PATHS_BLOCKED",
			frameType: FrameTypePathsBlocked,
			frame:     &PathsBlockedFrame{MaximumPathID: 7},
		},
		{
			name:      "PATH_CIDS_BLOCKED",
			frameType: FrameTypePathCIDsBlocked,
			frame:     &PathCIDsBlockedFrame{PathID: 3, NextSequenceNumber: 5},
		},
	}
}

func TestFrameParserMultipathFrames(t *testing.T) {
	encLevels := []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
		protocol.Encryption1RTT,
	}
	for _, tc := range multipathTestFrames() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.True(t, tc.frameType.IsMultipathFrameType())

			// Unless EnableMultipath was called, the frame types are unknown (section 12.4 of RFC 9000).
			for _, enableAddAddress := range []bool{false, true} {
				parser := NewFrameParser(true, true, true)
				if enableAddAddress {
					parser.EnableAddAddress()
				}
				require.False(t, parser.IsKnownFrameType(tc.frameType))
				for _, encLevel := range encLevels {
					_, _, err := parser.ParseType(b, encLevel)
					checkFrameUnsupported(t, err, uint64(tc.frameType))
				}
			}

			parser := NewFrameParser(false, false, false)
			parser.EnableMultipath()
			parser.SetAckDelayExponent(protocol.AckDelayExponent)
			require.True(t, parser.IsKnownFrameType(tc.frameType))
			// Section 4 of draft-ietf-quic-multipath: the frames are only allowed in 1-RTT packets.
			for _, encLevel := range encLevels[:3] {
				_, _, err := parser.ParseType(b, encLevel)
				var transportErr *qerr.TransportError
				require.ErrorAs(t, err, &transportErr)
				require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode, "encryption level %s", encLevel)
				require.Equal(t, uint64(tc.frameType), transportErr.FrameType)
			}

			frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
			require.NoError(t, err)
			require.Equal(t, tc.frameType, frameType)
			require.Equal(t, quicvarint.Len(uint64(tc.frameType)), l)
			var frame Frame
			var n int
			if frameType.IsPathAckFrameType() {
				require.False(t, frameType.IsAckFrameType())
				frame, n, err = parser.ParseAckFrame(frameType, b[l:], protocol.Encryption1RTT, protocol.Version1)
			} else {
				frame, n, err = parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
			}
			require.NoError(t, err)
			require.Equal(t, tc.frame, frame)
			require.Equal(t, len(b)-l, n)

			// truncated frames are a FRAME_ENCODING_ERROR
			if frameType.IsPathAckFrameType() {
				_, _, err = parser.ParseAckFrame(frameType, b[l:len(b)-1], protocol.Encryption1RTT, protocol.Version1)
			} else {
				_, _, err = parser.ParseLessCommonFrame(frameType, b[l:len(b)-1], protocol.Version1)
			}
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
			require.Equal(t, uint64(tc.frameType), transportErr.FrameType)
		})
	}
}

// Unknown frame types are passed to the extension frame handler.
// This includes the multipath frame types, unless EnableMultipath was called.
func TestFrameParserMultipathFramesAllowUnknownFrameTypes(t *testing.T) {
	for _, tc := range multipathTestFrames() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)

			parser := NewFrameParser(true, true, true)
			parser.AllowUnknownFrameTypes()
			for _, encLevel := range []protocol.EncryptionLevel{protocol.Encryption0RTT, protocol.Encryption1RTT} {
				frameType, _, err := parser.ParseType(b, encLevel)
				require.NoError(t, err)
				require.Equal(t, tc.frameType, frameType)
				require.False(t, parser.IsKnownFrameType(frameType))
			}

			parser.EnableMultipath()
			_, _, err = parser.ParseType(b, protocol.Encryption0RTT)
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
		})
	}
}

func TestFrameParserEnableAddAddress(t *testing.T) {
	f := &AddAddressFrame{AddressID: 1, SequenceNumber: 2, IPVersion: 4, Address: []byte{192, 0, 2, 1}, Port: 4433}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	// the multipath extension doesn't enable ADD_ADDRESS
	parser := NewFrameParser(true, true, true)
	parser.EnableMultipath()
	require.False(t, parser.IsKnownFrameType(FrameTypeAddAddress))
	_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
	checkFrameUnsupported(t, err, uint64(FrameTypeAddAddress))

	parser = NewFrameParser(true, true, true)
	parser.EnableAddAddress()
	require.True(t, parser.IsKnownFrameType(FrameTypeAddAddress))
	// Like the frames of the multipath extension, ADD_ADDRESS frames are only allowed in 1-RTT packets.
	// In particular, they are never accepted in 0-RTT packets, which can be replayed.
	for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
		_, _, err := parser.ParseType(b, encLevel)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode, "encryption level %s", encLevel)
		require.Equal(t, uint64(FrameTypeAddAddress), transportErr.FrameType)
	}
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAddAddress, frameType)
	frame, n, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l+n)
}

func TestFrameParserEnableObservedAddress(t *testing.T) {
	frames := []*ObservedAddressFrame{
		{SequenceNumber: 1, Address: netip.MustParseAddrPort("192.0.2.1:443")},
		{SequenceNumber: 2, Address: netip.MustParseAddrPort("[2001:db8::1]:4433")},
	}
	for _, f := range frames {
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		typ, _, err := quicvarint.Parse(b)
		require.NoError(t, err)
		frameType := FrameType(typ)

		// Unless EnableObservedAddress was called, the frame types are unknown (section 12.4 of RFC 9000).
		parser := NewFrameParser(true, true, true)
		parser.EnableMultipath()
		parser.EnableAddAddress()
		require.False(t, parser.IsKnownFrameType(frameType))
		_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
		checkFrameUnsupported(t, err, typ)

		parser = NewFrameParser(false, false, false)
		parser.EnableObservedAddress()
		require.True(t, parser.IsKnownFrameType(frameType))
		// Section 4.1 of draft-ietf-quic-address-discovery-01:
		// The frame is only allowed in the application data packet number space.
		for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
			_, _, err := parser.ParseType(b, encLevel)
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode, "encryption level %s", encLevel)
			require.Equal(t, typ, transportErr.FrameType)
		}
		for _, encLevel := range []protocol.EncryptionLevel{protocol.Encryption0RTT, protocol.Encryption1RTT} {
			ft, l, err := parser.ParseType(b, encLevel)
			require.NoError(t, err)
			require.Equal(t, frameType, ft)
			frame, n, err := parser.ParseLessCommonFrame(ft, b[l:], protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, f, frame)
			require.Equal(t, len(b), l+n)

			// truncated frames are a FRAME_ENCODING_ERROR
			_, _, err = parser.ParseLessCommonFrame(ft, b[l:len(b)-1], protocol.Version1)
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
			require.Equal(t, typ, transportErr.FrameType)
		}
	}
}

// The FrameParser reuses the same AckFrame for ACK and PATH_ACK frames.
func TestFrameParserReusesAckFrameForPathAck(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	parser.EnableMultipath()
	b, err := (&AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 5}}, PathID: 42, HasPathID: true}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	b, err = (&AckFrame{AckRanges: []AckRange{{Smallest: 3, Largest: 4}}}).Append(b, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypePathAck, frameType)
	b = b[l:]
	ack, l, err := parser.ParseAckFrame(frameType, b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.True(t, ack.HasPathID)
	require.Equal(t, protocol.PathID(42), ack.PathID)
	b = b[l:]

	frameType, l, err = parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAck, frameType)
	b = b[l:]
	ack, l, err = parser.ParseAckFrame(frameType, b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.False(t, ack.HasPathID)
	require.Zero(t, ack.PathID)
	require.Equal(t, []AckRange{{Smallest: 3, Largest: 4}}, ack.AckRanges)
	require.Equal(t, len(b), l)
}

// Like ACK frames, PATH_ACK frames are parsed by ParseAckFrame.
func TestFrameParserPathAckNotParsedAsLessCommonFrame(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	parser.EnableMultipath()
	b, err := (&AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 5}}, PathID: 1, HasPathID: true}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, err = parser.ParseLessCommonFrame(FrameTypePathAck, b[1:], protocol.Version1)
	checkFrameUnsupported(t, err, uint64(FrameTypePathAck))
}

func TestFrameParserDatagramFrame(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	f := &DatagramFrame{
		Data: []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeDatagramNoLength, frameType)
	require.Equal(t, 1, l)

	// ParseLessCommonFrame should not be used to handle DATAGRAM frames
	_, _, err = parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
	require.Error(t, err)

	// parseDatagramFrame should be used for this type
	datagramFrame, l, err := parser.ParseDatagramFrame(frameType, b[l:], protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &DatagramFrame{}, datagramFrame)
	require.Equal(t, 6, l)
	require.Equal(t, f.Data, datagramFrame.Data)
}

// DATAGRAM frames received without having advertised support are a PROTOCOL_VIOLATION (section 3 of RFC 9221),
// also if unknown frame types are handed to an extension frame handler.
func TestFrameParserDatagramUnsupported(t *testing.T) {
	for _, allowUnknown := range []bool{false, true} {
		parser := NewFrameParser(false, true, true)
		if allowUnknown {
			parser.AllowUnknownFrameTypes()
		}
		for _, dataLenPresent := range []bool{false, true} {
			f := &DatagramFrame{Data: []byte("foobar"), DataLenPresent: dataLenPresent}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)

			_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
			require.Equal(t, uint64(b[0]), transportErr.FrameType)
		}
	}
}

func TestFrameParserResetStreamAtUnsupported(t *testing.T) {
	parser := NewFrameParser(true, false, true)
	f := &ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdeadbeef}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
	checkFrameUnsupported(t, err, uint64(FrameTypeResetStreamAt))
}

func TestFrameParserAckFrequencyUnsupported(t *testing.T) {
	parser := NewFrameParser(true, true, false)

	t.Run("ACK_FREQUENCY", func(t *testing.T) {
		f := &AckFrequencyFrame{
			SequenceNumber:        1337,
			AckElicitingThreshold: 42,
			RequestMaxAckDelay:    42 * time.Millisecond,
			ReorderingThreshold:   1234,
		}
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
		checkFrameUnsupported(t, err, uint64(FrameTypeAckFrequency))
	})

	t.Run("IMMEDIATE_ACK", func(t *testing.T) {
		f := &ImmediateAckFrame{}
		b, err := f.Append(nil, protocol.Version1)
		require.NoError(t, err)
		_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
		checkFrameUnsupported(t, err, uint64(FrameTypeImmediateAck))
	})
}

func TestFrameParserInvalidFrameType(t *testing.T) {
	parser := NewFrameParser(true, true, true)

	_, l, err := parser.ParseType(encodeVarInt(0x42), protocol.Encryption1RTT)

	require.Equal(t, 2, l)

	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
}

func TestFrameParserAllowsUnknownFrameTypes(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	parser.AllowUnknownFrameTypes()

	require.False(t, parser.IsKnownFrameType(FrameType(0x42)))
	frameType, l, err := parser.ParseType(encodeVarInt(0x42), protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameType(0x42), frameType)
	require.Equal(t, 2, l)
}

func TestFrameParsingErrorsOnInvalidFrames(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	f := &MaxStreamDataFrame{
		StreamID:          0x1337,
		MaximumStreamData: 0xdeadbeef,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b[:len(b)-2], protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeMaxStreamData, frameType)
	require.Equal(t, 1, l)

	_, _, err = parser.ParseLessCommonFrame(frameType, b[1:len(b)-2], protocol.Version1)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
}

func writeFrames(tb testing.TB, frames ...Frame) []byte {
	var b []byte
	for _, f := range frames {
		var err error
		b, err = f.Append(b, protocol.Version1)
		require.NoError(tb, err)
	}
	return b
}

// This function is used in benchmarks, and also to ensure zero allocation for STREAM frame parsing.
// We can therefore not use the require framework, as it allocates.
func parseFrames(tb testing.TB, parser *FrameParser, data []byte, frames ...Frame) {
	for _, expectedFrame := range frames {
		frameType, l, err := parser.ParseType(data, protocol.Encryption1RTT)
		if err != nil {
			tb.Fatal(err)
		}
		data = data[l:]

		if frameType.IsStreamFrameType() {
			sf := expectedFrame.(*StreamFrame)
			frame, l, err := ParseStreamFrame(data, frameType, protocol.Version1)
			if err != nil {
				tb.Fatal(err)
			}
			if sf.StreamID != frame.StreamID || sf.Offset != frame.Offset {
				tb.Fatalf("STREAM frame does not match: %v vs %v", sf, frame)
			}
			frame.PutBack()
			data = data[l:]
			continue
		}

		if frameType.IsAckFrameType() || frameType.IsPathAckFrameType() {
			af, ok := expectedFrame.(*AckFrame)
			if !ok {
				tb.Fatalf("expected ACK, but got %v", expectedFrame)
			}

			f, l, err := parser.ParseAckFrame(frameType, data, protocol.Encryption1RTT, protocol.Version1)
			if f.DelayTime != af.DelayTime || f.ECNCE != af.ECNCE || f.ECT0 != af.ECT0 || f.ECT1 != af.ECT1 {
				tb.Fatal(err)
			}
			if f.HasPathID != af.HasPathID || f.PathID != af.PathID {
				tb.Fatalf("ACK frame path ID does not match: %v vs %v", af, f)
			}
			if f.DelayTime != af.DelayTime {
				tb.Fatalf("ACK frame does not match: %v vs %v", af, f)
			}
			if !slices.Equal(f.AckRanges, af.AckRanges) {
				tb.Fatalf("ACK frame ACK ranges don't match: %v vs %v", af, f)
			}
			data = data[l:]
			continue
		}

		if frameType.IsDatagramFrameType() {
			df, ok := expectedFrame.(*DatagramFrame)
			if !ok {
				tb.Fatalf("expected DATAGRAM, but got %v", expectedFrame)
			}

			f, l, err := parser.ParseDatagramFrame(frameType, data, protocol.Version1)
			if err != nil {
				tb.Fatal(err)
			}
			if df.DataLenPresent != f.DataLenPresent || !bytes.Equal(df.Data, f.Data) {
				tb.Fatalf("DATAGRAM frame does not match: %v vs %v", df, f)
			}
			data = data[l:]
			continue
		}

		f, l, err := parser.ParseLessCommonFrame(frameType, data, protocol.Version1)
		if err != nil {
			tb.Fatal(err)
		}
		data = data[l:]

		switch frameType {
		case FrameTypeMaxData:
			mdf, ok := expectedFrame.(*MaxDataFrame)
			if !ok {
				tb.Fatalf("expected MAX_DATA, but got %v", expectedFrame)
			}
			if *f.(*MaxDataFrame) != *mdf {
				tb.Fatalf("MAX_DATA frame does not match: %v vs %v", f, mdf)
			}
		case FrameTypeUniMaxStreams:
			msf, ok := expectedFrame.(*MaxStreamsFrame)
			if !ok {
				tb.Fatalf("expected MAX_STREAMS, but got %v", expectedFrame)
			}
			if *f.(*MaxStreamsFrame) != *msf {
				tb.Fatalf("MAX_STREAMS frame does not match: %v vs %v", f, msf)
			}
		case FrameTypeMaxStreamData:
			mdf, ok := expectedFrame.(*MaxStreamDataFrame)
			if !ok {
				tb.Fatalf("expected MAX_STREAM_DATA, but got %v", expectedFrame)
			}
			if *f.(*MaxStreamDataFrame) != *mdf {
				tb.Fatalf("MAX_STREAM_DATA frame does not match: %v vs %v", f, mdf)
			}
		case FrameTypeCrypto:
			cf, ok := expectedFrame.(*CryptoFrame)
			if !ok {
				tb.Fatalf("expected CRYPTO, but got %v", expectedFrame)
			}
			frame := f.(*CryptoFrame)
			if frame.Offset != cf.Offset || !bytes.Equal(frame.Data, cf.Data) {
				tb.Fatalf("CRYPTO frame does not match: %v vs %v", f, cf)
			}
		case FrameTypePing:
			_ = f.(*PingFrame)
		case FrameTypeResetStream:
			rsf, ok := expectedFrame.(*ResetStreamFrame)
			if !ok {
				tb.Fatalf("expected RESET_STREAM, but got %v", expectedFrame)
			}
			if *f.(*ResetStreamFrame) != *rsf {
				tb.Fatalf("RESET_STREAM frame does not match: %v vs %v", f, rsf)
			}
			continue
		default:
			tb.Fatalf("Frame type not supported in benchmark or should not occur: %v", frameType)
		}
	}
}

func TestFrameParserAllocs(t *testing.T) {
	t.Run("STREAM", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			frames = append(frames, &StreamFrame{
				StreamID:       protocol.StreamID(1337 + i),
				Offset:         protocol.ByteCount(1e7 + i),
				Data:           make([]byte, 200+i),
				DataLenPresent: true,
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})

	t.Run("ACK", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			frames = append(frames, &AckFrame{
				AckRanges: []AckRange{
					{Smallest: protocol.PacketNumber(5000 + i), Largest: protocol.PacketNumber(5200 + i)},
					{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)},
				},
				DelayTime: time.Duration(int64(time.Millisecond) * int64(i)),
				ECT0:      uint64(5000 + i),
				ECT1:      uint64(i),
				ECNCE:     uint64(10 + i),
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})

	t.Run("PATH_ACK", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			f := &AckFrame{
				AckRanges: []AckRange{
					{Smallest: protocol.PacketNumber(5000 + i), Largest: protocol.PacketNumber(5200 + i)},
					{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)},
				},
				DelayTime: time.Duration(int64(time.Millisecond) * int64(i)),
				PathID:    protocol.PathID(i),
				HasPathID: true,
			}
			if i%2 == 0 {
				f.ECT0 = uint64(5000 + i)
				f.ECT1 = uint64(i)
				f.ECNCE = uint64(10 + i)
			}
			frames = append(frames, f)
			// ACK frames after PATH_ACK frames, using the same AckFrame of the FrameParser
			frames = append(frames, &AckFrame{
				AckRanges: []AckRange{{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)}},
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})
}

func testFrameParserAllocs(t *testing.T, frames []Frame) float64 {
	buf := writeFrames(t, frames...)
	parser := NewFrameParser(true, true, true)
	parser.EnableMultipath()
	parser.SetAckDelayExponent(3)

	return testing.AllocsPerRun(100, func() {
		parseFrames(t, parser, buf, frames...)
	})
}

func BenchmarkParseOtherFrames(b *testing.B) {
	frames := []Frame{
		&MaxDataFrame{MaximumData: 123456},
		&MaxStreamsFrame{MaxStreamNum: 10},
		&MaxStreamDataFrame{StreamID: 1337, MaximumStreamData: 1e6},
		&CryptoFrame{Offset: 1000, Data: make([]byte, 128)},
		&PingFrame{},
		&ResetStreamFrame{StreamID: 87654, ErrorCode: 1234, FinalSize: 1e8},
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseAckFrame(b *testing.B) {
	var frames []Frame
	for i := range 10 {
		frames = append(frames, &AckFrame{
			AckRanges: []AckRange{
				{Smallest: protocol.PacketNumber(5000 + i), Largest: protocol.PacketNumber(5200 + i)},
				{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)},
			},
			DelayTime: time.Duration(int64(time.Millisecond) * int64(i)),
			ECT0:      uint64(5000 + i),
			ECT1:      uint64(i),
			ECNCE:     uint64(10 + i),
		})
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseStreamFrame(b *testing.B) {
	var frames []Frame
	for i := range 10 {
		data := make([]byte, 200+i)
		rand.Read(data)
		frames = append(frames, &StreamFrame{
			StreamID:       protocol.StreamID(1337 + i),
			Offset:         protocol.ByteCount(1e7 + i),
			Data:           data,
			DataLenPresent: true,
		})
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseDatagramFrame(b *testing.B) {
	var frames []Frame
	for i := range 10 {
		data := make([]byte, 200+i)
		rand.Read(data)
		frames = append(frames, &DatagramFrame{
			Data:           data,
			DataLenPresent: true,
		})
	}
	benchmarkFrames(b, frames...)
}

func benchmarkFrames(b *testing.B, frames ...Frame) {
	b.ReportAllocs()

	buf := writeFrames(b, frames...)
	parser := NewFrameParser(true, true, true)
	parser.SetAckDelayExponent(3)

	for b.Loop() {
		parseFrames(b, parser, buf, frames...)
	}
}

func FuzzFrames(f *testing.F) {
	corpus := ossfuzzseeds.New(f)

	const version = protocol.Version1

	for _, s := range []struct {
		encLevel protocol.EncryptionLevel
		frame    Frame
	}{
		{encLevel: protocol.EncryptionInitial, frame: &PingFrame{}},
		{encLevel: protocol.EncryptionHandshake, frame: &PingFrame{}},
		{encLevel: protocol.Encryption0RTT, frame: &PingFrame{}},
		{encLevel: protocol.EncryptionInitial, frame: &CryptoFrame{Offset: 42, Data: []byte("initial crypto")}},
		{encLevel: protocol.EncryptionHandshake, frame: &CryptoFrame{Offset: 123, Data: []byte("handshake crypto")}},
		{encLevel: protocol.EncryptionInitial, frame: &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 10}}}},
		{encLevel: protocol.EncryptionHandshake, frame: &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 10}}}},
		// multipath frames are only allowed in 1-RTT packets
		{encLevel: protocol.EncryptionInitial, frame: &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 10}}, PathID: 1, HasPathID: true}},
		{encLevel: protocol.EncryptionHandshake, frame: &PathAbandonFrame{PathID: 1}},
		{encLevel: protocol.Encryption0RTT, frame: &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 10}}, PathID: 1, HasPathID: true}},
		{encLevel: protocol.Encryption0RTT, frame: &MaxPathIDFrame{MaximumPathID: 3}},
	} {
		b, err := s.frame.Append(nil, version)
		require.NoError(f, err)
		corpus.Add(uint8(s.encLevel), uint16(protocol.MaxPacketBufferSize), b)
	}

	for _, fr := range []Frame{
		&PingFrame{},
		&StreamFrame{StreamID: 0x42, Fin: true},
		&StreamFrame{StreamID: 0x42, Data: []byte("foobar"), Fin: true},
		&StreamFrame{StreamID: 0x1337, Offset: 0xcafe, Data: []byte("foobar")},
		&StreamFrame{Offset: quicvarint.Max, Data: []byte("foo")}, // exceeds maximum offset
		&AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}},
		&AckFrame{
			AckRanges: []AckRange{{Smallest: 80, Largest: 100}, {Smallest: 1, Largest: 50}},
			DelayTime: time.Millisecond,
			ECT0:      42,
			ECT1:      13,
			ECNCE:     7,
		},
		&ResetStreamFrame{StreamID: 0x1337, ErrorCode: 0x42, FinalSize: 0xdead},
		&StopSendingFrame{StreamID: 0x42, ErrorCode: 0x1337},
		&CryptoFrame{Offset: 0x1337, Data: []byte("crypto data")},
		&NewTokenFrame{Token: []byte("token")},
		&MaxDataFrame{MaximumData: 0xcafe},
		&MaxStreamDataFrame{StreamID: 0xdead, MaximumStreamData: 0xbeef},
		&MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 0x42},
		&MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 0x42},
		&DataBlockedFrame{MaximumData: 0x1234},
		&StreamDataBlockedFrame{StreamID: 0xdead, MaximumStreamData: 0xbeef},
		&StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 0x42},
		&StreamsBlockedFrame{Type: protocol.StreamTypeUni, StreamLimit: 0x42},
		&NewConnectionIDFrame{
			SequenceNumber:      0x42,
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		&RetireConnectionIDFrame{SequenceNumber: 0x42},
		&PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		&PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		&ConnectionCloseFrame{ErrorCode: 0x42, ReasonPhrase: "foobar"},
		&ConnectionCloseFrame{IsApplicationError: true, ErrorCode: 0x42, ReasonPhrase: "foobar"},
		&HandshakeDoneFrame{},
		&DatagramFrame{Data: []byte("datagram")},
		&ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdead},
		&AckFrequencyFrame{
			SequenceNumber:        0x42,
			AckElicitingThreshold: 10,
			RequestMaxAckDelay:    25 * time.Millisecond,
			ReorderingThreshold:   5,
		},
		&ImmediateAckFrame{},
		&AddAddressFrame{AddressID: 1, SequenceNumber: 2, IPVersion: 4, Address: []byte{192, 0, 2, 1}, Port: 4433},
		&AddAddressFrame{AddressID: 0x1337, SequenceNumber: 0x42, IPVersion: 6, Address: []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}, Port: 443},
		&ObservedAddressFrame{SequenceNumber: 1, Address: netip.MustParseAddrPort("192.0.2.1:443")},
		&ObservedAddressFrame{SequenceNumber: quicvarint.Max, Address: netip.MustParseAddrPort("[2001:db8::1]:4433")},
		&ObservedAddressFrame{SequenceNumber: 7, Address: netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")},
		&AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}, HasPathID: true},
		&AckFrame{
			AckRanges: []AckRange{{Smallest: 80, Largest: 100}, {Smallest: 1, Largest: 50}},
			DelayTime: time.Millisecond,
			ECT0:      42,
			ECT1:      13,
			ECNCE:     7,
			PathID:    protocol.MaxPathID,
			HasPathID: true,
		},
		&AckFrame{AckRanges: []AckRange{{Smallest: 1000, Largest: 1001}}, PathID: quicvarint.Max, HasPathID: true},
		&PathAbandonFrame{PathID: 1, ErrorCode: 0x3e},
		&PathAbandonFrame{PathID: protocol.MaxPathID, ErrorCode: quicvarint.Max},
		&PathStatusFrame{PathID: 2, SequenceNumber: 3, Backup: true},
		&PathStatusFrame{PathID: quicvarint.Max, SequenceNumber: quicvarint.Max},
		&PathNewConnectionIDFrame{
			PathID:              1,
			SequenceNumber:      0x42,
			RetirePriorTo:       0x40,
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		&PathNewConnectionIDFrame{
			PathID:              protocol.MaxPathID,
			SequenceNumber:      quicvarint.Max,
			RetirePriorTo:       quicvarint.Max,
			ConnectionID:        protocol.ParseConnectionID(make([]byte, protocol.MaxConnIDLen)),
			StatelessResetToken: protocol.StatelessResetToken{15: 1},
		},
		&PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 0x42},
		&MaxPathIDFrame{MaximumPathID: 3},
		&MaxPathIDFrame{MaximumPathID: protocol.MaxPathID + 1},
		&PathsBlockedFrame{MaximumPathID: 3},
		&PathCIDsBlockedFrame{PathID: 2, NextSequenceNumber: 5},
	} {
		b, err := fr.Append(nil, version)
		require.NoError(f, err)
		maxSize := uint16(protocol.MaxPacketBufferSize)
		switch fr.(type) {
		case *StreamFrame, *DatagramFrame:
			maxSize = 256
		case *AckFrame:
			maxSize = 128
		}
		corpus.Add(uint8(protocol.Encryption1RTT), maxSize, b)
	}

	f.Fuzz(func(t *testing.T, encLevelRaw uint8, maxSize uint16, data []byte) {
		encLevel := protocol.EncryptionLevel(encLevelRaw)
		if encLevel != protocol.EncryptionInitial && encLevel != protocol.EncryptionHandshake && encLevel != protocol.Encryption1RTT && encLevel != protocol.Encryption0RTT {
			return
		}
		// maxSize is used to split off frames from the original frame (in the case of CRYPTO and STREAM frames),
		// and to truncate ACK frames.
		// This happens at the packet boundary, so values larger than the packet size are not interesting.
		if maxSize > 10_000 {
			return
		}

		parser := NewFrameParser(true, true, true)
		parser.EnableMultipath()
		parser.EnableAddAddress()
		parser.EnableObservedAddress()
		parser.SetAckDelayExponent(protocol.DefaultAckDelayExponent)

		var b []byte
		for len(data) > 0 {
			initialLen := len(data)
			frameType, l, err := parser.ParseType(data, encLevel)
			if err != nil {
				return
			}
			data = data[l:]

			var frame Frame
			switch {
			case frameType.IsStreamFrameType():
				frame, l, err = parser.ParseStreamFrame(frameType, data, version)
			case frameType.IsAckFrameType() || frameType.IsPathAckFrameType():
				frame, l, err = parser.ParseAckFrame(frameType, data, encLevel, version)
			case frameType == FrameTypeDatagramNoLength || frameType == FrameTypeDatagramWithLength:
				frame, l, err = parser.ParseDatagramFrame(frameType, data, version)
			default:
				frame, l, err = parser.ParseLessCommonFrame(frameType, data, version)
			}
			if err != nil {
				return
			}
			data = data[l:]
			if frameType.IsMultipathFrameType() && encLevel != protocol.Encryption1RTT {
				t.Fatalf("parsed frame type %#x at encryption level %s", uint64(frameType), encLevel)
			}
			if IsProbingFrame(frame) != IsProbingFrameType(frameType) {
				t.Fatalf("inconsistent probing frame classification for frame type %#x", uint64(frameType))
			}

			if sf, ok := frame.(*StreamFrame); ok {
				if sf.DataLen() == 0 {
					sf.PutBack()
					continue
				}
			}
			checkFrameInvariants(t, frame)

			if of, ok := frame.(*ObservedAddressFrame); ok && of.Address.Addr().Is4() != (frameType == FrameTypeObservedAddressIPv4) {
				t.Fatalf("OBSERVED_ADDRESS frame of type %#x contains address %s", uint64(frameType), of.Address)
			}

			startLen := len(b)
			parsedLen := initialLen - len(data)
			b, err = frame.Append(b, version)
			require.NoError(t, err)
			frameLen := protocol.ByteCount(len(b) - startLen)
			require.Equal(t, frameLen, frame.Length(version), "re-serialized frame")
			checkExtensionFrameRoundTrip(t, frameType, frame, b[startLen:], version)
			size := protocol.ByteCount(maxSize)
			switch f := frame.(type) {
			case *StreamFrame:
				orig := slices.Clone(f.Data)
				split, needsSplit := f.MaybeSplitOffFrame(size, version)
				if split != nil {
					require.LessOrEqual(t, split.Length(version), size, "split STREAM frame")
					require.Equal(t, orig, append(slices.Clone(split.Data), f.Data...), "split STREAM frame data")
					split.PutBack()
				} else {
					require.True(t, needsSplit || f.Length(version) <= size, "STREAM longer than maxSize but not split: len=%d maxSize=%d", f.Length(version), size)
				}
			case *CryptoFrame:
				orig := slices.Clone(f.Data)
				split, needsSplit := f.MaybeSplitOffFrame(size, version)
				if split != nil {
					require.LessOrEqual(t, split.Length(version), size, "split CRYPTO frame")
					require.Equal(t, orig, append(slices.Clone(split.Data), f.Data...), "split CRYPTO frame data")
				} else {
					require.True(t, needsSplit || f.Length(version) <= size, "CRYPTO longer than maxSize but not split: len=%d maxSize=%d", f.Length(version), size)
				}
			case *AckFrame:
				f.HasMissingRanges()
				// Truncate requires maxSize to fit at least one ACK range;
				// 64 bytes covers the worst case (8-byte varints, with ECN).
				if size >= 64 {
					f.Truncate(size, version)
					require.LessOrEqual(t, f.Length(version), size, "truncated ACK")
					checkFrameInvariants(t, f)
				}
			case *DatagramFrame:
				if n := f.MaxDataLen(size, version); n > 0 && protocol.ByteCount(len(f.Data)) > n {
					orig := f.Data
					f.Data = f.Data[:n]
					require.LessOrEqual(t, f.Length(version), size, "DATAGRAM with MaxDataLen")
					f.Data = orig
				}
			}
			if sf, ok := frame.(*StreamFrame); ok {
				sf.PutBack()
			}
			require.LessOrEqual(t, frameLen, protocol.ByteCount(parsedLen), "serialized length vs parsed length")
		}
	})
}

func checkFrameInvariants(t *testing.T, frame Frame) {
	t.Helper()

	switch f := frame.(type) {
	case *StreamFrame:
		if protocol.ByteCount(len(f.Data)) != f.DataLen() {
			t.Fatal("STREAM frame: inconsistent data length")
		}
	case *AckFrame:
		if f.DelayTime < 0 {
			t.Fatalf("invalid ACK delay_time: %s", f.DelayTime)
		}
		if f.LargestAcked() < f.LowestAcked() {
			t.Fatal("ACK: largest acknowledged is smaller than lowest acknowledged")
		}
		for _, r := range f.AckRanges {
			if r.Largest < 0 || r.Smallest < 0 {
				t.Fatal("ACK range contains a negative packet number")
			}
		}
		if !f.AcksPacket(f.LargestAcked()) {
			t.Fatal("ACK frame claims that largest acknowledged is not acknowledged")
		}
		if !f.AcksPacket(f.LowestAcked()) {
			t.Fatal("ACK frame claims that lowest acknowledged is not acknowledged")
		}
		_ = f.AcksPacket(100)
		_ = f.AcksPacket((f.LargestAcked() + f.LowestAcked()) / 2)
	case *NewConnectionIDFrame:
		if f.ConnectionID.Len() < 1 || f.ConnectionID.Len() > 20 {
			t.Fatalf("invalid NEW_CONNECTION_ID frame length: %s", f.ConnectionID)
		}
		if f.RetirePriorTo > f.SequenceNumber {
			t.Fatal("NEW_CONNECTION_ID frame with Retire Prior To larger than the Sequence Number")
		}
	case *PathNewConnectionIDFrame:
		if f.ConnectionID.Len() < 1 || f.ConnectionID.Len() > 20 {
			t.Fatalf("invalid PATH_NEW_CONNECTION_ID frame length: %s", f.ConnectionID)
		}
		if f.RetirePriorTo > f.SequenceNumber {
			t.Fatal("PATH_NEW_CONNECTION_ID frame with Retire Prior To larger than the Sequence Number")
		}
	case *NewTokenFrame:
		if len(f.Token) == 0 {
			t.Fatal("NEW_TOKEN frame with an empty token")
		}
	case *MaxStreamsFrame:
		if f.MaxStreamNum > protocol.MaxStreamCount {
			t.Fatal("MAX_STREAMS frame with an invalid Maximum Streams value")
		}
	case *StreamsBlockedFrame:
		if f.StreamLimit > protocol.MaxStreamCount {
			t.Fatal("STREAMS_BLOCKED frame with an invalid Maximum Streams value")
		}
	case *ConnectionCloseFrame:
		if f.IsApplicationError && f.FrameType != 0 {
			t.Fatal("CONNECTION_CLOSE for an application error containing a frame type")
		}
	case *ResetStreamFrame:
		if f.FinalSize < f.ReliableSize {
			t.Fatal("RESET_STREAM frame with a FinalSize smaller than the ReliableSize")
		}
	case *AckFrequencyFrame:
		if f.RequestMaxAckDelay < 0 {
			t.Fatal("ACK_FREQUENCY frame with a negative RequestMaxAckDelay")
		}
	case *AddAddressFrame:
		if (f.IPVersion != 4 || len(f.Address) != 4) && (f.IPVersion != 6 || len(f.Address) != 16) {
			t.Fatalf("ADD_ADDRESS frame with IP version %d and a %d byte address", f.IPVersion, len(f.Address))
		}
	case *ObservedAddressFrame:
		if !f.Address.Addr().IsValid() || f.Address.Addr().Zone() != "" {
			t.Fatalf("OBSERVED_ADDRESS frame with an invalid address: %s", f.Address)
		}
	}
}

// checkExtensionFrameRoundTrip checks that the frames of the multipath, address advertisement and
// address discovery extensions are parsed back into the same frame after serialization.
func checkExtensionFrameRoundTrip(t *testing.T, frameType FrameType, frame Frame, b []byte, v protocol.Version) {
	t.Helper()

	if !frameType.IsMultipathFrameType() && frameType != FrameTypeAddAddress && !frameType.IsObservedAddressFrameType() {
		return
	}
	// Use a separate parser: the ACK frame returned by a parser is overwritten by the next ACK frame it parses.
	parser := NewFrameParser(false, false, false)
	parser.EnableMultipath()
	parser.EnableAddAddress()
	parser.EnableObservedAddress()
	parser.SetAckDelayExponent(protocol.DefaultAckDelayExponent)
	typ, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	b = b[l:]
	var parsed Frame
	if typ.IsPathAckFrameType() {
		parsed, l, err = parser.ParseAckFrame(typ, b, protocol.Encryption1RTT, v)
	} else {
		parsed, l, err = parser.ParseLessCommonFrame(typ, b, v)
	}
	require.NoError(t, err)
	require.Equal(t, len(b), l, "re-parsed frame length")
	if af, ok := frame.(*AckFrame); ok {
		paf := parsed.(*AckFrame)
		require.True(t, paf.HasPathID, "PATH_ACK frame re-parsed without a Path ID")
		require.Equal(t, af.PathID, paf.PathID, "PATH_ACK Path ID")
		require.Equal(t, af.AckRanges, paf.AckRanges, "PATH_ACK ranges")
		require.Equal(t, [3]uint64{af.ECT0, af.ECT1, af.ECNCE}, [3]uint64{paf.ECT0, paf.ECT1, paf.ECNCE}, "PATH_ACK ECN counts")
		return
	}
	require.Equal(t, frame, parsed, "re-parsed frame")
}
