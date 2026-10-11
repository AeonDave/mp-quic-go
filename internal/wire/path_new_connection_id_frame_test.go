package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParsePathNewConnectionIDFrame(t *testing.T) {
	data := encodeVarInt(0x42)                                    // path ID
	data = append(data, encodeVarInt(0xdeadbeef)...)              // sequence number
	data = append(data, encodeVarInt(0xcafe)...)                  // retire prior to
	data = append(data, 10)                                       // connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // connection ID
	data = append(data, []byte("deadbeefdecafbad")...)            // stateless reset token
	frame, l, err := parsePathNewConnectionIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PathID(0x42), frame.PathID)
	require.Equal(t, uint64(0xdeadbeef), frame.SequenceNumber)
	require.Equal(t, uint64(0xcafe), frame.RetirePriorTo)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), frame.ConnectionID)
	require.Equal(t, "deadbeefdecafbad", string(frame.StatelessResetToken[:]))
	require.Equal(t, len(data), l)
}

func TestParsePathNewConnectionIDRetirePriorToLargerThanSequenceNumber(t *testing.T) {
	data := encodeVarInt(1)                    // path ID
	data = append(data, encodeVarInt(1000)...) // sequence number
	data = append(data, encodeVarInt(1001)...) // retire prior to
	data = append(data, 3)
	data = append(data, []byte{1, 2, 3}...)
	data = append(data, []byte("deadbeefdecafbad")...) // stateless reset token
	_, _, err := parsePathNewConnectionIDFrame(data, protocol.Version1)
	require.EqualError(t, err, "Retire Prior To value (1001) larger than Sequence Number (1000)")
}

func TestParsePathNewConnectionIDZeroLengthConnID(t *testing.T) {
	data := encodeVarInt(1)                  // path ID
	data = append(data, encodeVarInt(42)...) // sequence number
	data = append(data, encodeVarInt(12)...) // retire prior to
	data = append(data, 0)                   // connection ID length
	_, _, err := parsePathNewConnectionIDFrame(data, protocol.Version1)
	require.EqualError(t, err, "invalid zero-length connection ID")
}

func TestParsePathNewConnectionIDInvalidConnIDLength(t *testing.T) {
	data := encodeVarInt(1)                                                                                   // path ID
	data = append(data, encodeVarInt(0xdeadbeef)...)                                                          // sequence number
	data = append(data, encodeVarInt(0xcafe)...)                                                              // retire prior to
	data = append(data, 21)                                                                                   // connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}...) // connection ID
	data = append(data, []byte("deadbeefdecafbad")...)                                                        // stateless reset token
	_, _, err := parsePathNewConnectionIDFrame(data, protocol.Version1)
	require.ErrorIs(t, err, protocol.ErrInvalidConnectionIDLen)
}

// The FrameParser turns these errors into a FRAME_ENCODING_ERROR (section 19.15 of RFC 9000).
func TestParsePathNewConnectionIDFrameEncodingErrors(t *testing.T) {
	parser := NewFrameParser(false, false, false)
	parser.EnableMultipath()
	for _, tc := range []struct {
		name          string
		seq, rpt      uint64
		connIDLen     int
		expectedError string
	}{
		{name: "Retire Prior To larger than Sequence Number", seq: 5, rpt: 6, connIDLen: 4, expectedError: "Retire Prior To value (6) larger than Sequence Number (5)"},
		{name: "zero-length connection ID", seq: 5, rpt: 5, connIDLen: 0, expectedError: "invalid zero-length connection ID"},
		{name: "connection ID too long", seq: 5, rpt: 5, connIDLen: 21, expectedError: protocol.ErrInvalidConnectionIDLen.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := encodeVarInt(1)                      // path ID
			data = append(data, encodeVarInt(tc.seq)...) // sequence number
			data = append(data, encodeVarInt(tc.rpt)...) // retire prior to
			data = append(data, byte(tc.connIDLen))
			data = append(data, make([]byte, tc.connIDLen)...)
			data = append(data, []byte("deadbeefdecafbad")...) // stateless reset token
			_, _, err := parser.ParseLessCommonFrame(FrameTypePathNewConnectionID, data, protocol.Version1)
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
			require.Equal(t, uint64(FrameTypePathNewConnectionID), transportErr.FrameType)
			require.Equal(t, tc.expectedError, transportErr.ErrorMessage)
		})
	}
}

func TestParsePathNewConnectionIDErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0x1234)                                  // path ID
	data = append(data, encodeVarInt(0xdeadbeef)...)              // sequence number
	data = append(data, encodeVarInt(0xcafe1234)...)              // retire prior to
	data = append(data, 10)                                       // connection ID length
	data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // connection ID
	data = append(data, []byte("deadbeefdecafbad")...)            // stateless reset token
	_, l, err := parsePathNewConnectionIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathNewConnectionIDFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestWritePathNewConnectionIDFrame(t *testing.T) {
	token := protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	frame := &PathNewConnectionIDFrame{
		PathID:              3,
		SequenceNumber:      0x1337,
		RetirePriorTo:       0x42,
		ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6}),
		StatelessResetToken: token,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x7e, 0x78}
	expected = append(expected, encodeVarInt(3)...)
	expected = append(expected, encodeVarInt(0x1337)...)
	expected = append(expected, encodeVarInt(0x42)...)
	expected = append(expected, 6)
	expected = append(expected, []byte{1, 2, 3, 4, 5, 6}...)
	expected = append(expected, token[:]...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}

func TestPathNewConnectionIDFrameValues(t *testing.T) {
	token := protocol.StatelessResetToken{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	for _, pathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		for _, seq := range []uint64{0, uint64(protocol.MaxPathID), quicvarint.Max} {
			for _, connIDLen := range []int{1, 8, protocol.MaxConnIDLen} {
				connID := make([]byte, connIDLen)
				for i := range connID {
					connID[i] = byte(i + 1)
				}
				checkMultipathFrameRoundTrip(t, &PathNewConnectionIDFrame{
					PathID:              pathID,
					SequenceNumber:      seq,
					RetirePriorTo:       seq,
					ConnectionID:        protocol.ParseConnectionID(connID),
					StatelessResetToken: token,
				})
				checkMultipathFrameRoundTrip(t, &PathNewConnectionIDFrame{
					PathID:              pathID,
					SequenceNumber:      seq,
					ConnectionID:        protocol.ParseConnectionID(connID),
					StatelessResetToken: token,
				})
			}
		}
	}
}
