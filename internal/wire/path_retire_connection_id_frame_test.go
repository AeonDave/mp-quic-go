package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParsePathRetireConnectionID(t *testing.T) {
	data := encodeVarInt(0x42)                       // path ID
	data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
	frame, l, err := parsePathRetireConnectionIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PathID(0x42), frame.PathID)
	require.Equal(t, uint64(0xdeadbeef), frame.SequenceNumber)
	require.Equal(t, len(data), l)
}

func TestParsePathRetireConnectionIDErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xcafe)                     // path ID
	data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
	_, l, err := parsePathRetireConnectionIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathRetireConnectionIDFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestWritePathRetireConnectionID(t *testing.T) {
	frame := &PathRetireConnectionIDFrame{PathID: 5, SequenceNumber: 0x1337}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x7e, 0x79}
	expected = append(expected, encodeVarInt(5)...)
	expected = append(expected, encodeVarInt(0x1337)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}

func TestPathRetireConnectionIDFrameValues(t *testing.T) {
	for _, pathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		for _, seq := range []uint64{0, uint64(protocol.MaxPathID), quicvarint.Max} {
			checkMultipathFrameRoundTrip(t, &PathRetireConnectionIDFrame{PathID: pathID, SequenceNumber: seq})
		}
	}
}
