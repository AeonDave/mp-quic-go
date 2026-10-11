package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseMaxPathIDFrame(t *testing.T) {
	data := encodeVarInt(0xdecafbad)
	frame, l, err := parseMaxPathIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PathID(0xdecafbad), frame.MaximumPathID)
	require.Equal(t, len(data), l)
}

// Values larger than the maximum path ID are rejected when handling the frame,
// since they are a PROTOCOL_VIOLATION, not a FRAME_ENCODING_ERROR.
func TestParseMaxPathIDFrameLargerThanMaxPathID(t *testing.T) {
	data := encodeVarInt(uint64(protocol.MaxPathID) + 1)
	frame, l, err := parseMaxPathIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.MaxPathID+1, frame.MaximumPathID)
	require.Equal(t, len(data), l)
}

func TestParseMaxPathIDErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeefcafe13)
	_, l, err := parseMaxPathIDFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parseMaxPathIDFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestWriteMaxPathIDFrame(t *testing.T) {
	frame := &MaxPathIDFrame{MaximumPathID: 0xdeadbeef}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x7e, 0x7a}
	expected = append(expected, encodeVarInt(0xdeadbeef)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}

func TestMaxPathIDFrameValues(t *testing.T) {
	for _, maxPathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		checkMultipathFrameRoundTrip(t, &MaxPathIDFrame{MaximumPathID: maxPathID})
	}
}
