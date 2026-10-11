package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParsePathsBlockedFrame(t *testing.T) {
	data := encodeVarInt(0xdecafbad)
	frame, l, err := parsePathsBlockedFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PathID(0xdecafbad), frame.MaximumPathID)
	require.Equal(t, len(data), l)
}

func TestParsePathsBlockedErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeefcafe13)
	_, l, err := parsePathsBlockedFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathsBlockedFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestWritePathsBlockedFrame(t *testing.T) {
	frame := &PathsBlockedFrame{MaximumPathID: 0x1337}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x7e, 0x7b}
	expected = append(expected, encodeVarInt(0x1337)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}

func TestPathsBlockedFrameValues(t *testing.T) {
	for _, maxPathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		checkMultipathFrameRoundTrip(t, &PathsBlockedFrame{MaximumPathID: maxPathID})
	}
}
