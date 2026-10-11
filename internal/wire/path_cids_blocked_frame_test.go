package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParsePathCIDsBlockedFrame(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)           // path ID
	data = append(data, encodeVarInt(1337)...) // next sequence number
	frame, l, err := parsePathCIDsBlockedFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, &PathCIDsBlockedFrame{PathID: 0xdeadbeef, NextSequenceNumber: 1337}, frame)
	require.Equal(t, len(data), l)
}

func TestParsePathCIDsBlockedErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)             // path ID
	data = append(data, encodeVarInt(0xcafe)...) // next sequence number
	_, l, err := parsePathCIDsBlockedFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathCIDsBlockedFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestWritePathCIDsBlockedFrame(t *testing.T) {
	frame := &PathCIDsBlockedFrame{PathID: 2, NextSequenceNumber: 0x1337}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x7e, 0x7c}
	expected = append(expected, encodeVarInt(2)...)
	expected = append(expected, encodeVarInt(0x1337)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}

func TestPathCIDsBlockedFrameValues(t *testing.T) {
	for _, pathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		for _, seq := range []uint64{0, uint64(protocol.MaxPathID), quicvarint.Max} {
			checkMultipathFrameRoundTrip(t, &PathCIDsBlockedFrame{PathID: pathID, NextSequenceNumber: seq})
		}
	}
}
