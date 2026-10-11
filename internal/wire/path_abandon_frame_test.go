package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParsePathAbandonFrame(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)             // path ID
	data = append(data, encodeVarInt(0x3e76)...) // error code
	frame, l, err := parsePathAbandonFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PathID(0xdeadbeef), frame.PathID)
	require.Equal(t, qerr.PathUnstableOrPoor, frame.ErrorCode)
	require.Equal(t, len(data), l)
}

func TestParsePathAbandonErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                 // path ID
	data = append(data, encodeVarInt(0xdecafbad)...) // error code
	_, l, err := parsePathAbandonFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, _, err := parsePathAbandonFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestWritePathAbandonFrame(t *testing.T) {
	frame := &PathAbandonFrame{PathID: 0x1337, ErrorCode: qerr.ApplicationAbandonPath}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{0x7e, 0x75}
	expected = append(expected, encodeVarInt(0x1337)...)
	expected = append(expected, encodeVarInt(0x3e)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}

func TestPathAbandonFrameValues(t *testing.T) {
	for _, pathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		for _, errorCode := range []qerr.TransportErrorCode{qerr.NoError, qerr.NoCIDAvailableForPath, quicvarint.Max} {
			checkMultipathFrameRoundTrip(t, &PathAbandonFrame{PathID: pathID, ErrorCode: errorCode})
		}
	}
}
