package wire

import (
	"io"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParsePathStatusFrame(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)             // path ID
	data = append(data, encodeVarInt(0xcafe)...) // sequence number

	t.Run("PATH_STATUS_BACKUP", func(t *testing.T) {
		frame, l, err := parsePathStatusFrame(data, FrameTypePathStatusBackup, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, &PathStatusFrame{PathID: 0xdeadbeef, SequenceNumber: 0xcafe, Backup: true}, frame)
		require.Equal(t, len(data), l)
	})

	t.Run("PATH_STATUS_AVAILABLE", func(t *testing.T) {
		frame, l, err := parsePathStatusFrame(data, FrameTypePathStatusAvailable, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, &PathStatusFrame{PathID: 0xdeadbeef, SequenceNumber: 0xcafe}, frame)
		require.Equal(t, len(data), l)
	})
}

func TestParsePathStatusErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef)                 // path ID
	data = append(data, encodeVarInt(0xdecafbad)...) // sequence number
	for _, typ := range []FrameType{FrameTypePathStatusBackup, FrameTypePathStatusAvailable} {
		_, l, err := parsePathStatusFrame(data, typ, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(data), l)
		for i := range data {
			_, _, err := parsePathStatusFrame(data[:i], typ, protocol.Version1)
			require.ErrorIs(t, err, io.EOF)
		}
	}
}

func TestWritePathStatusFrame(t *testing.T) {
	t.Run("PATH_STATUS_BACKUP", func(t *testing.T) {
		frame := &PathStatusFrame{PathID: 0x1337, SequenceNumber: 42, Backup: true}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		expected := []byte{0x7e, 0x76}
		expected = append(expected, encodeVarInt(0x1337)...)
		expected = append(expected, encodeVarInt(42)...)
		require.Equal(t, expected, b)
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})

	t.Run("PATH_STATUS_AVAILABLE", func(t *testing.T) {
		frame := &PathStatusFrame{PathID: 0x1337, SequenceNumber: 42}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		expected := []byte{0x7e, 0x77}
		expected = append(expected, encodeVarInt(0x1337)...)
		expected = append(expected, encodeVarInt(42)...)
		require.Equal(t, expected, b)
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})
}

func TestPathStatusFrameValues(t *testing.T) {
	for _, pathID := range []protocol.PathID{0, protocol.MaxPathID, quicvarint.Max} {
		for _, seq := range []uint64{0, uint64(protocol.MaxPathID), quicvarint.Max} {
			checkMultipathFrameRoundTrip(t, &PathStatusFrame{PathID: pathID, SequenceNumber: seq, Backup: true})
			checkMultipathFrameRoundTrip(t, &PathStatusFrame{PathID: pathID, SequenceNumber: seq})
		}
	}
}
