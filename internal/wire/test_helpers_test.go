package wire

import (
	"bytes"
	"encoding/binary"
	"log"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func encodeVarInt(i uint64) []byte {
	return quicvarint.Append(nil, i)
}

func appendVersion(data []byte, v protocol.Version) []byte {
	offset := len(data)
	data = append(data, []byte{0, 0, 0, 0}...)
	binary.BigEndian.PutUint32(data[offset:], uint32(v))
	return data
}

func setupLogTest(t *testing.T, buf *bytes.Buffer) utils.Logger {
	logger := utils.DefaultLogger
	logger.SetLogLevel(utils.LogLevelDebug)
	originalOutput := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(originalOutput) })
	return logger
}

// parseMultipathFrame parses a frame of the multipath extension, using a FrameParser that supports these frames.
// It checks that the whole frame is consumed.
func parseMultipathFrame(t *testing.T, b []byte) Frame {
	t.Helper()
	parser := NewFrameParser(false, false, false)
	parser.EnableMultipath()
	parser.SetAckDelayExponent(protocol.AckDelayExponent)
	typ, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.True(t, typ.IsMultipathFrameType())
	var frame Frame
	var n int
	if typ.IsPathAckFrameType() {
		frame, n, err = parser.ParseAckFrame(typ, b[l:], protocol.Encryption1RTT, protocol.Version1)
	} else {
		frame, n, err = parser.ParseLessCommonFrame(typ, b[l:], protocol.Version1)
	}
	require.NoError(t, err)
	require.Equal(t, len(b), l+n)
	return frame
}

// checkMultipathFrameRoundTrip appends the frame, checks its length, and parses it again.
func checkMultipathFrameRoundTrip(t *testing.T, f Frame) {
	t.Helper()
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, b, int(f.Length(protocol.Version1)))
	require.Equal(t, f, parseMultipathFrame(t, b))
}
