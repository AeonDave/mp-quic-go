package wire

import (
	"bytes"
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestAddAddressFrame(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		frame := &AddAddressFrame{
			AddressID:      1,
			SequenceNumber: 100,
			IPVersion:      4,
			Address:        []byte{192, 168, 1, 1},
			Port:           8080,
		}

		// Test Append
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Test Parse (skip frame type varint)
		_, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		parsed, n, err := parseAddAddressFrame(b[l:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(b)-l, n)
		require.Equal(t, frame.AddressID, parsed.AddressID)
		require.Equal(t, frame.SequenceNumber, parsed.SequenceNumber)
		require.Equal(t, frame.IPVersion, parsed.IPVersion)
		require.Equal(t, frame.Address, parsed.Address)
		require.Equal(t, frame.Port, parsed.Port)

		// Test GetIPAddress
		ip := parsed.GetIPAddress()
		require.True(t, ip.Equal(net.IPv4(192, 168, 1, 1)), "IP addresses should be equal")

		// Test GetUDPAddr
		udpAddr := parsed.GetUDPAddr()
		require.Equal(t, "192.168.1.1:8080", udpAddr.String())
	})

	t.Run("IPv6", func(t *testing.T) {
		ipv6Addr := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		frame := &AddAddressFrame{
			AddressID:      2,
			SequenceNumber: 200,
			IPVersion:      6,
			Address:        ipv6Addr,
			Port:           9090,
		}

		// Test Append
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Test Parse
		_, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		parsed, n, err := parseAddAddressFrame(b[l:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(b)-l, n)
		require.Equal(t, frame.AddressID, parsed.AddressID)
		require.Equal(t, frame.SequenceNumber, parsed.SequenceNumber)
		require.Equal(t, frame.IPVersion, parsed.IPVersion)
		require.True(t, bytes.Equal(frame.Address, parsed.Address))
		require.Equal(t, frame.Port, parsed.Port)
	})

	t.Run("Length", func(t *testing.T) {
		frame := &AddAddressFrame{
			AddressID:      1,
			SequenceNumber: 100,
			IPVersion:      4,
			Address:        []byte{192, 168, 1, 1},
			Port:           8080,
		}
		b, _ := frame.Append(nil, protocol.Version1)
		require.Equal(t, protocol.ByteCount(len(b)), frame.Length(protocol.Version1))
	})
}

func TestPathsFrame(t *testing.T) {
	frame := &PathsFrame{
		AvailablePaths: 3,
		ActivePaths:    2,
	}

	// Test Append
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)

	// Test Parse
	_, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	parsed, n, err := parsePathsFrame(b[l:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b)-l, n)
	require.Equal(t, frame.AvailablePaths, parsed.AvailablePaths)
	require.Equal(t, frame.ActivePaths, parsed.ActivePaths)

	// Test Length
	require.Equal(t, protocol.ByteCount(len(b)), frame.Length(protocol.Version1))
}

func TestClosePathFrame(t *testing.T) {
	t.Run("WithReason", func(t *testing.T) {
		frame := &ClosePathFrame{
			PathID:       1,
			ErrorCode:    100,
			ReasonPhrase: "Path no longer available",
		}

		// Test Append
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Test Parse
		_, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		parsed, n, err := parseClosePathFrame(b[l:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(b)-l, n)
		require.Equal(t, frame.PathID, parsed.PathID)
		require.Equal(t, frame.ErrorCode, parsed.ErrorCode)
		require.Equal(t, frame.ReasonPhrase, parsed.ReasonPhrase)

		// Test Length
		require.Equal(t, protocol.ByteCount(len(b)), frame.Length(protocol.Version1))
	})

	t.Run("WithoutReason", func(t *testing.T) {
		frame := &ClosePathFrame{
			PathID:    2,
			ErrorCode: 0,
		}

		// Test Append
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Test Parse
		_, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		parsed, n, err := parseClosePathFrame(b[l:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(b)-l, n)
		require.Equal(t, frame.PathID, parsed.PathID)
		require.Equal(t, frame.ErrorCode, parsed.ErrorCode)
		require.Equal(t, "", parsed.ReasonPhrase)
	})
}

func TestFrameParserMultipath(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	parser.EnableMultipath()

	t.Run("ADD_ADDRESS", func(t *testing.T) {
		frame := &AddAddressFrame{
			AddressID:      1,
			SequenceNumber: 100,
			IPVersion:      4,
			Address:        []byte{10, 0, 0, 1},
			Port:           4433,
		}
		b, _ := frame.Append(nil, protocol.Version1)

		// Parse type
		frameType, n, err := parser.ParseType(b, protocol.Encryption1RTT)
		require.NoError(t, err)
		require.Equal(t, FrameTypeAddAddress, frameType)

		// Parse frame
		parsed, l, err := parser.ParseLessCommonFrame(frameType, b[n:], protocol.Version1)
		require.NoError(t, err)
		require.IsType(t, &AddAddressFrame{}, parsed)
		require.Equal(t, len(b)-n, l)
	})

	t.Run("PATHS", func(t *testing.T) {
		frame := &PathsFrame{
			AvailablePaths: 2,
			ActivePaths:    1,
		}
		b, _ := frame.Append(nil, protocol.Version1)

		frameType, n, err := parser.ParseType(b, protocol.Encryption1RTT)
		require.NoError(t, err)
		require.Equal(t, FrameTypePaths, frameType)

		parsed, l, err := parser.ParseLessCommonFrame(frameType, b[n:], protocol.Version1)
		require.NoError(t, err)
		require.IsType(t, &PathsFrame{}, parsed)
		require.Equal(t, len(b)-n, l)
	})

	t.Run("CLOSE_PATH", func(t *testing.T) {
		frame := &ClosePathFrame{
			PathID:       3,
			ErrorCode:    42,
			ReasonPhrase: "timeout",
		}
		b, _ := frame.Append(nil, protocol.Version1)

		frameType, n, err := parser.ParseType(b, protocol.Encryption1RTT)
		require.NoError(t, err)
		require.Equal(t, FrameTypeClosePath, frameType)

		parsed, l, err := parser.ParseLessCommonFrame(frameType, b[n:], protocol.Version1)
		require.NoError(t, err)
		require.IsType(t, &ClosePathFrame{}, parsed)
		require.Equal(t, len(b)-n, l)
	})
}
