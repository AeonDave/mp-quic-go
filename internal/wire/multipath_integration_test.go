package wire

import (
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// TestMultipathFramesParsing tests the complete multipath frame implementation:
// - Multipath frames (ADD_ADDRESS, PATHS, CLOSE_PATH)
// - Frame parser integration
// - EnableMultipath functionality
func TestMultipathFramesParsing(t *testing.T) {
	t.Run("FrameParserMultipathToggle", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)

		// Create a complete ADD_ADDRESS frame for testing
		testFrame := &AddAddressFrame{
			AddressID:      1,
			SequenceNumber: 0,
			IPVersion:      4,
			Address:        net.ParseIP("192.168.1.1").To4(),
			Port:           8080,
		}

		// Initially multipath should be disabled - ParseType will reject unknown frame
		data, err := testFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		_, _, err = parser.ParseType(data, protocol.Encryption1RTT)
		require.Error(t, err, "Should reject multipath frames when disabled")

		// Enable multipath
		parser.EnableMultipath()

		// Now should parse successfully
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		frame, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)
		require.IsType(t, &AddAddressFrame{}, frame)
	})

	t.Run("AllMultipathFramesKnown", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)
		parser.EnableMultipath()

		// All three multipath frames should be recognized
		require.True(t, parser.IsKnownFrameType(FrameTypeAddAddress))
		require.True(t, parser.IsKnownFrameType(FrameTypePaths))
		require.True(t, parser.IsKnownFrameType(FrameTypeClosePath))
	})

	t.Run("AddAddressFrameRoundTrip", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)
		parser.EnableMultipath()

		// Create IPv4 ADD_ADDRESS frame
		ipv4 := net.ParseIP("10.0.0.1")
		port := uint16(8080)
		originalFrame := &AddAddressFrame{
			IPVersion: 4,
			Address:   ipv4.To4(),
			Port:      port,
		}

		// Serialize
		data, err := originalFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse back
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsedFrame, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)

		addAddrFrame := parsedFrame.(*AddAddressFrame)
		require.Equal(t, uint8(4), addAddrFrame.IPVersion)
		require.True(t, net.IP(addAddrFrame.Address).Equal(ipv4.To4()))
		require.Equal(t, port, addAddrFrame.Port)
	})

	t.Run("PathsFrameRoundTrip", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)
		parser.EnableMultipath()

		originalFrame := &PathsFrame{
			AvailablePaths: 5,
			ActivePaths:    3,
		}

		// Serialize
		data, err := originalFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse back
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsedFrame, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)

		pathsFrame := parsedFrame.(*PathsFrame)
		require.Equal(t, uint64(5), pathsFrame.AvailablePaths)
		require.Equal(t, uint64(3), pathsFrame.ActivePaths)
	})

	t.Run("ClosePathFrameRoundTrip", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)
		parser.EnableMultipath()

		originalFrame := &ClosePathFrame{
			PathID:       42,
			ErrorCode:    100,
			ReasonPhrase: "Network unreachable",
		}

		// Serialize
		data, err := originalFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse back
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsedFrame, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)

		closePathFrame := parsedFrame.(*ClosePathFrame)
		require.Equal(t, uint64(42), closePathFrame.PathID)
		require.Equal(t, uint64(100), closePathFrame.ErrorCode)
		require.Equal(t, "Network unreachable", closePathFrame.ReasonPhrase)
	})

	t.Run("IPv6AddressSupport", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)
		parser.EnableMultipath()

		// Create IPv6 ADD_ADDRESS frame
		ipv6 := net.ParseIP("2001:db8::1")
		port := uint16(443)
		originalFrame := &AddAddressFrame{
			IPVersion: 6,
			Address:   ipv6,
			Port:      port,
		}

		// Serialize
		data, err := originalFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse back
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsedFrame, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)

		addAddrFrame := parsedFrame.(*AddAddressFrame)
		require.Equal(t, uint8(6), addAddrFrame.IPVersion)
		require.True(t, net.IP(addAddrFrame.Address).Equal(ipv6))
		require.Equal(t, port, addAddrFrame.Port)
	})
}

// TestMultipathFrameSequencing tests realistic frame exchange scenarios
func TestMultipathFrameSequencing(t *testing.T) {
	parser := NewFrameParser(false, false, false)
	parser.EnableMultipath()

	t.Run("AddressAnnouncementFlow", func(t *testing.T) {
		// Peer announces new address
		announceFrame := &AddAddressFrame{
			IPVersion: 4,
			Address:   net.ParseIP("192.168.1.100").To4(),
			Port:      5000,
		}

		data, err := announceFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse announcement
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsed, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)

		frame := parsed.(*AddAddressFrame)

		// Should be able to extract UDP address
		udpAddr := frame.GetUDPAddr()
		require.NotNil(t, udpAddr)
		require.Equal(t, "192.168.1.100:5000", udpAddr.String())
	})

	t.Run("PathSynchronizationFlow", func(t *testing.T) {
		// Initial state
		pathsFrame1 := &PathsFrame{
			AvailablePaths: 2,
			ActivePaths:    1,
		}

		data1, err := pathsFrame1.Append(nil, protocol.Version1)
		require.NoError(t, err)

		frameType1, n1, err := parser.ParseType(data1, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsed1, _, err := parser.ParseLessCommonFrame(frameType1, data1[n1:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, uint64(2), parsed1.(*PathsFrame).AvailablePaths)

		// After establishing new path
		pathsFrame2 := &PathsFrame{
			AvailablePaths: 3,
			ActivePaths:    2,
		}

		data2, err := pathsFrame2.Append(nil, protocol.Version1)
		require.NoError(t, err)

		frameType2, n2, err := parser.ParseType(data2, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsed2, _, err := parser.ParseLessCommonFrame(frameType2, data2[n2:], protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, uint64(3), parsed2.(*PathsFrame).AvailablePaths)
		require.Equal(t, uint64(2), parsed2.(*PathsFrame).ActivePaths)
	})

	t.Run("GracefulPathClosureFlow", func(t *testing.T) {
		// Close path with error
		closeFrame := &ClosePathFrame{
			PathID:       1,
			ErrorCode:    1, // NO_ERROR
			ReasonPhrase: "Switching to better path",
		}

		data, err := closeFrame.Append(nil, protocol.Version1)
		require.NoError(t, err)

		// Parse closure
		frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
		require.NoError(t, err)

		parsed, _, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
		require.NoError(t, err)

		frame := parsed.(*ClosePathFrame)
		require.Equal(t, uint64(1), frame.PathID)
		require.Equal(t, uint64(1), frame.ErrorCode)
		require.Contains(t, frame.ReasonPhrase, "better path")
	})

	t.Run("MultipleFramesInSequence", func(t *testing.T) {
		// Simulate realistic multipath negotiation sequence
		frames := []struct {
			frame interface{}
		}{
			// 1. Announce new address
			{&AddAddressFrame{
				IPVersion: 4,
				Address:   net.ParseIP("10.0.0.1").To4(),
				Port:      9000,
			}},
			// 2. Update path count
			{&PathsFrame{
				AvailablePaths: 2,
				ActivePaths:    1,
			}},
			// 3. Close old path
			{&ClosePathFrame{
				PathID:       0,
				ErrorCode:    0,
				ReasonPhrase: "Migration complete",
			}},
		}

		// Serialize all frames
		var combinedData []byte
		for _, f := range frames {
			var frameData []byte
			var err error
			switch frame := f.frame.(type) {
			case *AddAddressFrame:
				frameData, err = frame.Append(nil, protocol.Version1)
			case *PathsFrame:
				frameData, err = frame.Append(nil, protocol.Version1)
			case *ClosePathFrame:
				frameData, err = frame.Append(nil, protocol.Version1)
			}
			require.NoError(t, err)
			combinedData = append(combinedData, frameData...)
		}

		// Parse them back one by one
		data := combinedData
		parsedFrames := []Frame{}

		for len(data) > 0 {
			frameType, n, err := parser.ParseType(data, protocol.Encryption1RTT)
			require.NoError(t, err)

			parsed, consumed, err := parser.ParseLessCommonFrame(frameType, data[n:], protocol.Version1)
			require.NoError(t, err)
			parsedFrames = append(parsedFrames, parsed)

			data = data[n+consumed:]
		}

		// Verify all frames parsed
		require.Len(t, parsedFrames, 3)
		require.IsType(t, &AddAddressFrame{}, parsedFrames[0])
		require.IsType(t, &PathsFrame{}, parsedFrames[1])
		require.IsType(t, &ClosePathFrame{}, parsedFrames[2])
	})
}

// TestMultipathBackwardCompatibility ensures non-multipath peers reject frames gracefully
func TestMultipathBackwardCompatibility(t *testing.T) {
	t.Run("DisabledParserRejectsMultipathFrames", func(t *testing.T) {
		parser := NewFrameParser(false, false, false)
		// Don't call EnableMultipath()

		// Try to parse each multipath frame
		frames := []struct {
			name      string
			frameType uint64
			data      []byte
		}{
			{
				name:      "ADD_ADDRESS",
				frameType: uint64(FrameTypeAddAddress),
				data:      []byte{0x04, 192, 168, 1, 1, 0x1f, 0x90},
			},
			{
				name:      "PATHS",
				frameType: uint64(FrameTypePaths),
				data:      []byte{0x02, 0x01},
			},
			{
				name:      "CLOSE_PATH",
				frameType: uint64(FrameTypeClosePath),
				data:      []byte{0x01, 0x00, 0x00},
			},
		}

		for _, tc := range frames {
			t.Run(tc.name, func(t *testing.T) {
				data := quicvarint.Append(nil, tc.frameType)
				data = append(data, tc.data...)

				// ParseType should reject unknown frames
				_, _, err := parser.ParseType(data, protocol.Encryption1RTT)
				require.Error(t, err, "Should reject %s frame when multipath disabled", tc.name)
			})
		}
	})

	t.Run("IsKnownFrameTypeRespectMultipathFlag", func(t *testing.T) {
		parserDisabled := NewFrameParser(false, false, false)
		parserEnabled := NewFrameParser(false, false, false)
		parserEnabled.EnableMultipath()

		// When disabled, multipath frames are unknown
		require.False(t, parserDisabled.IsKnownFrameType(FrameTypeAddAddress))
		require.False(t, parserDisabled.IsKnownFrameType(FrameTypePaths))
		require.False(t, parserDisabled.IsKnownFrameType(FrameTypeClosePath))

		// When enabled, multipath frames are known
		require.True(t, parserEnabled.IsKnownFrameType(FrameTypeAddAddress))
		require.True(t, parserEnabled.IsKnownFrameType(FrameTypePaths))
		require.True(t, parserEnabled.IsKnownFrameType(FrameTypeClosePath))

		// Standard frames always known
		require.True(t, parserDisabled.IsKnownFrameType(0x00)) // PADDING
		require.True(t, parserDisabled.IsKnownFrameType(0x01)) // PING
		require.True(t, parserEnabled.IsKnownFrameType(0x00))
		require.True(t, parserEnabled.IsKnownFrameType(0x01))
	})
}
