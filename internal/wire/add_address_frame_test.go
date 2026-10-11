package wire

import (
	"bytes"
	"io"
	"net"
	"slices"
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

func TestFrameParserAddAddress(t *testing.T) {
	parser := NewFrameParser(true, true, true)
	parser.EnableAddAddress()

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
}

func TestAddAddressFrameValuesTooLarge(t *testing.T) {
	tooLarge := uint64(quicvarint.Max) + 1
	for _, f := range []Frame{
		&AddAddressFrame{AddressID: tooLarge, IPVersion: 4, Address: []byte{1, 2, 3, 4}},
		&AddAddressFrame{SequenceNumber: tooLarge, IPVersion: 4, Address: []byte{1, 2, 3, 4}},
	} {
		require.NotPanics(t, func() { f.Length(protocol.Version1) })
		_, err := f.Append(nil, protocol.Version1)
		require.ErrorIs(t, err, errVarintTooLarge)
	}
}

func TestParseAddAddressFrameErrors(t *testing.T) {
	frame := &AddAddressFrame{AddressID: 1, SequenceNumber: 2, IPVersion: 6, Address: make([]byte, 16), Port: 443}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	data := b[l:]
	_, n, err := parseAddAddressFrame(data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	for i := range data {
		_, _, err := parseAddAddressFrame(data[:i], protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
	}

	// only IPv4 and IPv6 addresses
	invalid := slices.Clone(data)
	invalid[2] = 5 // the IP version follows the address ID and the sequence number
	_, _, err = parseAddAddressFrame(invalid, protocol.Version1)
	require.EqualError(t, err, "invalid IP version: 5")
	_, err = (&AddAddressFrame{IPVersion: 5, Address: []byte{1, 2, 3, 4}}).Append(nil, protocol.Version1)
	require.EqualError(t, err, "invalid IP version: 5")
	_, err = (&AddAddressFrame{IPVersion: 4, Address: make([]byte, 16)}).Append(nil, protocol.Version1)
	require.Error(t, err)
	_, err = (&AddAddressFrame{IPVersion: 6, Address: make([]byte, 4)}).Append(nil, protocol.Version1)
	require.Error(t, err)
}
