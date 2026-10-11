package wire

import (
	"io"
	"net/netip"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseObservedAddressFrame(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		data := encodeVarInt(0xdecafbad)             // sequence number
		data = append(data, 192, 0, 2, 1, 0x1, 0xbb) // IPv4 address and port
		frame, l, err := parseObservedAddressFrame(data, FrameTypeObservedAddressIPv4, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, &ObservedAddressFrame{
			SequenceNumber: 0xdecafbad,
			Address:        netip.MustParseAddrPort("192.0.2.1:443"),
		}, frame)
		require.Equal(t, len(data), l)
	})

	t.Run("IPv6", func(t *testing.T) {
		data := encodeVarInt(0x42)                                                      // sequence number
		data = append(data, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) // IPv6 address
		data = append(data, 0x11, 0x51)                                                 // port
		frame, l, err := parseObservedAddressFrame(data, FrameTypeObservedAddressIPv6, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, &ObservedAddressFrame{
			SequenceNumber: 0x42,
			Address:        netip.MustParseAddrPort("[2001:db8::1]:4433"),
		}, frame)
		require.Equal(t, len(data), l)
	})

	// An IPv4-mapped IPv6 address is kept as an IPv6 address.
	t.Run("IPv4-mapped IPv6", func(t *testing.T) {
		data := encodeVarInt(0)
		data = append(data, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1, 0x1, 0xbb)
		frame, l, err := parseObservedAddressFrame(data, FrameTypeObservedAddressIPv6, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, netip.MustParseAddrPort("[::ffff:192.0.2.1]:443"), frame.Address)
		require.True(t, frame.Address.Addr().Is4In6())
		require.Equal(t, len(data), l)
	})
}

func TestParseObservedAddressFrameErrorsOnEOFs(t *testing.T) {
	for _, typ := range []FrameType{FrameTypeObservedAddressIPv4, FrameTypeObservedAddressIPv6} {
		data := encodeVarInt(0xdecafbad)
		if typ == FrameTypeObservedAddressIPv4 {
			data = append(data, make([]byte, 4+2)...)
		} else {
			data = append(data, make([]byte, 16+2)...)
		}
		_, l, err := parseObservedAddressFrame(data, typ, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, len(data), l)
		for i := range data {
			_, _, err := parseObservedAddressFrame(data[:i], typ, protocol.Version1)
			require.ErrorIs(t, err, io.EOF)
		}
	}
}

func TestWriteObservedAddressFrame(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		frame := &ObservedAddressFrame{SequenceNumber: 0x1337, Address: netip.MustParseAddrPort("192.0.2.1:443")}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		expected := []byte{0x80, 0x9f, 0x81, 0xa6}
		expected = append(expected, encodeVarInt(0x1337)...)
		expected = append(expected, 192, 0, 2, 1, 0x1, 0xbb)
		require.Equal(t, expected, b)
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})

	t.Run("IPv6", func(t *testing.T) {
		frame := &ObservedAddressFrame{SequenceNumber: 0, Address: netip.MustParseAddrPort("[2001:db8::1]:4433")}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		expected := []byte{0x80, 0x9f, 0x81, 0xa7}
		expected = append(expected, encodeVarInt(0)...)
		expected = append(expected, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x11, 0x51)
		require.Equal(t, expected, b)
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})

	t.Run("IPv4-mapped IPv6", func(t *testing.T) {
		frame := &ObservedAddressFrame{Address: netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")}
		b, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		require.Equal(t, []byte{0x80, 0x9f, 0x81, 0xa7}, b[:4])
		require.Len(t, b, int(frame.Length(protocol.Version1)))
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := (&ObservedAddressFrame{}).Append(nil, protocol.Version1)
		require.EqualError(t, err, "invalid address")
	})

	t.Run("sequence number too large", func(t *testing.T) {
		frame := &ObservedAddressFrame{SequenceNumber: quicvarint.Max + 1, Address: netip.MustParseAddrPort("192.0.2.1:443")}
		_, err := frame.Append(nil, protocol.Version1)
		require.ErrorIs(t, err, errVarintTooLarge)
	})
}

func TestObservedAddressFrameValues(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.1:443", "255.255.255.255:65535", "[::]:0", "[2001:db8::1]:4433", "[::ffff:192.0.2.1]:1"} {
		for _, seq := range []uint64{0, 63, 64, quicvarint.Max} {
			f := &ObservedAddressFrame{SequenceNumber: seq, Address: netip.MustParseAddrPort(addr)}
			b, err := f.Append(nil, protocol.Version1)
			require.NoError(t, err)
			require.Len(t, b, int(f.Length(protocol.Version1)))
			typ, l, err := quicvarint.Parse(b)
			require.NoError(t, err)
			parsed, n, err := parseObservedAddressFrame(b[l:], FrameType(typ), protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, len(b)-l, n)
			require.Equal(t, f, parsed)
		}
	}
}
