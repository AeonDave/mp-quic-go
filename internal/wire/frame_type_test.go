package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsStreamFrameType(t *testing.T) {
	for i := 0x08; i <= 0x0f; i++ {
		require.Truef(t, FrameType(i).IsStreamFrameType(), "FrameType(0x%x).IsStreamFrameType() = false, want true", i)
	}

	require.False(t, FrameType(0x1).IsStreamFrameType())
}

func TestIsAckFrameType(t *testing.T) {
	require.True(t, FrameTypeAck.IsAckFrameType(), "AckFrameType should be recognized as ACK")
	require.True(t, FrameTypeAckECN.IsAckFrameType(), "AckECNFrameType should be recognized as ACK")
	require.False(t, FrameTypePing.IsAckFrameType(), "PingFrameType should not be recognized as ACK")
	require.False(t, FrameType(0x10).IsAckFrameType(), "MaxDataFrameType should not be recognized as ACK")
}

func TestIsDatagramFrameType(t *testing.T) {
	require.True(t, FrameTypeDatagramNoLength.IsDatagramFrameType(), "DatagramNoLengthFrameType should be recognized as DATAGRAM")
	require.True(t, FrameTypeDatagramWithLength.IsDatagramFrameType(), "DatagramWithLengthFrameType should be recognized as DATAGRAM")
	require.False(t, FrameTypePing.IsDatagramFrameType(), "PingFrameType should not be recognized as DATAGRAM")
	require.False(t, FrameType(0x1e).IsDatagramFrameType(), "HandshakeDoneFrameType should not be recognized as DATAGRAM")
}

func TestIsPathAckFrameType(t *testing.T) {
	require.True(t, FrameType(0x3e).IsPathAckFrameType())
	require.True(t, FrameType(0x3f).IsPathAckFrameType())
	require.False(t, FrameTypeAck.IsPathAckFrameType())
	require.False(t, FrameTypeAckECN.IsPathAckFrameType())
	require.False(t, FrameTypePathAck.IsAckFrameType())
	require.False(t, FrameTypePathAckECN.IsAckFrameType())
}

func TestIsMultipathFrameType(t *testing.T) {
	for _, ft := range []FrameType{0x3e, 0x3f, 0x3e75, 0x3e76, 0x3e77, 0x3e78, 0x3e79, 0x3e7a, 0x3e7b, 0x3e7c} {
		require.True(t, ft.IsMultipathFrameType(), "frame type %#x", uint64(ft))
	}
	for _, ft := range []FrameType{0x2, 0x3, 0x3d, 0x40, 0x3e74, 0x3e7d, FrameTypeAddAddress, FrameTypeObservedAddressIPv4} {
		require.False(t, ft.IsMultipathFrameType(), "frame type %#x", uint64(ft))
	}
}

func TestIsObservedAddressFrameType(t *testing.T) {
	require.True(t, FrameType(0x9f81a6).IsObservedAddressFrameType())
	require.True(t, FrameType(0x9f81a7).IsObservedAddressFrameType())
	for _, ft := range []FrameType{0x9f81a5, 0x9f81a8, 0x9f81a176, FrameTypePathChallenge, FrameTypeAddAddress} {
		require.False(t, ft.IsObservedAddressFrameType(), "frame type %#x", uint64(ft))
	}
	// section 4.1 of draft-ietf-quic-address-discovery-01
	require.True(t, IsProbingFrameType(FrameTypeObservedAddressIPv4))
	require.True(t, IsProbingFrameType(FrameTypeObservedAddressIPv6))
	require.True(t, IsProbingFrame(&ObservedAddressFrame{}))
}

func TestIsReservedFrameType(t *testing.T) {
	for _, ft := range []uint64{
		0x0, 0x1, 0x6, 0x8, 0xf, 0x1e, // RFC 9000
		0x24,       // RESET_STREAM_AT
		0x30, 0x31, // DATAGRAM
		0x1f, 0xaf, // ACK_FREQUENCY, IMMEDIATE_ACK
		0x3e, 0x3f, 0x3e75, 0x3e76, 0x3e77, 0x3e78, 0x3e79, 0x3e7a, 0x3e7b, 0x3e7c, // multipath
		uint64(FrameTypeAddAddress),
		0x9f81a6, 0x9f81a7, // OBSERVED_ADDRESS
	} {
		require.True(t, IsReservedFrameType(ft), "frame type %#x", ft)
	}
	for _, ft := range []uint64{0x20, 0x3d, 0x40, 0x41, 0x42, 0x3e74, 0x3e7d, 0x1234, 0x9f81a5, 0x9f81a8} {
		require.False(t, IsReservedFrameType(ft), "frame type %#x", ft)
	}
}
