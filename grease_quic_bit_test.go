package quic

import (
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// The QUIC Bit is greased if the grease_quic_bit transport parameter is enabled locally, and the peer sent it
// (section 3.1 of RFC 9287).
func TestConnectionGreaseQUICBitNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		local, remote bool
	}{
		{name: "both", local: true, remote: true},
		{name: "only local", local: true},
		{name: "only remote", remote: true},
		{name: "neither"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			conn := newServerTestConnection(t,
				mockCtrl,
				&Config{EnableQUICBitGreasing: tc.local, DisablePathMTUDiscovery: true},
				false,
			)
			if tc.local && tc.remote {
				conn.packer.EXPECT().EnableQUICBitGreasing()
			}
			require.NoError(t, conn.conn.handleTransportParameters(&wire.TransportParameters{GreaseQUICBit: tc.remote}))
			require.True(t, mockCtrl.Satisfied())
			cs := conn.conn.ConnectionState()
			require.Equal(t, tc.local, cs.SupportsQUICBitGreasing.Local)
			require.Equal(t, tc.remote, cs.SupportsQUICBitGreasing.Remote)
		})
	}
}

// A client doesn't grease the QUIC Bit based on the transport parameters remembered for 0-RTT
// (section 3.1 of RFC 9287).
func TestConnectionGreaseQUICBitNotRestored(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tc := newClientTestConnection(t,
		mockCtrl,
		&Config{EnableQUICBitGreasing: true, DisablePathMTUDiscovery: true},
		false,
	)
	// The mock packer would fail the test if EnableQUICBitGreasing was called.
	tc.conn.restoreTransportParameters(&wire.TransportParameters{
		GreaseQUICBit:           true,
		ActiveConnectionIDLimit: 2,
		MaxDatagramFrameSize:    protocol.InvalidByteCount,
	})
}

// A peer might set the QUIC Bit of a stateless reset to 0, if the grease_quic_bit transport parameter was sent
// (section 3 of RFC 9287).
func TestConnectionStatelessResetGreasedQUICBit(t *testing.T) {
	for _, tc := range []struct {
		name             string
		greasing         bool
		firstByte        byte
		isStatelessReset bool
	}{
		{name: "QUIC Bit set", firstByte: 0x40, isStatelessReset: true},
		{name: "QUIC Bit set, greasing", greasing: true, firstByte: 0x40, isStatelessReset: true},
		{name: "QUIC Bit set to 0", firstByte: 0},
		{name: "QUIC Bit set to 0, greasing", greasing: true, firstByte: 0, isStatelessReset: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			unpacker := NewMockUnpacker(mockCtrl)
			conn := newClientTestConnection(t,
				mockCtrl,
				&Config{EnableQUICBitGreasing: tc.greasing, DisablePathMTUDiscovery: true},
				false,
				connectionOptUnpacker(unpacker),
			)
			token := protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
			conn.connRunner.EXPECT().AddResetToken(token, conn.conn)
			conn.conn.connIDManager.SetStatelessResetToken(token)
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
				protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, handshake.ErrDecryptionFailed,
			)

			data := append([]byte{tc.firstByte | 0x5}, conn.srcConnID.Bytes()...)
			data = append(data, make([]byte, 20)...)
			data = append(data, token[:]...)
			_, err := conn.conn.handleShortHeaderPacket(receivedPacket{
				remoteAddr: conn.remoteAddr,
				data:       data,
				buffer:     getPacketBuffer(),
				rcvTime:    monotime.Now(),
			}, false, 0)
			if tc.isStatelessReset {
				require.ErrorIs(t, err, &StatelessResetError{})
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConnectionAcceptsGreasedQUICBit(t *testing.T) {
	for _, greasing := range []bool{true, false} {
		tc := newServerTestConnection(t, nil, &Config{EnableQUICBitGreasing: greasing, DisablePathMTUDiscovery: true}, false)
		var h packetHandler = tc.conn
		a, ok := h.(greasedQUICBitAcceptor)
		require.True(t, ok)
		require.Equal(t, greasing, a.acceptsGreasedQUICBit())
	}
}
