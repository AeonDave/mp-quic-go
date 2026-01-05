package quic

import (
	"net"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type recordingMultipathController struct {
	ctx PathSelectionContext
}

func (c *recordingMultipathController) SelectPath(ctx PathSelectionContext) (PathInfo, bool) {
	c.ctx = ctx
	return PathInfo{
		ID:         1,
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4444},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5555},
	}, true
}

func (c *recordingMultipathController) PathIDForPacket(net.Addr, net.Addr) (PathID, bool) {
	return 0, false
}

type stubSentPacketHandler struct {
	bytesInFlight protocol.ByteCount
}

func (s *stubSentPacketHandler) BytesInFlight() protocol.ByteCount { return s.bytesInFlight }

func (s *stubSentPacketHandler) SentPacket(monotime.Time, protocol.PacketNumber, protocol.PacketNumber, []ackhandler.StreamFrame, []ackhandler.Frame, protocol.EncryptionLevel, protocol.ECN, protocol.ByteCount, bool, bool, protocol.PathID) {
}

func (s *stubSentPacketHandler) ReceivedAck(*wire.AckFrame, protocol.EncryptionLevel, monotime.Time, protocol.PathID) (bool, error) {
	return false, nil
}

func (s *stubSentPacketHandler) ReceivedPacket(protocol.EncryptionLevel, monotime.Time) {}

func (s *stubSentPacketHandler) ReceivedBytes(protocol.ByteCount, monotime.Time) {}

func (s *stubSentPacketHandler) DropPackets(protocol.EncryptionLevel, monotime.Time) {}

func (s *stubSentPacketHandler) ResetForRetry(monotime.Time) {}

func (s *stubSentPacketHandler) SendMode(monotime.Time) ackhandler.SendMode { return ackhandler.SendAny }

func (s *stubSentPacketHandler) TimeUntilSend() monotime.Time { return 0 }

func (s *stubSentPacketHandler) SetMaxDatagramSize(protocol.ByteCount) {}

func (s *stubSentPacketHandler) QueueProbePacket(protocol.EncryptionLevel) bool { return false }

func (s *stubSentPacketHandler) ECNMode(bool) protocol.ECN { return protocol.ECNNon }

func (s *stubSentPacketHandler) PeekPacketNumber(protocol.PathID, protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return 0, protocol.PacketNumberLen1
}

func (s *stubSentPacketHandler) PopPacketNumber(protocol.PathID, protocol.EncryptionLevel) protocol.PacketNumber {
	return 0
}

func (s *stubSentPacketHandler) GetLossDetectionTimeout() monotime.Time { return 0 }

func (s *stubSentPacketHandler) OnLossDetectionTimeout(monotime.Time) error { return nil }

func (s *stubSentPacketHandler) MigratedPath(monotime.Time, protocol.ByteCount) {}

func TestSelectPathForSendingPopulatesBytesInFlight(t *testing.T) {
	controller := &recordingMultipathController{}
	handler := &stubSentPacketHandler{bytesInFlight: 1337}
	conn := &Conn{
		multipathEnabled:    true,
		multipathController: controller,
		sentPacketHandler:   handler,
	}

	_, ok := conn.selectPathForSending(monotime.Now(), false, false)
	require.True(t, ok)
	require.Equal(t, protocol.ByteCount(1337), controller.ctx.BytesInFlight)
}
