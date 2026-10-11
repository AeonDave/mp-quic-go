package quic

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/mocks"
	mockackhandler "github.com/AeonDave/mp-quic-go/internal/mocks/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const testPackerConnIDLen = 4

type testPacketPacker struct {
	packer              *packetPacker
	initialStream       *initialCryptoStream
	handshakeStream     *cryptoStream
	datagramQueue       *datagramQueue
	pnManager           *mockackhandler.MockSentPacketHandler
	sealingManager      *MockSealingManager
	framer              *MockFrameSource
	ackFramer           *MockAckFrameSource
	retransmissionQueue *retransmissionQueue
}

func newTestPacketPacker(t *testing.T, mockCtrl *gomock.Controller, pers protocol.Perspective) *testPacketPacker {
	destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	require.Equal(t, testPackerConnIDLen, destConnID.Len())
	initialStream := newInitialCryptoStream(pers == protocol.PerspectiveClient)
	handshakeStream := newCryptoStream()
	pnManager := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	framer := NewMockFrameSource(mockCtrl)
	ackFramer := NewMockAckFrameSource(mockCtrl)
	sealingManager := NewMockSealingManager(mockCtrl)
	datagramQueue := newDatagramQueue(func() {}, utils.DefaultLogger)
	retransmissionQueue := newRetransmissionQueue()
	return &testPacketPacker{
		pnManager:           pnManager,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		sealingManager:      sealingManager,
		framer:              framer,
		ackFramer:           ackFramer,
		datagramQueue:       datagramQueue,
		retransmissionQueue: retransmissionQueue,
		packer: newPacketPacker(
			protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			func() protocol.ConnectionID { return destConnID },
			initialStream,
			handshakeStream,
			pnManager,
			retransmissionQueue,
			sealingManager,
			framer,
			ackFramer,
			datagramQueue,
			pers,
		),
	}
}

// newMockShortHeaderSealer returns a mock short header sealer that seals a short header packet
func newMockShortHeaderSealer(mockCtrl *gomock.Controller) *mocks.MockShortHeaderSealer {
	sealer := mocks.NewMockShortHeaderSealer(mockCtrl)
	sealer.EXPECT().KeyPhase().Return(protocol.KeyPhaseOne).AnyTimes()
	sealer.EXPECT().Overhead().Return(7).AnyTimes()
	sealer.EXPECT().EncryptHeader(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) []byte {
		return append(src, bytes.Repeat([]byte{'s'}, sealer.Overhead())...)
	}).AnyTimes()
	return sealer
}

func parsePacket(t *testing.T, data []byte) (hdrs []*wire.ExtendedHeader, more []byte) {
	t.Helper()
	for len(data) > 0 {
		if !wire.IsLongHeaderPacket(data[0]) {
			break
		}
		hdr, _, more, err := wire.ParsePacket(data)
		require.NoError(t, err)
		extHdr, err := hdr.ParseExtended(data)
		require.NoError(t, err)
		require.GreaterOrEqual(t, extHdr.Length+protocol.ByteCount(extHdr.PacketNumberLen), protocol.ByteCount(4))
		data = more
		hdrs = append(hdrs, extHdr)
	}
	return hdrs, data
}

func parseShortHeaderPacket(t *testing.T, data []byte, connIDLen int) {
	t.Helper()
	l, _, pnLen, _, err := wire.ParseShortHeader(data, connIDLen)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(data)-l+int(pnLen), 4)
}

func expectAppendFrames(framer *MockFrameSource, controlFrames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame) {
	framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(cf []ackhandler.Frame, sf []ackhandler.StreamFrame, maxSize protocol.ByteCount, _ monotime.Time, v protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range controlFrames {
				if length+f.Frame.Length(v) > maxSize {
					break
				}
				length += f.Frame.Length(v)
				cf = append(cf, f)
			}
			for _, f := range streamFrames {
				if length+f.Frame.Length(v) > maxSize {
					break
				}
				length += f.Frame.Length(v)
				sf = append(sf, f)
			}
			return cf, sf, length
		},
	)
}

func generateLargeACKFrame(t *testing.T, minSize protocol.ByteCount) *wire.AckFrame {
	t.Helper()

	ack := &wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: 42 * time.Millisecond,
	}
	var counter int
	for ack.Length(protocol.Version1) < minSize {
		counter++
		if counter > protocol.MaxNumAckRanges {
			t.Fatalf("max number of ACK ranges reached, size: %d", ack.Length(protocol.Version1))
		}
		pn := protocol.PacketNumber(1000 * counter)
		ack.AckRanges = append([]wire.AckRange{{Smallest: pn, Largest: pn + 100}}, ack.AckRanges...)
	}
	return ack
}

func TestPackLongHeaders(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)

	t.Run("with Handshake ACK", func(t *testing.T) {
		testPackLongHeaders(t, true)
	})

	t.Run("without Handshake ACK", func(t *testing.T) {
		testPackLongHeaders(t, false)
	})
}

func testPackLongHeaders(t *testing.T, includeACK bool) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	token := make([]byte, 20)
	rand.Read(token)
	tp.packer.SetToken(token)
	now := monotime.Now()

	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen3)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen4)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, false, gomock.Any())
	var numRanges int
	if includeACK {
		ack := generateLargeACKFrame(t, maxPacketSize-1000)
		numRanges = len(ack.AckRanges)
		tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, false, gomock.Any()).Return(ack)
	} else {
		tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, false, gomock.Any())
		tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	}
	clientHello, err := getClientHello("quic-go.net")
	require.NoError(t, err)
	tp.initialStream.Write(clientHello)
	tp.initialStream.Write(make([]byte, 900-len(clientHello))) // add some more data
	tp.packer.retransmissionQueue.addHandshake(&wire.PingFrame{})

	p, err := tp.packer.PackCoalescedPacket(false, maxPacketSize, now, protocol.Version1, 0)
	require.NoError(t, err)
	require.Equal(t, maxPacketSize, p.buffer.Len())
	require.Len(t, p.longHdrPackets, 2)
	require.Nil(t, p.shortHdrPacket)
	require.Equal(t, protocol.EncryptionInitial, p.longHdrPackets[0].EncryptionLevel())
	// the ClientHello is split into multiple frames
	require.GreaterOrEqual(t, len(p.longHdrPackets[0].frames), 3)
	for _, f := range p.longHdrPackets[0].frames {
		require.IsType(t, &wire.CryptoFrame{}, f.Frame)
	}
	require.Equal(t, protocol.EncryptionHandshake, p.longHdrPackets[1].EncryptionLevel())
	require.Len(t, p.longHdrPackets[1].frames, 1)
	require.IsType(t, &wire.PingFrame{}, p.longHdrPackets[1].frames[0].Frame)
	if includeACK {
		require.NotNil(t, p.longHdrPackets[1].ack)
		// the ACK frame was truncated
		require.Less(t, len(p.longHdrPackets[1].ack.AckRanges), numRanges)
	} else {
		require.Nil(t, p.longHdrPackets[1].ack)
	}

	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Len(t, hdrs, 2)
	require.Equal(t, protocol.PacketTypeInitial, hdrs[0].Type)
	require.Equal(t, token, hdrs[0].Token)
	require.Equal(t, protocol.PacketNumber(0x24), hdrs[0].PacketNumber)
	require.Equal(t, protocol.PacketNumberLen3, hdrs[0].PacketNumberLen)
	require.Equal(t, protocol.PacketTypeHandshake, hdrs[1].Type)
	require.Nil(t, hdrs[1].Token)
	require.Equal(t, protocol.PacketNumber(0x42), hdrs[1].PacketNumber)
	require.Equal(t, protocol.PacketNumberLen4, hdrs[1].PacketNumberLen)
	require.Empty(t, more)
}

func TestPackCoalescedAckOnlyPacketNothingToSend(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	// the packet number is not popped
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any())
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), true, gomock.Any())
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any())
	p, err := tp.packer.PackCoalescedPacket(true, 1234, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestPackInitialAckOnlyPacket(t *testing.T) {
	t.Run("client", func(t *testing.T) { testPackInitialAckOnlyPacket(t, protocol.PerspectiveClient) })
	t.Run("server", func(t *testing.T) { testPackInitialAckOnlyPacket(t, protocol.PerspectiveServer) })
}

func testPackInitialAckOnlyPacket(t *testing.T, pers protocol.Perspective) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, pers)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any()).Return(ack)
	p, err := tp.packer.PackCoalescedPacket(true, maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionInitial, p.longHdrPackets[0].EncryptionLevel())
	require.Equal(t, ack, p.longHdrPackets[0].ack)
	require.Empty(t, p.longHdrPackets[0].frames)
	// only the client needs to pad Initial packets
	switch pers {
	case protocol.PerspectiveClient:
		require.Equal(t, maxPacketSize, p.buffer.Len())
	case protocol.PerspectiveServer:
		require.Less(t, p.buffer.Len(), protocol.ByteCount(100))
	}
	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Empty(t, more)
	require.Len(t, hdrs, 1)
	require.Equal(t, protocol.PacketTypeInitial, hdrs[0].Type)
}

func TestPack1RTTAckOnlyPacket(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1300
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any()).Return(ack)
	p, buffer, err := tp.packer.PackAckOnlyPacket(maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Equal(t, ack, p.Ack)
	require.Empty(t, p.Frames)
	parsePacket(t, buffer.Data)
}

func TestPack0RTTPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any())
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42))
	cf := ackhandler.Frame{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}
	tp.framer.EXPECT().HasData().Return(true)
	// TODO: check sizes
	tp.framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(fs []ackhandler.Frame, sf []ackhandler.StreamFrame, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			return append(fs, cf), sf, cf.Frame.Length(protocol.Version1)
		},
	)
	p, err := tp.packer.PackCoalescedPacket(false, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.PacketType0RTT, p.longHdrPackets[0].header.Type)
	require.Equal(t, protocol.Encryption0RTT, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, cf.Frame, p.longHdrPackets[0].frames[0].Frame)
	require.NotNil(t, p.longHdrPackets[0].frames[0].Handler)
}

// After compatible version negotiation, the client sends 0-RTT packets using its Chosen Version,
// and all other packets using the Negotiated Version (section 4.1 of RFC 9369).
func TestPack0RTTPacketUsingChosenVersion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.packer.zeroRTTVersion = protocol.Version1
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any()).Return(
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}},
	)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42))
	cf := ackhandler.Frame{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}
	tp.framer.EXPECT().HasData().Return(true)
	tp.framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(fs []ackhandler.Frame, sf []ackhandler.StreamFrame, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			return append(fs, cf), sf, cf.Frame.Length(protocol.Version1)
		},
	)
	p, err := tp.packer.PackCoalescedPacket(false, 1250, monotime.Now(), protocol.Version2, 0)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 2)
	require.Equal(t, protocol.PacketTypeInitial, p.longHdrPackets[0].header.Type)
	require.Equal(t, protocol.Version2, p.longHdrPackets[0].header.Version)
	require.Equal(t, protocol.PacketType0RTT, p.longHdrPackets[1].header.Type)
	require.Equal(t, protocol.Version1, p.longHdrPackets[1].header.Version)

	// check the encoding of the packet types
	hdr, _, rest, err := wire.ParsePacket(p.buffer.Data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeInitial, hdr.Type)
	require.Equal(t, protocol.Version2, hdr.Version)
	hdr, _, _, err = wire.ParsePacket(rest)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketType0RTT, hdr.Type)
	require.Equal(t, protocol.Version1, hdr.Version)
}

// ACK frames can't be sent in 0-RTT packets
func TestPack0RTTPacketNoACK(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any())
	// no further calls to get an ACK frame
	p, err := tp.packer.PackCoalescedPacket(true, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestPackCoalescedAppData(t *testing.T) {
	t.Run("with large ACK", func(t *testing.T) {
		testPackCoalescedAppData(t, true)
	})

	t.Run("without ACK", func(t *testing.T) {
		testPackCoalescedAppData(t, false)
	})
}

func testPackCoalescedAppData(t *testing.T, withAck bool) {
	const maxPacketSize protocol.ByteCount = 1234

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false, gomock.Any())

	var numRanges int
	if withAck {
		// The ACK is too large and needs to be truncated
		ack := generateLargeACKFrame(t, maxPacketSize-1000)
		numRanges = len(ack.AckRanges)
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any()).Return(ack)
	} else {
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	}

	handshakeData := make([]byte, 1000)
	rand.Read(handshakeData)
	tp.handshakeStream.Write(handshakeData)
	expectAppendFrames(tp.framer, nil, []ackhandler.StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("foobar")}}})

	p, err := tp.packer.PackCoalescedPacket(false, maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionHandshake, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, handshakeData, p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data)
	require.NotNil(t, p.shortHdrPacket)
	require.Empty(t, p.shortHdrPacket.Frames)
	if withAck {
		require.NotNil(t, p.shortHdrPacket.Ack)
		require.Less(t, len(p.shortHdrPacket.Ack.AckRanges), numRanges)
		require.LessOrEqual(t, len(p.buffer.Data), int(maxPacketSize))
		require.Empty(t, p.shortHdrPacket.StreamFrames)
	} else {
		require.Nil(t, p.shortHdrPacket.Ack)
		require.Less(t, len(p.buffer.Data), int(maxPacketSize))
		require.Len(t, p.shortHdrPacket.StreamFrames, 1)
		require.Equal(t, []byte("foobar"), p.shortHdrPacket.StreamFrames[0].Frame.Data)
	}

	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Len(t, hdrs, 1)
	require.Equal(t, protocol.PacketTypeHandshake, hdrs[0].Type)
	require.NotEmpty(t, more)
	parseShortHeaderPacket(t, more, testPackerConnIDLen)
}

func TestPackConnectionCloseCoalesced(t *testing.T) {
	t.Run("client", func(t *testing.T) { testPackConnectionCloseCoalesced(t, protocol.PerspectiveClient) })
	t.Run("server", func(t *testing.T) { testPackConnectionCloseCoalesced(t, protocol.PerspectiveServer) })
}

func testPackConnectionCloseCoalesced(t *testing.T, pers protocol.Perspective) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, pers)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(1))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(2), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(2))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	switch pers {
	case protocol.PerspectiveClient:
		tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(3), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(3))
	case protocol.PerspectiveServer:
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(3), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(3))
	}
	p, err := tp.packer.PackApplicationClose(&qerr.ApplicationError{
		ErrorCode:    0x1337,
		ErrorMessage: "foobar",
	}, maxPacketSize, protocol.Version1, 0)
	require.NoError(t, err)
	switch pers {
	case protocol.PerspectiveClient:
		require.Len(t, p.longHdrPackets, 3)
		require.Nil(t, p.shortHdrPacket)
	case protocol.PerspectiveServer:
		require.Len(t, p.longHdrPackets, 2)
		require.NotNil(t, p.shortHdrPacket)
	}
	// for Initial packets, the error code is replace with a transport error of type APPLICATION_ERROR
	require.Equal(t, protocol.PacketTypeInitial, p.longHdrPackets[0].header.Type)
	require.Equal(t, protocol.PacketNumber(1), p.longHdrPackets[0].header.PacketNumber)
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[0].frames[0].Frame)
	ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.ApplicationErrorErrorCode), ccf.ErrorCode)
	require.Empty(t, ccf.ReasonPhrase)
	// for Handshake packets, the error code is replace with a transport error of type APPLICATION_ERROR
	require.Equal(t, protocol.PacketTypeHandshake, p.longHdrPackets[1].header.Type)
	require.Equal(t, protocol.PacketNumber(2), p.longHdrPackets[1].header.PacketNumber)
	require.Len(t, p.longHdrPackets[1].frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[1].frames[0].Frame)
	ccf = p.longHdrPackets[1].frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.ApplicationErrorErrorCode), ccf.ErrorCode)
	require.Empty(t, ccf.ReasonPhrase)

	// for application-data packet number space (1-RTT for the server, 0-RTT for the client),
	// the application-level error code is sent

	switch pers {
	case protocol.PerspectiveClient:
		require.Equal(t, protocol.PacketNumber(3), p.longHdrPackets[2].header.PacketNumber)
		require.Len(t, p.longHdrPackets[2].frames, 1)
		require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[2].frames[0].Frame)
		ccf = p.longHdrPackets[2].frames[0].Frame.(*wire.ConnectionCloseFrame)
	case protocol.PerspectiveServer:
		require.Equal(t, protocol.PacketNumber(3), p.shortHdrPacket.PacketNumber)
		require.Len(t, p.shortHdrPacket.Frames, 1)
		require.IsType(t, &wire.ConnectionCloseFrame{}, p.shortHdrPacket.Frames[0].Frame)
		ccf = p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
	}
	require.True(t, ccf.IsApplicationError)
	require.Equal(t, uint64(0x1337), ccf.ErrorCode)
	require.Equal(t, "foobar", ccf.ReasonPhrase)

	// the client needs to pad this packet to the max packet size
	switch pers {
	case protocol.PerspectiveClient:
		require.Equal(t, maxPacketSize, p.buffer.Len())
	case protocol.PerspectiveServer:
		require.Less(t, p.buffer.Len(), protocol.ByteCount(100))
	}
}

// Regression test for https://github.com/quic-go/quic-go/issues/5857
func TestPackConnectionCloseCoalescedClient1RTT(t *testing.T) {
	const maxPacketSize protocol.ByteCount = protocol.MaxPacketBufferSize
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	for i, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT} {
		pn := protocol.PacketNumber(i + 1)
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), encLevel).Return(pn, protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), encLevel).Return(pn)
	}
	p, err := tp.packer.PackApplicationClose(&qerr.ApplicationError{ErrorMessage: "connection closed"}, maxPacketSize, protocol.Version1, 0)
	require.NoError(t, err)
	defer p.buffer.Release()
	require.Len(t, p.longHdrPackets, 2)
	require.NotNil(t, p.shortHdrPacket)
	require.Equal(t, maxPacketSize, p.buffer.Len())
}

func TestPackConnectionCloseCryptoError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	quicErr := qerr.NewLocalCryptoError(0x42, errors.New("crypto error"))
	quicErr.FrameType = 0x1234
	p, err := tp.packer.PackConnectionClose(quicErr, protocol.MaxByteCount, protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.PacketTypeHandshake, p.longHdrPackets[0].header.Type)
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[0].frames[0].Frame)
	ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(0x100+0x42), ccf.ErrorCode)
	require.Equal(t, uint64(0x1234), ccf.FrameType)
	// for crypto errors, the reason phrase is cleared
	require.Empty(t, ccf.ReasonPhrase)
}

func TestPackConnectionClose1RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	// expect no framer.PopStreamFrames
	p, err := tp.packer.PackConnectionClose(&qerr.TransportError{
		ErrorCode:    qerr.CryptoBufferExceeded,
		ErrorMessage: "foo",
	}, protocol.MaxByteCount, protocol.Version1, 0)
	require.NoError(t, err)
	require.Empty(t, p.longHdrPackets)
	require.Len(t, p.shortHdrPacket.Frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.shortHdrPacket.Frames[0].Frame)
	ccf := p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.CryptoBufferExceeded), ccf.ErrorCode)
	require.Equal(t, "foo", ccf.ReasonPhrase)
}

func TestPack1RTTPacketNothingToSend(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	// don't expect any calls to PopPacketNumber
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any())
	tp.framer.EXPECT().HasData()
	_, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.ErrorIs(t, err, errNothingToPack)
}

// No packet is sent once the next packet number reaches the largest packet number (section 12.3 of RFC 9000).
func TestPackPacketNumberExhaustion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.MaxPacketNumber, protocol.PacketNumberLen4)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	expectAppendFrames(tp.framer, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil)
	_, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.ErrorIs(t, err, errPacketNumbersExhausted)
}

func TestPack1RTTPacketWithData(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	f := &wire.StreamFrame{
		StreamID: 5,
		Data:     []byte{0xde, 0xca, 0xfb, 0xad},
	}
	expectAppendFrames(
		tp.framer,
		[]ackhandler.Frame{
			{Frame: &wire.ResetStreamFrame{}, Handler: &mtuFinderAckHandler{}}, // set any non-nil ackhandler.FrameHandler
			{Frame: &wire.MaxDataFrame{}},
		},
		[]ackhandler.StreamFrame{{Frame: f}},
	)
	buffer := getPacketBuffer()
	buffer.Data = append(buffer.Data, []byte("foobar")...)
	p, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.StreamFrames, 1)
	var sawResetStream, sawMaxData bool
	for _, frame := range p.Frames {
		switch frame.Frame.(type) {
		case *wire.ResetStreamFrame:
			sawResetStream = true
			require.Equal(t, frame.Handler, &mtuFinderAckHandler{})
		case *wire.MaxDataFrame:
			sawMaxData = true
			require.NotNil(t, frame.Handler)
			require.NotEqual(t, frame.Handler, &mtuFinderAckHandler{})
		}
	}
	require.True(t, sawResetStream)
	require.True(t, sawMaxData)
	require.Equal(t, f.StreamID, p.StreamFrames[0].Frame.StreamID)
	require.Equal(t, buffer.Data[:6], []byte("foobar")) // make sure the packet was actually appended
	require.Contains(t, string(buffer.Data), string(b))
}

func TestPack1RTTPacketWithACK(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 42, Smallest: 1}}}
	tp.framer.EXPECT().HasData()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any()).Return(ack)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	p, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Equal(t, ack, p.Ack)
}

// testObservedAddressSource is an observedAddressSource with an OBSERVED_ADDRESS frame due on path 0.
type testObservedAddressSource struct {
	frame   *wire.ObservedAddressFrame
	appends int
}

func (s *testObservedAddressSource) HasObservedAddress(id protocol.PathID) bool {
	return id == 0 && s.frame != nil
}

func (s *testObservedAddressSource) AppendObservedAddress(frames []ackhandler.Frame, id protocol.PathID, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	s.appends++
	if !s.HasObservedAddress(id) || s.frame.Length(v) > maxLen {
		return frames, 0
	}
	f := s.frame
	s.frame = nil
	return append(frames, ackhandler.Frame{Frame: f, Handler: emptyHandler{}}), f.Length(v)
}

// OBSERVED_ADDRESS frames are sent in 1-RTT packets. They are a reason to send a packet.
func TestPack1RTTPacketWithObservedAddress(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	f := &wire.ObservedAddressFrame{SequenceNumber: 1, Address: netip.MustParseAddrPort("192.0.2.1:443")}
	src := &testObservedAddressSource{frame: f}
	tp.packer.EnableAddressDiscovery(src)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData()
	// an ACK is only added if one is queued, since the packet is sent anyway
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	p, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.Frames, 1)
	require.Equal(t, f, p.Frames[0].Frame)
	require.Equal(t, 1, src.appends)

	// nothing else to send
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any())
	_, err = tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.ErrorIs(t, err, errNothingToPack)
	require.Equal(t, 1, src.appends)
}

// OBSERVED_ADDRESS frames are never sent in 0-RTT packets.
func TestPack0RTTPacketWithoutObservedAddress(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	src := &testObservedAddressSource{frame: &wire.ObservedAddressFrame{Address: netip.MustParseAddrPort("192.0.2.1:443")}}
	tp.packer.EnableAddressDiscovery(src)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any())
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42))
	cf := ackhandler.Frame{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}
	tp.framer.EXPECT().HasData().Return(true)
	tp.framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(fs []ackhandler.Frame, sf []ackhandler.StreamFrame, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			return append(fs, cf), sf, cf.Frame.Length(protocol.Version1)
		},
	)
	p, err := tp.packer.PackCoalescedPacket(false, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.PacketType0RTT, p.longHdrPackets[0].header.Type)
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, cf.Frame, p.longHdrPackets[0].frames[0].Frame)
	require.Zero(t, src.appends)
}

func TestPackPathChallengeAndPathResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	frames := []ackhandler.Frame{
		{Frame: &wire.PathChallengeFrame{}},
		{Frame: &wire.PathResponseFrame{}},
		{Frame: &wire.DataBlockedFrame{}},
	}
	expectAppendFrames(tp.framer, frames, nil)
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.Frames, 3)
	var sawPathChallenge, sawPathResponse bool
	for _, f := range p.Frames {
		switch f.Frame.(type) {
		case *wire.PathChallengeFrame:
			sawPathChallenge = true
			// this means that the frame won't be retransmitted.
			require.Nil(t, f.Handler)
		case *wire.PathResponseFrame:
			sawPathResponse = true
			// this means that the frame won't be retransmitted.
			require.Nil(t, f.Handler)
		default:
			require.NotNil(t, f.Handler)
		}
	}
	require.True(t, sawPathChallenge)
	require.True(t, sawPathResponse)
	require.NotZero(t, buffer.Len())
}

// Datagrams containing PATH_RESPONSE frames are expanded to 1200 bytes (section 8.2.2 of RFC 9000),
// unless the anti-amplification limit doesn't allow this.
func TestPackPathResponsePadding(t *testing.T) {
	t.Run("1-RTT packet", func(t *testing.T) {
		buf := packPathResponsePacket(t, nil, protocol.MaxByteCount)
		require.Len(t, buf, protocol.MinInitialPacketSize)
	})
	t.Run("not larger than the maximum packet size", func(t *testing.T) {
		buf := packPathResponsePacket(t, nil, 1100)
		require.Len(t, buf, 1100)
	})
	t.Run("address validated", func(t *testing.T) {
		buf := packPathResponsePacket(t, func(protocol.PathID) protocol.ByteCount { return protocol.MaxByteCount }, protocol.MaxByteCount)
		require.Len(t, buf, protocol.MinInitialPacketSize)
	})
	t.Run("anti-amplification limit", func(t *testing.T) {
		var pathIDs []protocol.PathID
		buf := packPathResponsePacket(t, func(id protocol.PathID) protocol.ByteCount {
			pathIDs = append(pathIDs, id)
			return protocol.MinInitialPacketSize - 1
		}, protocol.MaxByteCount)
		require.Less(t, len(buf), 100)
		require.Equal(t, []protocol.PathID{0}, pathIDs)
	})
}

func packPathResponsePacket(t *testing.T, budget func(protocol.PathID) protocol.ByteCount, maxPacketSize protocol.ByteCount) []byte {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.packer.amplificationBudget = budget
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	expectAppendFrames(tp.framer, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3}}}}, nil)
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3}}}}, p.Frames)
	require.Equal(t, buffer.Len(), p.Length)
	return buffer.Data
}

// Packets without PATH_CHALLENGE and PATH_RESPONSE frames are not expanded.
func TestPackNoPaddingWithoutPathResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	expectAppendFrames(tp.framer, []ackhandler.Frame{{Frame: &wire.DataBlockedFrame{MaximumData: 1337}}}, nil)
	buffer := getPacketBuffer()
	_, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Less(t, buffer.Len(), protocol.ByteCount(100))
}

// A PATH_RESPONSE frame can be sent in a 1-RTT packet that is coalesced with a Handshake packet,
// for example when the server responds to a PATH_CHALLENGE frame received in a 0-RTT packet.
func TestPackCoalescedPathResponsePadding(t *testing.T) {
	t.Run("expanded", func(t *testing.T) {
		buf := packCoalescedPathResponsePacket(t, protocol.MaxByteCount)
		require.Len(t, buf, protocol.MinInitialPacketSize)
	})
	t.Run("anti-amplification limit", func(t *testing.T) {
		buf := packCoalescedPathResponsePacket(t, protocol.MinInitialPacketSize-1)
		require.Less(t, len(buf), 200)
	})
}

func packCoalescedPathResponsePacket(t *testing.T, budget protocol.ByteCount) []byte {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.packer.amplificationBudget = func(protocol.PathID) protocol.ByteCount { return budget }
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false, gomock.Any())
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	tp.handshakeStream.Write([]byte("handshake"))
	expectAppendFrames(tp.framer, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3}}}}, nil)
	p, err := tp.packer.PackCoalescedPacket(false, 1350, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.NotNil(t, p.shortHdrPacket)
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3}}}}, p.shortHdrPacket.Frames)
	return p.buffer.Data
}

func TestPackDatagramFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)

	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any())
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.datagramQueue.Add(&wire.DatagramFrame{
		DataLenPresent: true,
		Data:           []byte("foobar"),
	})
	tp.framer.EXPECT().HasData()
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.Frames, 1)
	require.IsType(t, &wire.DatagramFrame{}, p.Frames[0].Frame)
	require.Equal(t, []byte("foobar"), p.Frames[0].Frame.(*wire.DatagramFrame).Data)
	require.NotEmpty(t, buffer.Data)
}

func TestPackLargeDatagramFrame(t *testing.T) {
	// If a packet contains an ACK, and doesn't have enough space for the DATAGRAM frame,
	// it should be skipped. It will be packed in the next packet.
	const maxPacketSize = 1000
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any()).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}})
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	f := &wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, maxPacketSize-10)}
	tp.datagramQueue.Add(f)
	tp.framer.EXPECT().HasData()
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, p.Ack)
	require.Empty(t, p.Frames)
	require.NotEmpty(t, buffer.Data)
	require.Equal(t, f, tp.datagramQueue.Peek()) // make sure the frame is still there

	// Now try packing again, but with a smaller packet size.
	// The DATAGRAM frame should now be dropped, as we can't expect to ever be able tosend it out.
	const newMaxPacketSize = maxPacketSize - 10
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any())
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData()
	buffer = getPacketBuffer()
	p, err = tp.packer.AppendPacket(buffer, newMaxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.ErrorIs(t, err, errNothingToPack)
	require.Nil(t, tp.datagramQueue.Peek()) // make sure the frame is gone
}

func TestPackRetransmissions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	f := &wire.CryptoFrame{Data: []byte("Initial")}
	tp.retransmissionQueue.addInitial(f)
	tp.retransmissionQueue.addHandshake(&wire.CryptoFrame{Data: []byte("Handshake")})
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false, gomock.Any())
	p, err := tp.packer.PackCoalescedPacket(false, 1000, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionInitial, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, f, p.longHdrPackets[0].frames[0].Frame)
	require.NotNil(t, p.longHdrPackets[0].frames[0].Handler)
}

func packMaxNumNonAckElicitingAcks(t *testing.T, tp *testPacketPacker, mockCtrl *gomock.Controller, maxPacketSize protocol.ByteCount) {
	t.Helper()
	for range protocol.MaxNonAckElicitingAcks {
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.framer.EXPECT().HasData().Return(true)
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any()).Return(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
		)
		expectAppendFrames(tp.framer, nil, nil)
		p, err := tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, monotime.Now(), protocol.Version1, 0)
		require.NoError(t, err)
		require.NotNil(t, p.Ack)
		require.Empty(t, p.Frames)
	}
}

func TestPackEvery20thPacketAckEliciting(t *testing.T) {
	const maxPacketSize = 1000
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)

	// send the maximum number of non-ACK-eliciting packets
	packMaxNumNonAckElicitingAcks(t, tp, mockCtrl, maxPacketSize)

	// Now there's nothing to send, so we shouldn't generate a packet just to send a PING
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	tp.framer.EXPECT().HasData().Return(true)
	expectAppendFrames(tp.framer, nil, nil)
	_, err := tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.ErrorIs(t, err, errNothingToPack)

	// Now we have an ACK to send. We should bundle a PING to make the packet ack-eliciting.
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any()).Return(
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
	)
	expectAppendFrames(tp.framer, nil, nil)
	p, err := tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Len(t, p.Frames, 1)
	require.Equal(t, &wire.PingFrame{}, p.Frames[0].Frame)
	require.Nil(t, p.Frames[0].Handler) // make sure the PING is not retransmitted if lost

	// make sure the next packet doesn't contain another PING
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any()).Return(
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
	)
	expectAppendFrames(tp.framer, nil, nil)
	p, err = tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, p.Ack)
	require.Empty(t, p.Frames)
}

func TestPackLongHeaderPadToAtLeast4Bytes(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))

	sealer := newMockShortHeaderSealer(mockCtrl)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.retransmissionQueue.addHandshake(&wire.PingFrame{})
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false, gomock.Any())

	packet, err := tp.packer.PackCoalescedPacket(false, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, packet)
	require.Len(t, packet.longHdrPackets, 1)
	require.Nil(t, packet.shortHdrPacket)

	hdr, _, _, err := wire.ParsePacket(packet.buffer.Data)
	require.NoError(t, err)
	data := packet.buffer.Data
	extHdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumberLen1, extHdr.PacketNumberLen)

	data = data[extHdr.ParsedLen():]
	require.Len(t, data, 4-1 /* packet number length */ +sealer.Overhead())
	// first bytes should be 2 PADDING frames...
	require.Equal(t, []byte{0, 0}, data[:2])
	// ...followed by the PING frame
	frameParser := wire.NewFrameParser(false, false, false)

	frameType, lt, err := frameParser.ParseType(data[2:], protocol.EncryptionHandshake)
	require.NoError(t, err)
	require.Equal(t, 1, lt)
	frame, l, err := frameParser.ParseLessCommonFrame(frameType, data[2+lt:], protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &wire.PingFrame{}, frame)
	require.Zero(t, l)
	require.Equal(t, sealer.Overhead(), len(data)-2-lt)
}

func TestPackShortHeaderPadToAtLeast4Bytes(t *testing.T) {
	// small stream ID, such that only a single byte is consumed
	f := &wire.StreamFrame{StreamID: 0x10, Fin: true}
	require.Equal(t, protocol.ByteCount(2), f.Length(protocol.Version1))

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	sealer := newMockShortHeaderSealer(mockCtrl)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	expectAppendFrames(tp.framer, nil, []ackhandler.StreamFrame{{Frame: f}})

	buffer := getPacketBuffer()
	_, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	// cut off the tag that the mock sealer added
	buffer.Data = buffer.Data[:buffer.Len()-protocol.ByteCount(sealer.Overhead())]
	data := buffer.Data

	l, _, pnLen, _, err := wire.ParseShortHeader(data, testPackerConnIDLen)
	require.NoError(t, err)
	payload := data[l:]
	require.Equal(t, protocol.PacketNumberLen1, pnLen)
	require.Len(t, payload, 4-1 /* packet number length */)
	// the first byte of the payload should be a PADDING frame...
	require.Equal(t, byte(0), payload[0])

	// ... followed by the STREAM frame
	frameParser := wire.NewFrameParser(false, false, false)
	frameType, l, err := frameParser.ParseType(payload[1:], protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, 1, l)
	require.True(t, frameType.IsStreamFrameType())

	frame, frameLen, err := wire.ParseStreamFrame(payload[1+l:], frameType, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(payload)-2, frameLen)
}

func TestPackInitialProbePacket(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		t.Setenv(disableClientHelloScramblingEnv, "true")
		testPackProbePacket(t, protocol.EncryptionInitial, protocol.PerspectiveClient)
	})
	t.Run("server", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionInitial, protocol.PerspectiveServer)
	})
}

func TestPackHandshakeProbePacket(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionHandshake, protocol.PerspectiveClient)
	})
	t.Run("server", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionHandshake, protocol.PerspectiveServer)
	})
}

func testPackProbePacket(t *testing.T, encLevel protocol.EncryptionLevel, perspective protocol.Perspective) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, perspective)

	var cryptoData []byte
	switch encLevel {
	case protocol.EncryptionInitial:
		tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		var err error
		cryptoData, err = getClientHello("")
		require.NoError(t, err)
		tp.packer.initialStream.Write(cryptoData)
	case protocol.EncryptionHandshake:
		tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		cryptoData = []byte("foobar")
		tp.packer.handshakeStream.Write(cryptoData)
	}
	tp.ackFramer.EXPECT().GetAckFrame(encLevel, gomock.Any(), false, gomock.Any())
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), encLevel).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), encLevel).Return(protocol.PacketNumber(0x42))

	p, err := tp.packer.PackPTOProbePacket(encLevel, maxPacketSize, false, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 1)
	packet := p.longHdrPackets[0]
	require.Equal(t, encLevel, packet.EncryptionLevel())
	if encLevel == protocol.EncryptionInitial {
		require.GreaterOrEqual(t, p.buffer.Len(), protocol.ByteCount(protocol.MinInitialPacketSize))
		require.Equal(t, maxPacketSize, p.buffer.Len())
	}
	require.Len(t, packet.frames, 1)
	require.Equal(t, cryptoData, packet.frames[0].Frame.(*wire.CryptoFrame).Data)
	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Len(t, hdrs, 1)
	switch encLevel {
	case protocol.EncryptionInitial:
		require.Equal(t, protocol.PacketTypeInitial, hdrs[0].Type)
	case protocol.EncryptionHandshake:
		require.Equal(t, protocol.PacketTypeHandshake, hdrs[0].Type)
	}
	require.Empty(t, more)
}

func TestPack1RTTProbePacket(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 999

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false, gomock.Any())
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.framer.EXPECT().HasData().Return(true)
	tp.framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
		func(cf []ackhandler.Frame, sf []ackhandler.StreamFrame, size protocol.ByteCount, _ monotime.Time, v protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			f, split := (&wire.StreamFrame{Data: make([]byte, 2*maxPacketSize)}).MaybeSplitOffFrame(size, v)
			require.True(t, split)
			return cf, append(sf, ackhandler.StreamFrame{Frame: f}), f.Length(v)
		},
	)

	p, err := tp.packer.PackPTOProbePacket(protocol.Encryption1RTT, maxPacketSize, false, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.True(t, p.IsOnlyShortHeaderPacket())
	require.Empty(t, p.longHdrPackets)
	require.NotNil(t, p.shortHdrPacket)
	packet := p.shortHdrPacket
	require.Empty(t, packet.Frames)
	require.Len(t, packet.StreamFrames, 1)
	require.Equal(t, maxPacketSize, packet.Length)
}

func TestPackPTOProbePacketNothingToPack(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testPackPTOProbePacketNothingToPack(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testPackPTOProbePacketNothingToPack(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testPackPTOProbePacketNothingToPack(t, protocol.Encryption1RTT)
	})
}

func testPackPTOProbePacketNothingToPack(t *testing.T, encLevel protocol.EncryptionLevel) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)

	switch encLevel {
	case protocol.EncryptionInitial:
		tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).Times(2)
	case protocol.EncryptionHandshake:
		tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).Times(2)
	case protocol.Encryption1RTT:
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).Times(2)
		tp.framer.EXPECT().HasData().Times(2)
	}
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), encLevel).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).MaxTimes(2)
	tp.ackFramer.EXPECT().GetAckFrame(encLevel, gomock.Any(), true, gomock.Any()).Times(2)

	// don't force a PING to be sent
	packet, err := tp.packer.PackPTOProbePacket(encLevel, maxPacketSize, false, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Nil(t, packet)

	// now force a PING to be sent
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), encLevel).Return(protocol.PacketNumber(0x42))
	packet, err = tp.packer.PackPTOProbePacket(encLevel, maxPacketSize, true, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.NotNil(t, packet)
	var frames []ackhandler.Frame
	switch encLevel {
	case protocol.EncryptionInitial, protocol.EncryptionHandshake:
		require.Len(t, packet.longHdrPackets, 1)
		require.Nil(t, packet.shortHdrPacket)
		require.Equal(t, encLevel, packet.longHdrPackets[0].EncryptionLevel())
		frames = packet.longHdrPackets[0].frames
	case protocol.Encryption1RTT:
		require.Empty(t, packet.longHdrPackets)
		require.NotNil(t, packet.shortHdrPacket)
		frames = packet.shortHdrPacket.Frames
	}

	require.Len(t, frames, 1)
	require.Equal(t, &wire.PingFrame{}, frames[0].Frame)
	require.Equal(t, emptyHandler{}, frames[0].Handler)
}

func TestPackMTUProbePacket(t *testing.T) {
	const (
		maxPacketSize   protocol.ByteCount = 1000
		probePacketSize                    = maxPacketSize + 42
	)

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43))
	ping := ackhandler.Frame{Frame: &wire.PingFrame{}}
	p, buffer, err := tp.packer.PackMTUProbePacket(ping, probePacketSize, protocol.Version1, 0)
	require.NoError(t, err)
	require.Equal(t, probePacketSize, p.Length)
	require.Equal(t, protocol.PacketNumber(0x43), p.PacketNumber)
	require.Len(t, buffer.Data, int(probePacketSize))
	require.True(t, p.IsPathMTUProbePacket)
	require.False(t, p.IsPathProbePacket)
}

func TestPackPathProbePacket(t *testing.T) {
	t.Run("expanded to 1200 bytes", func(t *testing.T) {
		testPackPathProbePacket(t, protocol.MaxByteCount, protocol.MinInitialPacketSize)
	})
	// The anti-amplification limit doesn't allow expanding the datagram to 1200 bytes (section 8.2.1 of RFC 9000).
	t.Run("limited by the anti-amplification limit", func(t *testing.T) {
		testPackPathProbePacket(t, 300, 300)
	})
}

func testPackPathProbePacket(t *testing.T, maxPacketSize, expectedSize protocol.ByteCount) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43))

	p, buf, err := tp.packer.PackPathProbePacket(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		[]ackhandler.Frame{
			{Frame: &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
			{Frame: &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}},
		},
		maxPacketSize,
		protocol.Version1,
		0,
	)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x43), p.PacketNumber)
	require.Nil(t, p.Ack)
	require.Empty(t, p.StreamFrames)
	require.Len(t, p.Frames, 2)
	// the frame order is randomized
	frames := []wire.Frame{p.Frames[0].Frame, p.Frames[1].Frame}
	require.Contains(t, frames, &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}})
	require.Contains(t, frames, &wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}})
	require.Len(t, buf.Data, int(expectedSize))
	require.Equal(t, expectedSize, p.Length)
	require.True(t, p.IsPathProbePacket)
	require.False(t, p.IsPathMTUProbePacket)
}

func TestPackPathProbePacketTooLarge(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.PathID(0), protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)

	// 1 byte for the first byte, 4 bytes for the connection ID, 2 bytes for the packet number,
	// 9 bytes for the PATH_CHALLENGE frame, and 7 bytes for the AEAD overhead of the mock sealer
	_, _, err := tp.packer.PackPathProbePacket(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		[]ackhandler.Frame{{Frame: &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}}},
		1+4+2+9+7-1,
		protocol.Version1,
		0,
	)
	require.ErrorIs(t, err, errNothingToPack)
}

// goldenSealer protects packets like the AEAD and the header protection of RFC 9001,
// using fixed keys, so that the packer output is deterministic.
type goldenSealer struct {
	aead cipher.AEAD
	iv   [12]byte
	hp   cipher.Block
}

var _ handshake.ShortHeaderSealer = &goldenSealer{}

func newGoldenSealer(t *testing.T, label byte) *goldenSealer {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{label}, 16))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	hp, err := aes.NewCipher(bytes.Repeat([]byte{^label}, 16))
	require.NoError(t, err)
	s := &goldenSealer{aead: aead, hp: hp}
	for i := range s.iv {
		s.iv[i] = label + byte(i)
	}
	return s
}

func (s *goldenSealer) nonce(pathID protocol.PathID, pn protocol.PacketNumber) []byte {
	nonce := s.iv
	binary.BigEndian.PutUint32(nonce[:4], binary.BigEndian.Uint32(s.iv[:4])^uint32(pathID))
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(s.iv[4:])^uint64(pn))
	return nonce[:]
}

func (s *goldenSealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	return s.aead.Seal(dst, s.nonce(0, pn), src, ad)
}

func (s *goldenSealer) SealForPath(dst, src []byte, pathID protocol.PathID, pn protocol.PacketNumber, ad []byte) []byte {
	return s.aead.Seal(dst, s.nonce(pathID, pn), src, ad)
}

func (s *goldenSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	var mask [16]byte
	s.hp.Encrypt(mask[:], sample)
	if *firstByte&0x80 > 0 {
		*firstByte ^= mask[0] & 0xf
	} else {
		*firstByte ^= mask[0] & 0x1f
	}
	for i := range pnBytes {
		pnBytes[i] ^= mask[i+1]
	}
}

func (s *goldenSealer) Overhead() int                  { return s.aead.Overhead() }
func (s *goldenSealer) KeyPhase() protocol.KeyPhaseBit { return protocol.KeyPhaseZero }

// goldenSealingManager returns the sealer of an encryption level, or the error set for it.
type goldenSealingManager struct {
	sealers map[protocol.EncryptionLevel]*goldenSealer
	errs    map[protocol.EncryptionLevel]error
}

func (m *goldenSealingManager) get(encLevel protocol.EncryptionLevel) (*goldenSealer, error) {
	if err, ok := m.errs[encLevel]; ok {
		return nil, err
	}
	return m.sealers[encLevel], nil
}

func (m *goldenSealingManager) GetInitialSealer() (handshake.LongHeaderSealer, error) {
	s, err := m.get(protocol.EncryptionInitial)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (m *goldenSealingManager) GetHandshakeSealer() (handshake.LongHeaderSealer, error) {
	s, err := m.get(protocol.EncryptionHandshake)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (m *goldenSealingManager) Get0RTTSealer() (handshake.LongHeaderSealer, error) {
	s, err := m.get(protocol.Encryption0RTT)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (m *goldenSealingManager) Get1RTTSealer() (handshake.ShortHeaderSealer, error) {
	s, err := m.get(protocol.Encryption1RTT)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// goldenPacketNumberManager hands out consecutive packet numbers.
// 0-RTT and 1-RTT packets share a packet number space.
type goldenPacketNumberManager struct {
	next map[protocol.EncryptionLevel]protocol.PacketNumber
}

func (m *goldenPacketNumberManager) space(encLevel protocol.EncryptionLevel) protocol.EncryptionLevel {
	if encLevel == protocol.Encryption0RTT {
		return protocol.Encryption1RTT
	}
	return encLevel
}

func (m *goldenPacketNumberManager) PeekPacketNumber(_ protocol.PathID, encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.next[m.space(encLevel)], protocol.PacketNumberLen2
}

func (m *goldenPacketNumberManager) PopPacketNumber(_ protocol.PathID, encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	pn := m.next[m.space(encLevel)]
	m.next[m.space(encLevel)]++
	return pn
}

// goldenAckFrameSource returns every queued ACK frame once.
type goldenAckFrameSource struct {
	acks map[protocol.EncryptionLevel]*wire.AckFrame
}

func (s *goldenAckFrameSource) GetAckFrame(encLevel protocol.EncryptionLevel, _ monotime.Time, _ bool, _ protocol.PathID) *wire.AckFrame {
	ack := s.acks[encLevel]
	delete(s.acks, encLevel)
	return ack
}

func (s *goldenAckFrameSource) AckDuePaths(monotime.Time) []protocol.PathID { return nil }

// goldenFrameSource returns the queued frames in order.
type goldenFrameSource struct {
	controlFrames []ackhandler.Frame
	streamFrames  []ackhandler.StreamFrame
}

func (s *goldenFrameSource) HasData() bool {
	return len(s.controlFrames) > 0 || len(s.streamFrames) > 0
}

func (s *goldenFrameSource) Append(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	maxLen protocol.ByteCount,
	_ monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	var length protocol.ByteCount
	for len(s.controlFrames) > 0 && s.controlFrames[0].Frame.Length(v) <= maxLen-length {
		length += s.controlFrames[0].Frame.Length(v)
		frames = append(frames, s.controlFrames[0])
		s.controlFrames = s.controlFrames[1:]
	}
	for len(s.streamFrames) > 0 && s.streamFrames[0].Frame.Length(v) <= maxLen-length {
		length += s.streamFrames[0].Frame.Length(v)
		streamFrames = append(streamFrames, s.streamFrames[0])
		s.streamFrames = s.streamFrames[1:]
	}
	return frames, streamFrames, length
}

// The output of the packer on a single-path connection must not change when multipath support is added.
// This test packs a fixed sequence of packets and compares them to the output of the packer before
// IETF Multipath QUIC was implemented.
func TestPackSinglePathGolden(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			got := packGoldenSinglePathPackets(t, pers)
			want := goldenSinglePathPackets[pers]
			var gotDigests []string
			for _, p := range got {
				sum := sha256.Sum256(p.data)
				gotDigests = append(gotDigests, fmt.Sprintf("%s %d %x", p.name, len(p.data), sum[:8]))
			}
			require.Equal(t, want, gotDigests)
		})
	}
}

type goldenPacket struct {
	name string
	data []byte
}

// name, length and the first 8 bytes of the SHA-256 hash of every packet
var goldenSinglePathPackets = map[protocol.Perspective][]string{
	protocol.PerspectiveClient: {
		"initial 1252 54de42a9aea5a853",
		"initial ack 1252 ea4e4b87aa7ee33c",
		"handshake and 1-RTT 188 3187014a5a755e28",
		"handshake 1252 89f7b2f70d0c05bc",
		"1-RTT 1318 7a437c30b4cf3987",
		"1-RTT ack 32 691beef6501d0db3",
		"1-RTT probe 29 f57bef2a19afa09b",
		"MTU probe 1400 afc70524eca6a3f5",
		"path probe 1200 ddf208a0c0f2d99b",
		"CONNECTION_CLOSE 40 65dd8959b48d3443",
		"application CONNECTION_CLOSE 34 a0e473903e616a1d",
	},
	protocol.PerspectiveServer: {
		"initial 1252 af1087ca2895478d",
		"initial ack 47 68eabe5607420164",
		"handshake and 1-RTT 188 6530d20039097758",
		"handshake 1252 89f7b2f70d0c05bc",
		"1-RTT 1318 dee16ce996e8ed40",
		"1-RTT ack 32 1a12371e0cb2cf1e",
		"1-RTT probe 29 445366532517bff5",
		"MTU probe 1400 ac41101ba494945e",
		"path probe 1200 6be76d6af9a417ee",
		"CONNECTION_CLOSE 40 f05bb41f73af4302",
		"application CONNECTION_CLOSE 34 a1ec8b067bf3ebb7",
	},
}

func packGoldenSinglePathPackets(t *testing.T, pers protocol.Perspective) []goldenPacket {
	const maxPacketSize protocol.ByteCount = 1252
	now := monotime.Time(time.Hour)
	v := protocol.Version1
	destConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4})
	srcConnID := protocol.ParseConnectionID([]byte{0xca, 0xfe, 5, 6})

	// The initial crypto stream doesn't scramble the server's data.
	initialStream := newInitialCryptoStream(false)
	handshakeStream := newCryptoStream()
	sealingManager := &goldenSealingManager{
		sealers: map[protocol.EncryptionLevel]*goldenSealer{
			protocol.EncryptionInitial:   newGoldenSealer(t, 1),
			protocol.EncryptionHandshake: newGoldenSealer(t, 2),
			protocol.Encryption0RTT:      newGoldenSealer(t, 3),
			protocol.Encryption1RTT:      newGoldenSealer(t, 4),
		},
		errs: map[protocol.EncryptionLevel]error{
			protocol.EncryptionHandshake: handshake.ErrKeysNotYetAvailable,
			protocol.Encryption1RTT:      handshake.ErrKeysNotYetAvailable,
		},
	}
	if pers == protocol.PerspectiveServer {
		sealingManager.errs[protocol.Encryption0RTT] = handshake.ErrKeysNotYetAvailable
	}
	pnManager := &goldenPacketNumberManager{next: map[protocol.EncryptionLevel]protocol.PacketNumber{
		protocol.EncryptionInitial:   0,
		protocol.EncryptionHandshake: 0x10,
		protocol.Encryption1RTT:      0x100,
	}}
	acks := &goldenAckFrameSource{acks: make(map[protocol.EncryptionLevel]*wire.AckFrame)}
	framer := &goldenFrameSource{}
	datagramQueue := newDatagramQueue(func() {}, utils.DefaultLogger)
	retransmissionQueue := newRetransmissionQueue()
	packer := newPacketPacker(
		srcConnID,
		func() protocol.ConnectionID { return destConnID },
		initialStream,
		handshakeStream,
		pnManager,
		retransmissionQueue,
		sealingManager,
		framer,
		acks,
		datagramQueue,
		pers,
	)
	packer.rand = *mrand.New(mrand.NewPCG(1, 2))
	if pers == protocol.PerspectiveClient {
		packer.SetToken([]byte("token"))
	}

	var packets []goldenPacket
	add := func(name string, data []byte) {
		packets = append(packets, goldenPacket{name: name, data: slices.Clone(data)})
	}
	stream := func(id protocol.StreamID, offset protocol.ByteCount, length int, dataLenPresent bool) ackhandler.StreamFrame {
		return ackhandler.StreamFrame{Frame: &wire.StreamFrame{
			StreamID:       id,
			Offset:         offset,
			Data:           bytes.Repeat([]byte{byte(id)}, length),
			DataLenPresent: dataLenPresent,
		}}
	}

	// Initial packet, coalesced with a 0-RTT packet for the client
	initialStream.Write(bytes.Repeat([]byte{'i'}, 400))
	acks.acks[protocol.EncryptionInitial] = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 2}}, DelayTime: 3 * time.Millisecond}
	if pers == protocol.PerspectiveClient {
		framer.streamFrames = []ackhandler.StreamFrame{stream(0, 0, 50, true)}
	}
	p, err := packer.PackCoalescedPacket(false, maxPacketSize, now, v, 0)
	require.NoError(t, err)
	add("initial", p.buffer.Data)

	// Initial ACK-only packet
	acks.acks[protocol.EncryptionInitial] = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 5, Largest: 7}, {Smallest: 0, Largest: 3}}}
	p, err = packer.PackCoalescedPacket(true, maxPacketSize, now, v, 0)
	require.NoError(t, err)
	add("initial ack", p.buffer.Data)

	// Handshake packet with a retransmission, coalesced with a 1-RTT packet
	delete(sealingManager.errs, protocol.EncryptionHandshake)
	delete(sealingManager.errs, protocol.Encryption1RTT)
	sealingManager.errs[protocol.EncryptionInitial] = handshake.ErrKeysDropped
	sealingManager.errs[protocol.Encryption0RTT] = handshake.ErrKeysDropped
	handshakeStream.Write(bytes.Repeat([]byte{'h'}, 300))
	retransmissionQueue.addHandshake(&wire.CryptoFrame{Offset: 10, Data: bytes.Repeat([]byte{'r'}, 20)})
	acks.acks[protocol.EncryptionHandshake] = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0x10, Largest: 0x12}}, DelayTime: time.Millisecond}
	acks.acks[protocol.Encryption1RTT] = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 1}}, DelayTime: 2 * time.Millisecond}
	framer.controlFrames = []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}}
	framer.streamFrames = []ackhandler.StreamFrame{stream(4, 100, 80, false)}
	p, err = packer.PackCoalescedPacket(false, maxPacketSize, now, v, 0)
	require.NoError(t, err)
	add("handshake and 1-RTT", p.buffer.Data)
	handshakeStream.Write(bytes.Repeat([]byte{'h'}, 2000))
	p, err = packer.PackCoalescedPacket(false, maxPacketSize, now, v, 0)
	require.NoError(t, err)
	add("handshake", p.buffer.Data)
	sealingManager.errs[protocol.EncryptionHandshake] = handshake.ErrKeysDropped

	// 1-RTT packets
	buf := getPacketBuffer()
	acks.acks[protocol.Encryption1RTT] = &wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 10, Largest: 20}, {Smallest: 2, Largest: 5}},
		DelayTime: 5 * time.Millisecond,
		ECT0:      3,
		ECT1:      0,
		ECNCE:     1,
	}
	require.NoError(t, datagramQueue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("datagram")}))
	retransmissionQueue.addAppData(&wire.MaxStreamDataFrame{StreamID: 4, MaximumStreamData: 1000})
	framer.controlFrames = []ackhandler.Frame{
		{Frame: &wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{9, 8, 7, 6}),
			StatelessResetToken: protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		}},
		{Frame: &wire.ResetStreamFrame{StreamID: 8, ErrorCode: 42, FinalSize: 1000}},
		{Frame: &wire.PingFrame{}},
	}
	framer.streamFrames = []ackhandler.StreamFrame{stream(0, 50, 100, true), stream(4, 180, 1100, false)}
	_, err = packer.AppendPacket(buf, maxPacketSize, now, v, 0)
	require.NoError(t, err)
	_, err = packer.AppendPacket(buf, maxPacketSize, now, v, 0)
	require.NoError(t, err)
	add("1-RTT", buf.Data)

	acks.acks[protocol.Encryption1RTT] = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 30}}}
	_, buf, err = packer.PackAckOnlyPacket(maxPacketSize, now, v, 0)
	require.NoError(t, err)
	add("1-RTT ack", buf.Data)

	p, err = packer.PackPTOProbePacket(protocol.Encryption1RTT, maxPacketSize, true, now, v, 0)
	require.NoError(t, err)
	add("1-RTT probe", p.buffer.Data)

	_, buf, err = packer.PackMTUProbePacket(ackhandler.Frame{Frame: &wire.PingFrame{}}, 1400, v, 0)
	require.NoError(t, err)
	add("MTU probe", buf.Data)

	_, buf, err = packer.PackPathProbePacket(
		protocol.ParseConnectionID([]byte{5, 5, 5, 5}),
		[]ackhandler.Frame{{Frame: &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}}},
		protocol.MinInitialPacketSize,
		v,
		0,
	)
	require.NoError(t, err)
	add("path probe", buf.Data)

	p, err = packer.PackConnectionClose(&qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: "violation"}, maxPacketSize, v, 0)
	require.NoError(t, err)
	add("CONNECTION_CLOSE", p.buffer.Data)

	p, err = packer.PackApplicationClose(&qerr.ApplicationError{ErrorCode: 0x42, ErrorMessage: "bye"}, maxPacketSize, v, 0)
	require.NoError(t, err)
	add("application CONNECTION_CLOSE", p.buffer.Data)
	return packets
}

// multipathAckFrameSource returns the PATH_ACK frames queued for every path once.
type multipathAckFrameSource struct {
	acks map[protocol.PathID]*wire.AckFrame
}

func (s *multipathAckFrameSource) GetAckFrame(encLevel protocol.EncryptionLevel, _ monotime.Time, _ bool, pathID protocol.PathID) *wire.AckFrame {
	if encLevel != protocol.Encryption1RTT {
		return nil
	}
	ack := s.acks[pathID]
	delete(s.acks, pathID)
	return ack
}

func (s *multipathAckFrameSource) AckDuePaths(monotime.Time) []protocol.PathID {
	return slices.Sorted(maps.Keys(s.acks))
}

// multipathPacketNumberManager hands out consecutive packet numbers for every path.
type multipathPacketNumberManager struct {
	next map[protocol.PathID]protocol.PacketNumber
}

func (m *multipathPacketNumberManager) PeekPacketNumber(pathID protocol.PathID, _ protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.next[pathID], protocol.PacketNumberLen2
}

func (m *multipathPacketNumberManager) PopPacketNumber(pathID protocol.PathID, _ protocol.EncryptionLevel) protocol.PacketNumber {
	pn := m.next[pathID]
	m.next[pathID]++
	return pn
}

// multipathPathFrameSource holds the frames that need to be sent on a path.
type multipathPathFrameSource struct {
	frames map[protocol.PathID][]ackhandler.Frame
}

func (s *multipathPathFrameSource) HasPathFrames(pathID protocol.PathID) bool {
	return len(s.frames[pathID]) > 0
}

func (s *multipathPathFrameSource) AppendPathFrames(frames []ackhandler.Frame, pathID protocol.PathID, maxLen protocol.ByteCount, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	for len(s.frames[pathID]) > 0 && length+s.frames[pathID][0].Frame.Length(v) <= maxLen {
		length += s.frames[pathID][0].Frame.Length(v)
		frames = append(frames, s.frames[pathID][0])
		s.frames[pathID] = s.frames[pathID][1:]
	}
	return frames, length
}

// openGoldenShortHeaderPacket removes the packet protection applied by a goldenSealer.
// The nonce depends on the path ID.
func openGoldenShortHeaderPacket(t *testing.T, s *goldenSealer, data []byte, connIDLen int, pathID protocol.PathID) (protocol.PacketNumber, []byte) {
	t.Helper()
	data = slices.Clone(data)
	pnOffset := 1 + connIDLen
	var mask [16]byte
	s.hp.Encrypt(mask[:], data[pnOffset+4:pnOffset+4+16])
	data[0] ^= mask[0] & 0x1f
	pnLen := int(data[0]&0x3) + 1
	for i := range pnLen {
		data[pnOffset+i] ^= mask[i+1]
	}
	hdrLen, pn, _, _, err := wire.ParseShortHeader(data, connIDLen)
	require.NoError(t, err)
	payload, err := s.aead.Open(nil, s.nonce(pathID, pn), data[hdrLen:], data[:hdrLen])
	require.NoError(t, err, "decrypting packet for path %d", pathID)
	return pn, payload
}

type multipathTestPacker struct {
	packer     *packetPacker
	sealer     *goldenSealer
	acks       *multipathAckFrameSource
	pathFrames *multipathPathFrameSource
	framer     *goldenFrameSource
}

var multipathTestDestConnIDs = map[protocol.PathID]protocol.ConnectionID{
	0: protocol.ParseConnectionID([]byte{0, 0, 0, 0}),
	1: protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
	2: protocol.ParseConnectionID([]byte{2, 2, 2, 2}),
}

func newMultipathTestPacker(t *testing.T) *multipathTestPacker {
	sealer := newGoldenSealer(t, 4)
	acks := &multipathAckFrameSource{acks: make(map[protocol.PathID]*wire.AckFrame)}
	pathFrames := &multipathPathFrameSource{frames: make(map[protocol.PathID][]ackhandler.Frame)}
	framer := &goldenFrameSource{}
	packer := newPacketPacker(
		protocol.ParseConnectionID([]byte{9, 9, 9, 9}),
		func() protocol.ConnectionID { return multipathTestDestConnIDs[0] },
		newInitialCryptoStream(false),
		newCryptoStream(),
		&multipathPacketNumberManager{next: map[protocol.PathID]protocol.PacketNumber{0: 0x100, 1: 0x200, 2: 0x300}},
		newRetransmissionQueue(),
		&goldenSealingManager{
			sealers: map[protocol.EncryptionLevel]*goldenSealer{protocol.Encryption1RTT: sealer},
			errs: map[protocol.EncryptionLevel]error{
				protocol.EncryptionInitial:   handshake.ErrKeysDropped,
				protocol.EncryptionHandshake: handshake.ErrKeysDropped,
				protocol.Encryption0RTT:      handshake.ErrKeysDropped,
			},
		},
		framer,
		acks,
		newDatagramQueue(func() {}, utils.DefaultLogger),
		protocol.PerspectiveServer,
	)
	packer.EnableMultipath(func(id protocol.PathID) (protocol.ConnectionID, bool) {
		require.NotZero(t, id, "path 0 uses the connection ID of the connection ID manager")
		connID, ok := multipathTestDestConnIDs[id]
		return connID, ok
	}, pathFrames)
	return &multipathTestPacker{packer: packer, sealer: sealer, acks: acks, pathFrames: pathFrames, framer: framer}
}

func appendFrames(t *testing.T, frames ...wire.Frame) []byte {
	t.Helper()
	var b []byte
	for _, f := range frames {
		var err error
		b, err = f.Append(b, protocol.Version1)
		require.NoError(t, err)
	}
	return b
}

func TestPackMultipathPacket(t *testing.T) {
	tp := newMultipathTestPacker(t)
	ack0 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}, PathID: 0, HasPathID: true}
	ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 4}}, PathID: 1, HasPathID: true}
	ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 20}}, PathID: 2, HasPathID: true}
	tp.acks.acks = map[protocol.PathID]*wire.AckFrame{0: ack0, 1: ack1, 2: ack2}
	pathResponse := &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	tp.pathFrames.frames[2] = []ackhandler.Frame{{Frame: pathResponse}}
	tp.framer.controlFrames = []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: 1000}}}

	buf := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buf, protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(2), p.PathID)
	require.Equal(t, protocol.PacketNumber(0x300), p.PacketNumber)
	require.Equal(t, multipathTestDestConnIDs[2], p.DestConnID)
	// the PATH_ACK for the path the packet is sent on comes first, followed by the PATH_ACKs of the other paths
	require.Equal(t, ack2, p.Ack)
	require.Equal(t, []*wire.AckFrame{ack0, ack1}, p.ExtraAcks)
	require.Len(t, p.Frames, 2)
	require.Contains(t, []wire.Frame{p.Frames[0].Frame, p.Frames[1].Frame}, pathResponse)

	// the packet is sent to the path's connection ID, and the nonce contains the path ID
	connID, err := wire.ParseConnectionID(buf.Data, 4)
	require.NoError(t, err)
	require.Equal(t, multipathTestDestConnIDs[2], connID)
	pn, payload := openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 2)
	require.Equal(t, protocol.PacketNumber(0x300), pn)
	require.True(t, bytes.HasPrefix(payload, appendFrames(t, ack2, ack0, ack1)))

	// The extension uses the nonce of RFC 9001 for path 0.
	tp.framer.controlFrames = []ackhandler.Frame{{Frame: &wire.PingFrame{}}}
	buf = getPacketBuffer()
	p, err = tp.packer.AppendPacket(buf, protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.Zero(t, p.PathID)
	require.Equal(t, protocol.PacketNumber(0x100), p.PacketNumber)
	require.Nil(t, p.Ack)
	require.Empty(t, p.ExtraAcks)
	connID, err = wire.ParseConnectionID(buf.Data, 4)
	require.NoError(t, err)
	require.Equal(t, multipathTestDestConnIDs[0], connID)
	_, payload = openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 0)
	// the packet number and the payload are padded to 4 bytes
	require.Equal(t, append([]byte{0}, appendFrames(t, &wire.PingFrame{})...), payload)
}

// PATH_ACK frames for other paths are only added if they fit.
func TestPackMultipathPacketExtraAcksDontFit(t *testing.T) {
	tp := newMultipathTestPacker(t)
	ack0 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}, PathID: 0, HasPathID: true}
	ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 4}}, PathID: 1, HasPathID: true}
	tp.acks.acks = map[protocol.PathID]*wire.AckFrame{0: ack0, 1: ack1}
	// The packet only has space for a single PATH_ACK frame.
	p, buf, err := tp.packer.PackAckOnlyPacket(40, monotime.Now(), protocol.Version1, 0)
	require.NoError(t, err)
	require.LessOrEqual(t, buf.Len(), protocol.ByteCount(40))
	require.Equal(t, ack0, p.Ack)
	require.Empty(t, p.ExtraAcks)
	// the PATH_ACK for path 1 is still queued
	require.Contains(t, tp.acks.acks, protocol.PathID(1))

	// An ACK-only packet contains the PATH_ACK frames of all paths.
	p, buf, err = tp.packer.PackAckOnlyPacket(protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1, 2)
	require.NoError(t, err)
	require.Nil(t, p.Ack)
	require.Equal(t, []*wire.AckFrame{ack1}, p.ExtraAcks)
	_, payload := openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 2)
	require.True(t, bytes.HasPrefix(payload, appendFrames(t, ack1)))
}

func TestPackMultipathConnectionClose(t *testing.T) {
	tp := newMultipathTestPacker(t)
	p, err := tp.packer.PackConnectionClose(&qerr.TransportError{ErrorCode: qerr.NoViablePathError}, protocol.MaxPacketBufferSize, protocol.Version1, 1)
	require.NoError(t, err)
	require.Empty(t, p.longHdrPackets)
	require.NotNil(t, p.shortHdrPacket)
	require.Equal(t, uint64(1), p.shortHdrPacket.PathID)
	require.Equal(t, protocol.PacketNumber(0x200), p.shortHdrPacket.PacketNumber)
	connID, err := wire.ParseConnectionID(p.buffer.Data, 4)
	require.NoError(t, err)
	require.Equal(t, multipathTestDestConnIDs[1], connID)
	_, payload := openGoldenShortHeaderPacket(t, tp.sealer, p.buffer.Data, 4, 1)
	require.Equal(t, appendFrames(t, &wire.ConnectionCloseFrame{ErrorCode: uint64(qerr.NoViablePathError)}), payload)
}

// Packets validating a path of IETF Multipath QUIC carry the PATH_CHALLENGE and PATH_RESPONSE frames,
// and the PATH_ACK frame of the path. They are padded as requested.
func TestPackMultipathProbePacket(t *testing.T) {
	tp := newMultipathTestPacker(t)
	ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}, PathID: 1, HasPathID: true}
	ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 7}}, PathID: 2, HasPathID: true}
	tp.acks.acks = map[protocol.PathID]*wire.AckFrame{1: ack1, 2: ack2}
	challenge := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3}}
	response := &wire.PathResponseFrame{Data: [8]byte{4, 5, 6}}

	p, buf, err := tp.packer.PackMultipathProbePacket(1, multipathTestDestConnIDs[1], []ackhandler.Frame{{Frame: challenge}, {Frame: response}}, 1500, 1200, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.True(t, p.IsPathProbePacket)
	require.Equal(t, uint64(1), p.PathID)
	require.Equal(t, protocol.PacketNumber(0x200), p.PacketNumber)
	require.Equal(t, multipathTestDestConnIDs[1], p.DestConnID)
	require.Equal(t, protocol.ByteCount(1200), p.Length)
	require.Equal(t, 1200, len(buf.Data))
	// only the PATH_ACK frame of this path is added
	require.Equal(t, ack1, p.Ack)
	require.Empty(t, p.ExtraAcks)
	require.Contains(t, tp.acks.acks, protocol.PathID(2))
	require.Len(t, p.Frames, 2)
	for _, f := range p.Frames {
		require.NotNil(t, f.Handler)
	}
	connID, err := wire.ParseConnectionID(buf.Data, 4)
	require.NoError(t, err)
	require.Equal(t, multipathTestDestConnIDs[1], connID)
	pn, payload := openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 1)
	require.Equal(t, protocol.PacketNumber(0x200), pn)
	require.True(t, bytes.HasPrefix(payload, appendFrames(t, ack1)))

	// The packet isn't padded if the padding doesn't fit.
	p, buf, err = tp.packer.PackMultipathProbePacket(2, multipathTestDestConnIDs[2], []ackhandler.Frame{{Frame: challenge}}, 100, 1200, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(100), p.Length)
	require.Equal(t, 100, len(buf.Data))
	require.Equal(t, ack2, p.Ack)
	_, payload = openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 2)
	require.True(t, bytes.HasPrefix(payload, appendFrames(t, ack2)))

	// without padding
	p, buf, err = tp.packer.PackMultipathProbePacket(0, multipathTestDestConnIDs[0], []ackhandler.Frame{{Frame: response}}, 1500, 0, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, p.PathID)
	require.Equal(t, multipathTestDestConnIDs[0], p.DestConnID)
	require.Nil(t, p.Ack)
	_, payload = openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 0)
	require.Equal(t, appendFrames(t, response), payload)

	// The PATH_ACK frame is only added if it fits.
	tp.acks.acks[1] = ack1
	p, _, err = tp.packer.PackMultipathProbePacket(1, multipathTestDestConnIDs[1], []ackhandler.Frame{{Frame: challenge}}, 1+4+2+16+9+3, 0, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, p.Ack)
	require.Len(t, p.Frames, 1)

	// If the frames don't fit, nothing is packed, and no packet number is consumed.
	_, _, err = tp.packer.PackMultipathProbePacket(1, multipathTestDestConnIDs[1], []ackhandler.Frame{{Frame: challenge}}, 1+4+2+16+8, 0, monotime.Now(), protocol.Version1)
	require.ErrorIs(t, err, errNothingToPack)
	p, _, err = tp.packer.PackMultipathProbePacket(1, multipathTestDestConnIDs[1], []ackhandler.Frame{{Frame: challenge}}, 1500, 0, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x202), p.PacketNumber)

	// A PATH_RESPONSE sent to another 4-tuple uses another connection ID of the path.
	otherConnID := protocol.ParseConnectionID([]byte{1, 1, 1, 2})
	p, buf, err = tp.packer.PackMultipathProbePacket(1, otherConnID, []ackhandler.Frame{{Frame: response}}, 1500, 0, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, otherConnID, p.DestConnID)
	connID, err = wire.ParseConnectionID(buf.Data, 4)
	require.NoError(t, err)
	require.Equal(t, otherConnID, connID)
	pn, payload = openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 1)
	require.Equal(t, protocol.PacketNumber(0x203), pn)
	require.Equal(t, appendFrames(t, response), payload)
}

// Packets are never sent on a path of IETF Multipath QUIC that the peer didn't provide a connection ID for.
func TestPackMultipathPacketWithoutConnectionID(t *testing.T) {
	tp := newMultipathTestPacker(t)
	tp.framer.controlFrames = []ackhandler.Frame{{Frame: &wire.PingFrame{}}}
	const pathID protocol.PathID = 3
	require.NotContains(t, multipathTestDestConnIDs, pathID)

	_, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1, pathID)
	require.EqualError(t, err, "no connection ID available for path 3")
	_, err = tp.packer.PackPTOProbePacket(protocol.Encryption1RTT, protocol.MaxPacketBufferSize, true, monotime.Now(), protocol.Version1, pathID)
	require.EqualError(t, err, "no connection ID available for path 3")
	_, _, err = tp.packer.PackMTUProbePacket(ackhandler.Frame{Frame: &wire.PingFrame{}}, 1300, protocol.Version1, pathID)
	require.EqualError(t, err, "no connection ID available for path 3")
	_, err = tp.packer.PackConnectionClose(&qerr.TransportError{ErrorCode: qerr.NoViablePathError}, protocol.MaxPacketBufferSize, protocol.Version1, pathID)
	require.EqualError(t, err, "no connection ID available for path 3")
	// no packet number was consumed
	require.NotContains(t, tp.packer.pnManager.(*multipathPacketNumberManager).next, pathID)
	// the PING frame is still queued
	require.Len(t, tp.framer.controlFrames, 1)
}

// PackPathPacket packs a packet on a path that only carries the given frames, e.g. copies of frames sent on another
// path. The packet doesn't contain ACK frames.
func TestPackPathPacket(t *testing.T) {
	tp := newMultipathTestPacker(t)
	tp.acks.acks = map[protocol.PathID]*wire.AckFrame{1: {AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}, PathID: 1, HasPathID: true}}
	maxData := &wire.MaxDataFrame{MaximumData: 1337}
	str := &wire.StreamFrame{StreamID: 4, Offset: 100, Data: []byte("foobar"), DataLenPresent: true}

	p, buf, err := tp.packer.PackPathPacket(1, []ackhandler.Frame{{Frame: maxData}}, []ackhandler.StreamFrame{{Frame: str}}, 1500, protocol.Version1)
	require.NoError(t, err)
	require.False(t, p.IsPathProbePacket)
	require.Equal(t, uint64(1), p.PathID)
	require.Equal(t, protocol.PacketNumber(0x200), p.PacketNumber)
	require.Equal(t, multipathTestDestConnIDs[1], p.DestConnID)
	require.Nil(t, p.Ack)
	require.Empty(t, p.ExtraAcks)
	require.Equal(t, []ackhandler.Frame{{Frame: maxData}}, p.Frames)
	require.Equal(t, []ackhandler.StreamFrame{{Frame: str}}, p.StreamFrames)
	require.Equal(t, protocol.ByteCount(len(buf.Data)), p.Length)
	pn, payload := openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 1)
	require.Equal(t, protocol.PacketNumber(0x200), pn)
	require.Equal(t, appendFrames(t, maxData, str), payload)

	// a PING frame on path 0
	p, buf, err = tp.packer.PackPathPacket(0, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, nil, 1500, protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, p.PathID)
	require.Equal(t, multipathTestDestConnIDs[0], p.DestConnID)
	_, payload = openGoldenShortHeaderPacket(t, tp.sealer, buf.Data, 4, 0)
	// the payload is padded, such that header protection can be applied
	require.True(t, bytes.HasSuffix(payload, appendFrames(t, &wire.PingFrame{})))

	_, _, err = tp.packer.PackPathPacket(1, nil, nil, 1500, protocol.Version1)
	require.ErrorIs(t, err, errNothingToPack)
	// the frames don't fit
	_, _, err = tp.packer.PackPathPacket(1, []ackhandler.Frame{{Frame: maxData}}, []ackhandler.StreamFrame{{Frame: str}}, 30, protocol.Version1)
	require.Error(t, err)
}

// Once the peer sent the grease_quic_bit transport parameter, the QUIC Bit of every packet is set to an unpredictable
// value (section 3.1 of RFC 9287). The first byte is part of the associated data of the AEAD.
func TestPackGreasedQUICBit(t *testing.T) {
	t.Run("short header", func(t *testing.T) {
		testPackGreasedQUICBit(t, func(t *testing.T, tp *testPacketPacker) []byte {
			tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true, gomock.Any()).Return(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}},
			)
			_, buffer, err := tp.packer.PackAckOnlyPacket(1300, monotime.Now(), protocol.Version1, 0)
			require.NoError(t, err)
			require.False(t, wire.IsLongHeaderPacket(buffer.Data[0]))
			return buffer.Data
		})
	})
	t.Run("long header", func(t *testing.T) {
		testPackGreasedQUICBit(t, func(t *testing.T, tp *testPacketPacker) []byte {
			tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true, gomock.Any()).Return(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}},
			)
			p, err := tp.packer.PackCoalescedPacket(true, 1300, monotime.Now(), protocol.Version1, 0)
			require.NoError(t, err)
			require.Len(t, p.longHdrPackets, 1)
			require.True(t, wire.IsLongHeaderPacket(p.buffer.Data[0]))
			// the packet can be parsed by an endpoint that sent the grease_quic_bit transport parameter
			hdr, _, rest, err := wire.ParsePacketWithGreasedQUICBit(p.buffer.Data)
			require.NoError(t, err)
			require.Equal(t, protocol.PacketTypeInitial, hdr.Type)
			require.Empty(t, rest)
			return p.buffer.Data
		})
	})
}

func testPackGreasedQUICBit(t *testing.T, pack func(*testing.T, *testPacketPacker) []byte) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	var associatedData []byte
	sealer := mocks.NewMockShortHeaderSealer(mockCtrl)
	sealer.EXPECT().KeyPhase().Return(protocol.KeyPhaseZero).AnyTimes()
	sealer.EXPECT().Overhead().Return(16).AnyTimes()
	sealer.EXPECT().EncryptHeader(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_, src []byte, _ protocol.PacketNumber, ad []byte) []byte {
			associatedData = slices.Clone(ad)
			return append(src, make([]byte, 16)...)
		},
	).AnyTimes()
	tp.sealingManager.EXPECT().GetInitialSealer().Return(sealer, nil).AnyTimes()
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil).AnyTimes()
	tp.pnManager.EXPECT().PeekPacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0x42)).AnyTimes()

	// without greasing, the QUIC Bit is always set
	for range 100 {
		data := pack(t, tp)
		require.NotZero(t, data[0]&0x40)
		require.Equal(t, data[0], associatedData[0])
	}

	tp.packer.EnableQUICBitGreasing()
	var numCleared int
	const numPackets = 200
	for range numPackets {
		data := pack(t, tp)
		require.Equal(t, data[0], associatedData[0])
		if data[0]&0x40 == 0 {
			numCleared++
		}
	}
	// The probability that the bit is set (or cleared) in every packet is 2^-200.
	require.NotZero(t, numCleared)
	require.Less(t, numCleared, numPackets)
}
