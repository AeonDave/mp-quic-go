package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type testConnectionOpt func(*Conn)

func connectionOptCryptoSetup(cs *mocks.MockCryptoSetup) testConnectionOpt {
	return func(conn *Conn) { conn.cryptoStreamHandler = cs }
}

func connectionOptConnFlowController(cfc *connectionFlowController) testConnectionOpt {
	return func(conn *Conn) { conn.connFlowController = cfc }
}

func connectionOptTracer(r qlogwriter.Recorder) testConnectionOpt {
	return func(conn *Conn) { conn.qlogger = r }
}

func connectionOptSentPacketHandler(sph ackhandler.SentPacketHandler) testConnectionOpt {
	return func(conn *Conn) { conn.sentPacketHandler = sph }
}

func connectionOptUnpacker(u unpacker) testConnectionOpt {
	return func(conn *Conn) { conn.unpacker = u }
}

func connectionOptSender(s sender) testConnectionOpt {
	return func(conn *Conn) { conn.sendQueue = s }
}

func connectionOptHandshakeConfirmed() testConnectionOpt {
	return func(conn *Conn) {
		conn.handshakeComplete = true
		conn.handshakeConfirmed = true
	}
}

func connectionOptRTT(rtt time.Duration) testConnectionOpt {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)
	return func(conn *Conn) { conn.rttStats = rttStats }
}

func connectionOptRetrySrcConnID(rcid protocol.ConnectionID) testConnectionOpt {
	return func(conn *Conn) { conn.retrySrcConnID = &rcid }
}

type testConnection struct {
	conn       *Conn
	connRunner *MockConnRunner
	sendConn   *MockSendConn
	packer     *MockPacker
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID
	remoteAddr *net.UDPAddr
}

func (tc *testConnection) receivedPacketHandler() *ackhandler.ReceivedPacketHandler {
	return &tc.conn.receivedPacketHandler
}

func newServerTestConnection(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	gso bool,
	opts ...testConnectionOpt,
) *testConnection {
	return newServerTestConnectionWithPreferredAddr(t, mockCtrl, config, gso, nil, opts...)
}

// newServerTestConnectionWithPreferredAddr creates a server connection that sends the preferred address,
// if preferredAddr is set.
func newServerTestConnectionWithPreferredAddr(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	gso bool,
	preferredAddr *serverPreferredAddr,
	opts ...testConnectionOpt,
) *testConnection {
	if mockCtrl == nil {
		mockCtrl = gomock.NewController(t)
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	connRunner := NewMockConnRunner(mockCtrl)
	// the connection ID sent in the preferred_address transport parameter is added when the connection is created
	if preferredAddr != nil {
		connRunner.EXPECT().Add(gomock.Any(), gomock.Any()).AnyTimes()
	}
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{GSO: gso}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	packer := NewMockPacker(mockCtrl)
	b := make([]byte, 12)
	rand.Read(b)
	origDestConnID := protocol.ParseConnectionID(b[:6])
	srcConnID := protocol.ParseConnectionID(b[6:12])
	ctx, cancel := context.WithCancelCause(context.Background())
	if config == nil {
		config = &Config{DisablePathMTUDiscovery: true}
	}
	// A server that sends a preferred address uses connection IDs of non-zero length.
	connIDGenerator := &protocol.DefaultConnectionIDGenerator{}
	if preferredAddr != nil {
		connIDGenerator.ConnLen = srcConnID.Len()
	}
	wc := newConnection(
		ctx,
		cancel,
		sendConn,
		connRunner,
		origDestConnID,
		nil,
		origDestConnID,
		protocol.ConnectionID{},
		srcConnID,
		connIDGenerator,
		newStatelessResetter(nil),
		populateConfig(config),
		&tls.Config{},
		handshake.NewTokenGenerator(handshake.TokenProtectorKey{}),
		false,
		1337*time.Millisecond,
		preferredAddr,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.Nil(t, wc.testHooks)
	conn := wc.Conn
	conn.packer = packer
	for _, opt := range opts {
		opt(conn)
	}
	return &testConnection{
		conn:       conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: origDestConnID,
		srcConnID:  srcConnID,
		remoteAddr: remoteAddr,
	}
}

func newClientTestConnection(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	enable0RTT bool,
	opts ...testConnectionOpt,
) *testConnection {
	b := make([]byte, 6)
	rand.Read(b)
	return newClientTestConnectionWithSrcConnID(t, mockCtrl, config, enable0RTT, protocol.ParseConnectionID(b), opts...)
}

func newClientTestConnectionWithSrcConnID(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	enable0RTT bool,
	srcConnID protocol.ConnectionID,
	opts ...testConnectionOpt,
) *testConnection {
	if mockCtrl == nil {
		mockCtrl = gomock.NewController(t)
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	connRunner := NewMockConnRunner(mockCtrl)
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	packer := NewMockPacker(mockCtrl)
	b := make([]byte, 6)
	rand.Read(b)
	destConnID := protocol.ParseConnectionID(b)
	if config == nil {
		config = &Config{DisablePathMTUDiscovery: true}
	}
	conn := newClientConnection(
		context.Background(),
		sendConn,
		connRunner,
		destConnID,
		srcConnID,
		&protocol.DefaultConnectionIDGenerator{},
		newStatelessResetter(nil),
		populateConfig(config),
		&tls.Config{ServerName: "quic-go.net"},
		0,
		enable0RTT,
		false,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.Nil(t, conn.testHooks)
	conn.packer = packer
	for _, opt := range opts {
		opt(conn.Conn)
	}
	return &testConnection{
		conn:       conn.Conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: destConnID,
		srcConnID:  srcConnID,
	}
}

func TestConnectionHandleStreamRelatedFrames(t *testing.T) {
	const id protocol.StreamID = 5
	connID := protocol.ConnectionID{}

	tests := []struct {
		name  string
		frame wire.Frame
	}{
		{name: "RESET_STREAM", frame: &wire.ResetStreamFrame{StreamID: id, ErrorCode: 42, FinalSize: 1337}},
		{name: "STOP_SENDING", frame: &wire.StopSendingFrame{StreamID: id, ErrorCode: 42}},
		{name: "MAX_STREAM_DATA", frame: &wire.MaxStreamDataFrame{StreamID: id, MaximumStreamData: 1337}},
		{name: "STREAM_DATA_BLOCKED", frame: &wire.StreamDataBlockedFrame{StreamID: id, MaximumStreamData: 42}},
		{name: "STREAM_FRAME", frame: &wire.StreamFrame{StreamID: id, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Offset: 1337}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tc := newServerTestConnection(t, gomock.NewController(t), nil, false)
			data, err := test.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)
			_, _, _, err = tc.conn.handleFrames(data, connID, protocol.Encryption1RTT, nil, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
		})
	}
}

func TestConnectionHandleConnectionFlowControlFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	connFC := newConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
	require.Zero(t, connFC.SendWindowSize())
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptConnFlowController(connFC))
	now := monotime.Now()
	connID := protocol.ConnectionID{}
	// MAX_DATA frame
	_, err := tc.conn.handleFrame(&wire.MaxDataFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(1337), connFC.SendWindowSize())
	// DATA_BLOCKED frame
	_, err = tc.conn.handleFrame(&wire.DataBlockedFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now)
	require.NoError(t, err)
}

func TestConnectionServerInvalidFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tc := newServerTestConnection(t, mockCtrl, nil, false)

	for _, test := range []struct {
		Name  string
		Frame wire.Frame
	}{
		{Name: "NEW_TOKEN", Frame: &wire.NewTokenFrame{Token: []byte("foobar")}},
		{Name: "HANDSHAKE_DONE", Frame: &wire.HandshakeDoneFrame{}},
		{Name: "PATH_RESPONSE", Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
	} {
		t.Run(test.Name, func(t *testing.T) {
			_, err := tc.conn.handleFrame(test.Frame, protocol.Encryption1RTT, protocol.ConnectionID{}, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		})
	}
}

func TestConnectionClose(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		expectedErr := &qerr.TransportError{
			ErrorCode:    1337,
			FrameType:    42,
			ErrorMessage: "foobar",
		}
		testConnectionClose(t, false, expectedErr)
	})
	t.Run("application error", func(t *testing.T) {
		expectedErr := &qerr.ApplicationError{
			ErrorCode:    1337,
			ErrorMessage: "foobar",
		}
		testConnectionClose(t, true, expectedErr)
	})
}

func testConnectionClose(t *testing.T, useApplicationClose bool, expectedErr error) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))
		errChan := make(chan error, 1)

		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		b := getPacketBuffer()
		b.Data = append(b.Data, []byte("connection close")...)
		if useApplicationClose {
			tc.packer.EXPECT().PackApplicationClose(expectedErr, gomock.Any(), protocol.Version1, gomock.Any()).Return(&coalescedPacket{buffer: b}, nil)
		} else {
			tc.packer.EXPECT().PackConnectionClose(expectedErr, gomock.Any(), protocol.Version1, gomock.Any()).Return(&coalescedPacket{buffer: b}, nil)
		}
		tc.sendConn.EXPECT().Write([]byte("connection close"), gomock.Any(), gomock.Any())
		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		go func() { errChan <- tc.conn.run() }()
		tc.conn.closeLocal(expectedErr)

		synctest.Wait()

		var want qlog.ConnectionClosed
		if useApplicationClose {
			code := expectedErr.(*qerr.ApplicationError).ErrorCode
			want = qlog.ConnectionClosed{
				Initiator:        qlog.InitiatorLocal,
				ApplicationError: &code,
				Reason:           expectedErr.(*qerr.ApplicationError).ErrorMessage,
			}
		} else {
			code := expectedErr.(*qerr.TransportError).ErrorCode
			want = qlog.ConnectionClosed{
				Initiator:       qlog.InitiatorLocal,
				ConnectionError: &code,
				Reason:          expectedErr.(*qerr.TransportError).ErrorMessage,
			}
		}
		require.Equal(t,
			[]qlogwriter.Event{want},
			eventRecorder.Events(qlog.ConnectionClosed{}),
		)
		eventRecorder.Clear()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, expectedErr)
		default:
			t.Fatal("connection was not closed")
		}

		// further calls to CloseWithError don't do anything
		tc.conn.CloseWithError(42, "another error")
		require.Empty(t, eventRecorder.Events(qlog.ConnectionClosed{}))
	})
}

func TestConnectionStatelessReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))
		errChan := make(chan error, 1)
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()

		go func() { errChan <- tc.conn.run() }()
		tc.conn.destroy(&StatelessResetError{})

		synctest.Wait()

		require.Equal(t,
			[]qlogwriter.Event{qlog.ConnectionClosed{Initiator: qlog.InitiatorLocal, Trigger: qlog.ConnectionCloseTriggerStatelessReset}},
			eventRecorder.Events(qlog.ConnectionClosed{}),
		)
	})
}

// A stateless reset received by the connection itself (and not by the Transport, as happens with a zero-length
// connection ID) closes the connection without sending any further packets (section 10.3.1 of RFC 9000).
func TestConnectionStatelessResetReceived(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		var eventRecorder events.Recorder
		tc := newClientTestConnectionWithSrcConnID(t,
			mockCtrl,
			nil,
			false,
			protocol.ConnectionID{},
			connectionOptHandshakeConfirmed(),
			connectionOptUnpacker(unpacker),
			connectionOptTracer(&eventRecorder),
		)
		tc.conn.sentFirstPacket = true
		token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		tc.connRunner.EXPECT().AddResetToken(token, gomock.Any())
		tc.conn.connIDManager.SetStatelessResetToken(token)

		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, handshake.ErrDecryptionFailed,
		)
		// No packet is packed or sent: neither the packer nor the send conn expect any calls.
		tc.connRunner.EXPECT().RemoveResetToken(token)
		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), nil, gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		data := make([]byte, 30)
		data[0] = 0b01000000
		copy(data[len(data)-16:], token[:])
		tc.conn.handlePacket(receivedPacket{
			remoteAddr: tc.remoteAddr,
			data:       data,
			buffer:     getPacketBuffer(),
			rcvTime:    monotime.Now(),
		})
		synctest.Wait()

		select {
		case err := <-errChan:
			var statelessResetErr *StatelessResetError
			require.ErrorAs(t, err, &statelessResetErr)
		default:
			t.Fatal("connection was not closed")
		}
		require.Equal(t,
			[]qlogwriter.Event{qlog.ConnectionClosed{Initiator: qlog.InitiatorLocal, Trigger: qlog.ConnectionCloseTriggerStatelessReset}},
			eventRecorder.Events(qlog.ConnectionClosed{}),
		)
	})
}

// Any datagram ending in a valid stateless reset token is a stateless reset, also if it starts with a long header
// that can't be processed (section 10.3 of RFC 9000).
func TestConnectionStatelessResetLongHeader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tc := newClientTestConnectionWithSrcConnID(t,
			mockCtrl,
			nil,
			false,
			protocol.ConnectionID{},
			connectionOptHandshakeConfirmed(),
		)
		tc.conn.sentFirstPacket = true
		token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		tc.connRunner.EXPECT().AddResetToken(token, gomock.Any())
		tc.conn.connIDManager.SetStatelessResetToken(token)

		// No packet is packed or sent: neither the packer nor the send conn expect any calls.
		tc.connRunner.EXPECT().RemoveResetToken(token)
		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), nil, gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		data := make([]byte, 40)
		data[0] = 0xc0                                   // long header
		binary.BigEndian.PutUint32(data[1:], 0x1a2a3a4a) // unknown version
		copy(data[len(data)-16:], token[:])
		tc.conn.handlePacket(receivedPacket{
			remoteAddr: tc.remoteAddr,
			data:       data,
			buffer:     getPacketBuffer(),
			rcvTime:    monotime.Now(),
		})
		synctest.Wait()

		select {
		case err := <-errChan:
			var statelessResetErr *StatelessResetError
			require.ErrorAs(t, err, &statelessResetErr)
		default:
			t.Fatal("connection was not closed")
		}
	})
}

// The client only switches to a connection ID that the server provided in a NEW_CONNECTION_ID frame once the
// handshake is confirmed. Until then, it might still send Initial and Handshake packets, and some servers drop long
// header packets that don't use the connection ID chosen during the handshake.
func TestConnectionClientConnIDChangeAfterHandshakeConfirmation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs))
	c := tc.conn
	c.peerParams = &wire.TransportParameters{ActiveConnectionIDLimit: 2}
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().RemoveResetToken(gomock.Any()).AnyTimes()
	newConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	require.NoError(t, c.connIDManager.Add(&wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        newConnID,
		StatelessResetToken: protocol.StatelessResetToken{1},
	}))

	require.NoError(t, c.handleHandshakeComplete(monotime.Now()))
	require.Equal(t, tc.destConnID, c.connIDManager.Get())

	cs.EXPECT().DiscardInitialKeys().AnyTimes()
	cs.EXPECT().SetHandshakeConfirmed()
	require.NoError(t, c.handleHandshakeConfirmed(monotime.Now()))
	require.Equal(t, newConnID, c.connIDManager.Get())
}

func getLongHeaderPacket(t *testing.T, remoteAddr net.Addr, extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
	t.Helper()
	b, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	return receivedPacket{
		remoteAddr: remoteAddr,
		data:       append(b, data...),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}
}

func getShortHeaderPacket(t *testing.T, remoteAddr net.Addr, connID protocol.ConnectionID, pn protocol.PacketNumber, data []byte) receivedPacket {
	t.Helper()
	b, err := wire.AppendShortHeader(nil, connID, pn, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
	require.NoError(t, err)
	return receivedPacket{
		remoteAddr: remoteAddr,
		data:       append(b, data...),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}
}

func TestConnectionServerInvalidPackets(t *testing.T) {
	t.Run("Retry", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{Header: wire.Header{
				Type:             protocol.PacketTypeRetry,
				DestConnectionID: tc.conn.origDestConnID,
				SrcConnectionID:  tc.srcConnID,
				Version:          tc.conn.version,
				Token:            []byte("foobar"),
			}},
			make([]byte, 16), /* Retry integrity tag */
		)
		wasProcessed, err := tc.conn.handleOnePacket(p, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketTypeRetry,
						SrcConnectionID:  tc.srcConnID,
						DestConnectionID: tc.conn.origDestConnID,
						Version:          tc.conn.version,
					},
					Raw:     qlog.RawInfo{Length: int(p.Size())},
					Trigger: qlog.PacketDropUnexpectedPacket,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("version negotiation", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		b := wire.ComposeVersionNegotiation(
			protocol.ArbitraryLenConnectionID(tc.srcConnID.Bytes()),
			protocol.ArbitraryLenConnectionID(tc.conn.origDestConnID.Bytes()),
			[]Version{Version1},
		)
		wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{data: b, buffer: getPacketBuffer()}, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
					Raw:     qlog.RawInfo{Length: len(b)},
					Trigger: qlog.PacketDropUnexpectedPacket,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("unsupported version", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: 1234},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		wasProcessed, err := tc.conn.handleOnePacket(p, 42)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:                  qlog.PacketHeader{Version: 1234},
					Raw:                     qlog.RawInfo{Length: int(p.Size())},
					DatagramPayloadChecksum: 42,
					Trigger:                 qlog.PacketDropUnsupportedVersion,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("invalid header", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: Version1},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		p.data[0] ^= 0x40 // unset the QUIC bit
		wasProcessed, err := tc.conn.handleOnePacket(p, 42)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:                  qlog.PacketHeader{},
					Raw:                     qlog.RawInfo{Length: int(p.Size())},
					DatagramPayloadChecksum: 42,
					Trigger:                 qlog.PacketDropHeaderParseError,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})
}

func TestConnectionClientDrop0RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

	p := getLongHeaderPacket(t,
		tc.remoteAddr,
		&wire.ExtendedHeader{
			Header:          wire.Header{Type: protocol.PacketType0RTT, Length: 2, Version: protocol.Version1},
			PacketNumberLen: protocol.PacketNumberLen2,
		},
		nil,
	)
	wasProcessed, err := tc.conn.handleOnePacket(p, 1234)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size())},
				DatagramPayloadChecksum: 1234,
				Trigger:                 qlog.PacketDropUnexpectedPacket,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func TestConnectionClientDropsInvalidInitialPackets(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		// Initial packets sent by the server must have an empty token (section 17.2.2 of RFC 9000)
		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					SrcConnectionID:  tc.destConnID,
					Token:            []byte("token"),
					Length:           2,
					Version:          protocol.Version1,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		wasProcessed, err := tc.conn.handleOnePacket(p, 1234)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:   qlog.PacketTypeInitial,
						PacketNumber: protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(p.Size())},
					DatagramPayloadChecksum: 1234,
					Trigger:                 qlog.PacketDropUnexpectedPacket,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("source connection ID", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))
		tc.conn.receivedFirstPacket = true
		tc.conn.handshakeDestConnID = tc.destConnID

		// once a packet was received, Initial packets with another source connection ID are dropped
		// (section 7.2 of RFC 9000)
		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Length:           2,
					Version:          protocol.Version1,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		wasProcessed, err := tc.conn.handleOnePacket(p, 1234)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:   qlog.PacketTypeInitial,
						PacketNumber: protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(p.Size())},
					DatagramPayloadChecksum: 1234,
					Trigger:                 qlog.PacketDropUnknownConnectionID,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})
}

// When the packet numbers are exhausted, the connection is closed without sending any further packets,
// not even a CONNECTION_CLOSE (section 12.3 of RFC 9000).
func TestConnectionPacketNumberExhaustion(t *testing.T) {
	testConnectionStopSending(t, errPacketNumbersExhausted)
}

// When the confidentiality limit is reached and the keys can't be updated, the connection is closed without sending
// any further packets (section 6.6 of RFC 9001).
func TestConnectionConfidentialityLimitReached(t *testing.T) {
	testConnectionStopSending(t, handshake.ErrConfidentialityLimitReached)
}

func testConnectionStopSending(t *testing.T, packErr error) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptHandshakeConfirmed())
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{}, packErr,
		)
		// No CONNECTION_CLOSE is packed or sent: neither the packer nor the send conn expect any further calls.

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.queueControlFrame(&wire.PingFrame{})
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, packErr)
		default:
			t.Fatal("connection was not closed")
		}
	})
}

func TestConnectionUnpacking(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
		connectionOptTracer(&eventRecorder),
	)

	// receive a long header packet
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    0x37,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	unpackedHdr := *hdr
	unpackedHdr.PacketNumber = 0x1337
	packet := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	packet.ecn = protocol.ECNCE
	rcvTime := monotime.Now().Add(-10 * time.Second)
	packet.rcvTime = rcvTime
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)

	wasProcessed, err := tc.conn.handleOnePacket(packet, 42)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(0x1337),
					Version:          protocol.Version1,
				},
				Frames:                  []qlog.Frame{},
				ECN:                     qlog.ECNCE,
				Raw:                     qlog.RawInfo{Length: int(packet.Size()), PayloadLength: 1},
				DatagramPayloadChecksum: 42,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// receive a duplicate of this packet
	packet = getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	wasProcessed, err = tc.conn.handleOnePacket(packet, 43)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(0x1337),
					Version:          protocol.Version1,
				},
				Raw:                     qlog.RawInfo{Length: int(packet.Size()), PayloadLength: 1},
				DatagramPayloadChecksum: 43,
				Trigger:                 qlog.PacketDropDuplicate,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// receive a short header packet
	packet = getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x37, nil)
	packet.ecn = protocol.ECT1
	packet.rcvTime = rcvTime
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(0x1337), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0} /* PADDING */, nil,
	)
	wasProcessed, err = tc.conn.handleOnePacket(packet, 0)
	require.NoError(t, err)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketType1RTT,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(0x1337),
					KeyPhaseBit:      protocol.KeyPhaseZero,
				},
				Raw:    qlog.RawInfo{Length: int(packet.Size())},
				Frames: []qlog.Frame{},
				ECN:    qlog.ECT1,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
	require.True(t, wasProcessed)
}

func TestConnectionUnpackCoalescedPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
		connectionOptTracer(&eventRecorder),
	)
	hdr1 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    37,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	hdr2 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    38,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	// add a packet with a different source connection ID
	incorrectSrcConnID := protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc})
	hdr3 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: incorrectSrcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    0x42,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	unpackedHdr1 := *hdr1
	unpackedHdr1.PacketNumber = 1337
	unpackedHdr2 := *hdr2
	unpackedHdr2.PacketNumber = 1338

	packet := getLongHeaderPacket(t, tc.remoteAddr, hdr1, nil)
	firstPacketLen := packet.Size()
	packet2 := getLongHeaderPacket(t, tc.remoteAddr, hdr2, nil)
	packet3 := getLongHeaderPacket(t, tc.remoteAddr, hdr3, nil)
	packet.data = append(packet.data, packet2.data...)
	packet.data = append(packet.data, packet3.data...)
	packet.ecn = protocol.ECT1
	rcvTime := monotime.Now()
	packet.rcvTime = rcvTime

	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr1,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionHandshake,
		hdr:             &unpackedHdr2,
		data:            []byte{1}, // one PING frame
	}, nil)
	wasProcessed, err := tc.conn.handleOnePacket(packet, 42)
	require.NoError(t, err)
	require.True(t, wasProcessed)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(1337),
					Version:          protocol.Version1,
				},
				Raw:                     qlog.RawInfo{Length: int(firstPacketLen), PayloadLength: 1},
				DatagramPayloadChecksum: 42,
				Frames:                  []qlog.Frame{},
				ECN:                     qlog.ECT1,
			},
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeHandshake,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(1338),
					Version:          protocol.Version1,
				},
				Raw:                     qlog.RawInfo{Length: int(packet2.Size()), PayloadLength: 1},
				DatagramPayloadChecksum: 42,
				Frames:                  []qlog.Frame{{Frame: &wire.PingFrame{}}},
				ECN:                     qlog.ECT1,
			},
			qlog.PacketDropped{
				Header:                  qlog.PacketHeader{DestConnectionID: incorrectSrcConnID},
				Raw:                     qlog.RawInfo{Length: int(packet3.Size())},
				DatagramPayloadChecksum: 42,
				Trigger:                 qlog.PacketDropUnknownConnectionID,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
}

func TestConnectionUnpackFailuresFatal(t *testing.T) {
	t.Run("other errors", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailureFatal(t, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}),
			&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
		)
	})

	t.Run("invalid reserved bits", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailureFatal(t, wire.ErrInvalidReservedBits),
			&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
		)
	})
}

func testConnectionUnpackFailureFatal(t *testing.T, unpackErr error) error {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
	)

	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, unpackErr)
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
	tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x42, nil))

	select {
	case err := <-errChan:
		require.Error(t, err)
		return err
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return nil
}

func TestConnectionUnpackFailureDropped(t *testing.T) {
	t.Run("keys dropped", func(t *testing.T) {
		testConnectionUnpackFailureDropped(t, handshake.ErrKeysDropped, qlog.PacketDropKeyUnavailable)
	})

	t.Run("decryption failed", func(t *testing.T) {
		testConnectionUnpackFailureDropped(t, handshake.ErrDecryptionFailed, qlog.PacketDropPayloadDecryptError)
	})

	t.Run("header parse error", func(t *testing.T) {
		testConnectionUnpackFailureDropped(t, &headerParseError{err: assert.AnError}, qlog.PacketDropHeaderParseError)
	})
}

func testConnectionUnpackFailureDropped(t *testing.T, unpackErr error, packetDropReason qlog.PacketDropReason) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptUnpacker(unpacker),
			connectionOptTracer(&eventRecorder),
		)

		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, unpackErr)
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		packet := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x42, nil)
		tc.conn.handlePacket(packet)
		synctest.Wait()

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketType1RTT,
						DestConnectionID: tc.srcConnID,
						PacketNumber:     protocol.InvalidPacketNumber,
					},
					Raw:     qlog.RawInfo{Length: int(packet.Size())},
					Trigger: packetDropReason,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case <-errChan:
		default:
			t.Fatal("timeout")
		}
	})
}

func TestConnectionMaxUnprocessedPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		for range protocol.MaxConnUnprocessedPackets {
			// nothing here should block
			tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})
		}
		tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})

		synctest.Wait()

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Raw:     qlog.RawInfo{Length: 6},
					Trigger: qlog.PacketDropDOSPrevention,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})
}

func TestConnectionRemoteClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptTracer(&eventRecorder),
			connectionOptUnpacker(unpacker),
		)
		ccf, err := (&wire.ConnectionCloseFrame{
			ErrorCode:    uint64(qerr.StreamLimitError),
			ReasonPhrase: "foobar",
		}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseBit(0), ccf, nil)

		tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		p := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 1, []byte("encrypted"))
		tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

		synctest.Wait()

		expectedErr := &qerr.TransportError{ErrorCode: qerr.StreamLimitError, ErrorMessage: "foobar", Remote: true}
		select {
		case err := <-errChan:
			require.ErrorIs(t, err, expectedErr)
		default:
			t.Fatal("timeout")
		}

		code := expectedErr.ErrorCode
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.ConnectionClosed{
					Initiator:       qlog.InitiatorRemote,
					ConnectionError: &code,
					Reason:          expectedErr.ErrorMessage,
				},
			},
			eventRecorder.Events(qlog.ConnectionClosed{}),
		)
	})
}

func TestConnectionIdleTimeoutDuringHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 7 * time.Second
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{HandshakeIdleTimeout: timeout},
			false,
			connectionOptTracer(&eventRecorder),
		)
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).AnyTimes()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		start := monotime.Now()
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &IdleTimeoutError{})
			require.Equal(t, timeout, monotime.Since(start))
		case <-time.After(timeout + time.Nanosecond):
			t.Fatal("timeout")
		}

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.ConnectionClosed{
					Initiator: qlog.InitiatorLocal,
					Trigger:   qlog.ConnectionCloseTriggerIdleTimeout,
				},
			},
			eventRecorder.Events(qlog.ConnectionClosed{}),
		)
	})
}

func TestConnectionHandshakeIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{HandshakeIdleTimeout: 7 * time.Second},
			false,
			connectionOptTracer(&eventRecorder),
			func(c *Conn) { c.creationTime = monotime.Now().Add(-20 * time.Second) },
		)
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).AnyTimes()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &HandshakeTimeoutError{})
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.ConnectionClosed{
					Initiator: qlog.InitiatorLocal,
					Trigger:   qlog.ConnectionCloseTriggerIdleTimeout,
				},
			},
			eventRecorder.Events(qlog.ConnectionClosed{}),
		)
	})
}

func TestConnectionTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	connFC := newConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
	require.Zero(t, connFC.SendWindowSize())
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptConnFlowController(connFC),
	)
	_, err := tc.conn.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	_, err = tc.conn.OpenUniStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	params := &wire.TransportParameters{
		MaxIdleTimeout:                90 * time.Second,
		InitialMaxStreamDataBidiLocal: 0x5000,
		InitialMaxData:                1337,
		ActiveConnectionIDLimit:       3,
		// marshaling always sets it to this value
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxBidiStreamNum:                1,
		MaxUniStreamNum:                 1,
	}
	require.NoError(t, tc.conn.handleTransportParameters(params))
	require.Equal(t, protocol.ByteCount(1337), connFC.SendWindowSize())
	_, err = tc.conn.OpenStream()
	require.NoError(t, err)
	_, err = tc.conn.OpenUniStream()
	require.NoError(t, err)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.ParametersSet{
				Initiator:                     qlog.InitiatorRemote,
				MaxIdleTimeout:                90 * time.Second,
				InitialMaxStreamDataBidiLocal: 0x5000,
				InitialMaxData:                1337,
				ActiveConnectionIDLimit:       3,
				// marshaling always sets it to this value
				MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
				OriginalDestinationConnectionID: tc.destConnID,
				InitialMaxStreamsBidi:           1,
				InitialMaxStreamsUni:            1,
			},
		},
		eventRecorder.Events(qlog.ParametersSet{}),
	)
}

func TestConnectionHandleMaxStreamsFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		connFC := newConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptConnFlowController(connFC))
		tc.conn.handleTransportParameters(&wire.TransportParameters{})

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		uniStreamChan := make(chan error)
		go func() {
			_, err := tc.conn.OpenUniStreamSync(ctx)
			uniStreamChan <- err
		}()
		bidiStreamChan := make(chan error)
		go func() {
			_, err := tc.conn.OpenStreamSync(ctx)
			bidiStreamChan <- err
		}()

		synctest.Wait()
		select {
		case <-uniStreamChan:
			t.Fatal("uni stream should be blocked")
		case <-bidiStreamChan:
			t.Fatal("bidi stream should be blocked")
		default:
		}

		// MAX_STREAMS frame for bidirectional stream
		_, err := tc.conn.handleFrame(
			&wire.MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 10},
			protocol.Encryption1RTT,
			protocol.ConnectionID{},
			monotime.Now(),
		)
		require.NoError(t, err)

		synctest.Wait()

		select {
		case <-uniStreamChan:
			t.Fatal("uni stream should be blocked")
		default:
		}
		select {
		case err := <-bidiStreamChan:
			require.NoError(t, err)
		default:
			t.Fatal("bidi stream should be unblocked")
		}

		// MAX_STREAMS frame for bidirectional stream
		_, err = tc.conn.handleFrame(
			&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 10},
			protocol.Encryption1RTT,
			protocol.ConnectionID{},
			monotime.Now(),
		)
		require.NoError(t, err)

		synctest.Wait()
		select {
		case err := <-uniStreamChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
}

func TestConnectionTransportParameterValidationFailureServer(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	err := tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	})
	assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
	assert.ErrorContains(t, err, "expected initial_source_connection_id to equal")
}

func TestConnectionTransportParameterValidationFailureClient(t *testing.T) {
	t.Run("initial_source_connection_id", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		err := tc.conn.handleTransportParameters(&wire.TransportParameters{
			InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected initial_source_connection_id to equal")
	})

	t.Run("original_destination_connection_id", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		err := tc.conn.handleTransportParameters(&wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected original_destination_connection_id to equal")
	})

	t.Run("retry_source_connection_id if no retry", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		rcid := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
			RetrySourceConnectionID:         &rcid,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "received retry_source_connection_id, although no Retry was performed")
	})

	t.Run("retry_source_connection_id missing", func(t *testing.T) {
		tc := newClientTestConnection(t,
			nil,
			nil,
			false,
			connectionOptRetrySrcConnID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})),
		)
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "missing retry_source_connection_id")
	})

	t.Run("retry_source_connection_id incorrect", func(t *testing.T) {
		tc := newClientTestConnection(t,
			nil,
			nil,
			false,
			connectionOptRetrySrcConnID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})),
		)
		wrongCID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
			RetrySourceConnectionID:         &wrongCID,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected retry_source_connection_id to equal")
	})
}

func TestConnectionHandshakeServer(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(
		t,
		mockCtrl,
		nil,
		false,
		connectionOptCryptoSetup(cs),
		connectionOptUnpacker(unpacker),
	)

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	cs.EXPECT().DiscardInitialKeys().Times(2)
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		cs.EXPECT().SetHandshakeConfirmed(),
		cs.EXPECT().GetSessionTicket().Return([]byte("session ticket"), nil),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	var foundSessionTicket, foundHandshakeDone, foundNewToken bool
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	for _, frame := range frames {
		switch f := frame.Frame.(type) {
		case *wire.CryptoFrame:
			assert.Equal(t, []byte("session ticket"), f.Data)
			foundSessionTicket = true
		case *wire.HandshakeDoneFrame:
			foundHandshakeDone = true
		case *wire.NewTokenFrame:
			assert.NotEmpty(t, f.Token)
			foundNewToken = true
		}
	}
	assert.True(t, foundSessionTicket)
	assert.True(t, foundHandshakeDone)
	assert.True(t, foundNewToken)

	// test teardown
	cs.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionFinishesCryptoStreamWhenReadKeysBecomeAvailable(t *testing.T) {
	for _, test := range []struct {
		event    handshake.EventKind
		previous protocol.EncryptionLevel
	}{
		{handshake.EventReceivedHandshakeReadKeys, protocol.EncryptionInitial},
		{handshake.EventReceived1RTTReadKeys, protocol.EncryptionHandshake},
	} {
		t.Run(test.event.String(), func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			cs := mocks.NewMockCryptoSetup(mockCtrl)
			tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs))
			require.NoError(t, tc.conn.cryptoStreamManager.HandleCryptoFrame(
				&wire.CryptoFrame{Offset: 1, Data: []byte("foo")},
				test.previous,
			))

			cs.EXPECT().NextEvent().Return(handshake.Event{Kind: test.event})
			err := tc.conn.handleHandshakeEvents(monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
			require.ErrorContains(t, err, "encryption level changed, but crypto stream has more data to read")
		})
	}
}

func TestConnectionHandshakeClient(t *testing.T) {
	t.Run("without preferred address", func(t *testing.T) {
		testConnectionHandshakeClient(t, false)
	})
	t.Run("with preferred address", func(t *testing.T) {
		testConnectionHandshakeClient(t, true)
	})
}

func testConnectionHandshakeClient(t *testing.T, usePreferredAddress bool) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs), connectionOptUnpacker(unpacker))
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// the state transition is driven by processing of a CRYPTO frame
	serverConnID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:            protocol.PacketTypeHandshake,
			SrcConnectionID: serverConnID,
			Version:         protocol.Version1,
		},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	tp := &wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		InitialSourceConnectionID:       serverConnID,
		MaxIdleTimeout:                  time.Hour,
	}
	preferredAddressConnID := protocol.ParseConnectionID([]byte{10, 8, 6, 4})
	preferredAddressResetToken := protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	if usePreferredAddress {
		tp.PreferredAddress = &wire.PreferredAddress{
			IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 42),
			IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13),
			ConnectionID:        preferredAddressConnID,
			StatelessResetToken: preferredAddressResetToken,
		}
	}

	packedFirstPacket := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version, _ protocol.PathID) (*coalescedPacket, error) {
				close(packedFirstPacket)
				return &coalescedPacket{buffer: getPacketBuffer(), longHdrPackets: []*longHeaderPacket{{header: hdr}}}, nil
			},
		),
		// initial keys are dropped when the first handshake packet is sent
		cs.EXPECT().DiscardInitialKeys(),
		// no more data to send
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedTransportParameters, TransportParameters: tp}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).Return(nil, nil).AnyTimes()
	// The connection ID from the preferred_address transport parameter is used for migrating to the preferred
	// address. Its stateless reset token is active.
	if usePreferredAddress {
		tc.connRunner.EXPECT().AddResetToken(preferredAddressResetToken, gomock.Any())
	}

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.True(t, mockCtrl.Satisfied())
	// the handshake isn't confirmed until we receive a HANDSHAKE_DONE frame from the server

	data, err = (&wire.HandshakeDoneFrame{}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	done := make(chan struct{})
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).Return(nil, nil).AnyTimes()
	gomock.InOrder(
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.Encryption1RTT, data: data}, nil,
		),
		cs.EXPECT().DiscardInitialKeys(),
		cs.EXPECT().SetHandshakeConfirmed(),
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
				close(done)
				return shortHeaderPacket{}, errNothingToPack
			},
		),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
	// Once the handshake is confirmed, the client validates the preferred address,
	// using the connection ID from the preferred_address transport parameter.
	probeSent := make(chan struct{})
	if usePreferredAddress {
		tc.packer.EXPECT().PackPathProbePacket(preferredAddressConnID, gomock.Any(), gomock.Any(), protocol.Version1, protocol.PathID(0)).DoAndReturn(
			func(_ protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
				require.IsType(t, &wire.PathChallengeFrame{}, frames[0].Frame)
				return shortHeaderPacket{IsPathProbePacket: true, Frames: frames}, getPacketBuffer(), nil
			},
		).MinTimes(1)
		tc.sendConn.EXPECT().WriteTo(gomock.Any(), net.UDPAddrFromAddrPort(tp.PreferredAddress.IPv4), packetInfo{}).DoAndReturn(
			func([]byte, net.Addr, packetInfo) error {
				select {
				case <-probeSent:
				default:
					close(probeSent)
				}
				return nil
			},
		).MinTimes(1)
	}
	p = getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	if usePreferredAddress {
		select {
		case <-probeSent:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}

	// test teardown
	cs.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	if usePreferredAddress {
		tc.connRunner.EXPECT().RemoveResetToken(preferredAddressResetToken)
	}
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnection0RTTTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs), connectionOptUnpacker(unpacker))
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	restored := &wire.TransportParameters{
		ActiveConnectionIDLimit:        3,
		InitialMaxData:                 0x5000,
		InitialMaxStreamDataBidiLocal:  0x5000,
		InitialMaxStreamDataBidiRemote: 1000,
		InitialMaxStreamDataUni:        1000,
		MaxBidiStreamNum:               500,
		MaxUniStreamNum:                500,
	}
	new := *restored
	new.MaxBidiStreamNum-- // the server is not allowed to reduce the limit
	new.OriginalDestinationConnectionID = tc.destConnID

	packedFirstPacket := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventRestoredTransportParameters, TransportParameters: restored}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version, _ protocol.PathID) (*coalescedPacket, error) {
				close(packedFirstPacket)
				return &coalescedPacket{buffer: getPacketBuffer(), longHdrPackets: []*longHeaderPacket{{header: hdr}}}, nil
			},
		),
		// initial keys are dropped when the first handshake packet is sent
		cs.EXPECT().DiscardInitialKeys(),
		// no more data to send
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedTransportParameters, TransportParameters: &new}),
		cs.EXPECT().ConnectionState().Return(handshake.ConnectionState{Used0RTT: true}),
		// cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		cs.EXPECT().Close(),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).Return(nil, nil).AnyTimes()
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "server sent reduced limits after accepting 0-RTT data")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionReceivePrioritization(t *testing.T) {
	for _, handshakeComplete := range []bool{true, false} {
		t.Run(fmt.Sprintf("handshake complete: %t", handshakeComplete), func(t *testing.T) {
			events := testConnectionReceivePrioritization(t, handshakeComplete, 5)
			require.Equal(t, []string{"unpack", "unpack", "unpack", "unpack", "unpack", "pack"}, events)
		})
	}
}

func testConnectionReceivePrioritization(t *testing.T, handshakeComplete bool, numPackets int) []string {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	opts := []testConnectionOpt{connectionOptUnpacker(unpacker)}
	if handshakeComplete {
		opts = append(opts, connectionOptHandshakeConfirmed())
	}
	tc := newServerTestConnection(t, mockCtrl, nil, false, opts...)

	var events []string
	var counter int
	var testDone bool
	done := make(chan struct{})
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(rcvTime monotime.Time, data []byte, _ protocol.PathID) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
			counter++
			if counter == numPackets {
				testDone = true
			}
			events = append(events, "unpack")
			return protocol.PacketNumber(counter), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0, 1} /* PADDING, PING */, nil
		},
	).Times(numPackets)
	switch handshakeComplete {
	case false:
		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version, _ protocol.PathID) (*coalescedPacket, error) {
				events = append(events, "pack")
				if testDone {
					close(done)
				}
				return nil, nil
			},
		).AnyTimes()
	case true:
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(b *packetBuffer, bc protocol.ByteCount, t monotime.Time, v protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
				events = append(events, "pack")
				if testDone {
					close(done)
				}
				return shortHeaderPacket{}, errNothingToPack
			},
		).AnyTimes()
	}

	for i := range numPackets {
		tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i), []byte("foobar")))
	}

	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return events
}

func TestConnectionPacketBuffering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		cs := mocks.NewMockCryptoSetup(mockCtrl)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptUnpacker(unpacker),
			connectionOptCryptoSetup(cs),
			connectionOptTracer(&eventRecorder),
		)

		cs.EXPECT().DiscardInitialKeys()

		hdr1 := wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: tc.srcConnID,
				SrcConnectionID:  tc.destConnID,
				Length:           8,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen1,
			PacketNumber:    1,
		}
		hdr2 := hdr1
		hdr2.PacketNumber = 2
		cs.EXPECT().StartHandshake(gomock.Any())
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		hdrs := make(map[string]*wire.ExtendedHeader)

		packet1 := getLongHeaderPacket(t, tc.remoteAddr, &hdr1, []byte("packet1"))
		datagramPayloadChecksum1 := qlog.CalculateDatagramPayloadChecksum(packet1.data)
		hdrs["packet1"] = &hdr1
		tc.conn.handlePacket(packet1)
		packet2 := getLongHeaderPacket(t, tc.remoteAddr, &hdr2, []byte("packet2"))
		datagramPayloadChecksum2 := qlog.CalculateDatagramPayloadChecksum(packet2.data)
		hdrs["packet2"] = &hdr2
		tc.conn.handlePacket(packet2)
		synctest.Wait()

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketBuffered{
					Header: qlog.PacketHeader{
						PacketType:   qlog.PacketTypeHandshake,
						PacketNumber: protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(packet1.Size())},
					DatagramPayloadChecksum: datagramPayloadChecksum1,
				},
				qlog.PacketBuffered{
					Header: qlog.PacketHeader{
						PacketType:   qlog.PacketTypeHandshake,
						PacketNumber: protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(packet2.Size())},
					DatagramPayloadChecksum: datagramPayloadChecksum2,
				},
			},
			eventRecorder.Events(qlog.PacketBuffered{}),
		)

		eventRecorder.Clear()

		// Now send another packet.
		// In reality, this packet would contain a CRYPTO frame that advances the TLS handshake
		// such that new keys become available.
		var packets []string
		hdr3 := hdr1
		hdr3.PacketNumber = 3
		hdrs["packet3"] = &hdr3
		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceived1RTTReadKeys})
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})

		gomock.InOrder(
			// packet 3 contains a CRYPTO frame and triggers the keys to become available
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
				func(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
					id := string(data[len(data)-7:])
					packets = append(packets, id)
					cf := &wire.CryptoFrame{Data: []byte("foobar")}
					b, _ := cf.Append(nil, protocol.Version1)
					extHdr, ok := hdrs[id]
					if !ok {
						panic(fmt.Sprintf("unknown header: %v", id))
					}
					return &unpackedPacket{hdr: extHdr, encryptionLevel: protocol.EncryptionHandshake, data: b}, nil
				},
			),
			cs.EXPECT().HandleMessage(gomock.Any(), gomock.Any()),
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
				func(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
					id := string(data[len(data)-7:])
					extHdr, ok := hdrs[id]
					if !ok {
						panic(fmt.Sprintf("unknown header: %v", id))
					}
					packets = append(packets, id)
					return &unpackedPacket{hdr: extHdr, encryptionLevel: protocol.EncryptionHandshake, data: []byte{0} /* PADDING */}, nil
				},
			).Times(2),
		)

		packet3 := getLongHeaderPacket(t, tc.remoteAddr, &hdr3, []byte("packet3"))
		datagramPayloadChecksum3 := qlog.CalculateDatagramPayloadChecksum(packet3.data)
		tc.conn.handlePacket(packet3)

		synctest.Wait()

		// packet3 triggered the keys to become available
		// packet1 and packet2 are processed from the buffer in order
		require.Equal(t, []string{"packet3", "packet1", "packet2"}, packets)

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketReceived{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketTypeHandshake,
						DestConnectionID: tc.srcConnID,
						SrcConnectionID:  tc.destConnID,
						PacketNumber:     3,
						Version:          protocol.Version1,
					},
					Raw:                     qlog.RawInfo{Length: int(packet3.Size()), PayloadLength: 8},
					DatagramPayloadChecksum: datagramPayloadChecksum3,
					Frames:                  []qlog.Frame{{Frame: &qlog.CryptoFrame{Length: 6}}},
				},
				qlog.PacketReceived{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketTypeHandshake,
						DestConnectionID: tc.srcConnID,
						SrcConnectionID:  tc.destConnID,
						PacketNumber:     1,
						Version:          protocol.Version1,
					},
					Raw:                     qlog.RawInfo{Length: int(packet1.Size()), PayloadLength: 8},
					DatagramPayloadChecksum: datagramPayloadChecksum1,
					Frames:                  []qlog.Frame{},
				},
				qlog.PacketReceived{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketTypeHandshake,
						DestConnectionID: tc.srcConnID,
						SrcConnectionID:  tc.destConnID,
						PacketNumber:     2,
						Version:          protocol.Version1,
					},
					Raw:                     qlog.RawInfo{Length: int(packet1.Size()), PayloadLength: 8},
					DatagramPayloadChecksum: datagramPayloadChecksum2,
					Frames:                  []qlog.Frame{},
				},
			},
			eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketBuffered{}),
		)

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		cs.EXPECT().Close()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestConnectionPacketPacing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sender := NewMockSender(mockCtrl)

		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptSentPacketHandler(sph),
			connectionOptSender(sender),
			connectionOptHandshakeConfirmed(),
		)
		sender.EXPECT().Run()

		const step = 50 * time.Millisecond

		sph.EXPECT().GetLossDetectionTimeout().Return(monotime.Now().Add(time.Hour)).AnyTimes()
		gomock.InOrder(
			// 1. allow 2 packets to be sent
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
			// 2. become pacing limited for 25ms
			sph.EXPECT().TimeUntilSend().DoAndReturn(func() monotime.Time { return monotime.Now().Add(step) }),
			// 3. send another packet
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
			// 4. become pacing limited for 25ms...
			sph.EXPECT().TimeUntilSend().DoAndReturn(func() monotime.Time { return monotime.Now().Add(step) }),
			// ... but this time we're still pacing limited when waking up.
			// In this case, we can only send an ACK.
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
			// 5. stop the test by becoming pacing limited forever
			sph.EXPECT().TimeUntilSend().Return(monotime.Now().Add(time.Hour)),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		)
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		for i := range 3 {
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), Version1, gomock.Any()).DoAndReturn(
				func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buf.Data = append(buf.Data, []byte("packet"+strconv.Itoa(i+1))...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i + 1)}, nil
				},
			)
		}
		tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
				buf := getPacketBuffer()
				buf.Data = []byte("ack")
				return shortHeaderPacket{PacketNumber: 1}, buf, nil
			},
		)
		sender.EXPECT().WouldBlock().AnyTimes()

		type sentPacket struct {
			time monotime.Time
			data []byte
		}
		sendChan := make(chan sentPacket, 10)
		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(b *packetBuffer, _ uint16, _ protocol.ECN) {
			sendChan <- sentPacket{time: monotime.Now(), data: b.Data}
		}).Times(4)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		var times []monotime.Time
		for i := range 3 {
			select {
			case b := <-sendChan:
				require.Equal(t, []byte("packet"+strconv.Itoa(i+1)), b.data)
				times = append(times, b.time)
			case <-time.After(time.Hour):
				t.Fatal("should have sent a packet")
			}
		}
		select {
		case b := <-sendChan:
			require.Equal(t, []byte("ack"), b.data)
			times = append(times, b.time)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		require.Equal(t, times[0], times[1])
		require.Equal(t, times[2], times[1].Add(step))
		require.Equal(t, times[3], times[2].Add(step))

		synctest.Wait() // make sure that no more packets are sent
		require.True(t, mockCtrl.Satisfied())

		// test teardown
		sender.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case <-sendChan:
			t.Fatal("should not have sent any more packets")
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

// When the send queue blocks, we need to reset the pacing timer, otherwise the run loop might busy-loop.
// See https://github.com/quic-go/quic-go/pull/4943 for more details.
func TestConnectionPacingAndSendQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sender := NewMockSender(mockCtrl)

		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptSentPacketHandler(sph),
			connectionOptSender(sender),
			connectionOptHandshakeConfirmed(),
		)
		sender.EXPECT().Run()

		sendQueueAvailable := make(chan struct{})
		pacingDeadline := monotime.Now().Add(-time.Millisecond)
		var counter int
		// allow exactly one packet to be sent, then become blocked
		sender.EXPECT().WouldBlock().Return(false)
		sender.EXPECT().WouldBlock().DoAndReturn(func() bool { counter++; return true }).AnyTimes()
		sender.EXPECT().Available().Return(sendQueueAvailable).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().Return(monotime.Now().Add(time.Hour)).AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited).AnyTimes()
		sph.EXPECT().TimeUntilSend().Return(pacingDeadline).AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECNNon).AnyTimes()
		tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{}, nil, errNothingToPack,
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		sender.EXPECT().Close()
		tc.conn.destroy(nil)

		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}

		// make sure the run loop didn't do too many iterations
		require.Less(t, counter, 3)
	})
}

func TestConnectionIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{MaxIdleTimeout: time.Minute},
			false,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
			connectionOptRTT(time.Millisecond),
		)
		// the idle timeout is set when the transport parameters are received
		const idleTimeout = 500 * time.Millisecond
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
			MaxIdleTimeout: idleTimeout,
		}))

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		var lastSendTime monotime.Time
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
				buf.Data = append(buf.Data, []byte("foobar")...)
				lastSendTime = monotime.Now()
				return shortHeaderPacket{Frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, Length: 6}, nil
			},
		)
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &IdleTimeoutError{})
			require.NotZero(t, lastSendTime)
			require.Equal(t, idleTimeout, monotime.Since(lastSendTime))
		case <-time.After(time.Hour):
			t.Fatal("should have timed out")
		}
	})
}

func TestConnectionKeepAlive(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testConnectionKeepAlive(t, true, true)
	})

	t.Run("disabled", func(t *testing.T) {
		testConnectionKeepAlive(t, false, false)
	})
}

func testConnectionKeepAlive(t *testing.T, enable, expectKeepAlive bool) {
	synctest.Test(t, func(t *testing.T) {
		var keepAlivePeriod time.Duration
		if enable {
			keepAlivePeriod = time.Second
		}

		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{MaxIdleTimeout: time.Second, KeepAlivePeriod: keepAlivePeriod},
			false,
			connectionOptUnpacker(unpacker),
			connectionOptHandshakeConfirmed(),
			connectionOptRTT(time.Millisecond),
		)
		// the idle timeout is set when the transport parameters are received
		const idleTimeout = 50 * time.Millisecond
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
			MaxIdleTimeout: idleTimeout,
		}))

		// Receive a packet. This starts the keep-alive timer.
		buf := getPacketBuffer()
		var err error
		buf.Data, err = wire.AppendShortHeader(buf.Data, tc.srcConnID, 1, protocol.PacketNumberLen1, protocol.KeyPhaseZero)
		require.NoError(t, err)
		buf.Data = append(buf.Data, []byte("packet")...)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		var unpackTime, packTime monotime.Time
		done := make(chan struct{})
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(t monotime.Time, bytes []byte, _ protocol.PathID) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				unpackTime = monotime.Now()
				return protocol.PacketNumber(1), protocol.PacketNumberLen1, protocol.KeyPhaseZero, []byte{0} /* PADDING */, nil
			},
		)
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)

		switch expectKeepAlive {
		case true:
			// record the time of the keep-alive is sent
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					packTime = monotime.Now()
					close(done)
					return shortHeaderPacket{}, errNothingToPack
				},
			)
			tc.conn.handlePacket(receivedPacket{data: buf.Data, buffer: buf, rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr})
			select {
			case <-done:
				// the keep-alive packet should be sent after half the idle timeout
				require.Equal(t, unpackTime.Add(idleTimeout/2), packTime)
			case <-time.After(idleTimeout):
				t.Fatal("timeout")
			}
		case false: // if keep-alives are disabled, the connection will run into an idle timeout
			tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			tc.conn.handlePacket(receivedPacket{data: buf.Data, buffer: buf, rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr})
		}

		// test teardown
		if expectKeepAlive {
			tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			tc.conn.destroy(nil)
		}

		synctest.Wait()

		select {
		case err := <-errChan:
			if expectKeepAlive {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, &IdleTimeoutError{})
			}
		case <-time.After(time.Hour):
			t.Fatal("timeout")
		}
	})
}

func TestConnectionACKTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{MaxIdleTimeout: time.Second},
			false,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)
		const alarmTimeout = 500 * time.Millisecond

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		// Set initial alarm timeout far in the future
		_ = tc.receivedPacketHandler().ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, monotime.Now().Add(time.Hour), true, 0)

		var times []monotime.Time
		done := make(chan struct{}, 5)
		var calls []any

		for range 2 {
			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buf.Data = append(buf.Data, []byte("foobar")...)
					times = append(times, monotime.Now())
					rph := tc.receivedPacketHandler()
					if len(times) == 1 {
						// After first packet is sent, set alarm timeout for the next iteration
						// Get the ACK frame to reset state, then receive a new packet to set alarm
						_ = rph.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), false, 0)
						alarmRcvTime := monotime.Now().Add(alarmTimeout - protocol.MaxAckDelay)
						_ = rph.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, alarmRcvTime, true, 0)
					} else {
						// After second packet is sent, set alarm timeout far in the future
						_ = rph.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), false, 0)
						_ = rph.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, monotime.Now().Add(time.Hour), true, 0)
					}
					return shortHeaderPacket{Frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, Length: 6}, nil
				},
			))
			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					done <- struct{}{}
					return shortHeaderPacket{}, errNothingToPack
				},
			))
		}
		gomock.InOrder(calls...)
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		for range 2 {
			synctest.Wait()

			select {
			case <-done:
			case <-time.After(time.Hour):
				t.Fatal("timeout")
			}
		}

		assert.Len(t, times, 2)
		require.Equal(t, times[0].Add(alarmTimeout), times[1])

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

// Send a GSO batch, until we have no more data to send.
func TestConnectionGSOBatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			true,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)

		// allow packets to be sent
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

		maxPacketSize := tc.conn.maxPacketSize()
		var expectedData []byte
		for i := range 4 {
			data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			expectedData = append(expectedData, data...)

			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, data...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i)}, nil
				},
			)
		}
		done := make(chan struct{})
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)
		tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1).DoAndReturn(
			func([]byte, uint16, protocol.ECN) error { close(done); return nil },
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("should have sent a packet")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

// Send a GSO batch, until a packet smaller than the maximum size is packed
func TestConnectionGSOBatchPacketSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			true,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)

		// allow packets to be sent
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

		maxPacketSize := tc.conn.maxPacketSize()
		var expectedData []byte
		var calls []any
		for i := range 4 {
			var data []byte
			if i == 3 {
				data = bytes.Repeat([]byte{byte(i)}, int(maxPacketSize-1))
			} else {
				data = bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			}
			expectedData = append(expectedData, data...)

			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, data...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(10 + i)}, nil
				},
			))
		}
		// The smaller (fourth) packet concluded this GSO batch, but the send loop will immediately start composing the next batch.
		// We therefore send a "foobar", so we can check that we're actually generating two GSO batches.
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, []byte("foobar")...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(14)}, nil
				},
			),
		)
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack),
		)
		gomock.InOrder(calls...)

		done := make(chan struct{})
		gomock.InOrder(
			tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1),
			tc.sendConn.EXPECT().Write([]byte("foobar"), uint16(maxPacketSize), protocol.ECT1).DoAndReturn(
				func([]byte, uint16, protocol.ECN) error { close(done); return nil },
			),
		)
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("should have sent a packet")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

func TestConnectionGSOBatchECN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			true,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)

		// allow packets to be sent
		ecnMode := protocol.ECT1
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).DoAndReturn(func(bool) protocol.ECN { return ecnMode }).AnyTimes()

		// 3. Send a GSO batch, until the ECN marking changes.
		var expectedData []byte
		var calls []any
		maxPacketSize := tc.conn.maxPacketSize()
		for i := range 3 {
			data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			expectedData = append(expectedData, data...)

			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, data...)
					if i == 2 {
						ecnMode = protocol.ECNCE
					}
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(20 + i)}, nil
				},
			))
		}
		// The smaller (fourth) packet concluded this GSO batch, but the send loop will immediately start composing the next batch.
		// We therefore send a "foobar", so we can check that we're actually generating two GSO batches.
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, []byte("foobar")...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(24)}, nil
				},
			),
		)
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack),
		)
		gomock.InOrder(calls...)

		done3 := make(chan struct{})
		tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1)
		tc.sendConn.EXPECT().Write([]byte("foobar"), uint16(maxPacketSize), protocol.ECNCE).DoAndReturn(
			func([]byte, uint16, protocol.ECN) error { close(done3); return nil },
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done3:
		default:
			t.Fatal("should have sent a packet")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

func TestConnectionPTOProbePackets(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.Encryption1RTT)
	})
}

func testConnectionPTOProbePackets(t *testing.T, encLevel protocol.EncryptionLevel) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptSentPacketHandler(sph),
		)

		var sendMode ackhandler.SendMode
		switch encLevel {
		case protocol.EncryptionInitial:
			sendMode = ackhandler.SendPTOInitial
		case protocol.EncryptionHandshake:
			sendMode = ackhandler.SendPTOHandshake
		case protocol.Encryption1RTT:
			sendMode = ackhandler.SendPTOAppData
		}

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(sendMode)
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
		sph.EXPECT().ECNMode(gomock.Any())
		sph.EXPECT().QueueProbePacket(encLevel).Return(false)
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		tc.packer.EXPECT().PackPTOProbePacket(encLevel, gomock.Any(), true, gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(protocol.EncryptionLevel, protocol.ByteCount, bool, monotime.Time, protocol.Version, protocol.PathID) (*coalescedPacket, error) {
				return &coalescedPacket{
					buffer:         getPacketBuffer(),
					shortHdrPacket: &shortHeaderPacket{PacketNumber: 1},
				}, nil
			},
		)
		done := make(chan struct{})
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
			func([]byte, uint16, protocol.ECN) error { close(done); return nil },
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

func TestConnectionCongestionControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)

		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(true).AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(2)
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck).MaxTimes(1)
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
		// Since we're already sending out packets, we don't expect any calls to PackAckOnlyPacket
		for i := range 2 {
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, []byte("foobar")...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i)}, nil
				},
			)
		}
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
		done1 := make(chan struct{})
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
			func([]byte, uint16, protocol.ECN) error { close(done1); return nil },
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done1:
		default:
			t.Fatal("should have sent a packet")
		}
		require.True(t, mockCtrl.Satisfied())

		// Now that we're congestion limited, we can only send an ack-only packet
		done2 := make(chan struct{})
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck)
		tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
				close(done2)
				return shortHeaderPacket{}, nil, errNothingToPack
			},
		)
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done2:
		default:
			t.Fatal("should have sent an ack-only packet")
		}
		require.True(t, mockCtrl.Satisfied())

		// If the send mode is "none", we can't even send an ack-only packet
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
		tc.conn.scheduleSending()
		synctest.Wait() // make sure there are no calls to the packer

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
}

func TestConnectionSendQueue(t *testing.T) {
	t.Run("with GSO", func(t *testing.T) {
		testConnectionSendQueue(t, true)
	})
	t.Run("without GSO", func(t *testing.T) {
		testConnectionSendQueue(t, false)
	})
}

func testConnectionSendQueue(t *testing.T, enableGSO bool) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sender := NewMockSender(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			enableGSO,
			connectionOptSender(sender),
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)

		sender.EXPECT().Run().MaxTimes(1)
		sender.EXPECT().WouldBlock()
		sender.EXPECT().WouldBlock().Return(true).Times(2)
		available := make(chan struct{})
		blocked := make(chan struct{})
		sender.EXPECT().Available().DoAndReturn(
			func() <-chan struct{} {
				close(blocked)
				return available
			},
		)
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{PacketNumber: protocol.PacketNumber(1)}, nil,
		)
		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-blocked:
		default:
			t.Fatal("should have blocked")
		}
		require.True(t, mockCtrl.Satisfied())

		// now make room in the send queue
		sender.EXPECT().WouldBlock().AnyTimes()
		unblocked := make(chan struct{})
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, error) {
				close(unblocked)
				return shortHeaderPacket{}, errNothingToPack
			},
		)
		available <- struct{}{}

		synctest.Wait()

		select {
		case <-unblocked:
		default:
			t.Fatal("should have unblocked")
		}

		// test teardown
		sender.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
}

// A client discards packets from server addresses other than the one it sent the handshake to (section 9 of RFC 9000).
func TestConnectionClientDropsPacketsFromUnknownServerAddress(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptUnpacker(unpacker),
		connectionOptTracer(&eventRecorder),
	)
	c := tc.conn
	unknownAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4322}

	t.Run("1-RTT packet", func(t *testing.T) {
		eventRecorder.Clear()
		wasProcessed, err := c.handleOnePacket(getShortHeaderPacket(t, unknownAddr, tc.srcConnID, 1, []byte("foobar")), 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{qlog.PacketDropped{Raw: qlog.RawInfo{Length: 1 + tc.srcConnID.Len() + 2 + 6}, Trigger: qlog.PacketDropUnexpectedPacket}},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("Handshake packet", func(t *testing.T) {
		eventRecorder.Clear()
		p := getLongHeaderPacket(t, unknownAddr, &wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: tc.srcConnID,
				SrcConnectionID:  tc.destConnID,
				Length:           8,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}, make([]byte, 6))
		wasProcessed, err := c.handleOnePacket(p, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Len(t, eventRecorder.Events(qlog.PacketDropped{}), 1)
	})

	// IPv4-mapped IPv6 addresses are equal to the corresponding IPv4 addresses
	t.Run("IPv4-mapped server address", func(t *testing.T) {
		eventRecorder.Clear()
		addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4).To16(), Port: 4321}
		require.Len(t, addr.IP, net.IPv6len)
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			protocol.PacketNumber(2), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{1} /* PING */, nil,
		)
		wasProcessed, err := c.handleOnePacket(getShortHeaderPacket(t, addr, tc.srcConnID, 2, []byte("foobar")), 0)
		require.NoError(t, err)
		require.True(t, wasProcessed)
		require.Empty(t, eventRecorder.Events(qlog.PacketDropped{}))
	})

	// A net.PacketConn that doesn't use UDP addresses might not report the server address.
	t.Run("address of another type", func(t *testing.T) {
		eventRecorder.Clear()
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			protocol.PacketNumber(3), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{1} /* PING */, nil,
		)
		wasProcessed, err := c.handleOnePacket(getShortHeaderPacket(t, &mockAddr{str: "relay"}, tc.srcConnID, 3, []byte("foobar")), 0)
		require.NoError(t, err)
		require.True(t, wasProcessed)
		require.Empty(t, eventRecorder.Events(qlog.PacketDropped{}))
	})
}

// With IETF Multipath QUIC, the client discards long header packets from unknown server addresses as well.
func TestConnectionClientDropsLongHeaderPacketsFromUnknownServerAddressMultipath(t *testing.T) {
	var eventRecorder events.Recorder
	tc := newIETFMultipathTestConnection(t, protocol.PerspectiveClient, 2, 2, true, connectionOptTracer(&eventRecorder))
	p := getLongHeaderPacket(t, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4322}, &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: tc.srcConnID,
			SrcConnectionID:  tc.destConnID,
			Length:           8,
			Version:          protocol.Version1,
		},
		PacketNumberLen: protocol.PacketNumberLen2,
	}, make([]byte, 6))
	wasProcessed, err := tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Len(t, eventRecorder.Events(qlog.PacketDropped{}), 1)
}

// sourceRewritingConn reports a wrong source address for every third datagram received while rewrite is set.
type sourceRewritingConn struct {
	net.PacketConn
	addr    net.Addr
	rewrite atomic.Bool
	count   atomic.Int64
}

func (c *sourceRewritingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && c.rewrite.Load() && c.count.Add(1)%3 == 0 {
		return n, c.addr, nil
	}
	return n, addr, err
}

// Packets that appear to come from another server address are discarded. The connection recovers from the loss.
func TestConnectionClientDropsPacketsFromUnknownServerAddressEndToEnd(t *testing.T) {
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()
	clientConn := &sourceRewritingConn{
		PacketConn: newUDPConnLocalhost(t),
		addr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.Addr().(*net.UDPAddr).Port + 1},
	}
	clientTr := &Transport{Conn: clientConn}
	defer clientTr.Close()

	var recorder events.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), &Config{Tracer: multipathTestTracer(&recorder)})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	clientConn.rewrite.Store(true)
	data := make([]byte, 50_000)
	rand.Read(data)
	go func() {
		str, err := sconn.OpenUniStream()
		if err != nil {
			return
		}
		str.Write(data)
		str.Close()
	}()
	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	received, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, data, received)

	var dropped int
	for _, ev := range recorder.Events(qlog.PacketDropped{}) {
		if ev.(qlog.PacketDropped).Trigger == qlog.PacketDropUnexpectedPacket {
			dropped++
		}
	}
	require.NotZero(t, dropped)
}

// If the client dialed an unspecified IP address, the operating system chooses the server address.
// The client learns it from the first packet that is processed, and discards packets from other addresses after that.
func TestConnectionClientDialedUnspecifiedAddress(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptUnpacker(unpacker),
		connectionOptTracer(&eventRecorder),
	)
	c := tc.conn
	c.peerHandshakeAddr = &net.UDPAddr{IP: net.IPv6unspecified, Port: 4321}

	// before the first packet was processed, packets from other ports are discarded
	wasProcessed, err := c.handleOnePacket(getShortHeaderPacket(t, &net.UDPAddr{IP: net.IPv6loopback, Port: 4322}, tc.srcConnID, 1, []byte("foobar")), 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Len(t, eventRecorder.Events(qlog.PacketDropped{}), 1)
	require.Nil(t, c.unspecifiedServerAddr)

	// a packet that can't be decrypted doesn't determine the server address
	eventRecorder.Clear()
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, handshake.ErrDecryptionFailed,
	)
	wasProcessed, err = c.handleOnePacket(getShortHeaderPacket(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4321}, tc.srcConnID, 2, []byte("foobar")), 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Nil(t, c.unspecifiedServerAddr)

	serverAddr := &net.UDPAddr{IP: net.IPv6loopback, Port: 4321}
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(3), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{1} /* PING */, nil,
	)
	wasProcessed, err = c.handleOnePacket(getShortHeaderPacket(t, serverAddr, tc.srcConnID, 3, []byte("foobar")), 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.Equal(t, serverAddr, c.unspecifiedServerAddr)

	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(4), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{1} /* PING */, nil,
	)
	wasProcessed, err = c.handleOnePacket(getShortHeaderPacket(t, &net.UDPAddr{IP: net.IPv6loopback, Port: 4321}, tc.srcConnID, 4, []byte("foobar")), 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)

	// packets from other addresses are discarded now
	eventRecorder.Clear()
	wasProcessed, err = c.handleOnePacket(getShortHeaderPacket(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4321}, tc.srcConnID, 5, []byte("foobar")), 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Len(t, eventRecorder.Events(qlog.PacketDropped{}), 1)
}

// A client can dial the address of a listener on an unspecified IP address, e.g. "0.0.0.0:1234".
func TestConnectionClientDialUnspecifiedAddressEndToEnd(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		t.Run(fmt.Sprintf("multipath: %t", multipath), func(t *testing.T) {
			t.Run("IPv4", func(t *testing.T) {
				testConnectionClientDialUnspecifiedAddressEndToEnd(t, "udp4", &net.UDPAddr{IP: net.IPv4zero}, "udp4", multipath)
			})
			t.Run("IPv6", func(t *testing.T) {
				testConnectionClientDialUnspecifiedAddressEndToEnd(t, "udp6", &net.UDPAddr{IP: net.IPv6unspecified}, "udp6", multipath)
			})
			// ListenAddr("0.0.0.0:0") and DialAddr use dual-stack sockets
			t.Run("dual-stack", func(t *testing.T) {
				testConnectionClientDialUnspecifiedAddressEndToEnd(t, "udp", &net.UDPAddr{IP: net.IPv4zero}, "", multipath)
			})
		})
	}
}

func testConnectionClientDialUnspecifiedAddressEndToEnd(t *testing.T, network string, addr *net.UDPAddr, clientNetwork string, multipath bool) {
	udpConn, err := net.ListenUDP(network, addr)
	if err != nil {
		t.Skipf("can't listen on %s: %s", addr, err)
	}
	newConfig := func() *Config {
		if !multipath {
			return nil
		}
		return &Config{MultipathControllerFactory: func() MultipathController { return NewDefaultMultipathController(nil) }}
	}
	serverTr := &Transport{Conn: udpConn}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), newConfig())
	require.NoError(t, err)
	defer ln.Close()
	require.True(t, ln.Addr().(*net.UDPAddr).IP.IsUnspecified())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var conn *Conn
	if clientNetwork == "" {
		conn, err = DialAddr(ctx, ln.Addr().String(), generateTLSConfigWithServerName("localhost"), newConfig())
	} else {
		clientConn, lerr := net.ListenUDP(clientNetwork, nil)
		require.NoError(t, lerr)
		clientTr := &Transport{Conn: clientConn}
		defer clientTr.Close()
		conn, err = clientTr.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), newConfig())
	}
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	require.Equal(t, multipath, conn.ConnectionState().SupportsMultipath)

	str, err := sconn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	rstr, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(rstr)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
}

func getVersionNegotiationPacket(src, dest protocol.ConnectionID, versions []protocol.Version) receivedPacket {
	b := wire.ComposeVersionNegotiation(
		protocol.ArbitraryLenConnectionID(src.Bytes()),
		protocol.ArbitraryLenConnectionID(dest.Bytes()),
		versions,
	)
	return receivedPacket{
		rcvTime: monotime.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionVersionNegotiation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
		tc.connRunner.EXPECT().Remove(gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		vnp := getVersionNegotiationPacket(
			tc.destConnID,
			tc.srcConnID,
			[]protocol.Version{1234, protocol.Version2},
		)
		// the version negotiation packet might contained greased versions
		_, _, vnpVersions, err := wire.ParseVersionNegotiationPacket(vnp.data)
		require.NoError(t, err)
		tc.conn.handlePacket(vnp)

		synctest.Wait()

		select {
		case err := <-errChan:
			var rerr *errCloseForRecreating
			require.ErrorAs(t, err, &rerr)
			require.Equal(t, rerr.nextVersion, protocol.Version2)
		default:
			t.Fatal("should have received a Version Negotiation packet")
		}
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.VersionNegotiationReceived{
					Header: qlog.PacketHeaderVersionNegotiation{
						SrcConnectionID:  protocol.ArbitraryLenConnectionID(tc.destConnID.Bytes()),
						DestConnectionID: protocol.ArbitraryLenConnectionID(tc.srcConnID.Bytes()),
					},
					SupportedVersions: vnpVersions,
				},
				qlog.VersionInformation{
					ServerVersions: vnpVersions,
					ClientVersions: []qlog.Version{protocol.Version1, protocol.Version2},
					ChosenVersion:  protocol.Version2,
				},
			},
			eventRecorder.Events(qlog.VersionNegotiationReceived{}, qlog.VersionInformation{}),
		)
	})
}

func TestConnectionVersionNegotiationNoMatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t,
			mockCtrl,
			&Config{Versions: []protocol.Version{protocol.Version1}},
			false,
			connectionOptTracer(&eventRecorder),
		)

		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
		tc.connRunner.EXPECT().Remove(gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		vnp := getVersionNegotiationPacket(
			tc.destConnID,
			tc.srcConnID,
			[]protocol.Version{protocol.Version2},
		)
		_, _, vnpVersions, err := wire.ParseVersionNegotiationPacket(vnp.data)
		require.NoError(t, err)
		tc.conn.handlePacket(vnp)

		synctest.Wait()

		select {
		case err := <-errChan:
			var verr *VersionNegotiationError
			require.ErrorAs(t, err, &verr)
			require.Contains(t, verr.Theirs, protocol.Version2)
			require.Equal(t,
				[]qlogwriter.Event{
					qlog.VersionNegotiationReceived{
						Header: qlog.PacketHeaderVersionNegotiation{
							SrcConnectionID:  protocol.ArbitraryLenConnectionID(tc.destConnID.Bytes()),
							DestConnectionID: protocol.ArbitraryLenConnectionID(tc.srcConnID.Bytes()),
						},
						SupportedVersions: vnpVersions,
					},
					qlog.ConnectionClosed{
						Initiator: qlog.InitiatorLocal,
						Trigger:   qlog.ConnectionCloseTriggerVersionMismatch,
					},
				},
				eventRecorder.Events(qlog.VersionNegotiationReceived{}, qlog.ConnectionClosed{}),
			)
		default:
			t.Fatal("should have received a Version Negotiation packet")
		}
	})
}

func TestConnectionVersionNegotiationInvalidPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
	)

	// offers the current version
	vnp := getVersionNegotiationPacket(
		tc.destConnID,
		tc.srcConnID,
		[]protocol.Version{1234, protocol.Version1},
	)
	wasProcessed, err := tc.conn.handleOnePacket(vnp, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(vnp.Size())},
				Trigger: qlog.PacketDropUnexpectedVersion,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	require.True(t, mockCtrl.Satisfied())
	eventRecorder.Clear()

	// unparseable, since it's missing 2 bytes
	vnp.data = vnp.data[:len(vnp.data)-2]
	wasProcessed, err = tc.conn.handleOnePacket(vnp, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(vnp.Size())},
				Trigger: qlog.PacketDropHeaderParseError,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func getRetryPacket(t *testing.T, src, dest, origDest protocol.ConnectionID, token []byte) receivedPacket {
	hdr := wire.Header{
		Type:             protocol.PacketTypeRetry,
		SrcConnectionID:  src,
		DestConnectionID: dest,
		Token:            token,
		Version:          protocol.Version1,
	}
	b, err := (&wire.ExtendedHeader{Header: hdr}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	tag := handshake.GetRetryIntegrityTag(b, origDest, protocol.Version1)
	b = append(b, tag[:]...)
	return receivedPacket{
		rcvTime: monotime.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionRetryDrops(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptUnpacker(unpacker),
	)

	newConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})

	// invalid integrity tag
	retry := getRetryPacket(t, newConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	retry.data[len(retry.data)-1]++
	wasProcessed, err := tc.conn.handleOnePacket(retry, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  newConnID,
					DestConnectionID: tc.srcConnID,
					Version:          protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(retry.Size())},
				Trigger: qlog.PacketDropPayloadDecryptError,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// receive a retry that doesn't change the connection ID
	retry = getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	wasProcessed, err = tc.conn.handleOnePacket(retry, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  tc.destConnID,
					DestConnectionID: tc.srcConnID,
					Version:          protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(retry.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func TestConnectionRetryAfterReceivedPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptUnpacker(unpacker),
	)

	// receive a regular packet
	regular := getPacketWithPacketType(t, tc.srcConnID, protocol.PacketTypeInitial, 200)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
		&unpackedPacket{
			hdr:             &wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeInitial}},
			encryptionLevel: protocol.EncryptionInitial,
		}, nil,
	)
	wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{
		data:       regular,
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
		remoteAddr: tc.remoteAddr,
	}, 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)

	require.Len(t, eventRecorder.Events(qlog.PacketReceived{}), 1)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.VersionInformation{
				ChosenVersion:  protocol.Version1,
				ClientVersions: tc.conn.config.Versions,
			},
		},
		eventRecorder.Events(qlog.VersionInformation{}),
	)
	eventRecorder.Clear()

	// receive a retry
	retry := getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	wasProcessed, err = tc.conn.handleOnePacket(retry, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  tc.conn.origDestConnID,
					DestConnectionID: tc.srcConnID,
					Version:          tc.conn.version,
				},
				Raw:     qlog.RawInfo{Length: int(retry.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	eventRecorder.Clear()
}

// A client that advertised the initial_max_path_id transport parameter can't use a zero-length connection ID
// after a Retry (section 2.1 of draft-ietf-quic-multipath-21).
func TestConnectionRetryZeroLengthConnIDMultipath(t *testing.T) {
	t.Run("multipath advertised", func(t *testing.T) {
		testConnectionRetryZeroLengthConnIDMultipath(t, true)
	})
	t.Run("multipath not advertised", func(t *testing.T) {
		testConnectionRetryZeroLengthConnIDMultipath(t, false)
	})
}

func testConnectionRetryZeroLengthConnIDMultipath(t *testing.T, advertisedMultipath bool) {
	mockCtrl := gomock.NewController(t)
	tc := newClientTestConnection(t, mockCtrl, nil, false)
	tc.conn.advertisedMultipath = advertisedMultipath

	retry := getRetryPacket(t, protocol.ConnectionID{}, tc.srcConnID, tc.destConnID, []byte("foobar"))
	if !advertisedMultipath {
		tc.packer.EXPECT().SetToken([]byte("foobar"))
	}
	wasProcessed, err := tc.conn.handleOnePacket(retry, 0)
	require.NoError(t, err)
	require.Equal(t, !advertisedMultipath, wasProcessed)
	if !advertisedMultipath {
		require.Nil(t, tc.conn.closeErr.Load())
		require.True(t, tc.conn.receivedRetry)
		require.Zero(t, tc.conn.handshakeDestConnID.Len())
		return
	}
	// The server didn't create any state for the connection, so no CONNECTION_CLOSE is sent.
	closeErr := tc.conn.closeErr.Load()
	require.NotNil(t, closeErr)
	require.True(t, closeErr.immediate)
	require.ErrorIs(t, closeErr.err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	require.False(t, tc.conn.receivedRetry)
	require.Equal(t, tc.destConnID, tc.conn.handshakeDestConnID)
	require.Nil(t, tc.conn.retrySrcConnID)
}

func TestConnectionConnectionIDChanges(t *testing.T) {
	t.Run("with retry", func(t *testing.T) {
		testConnectionConnectionIDChanges(t, true)
	})
	t.Run("without retry", func(t *testing.T) {
		testConnectionConnectionIDChanges(t, false)
	})
}

func testConnectionConnectionIDChanges(t *testing.T, sendRetry bool) {
	synctest.Test(t, func(t *testing.T) {
		makeInitialPacket := func(t *testing.T, hdr *wire.ExtendedHeader) []byte {
			t.Helper()
			data, err := hdr.Append(nil, protocol.Version1)
			require.NoError(t, err)
			data = append(data, make([]byte, hdr.Length-protocol.ByteCount(hdr.PacketNumberLen))...)
			return data
		}

		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newClientTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptTracer(&eventRecorder),
			connectionOptUnpacker(unpacker),
		)

		dstConnID := tc.destConnID
		b := make([]byte, 3*10)
		rand.Read(b)
		newConnID := protocol.ParseConnectionID(b[:11])
		newConnID2 := protocol.ParseConnectionID(b[11:20])

		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		require.Equal(t, dstConnID, tc.conn.connIDManager.Get())

		var retryConnID protocol.ConnectionID
		if sendRetry {
			retryConnID = protocol.ParseConnectionID(b[20:30])
			tc.packer.EXPECT().SetToken([]byte("foobar"))

			retry := getRetryPacket(t, retryConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
			tc.conn.handlePacket(retry)

			synctest.Wait()

			require.Equal(t,
				[]qlogwriter.Event{
					qlog.PacketReceived{
						Header: qlog.PacketHeader{
							PacketType:       qlog.PacketTypeRetry,
							SrcConnectionID:  retryConnID,
							DestConnectionID: dstConnID,
							Version:          protocol.Version1,
							Token:            &qlog.Token{Raw: []byte("foobar")},
						},
						Raw: qlog.RawInfo{Length: int(retry.Size())},
					},
				},
				eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
			)
		}
		eventRecorder.Clear()

		// Send the first packet. The server changes the connection ID to newConnID.
		hdr1 := wire.ExtendedHeader{
			Header: wire.Header{
				SrcConnectionID:  newConnID,
				DestConnectionID: tc.srcConnID,
				Type:             protocol.PacketTypeInitial,
				Length:           200,
				Version:          protocol.Version1,
			},
			PacketNumber:    1,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr2 := hdr1
		hdr2.SrcConnectionID = newConnID2

		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: &hdr1, encryptionLevel: protocol.EncryptionInitial}, nil,
		)
		eventRecorder.Clear()
		packet1 := getLongHeaderPacket(t, tc.remoteAddr, &hdr1, make([]byte, 198))
		tc.conn.handlePacket(packet1)

		synctest.Wait()

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketReceived{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketTypeInitial,
						SrcConnectionID:  newConnID,
						DestConnectionID: tc.srcConnID,
						PacketNumber:     1,
						Version:          protocol.Version1,
					},
					Raw:                     qlog.RawInfo{Length: int(packet1.Size()), PayloadLength: int(hdr1.Length)},
					DatagramPayloadChecksum: qlog.CalculateDatagramPayloadChecksum(packet1.data),
					Frames:                  []qlog.Frame{},
				},
			},
			eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
		)
		eventRecorder.Clear()

		// Send the second packet. We refuse to accept it, because the connection ID is changed again.
		packet2 := receivedPacket{data: makeInitialPacket(t, &hdr2), buffer: getPacketBuffer(), rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr}
		tc.conn.handlePacket(packet2)

		synctest.Wait()

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:   qlog.PacketTypeInitial,
						PacketNumber: protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(packet2.Size())},
					DatagramPayloadChecksum: qlog.CalculateDatagramPayloadChecksum(packet2.data),
					Trigger:                 qlog.PacketDropUnknownConnectionID,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}, qlog.PacketReceived{}),
		)
		// the connection ID should not have changed
		require.Equal(t, newConnID, tc.conn.connIDManager.Get())

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any())
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have shut down")
		}
	})
}

// When the connection is closed before sending the first packet,
// we don't send a CONNECTION_CLOSE.
// This can happen if there's something wrong the tls.Config, and
// crypto/tls refuses to start the handshake.
func TestConnectionEarlyClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		cryptoSetup := mocks.NewMockCryptoSetup(mockCtrl)
		tc := newClientTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptTracer(&eventRecorder),
			connectionOptCryptoSetup(cryptoSetup),
		)

		tc.conn.sentFirstPacket = false
		cryptoSetup.EXPECT().StartHandshake(gomock.Any()).Do(func(context.Context) error {
			tc.conn.closeLocal(errors.New("early error"))
			return nil
		})
		cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
		cryptoSetup.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorContains(t, err, "early error")
			code := qerr.InternalError
			require.Equal(t,
				[]qlogwriter.Event{
					qlog.ConnectionClosed{
						Initiator:       qlog.InitiatorLocal,
						ConnectionError: &code,
						Reason:          "early error",
					},
				},
				eventRecorder.Events(qlog.ConnectionClosed{}),
			)
		default:
			t.Fatal("should have shut down")
		}
	})
}

func TestConnectionPathValidation(t *testing.T) {
	t.Run("NAT rebinding", func(t *testing.T) {
		testConnectionPathValidation(t, true)
	})

	t.Run("intentional migration", func(t *testing.T) {
		testConnectionPathValidation(t, false)
	})
}

// If the PATH_RESPONSE is lost while the packet containing the PATH_CHALLENGE is acknowledged, the server sends
// another PATH_CHALLENGE when it receives packets on the path after a PTO (section 8.2.1 of RFC 9000).
// Otherwise, the path would never be validated, and the server would keep sending to the client's old address.
func TestConnectionPathValidationRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(
			t,
			mockCtrl,
			nil,
			false,
			connectionOptUnpacker(unpacker),
			connectionOptHandshakeConfirmed(),
			connectionOptRTT(time.Second),
		)
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{MaxUDPPayloadSize: 1456}))
		// the client's address was validated during the handshake
		tc.conn.sentPacketHandler.ReceivedPacket(protocol.EncryptionHandshake, monotime.Now())

		// the client's NAT rebinds to a new address
		newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		var pathChallenges []*wire.PathChallengeFrame
		var sentPN protocol.PacketNumber
		expectPathChallenge := func() []any {
			return []any{
				tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
						require.Len(t, frames, 1)
						pathChallenges = append(pathChallenges, frames[0].Frame.(*wire.PathChallengeFrame))
						sentPN++
						return shortHeaderPacket{PacketNumber: sentPN, IsPathProbePacket: true, Length: protocol.MinInitialPacketSize}, getPacketBuffer(), nil
					},
				),
				tc.sendConn.EXPECT().WriteTo(gomock.Any(), newRemoteAddr, packetInfo{}),
			}
		}
		start := monotime.Now()
		receivePacket := func(pn protocol.PacketNumber, payload []byte, rcvTime monotime.Time) {
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
				pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
			)
			tc.conn.handlePacket(receivedPacket{
				data:       make([]byte, 400),
				buffer:     getPacketBuffer(),
				remoteAddr: newRemoteAddr,
				rcvTime:    rcvTime,
			})
			synctest.Wait()
		}
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{}, errNothingToPack,
		).AnyTimes()

		ping := []byte{1} // PING frame
		gomock.InOrder(expectPathChallenge()...)
		receivePacket(10, ping, start)
		require.Len(t, pathChallenges, 1)

		// The PATH_RESPONSE is lost. Packets received before the PTO expires don't trigger another PATH_CHALLENGE.
		receivePacket(11, ping, start.Add(time.Second))
		require.Len(t, pathChallenges, 1)
		require.Equal(t, tc.remoteAddr, tc.conn.RemoteAddr())

		// the PTO is a few seconds
		gomock.InOrder(expectPathChallenge()...)
		receivePacket(12, ping, start.Add(time.Minute))
		require.Len(t, pathChallenges, 2)
		require.NotEqual(t, pathChallenges[0].Data, pathChallenges[1].Data)

		// the response to the second PATH_CHALLENGE validates the path, and the server migrates
		migrated := make(chan struct{})
		tc.sendConn.EXPECT().ChangeRemoteAddr(newRemoteAddr, gomock.Any()).Do(
			func(net.Addr, packetInfo) { close(migrated) },
		)
		// after migrating, the server validates the previous path (section 9.3.3 of RFC 9000)
		tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{PacketNumber: 3, IsPathProbePacket: true, Length: protocol.MinInitialPacketSize}, getPacketBuffer(), nil,
		)
		tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.remoteAddr, packetInfo{})
		payload, err := (&wire.PathResponseFrame{Data: pathChallenges[1].Data}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		receivePacket(13, payload, start.Add(time.Minute+time.Second))
		select {
		case <-migrated:
		default:
			t.Fatal("should have migrated")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have shut down")
		}
	})
}

func testConnectionPathValidation(t *testing.T, isNATRebinding bool) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(
			t,
			mockCtrl,
			nil,
			false,
			connectionOptUnpacker(unpacker),
			connectionOptHandshakeConfirmed(),
			connectionOptRTT(time.Second),
		)
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{MaxUDPPayloadSize: 1456}))
		// the client's address was validated during the handshake
		tc.conn.sentPacketHandler.ReceivedPacket(protocol.EncryptionHandshake, monotime.Now())

		newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
		require.NotEqual(t, tc.remoteAddr, newRemoteAddr)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		probeSent := make(chan struct{})
		var pathChallenge *wire.PathChallengeFrame
		payload := []byte{0} // PADDING frame
		if isNATRebinding {
			payload = []byte{1} // PING frame
		}
		gomock.InOrder(
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
				protocol.PacketNumber(10), protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
			),
			tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
					require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), maxSize)
					pathChallenge = frames[0].Frame.(*wire.PathChallengeFrame)
					return shortHeaderPacket{IsPathProbePacket: true, Length: protocol.MinInitialPacketSize}, getPacketBuffer(), nil
				},
			),
			tc.sendConn.EXPECT().WriteTo(gomock.Any(), newRemoteAddr, packetInfo{}).DoAndReturn(
				func([]byte, net.Addr, packetInfo) error { close(probeSent); return nil },
			),
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
				shortHeaderPacket{}, errNothingToPack,
			),
		)

		// The datagram is large enough for the anti-amplification limit to allow a probe packet of 1200 bytes.
		tc.conn.handlePacket(receivedPacket{
			data:       make([]byte, 400),
			buffer:     getPacketBuffer(),
			remoteAddr: newRemoteAddr,
			rcvTime:    monotime.Now(),
		})

		synctest.Wait()

		select {
		case <-probeSent:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		// Receive a packed containing a PATH_RESPONSE frame.
		// Only if the first packet received on the path was a probing packet
		// (i.e. we're dealing with a NAT rebinding), this makes us switch to the new path.
		migrated := make(chan struct{})
		data, err := (&wire.PathResponseFrame{Data: pathChallenge.Data}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		calls := []any{
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
				protocol.PacketNumber(11), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
			),
		}
		// After migrating, the server validates the previous path (section 9.3.3 of RFC 9000).
		var prevPathChallenge *wire.PathChallengeFrame
		expectPrevPathValidation := func() []any {
			return []any{
				tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
						require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), maxSize)
						require.Len(t, frames, 1)
						prevPathChallenge = frames[0].Frame.(*wire.PathChallengeFrame)
						return shortHeaderPacket{PacketNumber: 1, IsPathProbePacket: true, Length: protocol.MinInitialPacketSize}, getPacketBuffer(), nil
					},
				),
				tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.remoteAddr, packetInfo{}),
			}
		}
		if isNATRebinding {
			calls = append(calls,
				tc.sendConn.EXPECT().ChangeRemoteAddr(newRemoteAddr, gomock.Any()).Do(
					func(net.Addr, packetInfo) { close(migrated) },
				),
			)
			calls = append(calls, expectPrevPathValidation()...)
		}
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
				shortHeaderPacket{}, errNothingToPack,
			).MaxTimes(1),
		)
		gomock.InOrder(calls...)
		require.Equal(t, tc.remoteAddr, tc.conn.RemoteAddr())
		// the PATH_RESPONSE can be sent on the old path, if the client is just probing the new path
		addr := tc.remoteAddr
		if isNATRebinding {
			addr = newRemoteAddr
		}
		tc.conn.handlePacket(receivedPacket{
			data:       make([]byte, 100),
			buffer:     getPacketBuffer(),
			remoteAddr: addr,
			rcvTime:    monotime.Now(),
		})

		synctest.Wait()

		if !isNATRebinding {
			// If the first packet was a probing packet, we only switch to the new path when we
			// receive a non-probing packet on that path.
			select {
			case <-migrated:
				t.Fatal("didn't expect a migration yet")
			default:
			}

			payload := []byte{1} // PING frame
			payload, err = (&wire.PathResponseFrame{Data: pathChallenge.Data}).Append(payload, protocol.Version1)
			require.NoError(t, err)
			calls := []any{
				unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					protocol.PacketNumber(12), protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
				),
				tc.sendConn.EXPECT().ChangeRemoteAddr(newRemoteAddr, gomock.Any()).Do(
					func(net.Addr, packetInfo) { close(migrated) },
				),
			}
			calls = append(calls, expectPrevPathValidation()...)
			calls = append(calls,
				tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					shortHeaderPacket{}, errNothingToPack,
				).MaxTimes(1),
			)
			gomock.InOrder(calls...)
			tc.conn.handlePacket(receivedPacket{
				data:       make([]byte, 100),
				buffer:     getPacketBuffer(),
				remoteAddr: newRemoteAddr,
				rcvTime:    monotime.Now(),
			})
		}

		synctest.Wait()

		select {
		case <-migrated:
		default:
			t.Fatal("should have migrated")
		}
		require.NotNil(t, prevPathChallenge)
		require.NotEqual(t, pathChallenge.Data, prevPathChallenge.Data)

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have shut down")
		}
	})
}

// recordingSendQueue records the destination address, the packet info and the ECN marking of the packets sent.
type recordingSendQueue struct {
	sent  []net.Addr
	infos []packetInfo   // the packet info of each sent packet
	ecns  []protocol.ECN // the ECN marking of each sent packet
}

var _ sender = &recordingSendQueue{}

func (q *recordingSendQueue) Send(p *packetBuffer, _ uint16, ecn protocol.ECN) {
	q.record(nil, packetInfo{}, ecn)
	p.Release()
}

func (q *recordingSendQueue) SendOnConn(p *packetBuffer, _ uint16, ecn protocol.ECN, conn sendConn) {
	q.record(conn.RemoteAddr(), packetInfo{}, ecn)
	p.Release()
}

func (q *recordingSendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	q.record(addr, info, protocol.ECNUnsupported)
	p.Release()
}

func (q *recordingSendQueue) record(addr net.Addr, info packetInfo, ecn protocol.ECN) {
	q.sent = append(q.sent, addr)
	q.infos = append(q.infos, info)
	q.ecns = append(q.ecns, ecn)
}

func (q *recordingSendQueue) Run() error                 { return nil }
func (q *recordingSendQueue) WouldBlock() bool           { return false }
func (q *recordingSendQueue) Available() <-chan struct{} { return make(chan struct{}) }
func (q *recordingSendQueue) Close()                     {}

// receivePathChallenge makes the connection receive a 1-RTT packet containing a PATH_CHALLENGE.
func receivePathChallenge(t *testing.T, tc *testConnection, unpacker *MockUnpacker, data [8]byte, p receivedPacket) {
	t.Helper()
	payload, err := (&wire.PathChallengeFrame{Data: data}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		tc.conn.largestRcvdAppData+1, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
	)
	p.data = make([]byte, 10)
	p.buffer = getPacketBuffer()
	p.rcvTime = monotime.Now()
	processed, err := tc.conn.handleShortHeaderPacket(p, false, 0)
	require.NoError(t, err)
	require.True(t, processed)
}

// The client can validate the current path at any time, see section 8.2 of RFC 9000.
func TestConnectionServerPathChallengeOnCurrentPath(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	receivePathChallenge(t, tc, unpacker, challenge, receivedPacket{remoteAddr: tc.remoteAddr})
	// the PATH_RESPONSE is queued, and sent with the next packet on the current path
	require.Empty(t, sendQueue.sent)
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	require.Equal(t, &wire.PathResponseFrame{Data: challenge}, frames[0].Frame)
}

// queuedPathResponses returns the data of the PATH_RESPONSE frames queued for path 0, in the order they are sent.
func queuedPathResponses(c *Conn) [][8]byte {
	var data [][8]byte
	for c.mp != nil && c.mp.HasPathFrames(0) {
		frames, _ := c.mp.AppendPathFrames(nil, 0, protocol.MaxByteCount, protocol.Version1)
		for _, f := range frames {
			data = append(data, f.Frame.(*wire.PathResponseFrame).Data)
		}
	}
	// The framer packs a single PATH_RESPONSE frame per packet.
	for {
		var found bool
		for _, f := range queuedFrames(c) {
			if pr, ok := f.Frame.(*wire.PathResponseFrame); ok {
				data = append(data, pr.Data)
				found = true
			}
		}
		if !found {
			return data
		}
	}
}

// Every PATH_CHALLENGE frame is answered, even if a packet contains multiple PATH_CHALLENGE frames
// (section 8.2.2 of RFC 9000).
func TestConnectionPathChallengesInOnePacket(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			for _, mode := range []string{"without multipath", "IETF Multipath QUIC before activation", "IETF Multipath QUIC"} {
				t.Run(mode, func(t *testing.T) {
					mockCtrl := gomock.NewController(t)
					unpacker := NewMockUnpacker(mockCtrl)
					opts := []testConnectionOpt{connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed()}
					var tc *testConnection
					switch {
					case mode != "without multipath":
						tc = newIETFMultipathTestConnection(t, pers, 2, 2, mode == "IETF Multipath QUIC", opts...)
					case pers == protocol.PerspectiveClient:
						tc = newClientTestConnection(t, mockCtrl, nil, false, opts...)
					default:
						tc = newServerTestConnection(t, mockCtrl, nil, false, opts...)
					}
					c := tc.conn
					queuedFrames(c)

					var data []byte
					for _, f := range []wire.Frame{
						&wire.PathChallengeFrame{Data: [8]byte{1}},
						&wire.PingFrame{},
						&wire.PathChallengeFrame{Data: [8]byte{2}},
						&wire.PathChallengeFrame{Data: [8]byte{3}},
					} {
						var err error
						data, err = f.Append(data, protocol.Version1)
						require.NoError(t, err)
					}
					unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(0)).Return(
						protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
					)
					// With IETF Multipath QUIC, the client drops packets from unknown server addresses.
					_, err := c.handleOnePacket(getShortHeaderPacket(t, c.conn.RemoteAddr(), tc.srcConnID, 1, []byte("encrypted")), 0)
					require.NoError(t, err)

					// With IETF Multipath QUIC, the PATH_RESPONSE frames are sent on path 0.
					if mode == "IETF Multipath QUIC" {
						require.True(t, c.mp.HasPathFrames(0))
					}
					require.Equal(t, [][8]byte{{1}, {2}, {3}}, queuedPathResponses(c))
				})
			}
		})
	}
}

// PATH_CHALLENGE frames are allowed in 0-RTT packets (section 12.4 of RFC 9000).
func TestConnectionServerPathChallengeIn0RTTPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptUnpacker(unpacker))
	c := tc.conn
	queuedFrames(c)

	var data []byte
	for _, f := range []wire.Frame{&wire.PathChallengeFrame{Data: [8]byte{1}}, &wire.PathChallengeFrame{Data: [8]byte{2}}} {
		var err error
		data, err = f.Append(data, protocol.Version1)
		require.NoError(t, err)
	}
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketType0RTT,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           2,
		},
		PacketNumber:    1,
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.Encryption0RTT,
		hdr:             hdr,
		data:            data,
	}, nil)
	wasProcessed, err := c.handleOnePacket(getLongHeaderPacket(t, tc.remoteAddr, hdr, nil), 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.Equal(t, [][8]byte{{1}, {2}}, queuedPathResponses(c))
}

// The probe packet sent when the client probes a new path contains the PATH_RESPONSE.
// It must be sent on the path that the PATH_CHALLENGE was received on (see section 8.2.2 of RFC 9000),
// i.e. from the local address the packet was received on.
func TestConnectionServerPathProbeFromArrivalAddress(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
	localAddr := netip.MustParseAddr("127.0.0.2")

	var sentFrames []wire.Frame
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.PathID(0)).DoAndReturn(
		func(_ protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			for _, f := range frames {
				sentFrames = append(sentFrames, f.Frame)
			}
			return shortHeaderPacket{IsPathProbePacket: true, Frames: frames}, getPacketBuffer(), nil
		},
	)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	receivePathChallenge(t, tc, unpacker, challenge, receivedPacket{remoteAddr: newRemoteAddr, info: packetInfo{addr: localAddr}})
	require.Len(t, sentFrames, 2)
	require.IsType(t, &wire.PathChallengeFrame{}, sentFrames[0])
	require.Equal(t, &wire.PathResponseFrame{Data: challenge}, sentFrames[1])
	require.Equal(t, []net.Addr{newRemoteAddr}, sendQueue.sent)
	require.Equal(t, []packetInfo{{addr: localAddr}}, sendQueue.infos)
	require.Equal(t, []protocol.ECN{protocol.ECNUnsupported}, sendQueue.ecns)
	// only a single PATH_RESPONSE is sent
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, frames)
	require.Equal(t, tc.remoteAddr, tc.conn.RemoteAddr())
}

// The server limits the probe packets sent to a new client address to 3 times the size of the datagram received,
// until the client's address is validated (sections 8 and 9.3 of RFC 9000). If the datagram containing the
// PATH_CHALLENGE couldn't be expanded to 1200 bytes, the path MTU is validated with a second PATH_CHALLENGE in an
// expanded datagram (section 8.2.1 of RFC 9000).
func TestConnectionServerPathProbeAmplificationLimit(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
	info := packetInfo{addr: netip.MustParseAddr("127.0.0.2")}

	type probe struct {
		frames  []wire.Frame
		maxSize protocol.ByteCount
	}
	var probes []probe
	var pn protocol.PacketNumber
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.PathID(0)).DoAndReturn(
		func(_ protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			pr := probe{maxSize: maxSize}
			for _, f := range frames {
				pr.frames = append(pr.frames, f.Frame)
			}
			probes = append(probes, pr)
			pn++
			return shortHeaderPacket{PacketNumber: pn, IsPathProbePacket: true, Frames: frames, Length: min(maxSize, protocol.MinInitialPacketSize)}, getPacketBuffer(), nil
		},
	).AnyTimes()

	// The client probes a new path with a datagram of 10 bytes.
	receivePathChallenge(t, tc, unpacker, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, receivedPacket{remoteAddr: newRemoteAddr, info: info})
	require.Len(t, probes, 1)
	require.Equal(t, protocol.ByteCount(30), probes[0].maxSize)
	require.Len(t, probes[0].frames, 2)
	require.Contains(t, probes[0].frames, &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}})
	var challenge *wire.PathChallengeFrame
	for _, f := range probes[0].frames {
		if pc, ok := f.(*wire.PathChallengeFrame); ok {
			challenge = pc
		}
	}
	require.NotNil(t, challenge)
	require.NoError(t, tc.conn.sendDuePathChallenges(monotime.Now()))
	require.Len(t, probes, 1)

	// The PATH_RESPONSE validates the client's address, but not the path MTU.
	payload, err := (&wire.PathResponseFrame{Data: challenge.Data}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		tc.conn.largestRcvdAppData+1, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
	)
	_, err = tc.conn.handleShortHeaderPacket(receivedPacket{
		remoteAddr: newRemoteAddr,
		info:       info,
		data:       make([]byte, 10),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}, false, 0)
	require.NoError(t, err)
	require.Len(t, probes, 1)
	require.NoError(t, tc.conn.sendDuePathChallenges(monotime.Now()))
	require.Len(t, probes, 2)
	require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), probes[1].maxSize)
	require.Len(t, probes[1].frames, 1)
	require.IsType(t, &wire.PathChallengeFrame{}, probes[1].frames[0])
	require.NotEqual(t, challenge, probes[1].frames[0])
	require.Equal(t, []net.Addr{newRemoteAddr, newRemoteAddr}, sendQueue.sent)
	require.Equal(t, []packetInfo{info, info}, sendQueue.infos)

	// The anti-amplification limit doesn't apply to the validated address anymore.
	receivePathChallenge(t, tc, unpacker, [8]byte{8, 7, 6, 5, 4, 3, 2, 1}, receivedPacket{remoteAddr: newRemoteAddr, info: info})
	require.Len(t, probes, 3)
	require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), probes[2].maxSize)
	require.Equal(t, []wire.Frame{&wire.PathResponseFrame{Data: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}}, probes[2].frames)
	require.Equal(t, tc.remoteAddr, tc.conn.RemoteAddr())
}

// Every PATH_CHALLENGE frame received on a new path is answered, as far as the anti-amplification limit allows.
// The frames are sent in as few probe packets as possible.
func TestConnectionServerPathChallengesOnNewPath(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}

	var probes [][]wire.Frame
	var maxSizes []protocol.ByteCount
	var pn protocol.PacketNumber
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.PathID(0)).DoAndReturn(
		func(_ protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			maxSizes = append(maxSizes, maxSize)
			// a packet of 100 bytes has room for 2 frames
			if maxSize < 100 || len(frames) > 2 {
				return shortHeaderPacket{}, nil, errNothingToPack
			}
			var probe []wire.Frame
			for _, f := range frames {
				probe = append(probe, f.Frame)
			}
			probes = append(probes, probe)
			pn++
			return shortHeaderPacket{PacketNumber: pn, IsPathProbePacket: true, Frames: frames, Length: 100}, getPacketBuffer(), nil
		},
	).AnyTimes()

	var data []byte
	for i := range 4 {
		var err error
		data, err = (&wire.PathChallengeFrame{Data: [8]byte{byte(i + 1)}}).Append(data, protocol.Version1)
		require.NoError(t, err)
	}
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
	)
	// 3 times 80 bytes allows two probe packets of 100 bytes
	_, err := tc.conn.handleShortHeaderPacket(receivedPacket{
		remoteAddr: newRemoteAddr,
		data:       make([]byte, 80),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}, false, 0)
	require.NoError(t, err)
	require.Equal(t, []protocol.ByteCount{240, 240, 240, 140, 140, 40}, maxSizes)
	require.Len(t, probes, 2)
	require.IsType(t, &wire.PathChallengeFrame{}, probes[0][0])
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1}}, probes[0][1])
	require.Equal(t, []wire.Frame{
		&wire.PathResponseFrame{Data: [8]byte{2}},
		&wire.PathResponseFrame{Data: [8]byte{3}},
	}, probes[1])
	require.Len(t, sendQueue.sent, 2)
}

// A datagram with many PATH_CHALLENGE frames received from a validated client address that isn't the current
// address (e.g. the previous path) is answered in as few probe packets as possible. The probe packets sent in response
// are limited to 3 times the size of the datagram, or 1200 bytes for small datagrams.
func TestConnectionServerPathChallengesFromValidatedAddress(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	c := tc.conn
	prevAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
	c.pathManager = newPathManager(c.connIDManager.GetConnIDForPath, c.connIDManager.RetireConnIDForPath, func() time.Duration { return time.Second }, c.logger)
	c.pathManager.AddPreviousPath(prevAddr, netip.Addr{}, packetInfo{}, monotime.Now())
	require.True(t, c.pathManager.AddrValidated(prevAddr, netip.Addr{}))

	// a packer that packs the frames into packets of at most maxSize bytes, expanded to 1200 bytes
	const overhead = 30
	var probeSizes []protocol.ByteCount
	var responses int
	var pn protocol.PacketNumber
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.PathID(0)).DoAndReturn(
		func(_ protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, v protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			size := protocol.ByteCount(overhead)
			for _, f := range frames {
				size += f.Frame.Length(v)
			}
			if size > maxSize {
				return shortHeaderPacket{}, nil, errNothingToPack
			}
			size = max(size, min(maxSize, protocol.MinInitialPacketSize))
			for _, f := range frames {
				if _, ok := f.Frame.(*wire.PathResponseFrame); ok {
					responses++
				}
			}
			probeSizes = append(probeSizes, size)
			pn++
			return shortHeaderPacket{PacketNumber: pn, IsPathProbePacket: true, Frames: frames, Length: size}, getPacketBuffer(), nil
		},
	).AnyTimes()

	receive := func(numChallenges int, size protocol.ByteCount) {
		t.Helper()
		var data []byte
		for i := range numChallenges {
			var err error
			data, err = (&wire.PathChallengeFrame{Data: [8]byte{byte(i), byte(i >> 8)}}).Append(data, protocol.Version1)
			require.NoError(t, err)
		}
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			c.largestRcvdAppData+1, protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
		)
		_, err := c.handleShortHeaderPacket(receivedPacket{
			remoteAddr: prevAddr,
			data:       make([]byte, size),
			buffer:     getPacketBuffer(),
			rcvTime:    monotime.Now(),
		}, false, 0)
		require.NoError(t, err)
	}

	// A datagram of 1250 bytes has room for 135 PATH_CHALLENGE frames.
	// They are answered in 2 packets: one packet only has room for 130 PATH_RESPONSE frames.
	receive(135, 1250)
	require.Equal(t, 135, responses)
	require.Len(t, probeSizes, 2)
	var sent protocol.ByteCount
	for _, s := range probeSizes {
		sent += s
	}
	require.LessOrEqual(t, sent, 3*protocol.ByteCount(1250))
	require.Len(t, sendQueue.sent, 2)

	// A small datagram is answered in a datagram of 1200 bytes (section 8.2.2 of RFC 9000).
	probeSizes = nil
	responses = 0
	receive(1, 50)
	require.Equal(t, []protocol.ByteCount{protocol.MinInitialPacketSize}, probeSizes)
	require.Equal(t, 1, responses)
	require.Equal(t, tc.remoteAddr, c.RemoteAddr())
}

// After the client migrated, the server uses the connection ID it used to validate the new path,
// since the connection ID used so far was used towards the previous client address (section 9.5 of RFC 9000).
// It validates the previous path (section 9.3.3 of RFC 9000), using a connection ID that is only used for that path.
// A non-probing packet received on the previous path then switches the connection back.
func TestConnectionServerMigrationValidatesPreviousPath(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	tc := newServerTestConnection(t, mockCtrl, nil, false,
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	c := tc.conn
	require.NoError(t, c.handleTransportParameters(&wire.TransportParameters{MaxUDPPayloadSize: 1456}))
	// the client's address was validated during the handshake
	c.sentPacketHandler.ReceivedPacket(protocol.EncryptionHandshake, monotime.Now())
	// the client uses a connection ID of non-zero length
	handshakeConnID := protocol.ParseConnectionID([]byte{9, 9, 9, 9})
	c.connIDManager = newConnIDManager(handshakeConnID, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, c.queueControlFrame)
	c.peerConnIDs = newPathConnIDManagers(c.connIDManager)
	// the sendConn keeps track of the remote address
	rawConn := NewMockRawConn(mockCtrl)
	rawConn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}).AnyTimes()
	c.conn = newSendConn(rawConn, tc.remoteAddr, packetInfo{}, utils.DefaultLogger)
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		protocol.ParseConnectionID([]byte{2, 2, 2, 2}),
		protocol.ParseConnectionID([]byte{3, 3, 3, 3}),
	}
	for i, connID := range connIDs {
		require.NoError(t, c.peerConnIDs.AddNewConnectionID(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(i + 1),
			ConnectionID:        connID,
			StatelessResetToken: protocol.StatelessResetToken{byte(i + 1)},
		}))
	}
	require.Equal(t, handshakeConnID, c.connIDManager.Get())
	queuedFrames(c)

	type probe struct {
		connID protocol.ConnectionID
		frames []wire.Frame
	}
	var probes []probe
	var pn protocol.PacketNumber
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.PathID(0)).DoAndReturn(
		func(connID protocol.ConnectionID, frames []ackhandler.Frame, maxSize protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			pr := probe{connID: connID}
			for _, f := range frames {
				pr.frames = append(pr.frames, f.Frame)
			}
			probes = append(probes, pr)
			pn++
			return shortHeaderPacket{PacketNumber: pn, IsPathProbePacket: true, Frames: frames, Length: min(maxSize, protocol.MinInitialPacketSize)}, getPacketBuffer(), nil
		},
	).AnyTimes()
	challengeData := func(pr probe) [8]byte {
		for _, f := range pr.frames {
			if pc, ok := f.(*wire.PathChallengeFrame); ok {
				return pc.Data
			}
		}
		t.Fatal("no PATH_CHALLENGE")
		return [8]byte{}
	}
	var rcvPN protocol.PacketNumber
	receive := func(addr net.Addr, frames ...wire.Frame) {
		t.Helper()
		var payload []byte
		for _, f := range frames {
			var err error
			payload, err = f.Append(payload, protocol.Version1)
			require.NoError(t, err)
		}
		rcvPN++
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			rcvPN, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
		)
		_, err := c.handleShortHeaderPacket(receivedPacket{
			remoteAddr: addr,
			data:       make([]byte, 1000),
			buffer:     getPacketBuffer(),
			rcvTime:    monotime.Now(),
		}, false, 0)
		require.NoError(t, err)
	}

	// the client migrates to a new address
	newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
	receive(newRemoteAddr, &wire.PingFrame{})
	require.Len(t, probes, 1)
	require.Equal(t, connIDs[0], probes[0].connID)
	receive(newRemoteAddr, &wire.PingFrame{}, &wire.PathResponseFrame{Data: challengeData(probes[0])})
	require.Equal(t, newRemoteAddr, c.RemoteAddr())
	require.Equal(t, connIDs[0], c.connIDManager.Get())
	// The connection ID used during the handshake is retired: the client didn't provide a stateless reset token for
	// it. The previous path is validated using another connection ID.
	require.Contains(t, queuedFrames(c), ackhandler.Frame{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 0}})
	require.NoError(t, c.sendDuePathChallenges(monotime.Now()))
	require.Len(t, probes, 2)
	require.Equal(t, connIDs[1], probes[1].connID)
	require.Len(t, probes[1].frames, 1)
	require.Equal(t, []net.Addr{newRemoteAddr, tc.remoteAddr}, sendQueue.sent)

	// The previous path is validated. A non-probing packet received on it switches the connection back.
	receive(tc.remoteAddr, &wire.PathResponseFrame{Data: challengeData(probes[1])})
	receive(tc.remoteAddr, &wire.PingFrame{})
	require.Equal(t, tc.remoteAddr, c.RemoteAddr())
	require.Equal(t, connIDs[1], c.connIDManager.Get())
	// The connection ID used on the new path is kept for validating that path, since the client provided
	// a stateless reset token for it.
	require.NotContains(t, queuedFrames(c), ackhandler.Frame{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 1}})
	require.NoError(t, c.sendDuePathChallenges(monotime.Now()))
	require.Len(t, probes, 3)
	require.Equal(t, connIDs[0], probes[2].connID)
	require.Equal(t, []net.Addr{newRemoteAddr, tc.remoteAddr, newRemoteAddr}, sendQueue.sent)
}

func TestConnectionMigrationServer(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	_, err := tc.conn.AddPath(&Transport{})
	require.ErrorContains(t, err, "server cannot initiate connection migration")
}

func TestConnectionMigration(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		testConnectionMigration(t, false)
	})

	t.Run("enabled", func(t *testing.T) {
		testConnectionMigration(t, true)
	})
}

func testConnectionMigration(t *testing.T, enabled bool) {
	tc := newClientTestConnection(t, nil, nil, false, connectionOptHandshakeConfirmed())
	require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
		DisableActiveMigration:          !enabled,
	}))

	tr := &Transport{
		Conn:              newUDPConnLocalhost(t),
		StatelessResetKey: &StatelessResetKey{},
	}
	defer tr.Close()
	path, err := tc.conn.AddPath(tr)
	if !enabled {
		require.ErrorContains(t, err, "server disabled connection migration")
		return
	}
	require.NoError(t, err)
	require.NotNil(t, path)

	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		shortHeaderPacket{}, errNothingToPack,
	).AnyTimes()
	packedProbe := make(chan struct{})
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ protocol.ConnectionID, _ []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			defer close(packedProbe)
			return shortHeaderPacket{IsPathProbePacket: true}, getPacketBuffer(), nil
		},
	).AnyTimes()
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any())
	// add a new connection ID, so the path can be probed
	_, err = tc.conn.handleFrame(&wire.NewConnectionIDFrame{
		SequenceNumber: 1,
		ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	}, protocol.EncryptionInitial, tc.destConnID, monotime.Now())
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	// Adding the path initialized the transport.
	// We can test this by triggering a stateless reset.
	conn := newUDPConnLocalhost(t)
	_, err = conn.WriteTo(append([]byte{0x40}, make([]byte, 100)...), tr.Conn.LocalAddr())
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = conn.ReadFrom(make([]byte, 100))
	require.NoError(t, err)

	go func() { path.Probe(context.Background()) }()
	select {
	case <-packedProbe:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().RemoveResetToken(gomock.Any()).MaxTimes(1)
	tc.conn.destroy(nil)
	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// A PATH_CHALLENGE received on a path that the client probes is answered on that path (section 8.2.2 of RFC 9000):
// the PATH_RESPONSE is sent from the path's Transport, using the path's connection ID.
func TestConnectionClientPathChallengeOnProbedPath(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptHandshakeConfirmed(), connectionOptUnpacker(unpacker))
	require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
	}))
	c := tc.conn
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any()).AnyTimes()
	pathConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	_, err := c.handleFrame(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: pathConnID}, protocol.Encryption1RTT, tc.destConnID, monotime.Now())
	require.NoError(t, err)

	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()
	path, err := c.AddPath(tr)
	require.NoError(t, err)
	// add the path to the path manager, as Path.Probe does
	pm := c.pathManagerOutgoing.Load()
	pm.addPath(path, func() {})
	serverConn := newUDPConnLocalhost(t)
	queuedFrames(c)

	receive := func(transport *Transport, data [8]byte) {
		t.Helper()
		payload, err := (&wire.PathChallengeFrame{Data: data}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			c.largestRcvdAppData+1, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
		)
		_, err = c.handleShortHeaderPacket(receivedPacket{
			remoteAddr: serverConn.LocalAddr(),
			data:       make([]byte, 1200),
			buffer:     getPacketBuffer(),
			rcvTime:    monotime.Now(),
			transport:  transport,
		}, false, 0)
		require.NoError(t, err)
	}

	tc.packer.EXPECT().PackPathProbePacket(pathConnID, gomock.Any(), protocol.ByteCount(protocol.MinInitialPacketSize), protocol.Version1, protocol.PathID(0)).DoAndReturn(
		func(_ protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3}}, Handler: emptyHandler{}}}, frames)
			buf := getPacketBuffer()
			buf.Data = append(buf.Data, "path response"...)
			return shortHeaderPacket{PacketNumber: 1, IsPathProbePacket: true, Frames: frames, Length: buf.Len()}, buf, nil
		},
	)
	receive(tr, [8]byte{1, 2, 3})
	require.Empty(t, queuedFrames(c))
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 100)
	n, addr, err := serverConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, "path response", string(b[:n]))
	require.Equal(t, tr.Conn.LocalAddr(), addr)

	// a PATH_CHALLENGE received on the active path is answered on the active path
	receive(nil, [8]byte{4, 5, 6})
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{4, 5, 6}}}}, queuedFrames(c))
	receive(&Transport{}, [8]byte{7, 8, 9})
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{7, 8, 9}}}}, queuedFrames(c))

	// once the connection switched to the path, it is the active path
	pm.paths[path.id].isValidated = true
	require.NoError(t, path.Switch())
	receive(tr, [8]byte{10, 11, 12})
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{10, 11, 12}}}}, queuedFrames(c))
}

// After the client switched paths, the server validates the previous path (section 9.3.3 of RFC 9000).
// The client answers its PATH_CHALLENGE from the Transport used for the handshake (section 8.2.2 of RFC 9000),
// using a connection ID that wasn't used on any other path (section 9.5 of RFC 9000).
func TestConnectionClientPathChallengeOnHandshakePath(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptHandshakeConfirmed(), connectionOptUnpacker(unpacker))
	require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
	}))
	c := tc.conn
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any()).AnyTimes()
	pathConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	_, err := c.handleFrame(&wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: pathConnID}, protocol.Encryption1RTT, tc.destConnID, monotime.Now())
	require.NoError(t, err)

	handshakeTr := &Transport{Conn: newUDPConnLocalhost(t)}
	require.NoError(t, handshakeTr.init(false))
	defer handshakeTr.Close()
	c.handshakeTransport = handshakeTr
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()
	path, err := c.AddPath(tr)
	require.NoError(t, err)
	// add the path to the path manager and take its connection ID, as Path.Probe does
	pm := c.pathManagerOutgoing.Load()
	pm.addPath(path, func() {})
	connID, ok := c.connIDManager.GetConnIDForPath(path.id)
	require.True(t, ok)
	require.Equal(t, pathConnID, connID)
	serverConn := newUDPConnLocalhost(t)
	queuedFrames(c)

	receive := func(transport *Transport, data [8]byte) {
		t.Helper()
		payload, err := (&wire.PathChallengeFrame{Data: data}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			c.largestRcvdAppData+1, protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
		)
		_, err = c.handleShortHeaderPacket(receivedPacket{
			remoteAddr: serverConn.LocalAddr(),
			data:       make([]byte, 1200),
			buffer:     getPacketBuffer(),
			rcvTime:    monotime.Now(),
			transport:  transport,
		}, false, 0)
		require.NoError(t, err)
	}

	// before switching, the handshake Transport is used by the active path
	receive(handshakeTr, [8]byte{1, 2, 3})
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3}}}}, queuedFrames(c))

	pm.paths[path.id].isValidated = true
	require.NoError(t, path.Switch())

	// Without an unused connection ID, the PATH_CHALLENGE is not answered.
	// It must not be answered on the active path.
	receive(handshakeTr, [8]byte{4, 5, 6})
	require.Empty(t, queuedFrames(c))

	newConnID := protocol.ParseConnectionID([]byte{5, 6, 7, 8})
	_, err = c.handleFrame(&wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: newConnID}, protocol.Encryption1RTT, tc.destConnID, monotime.Now())
	require.NoError(t, err)
	tc.packer.EXPECT().PackPathProbePacket(newConnID, gomock.Any(), protocol.ByteCount(protocol.MinInitialPacketSize), protocol.Version1, protocol.PathID(0)).DoAndReturn(
		func(_ protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{7, 8, 9}}, Handler: emptyHandler{}}}, frames)
			buf := getPacketBuffer()
			buf.Data = append(buf.Data, "path response"...)
			return shortHeaderPacket{PacketNumber: 1, IsPathProbePacket: true, Frames: frames, Length: buf.Len()}, buf, nil
		},
	)
	receive(handshakeTr, [8]byte{7, 8, 9})
	require.Empty(t, queuedFrames(c))
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 100)
	n, addr, err := serverConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, "path response", string(b[:n]))
	require.Equal(t, handshakeTr.Conn.LocalAddr(), addr)

	// PATH_CHALLENGE frames received on the active path are answered on the active path
	receive(tr, [8]byte{10, 11, 12})
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{10, 11, 12}}}}, queuedFrames(c))
}

// The client answers the PATH_CHALLENGE that the server sends to validate the previous path after the client switched
// paths (section 9.3.3 of RFC 9000) from the Transport used for the handshake (section 8.2.2 of RFC 9000).
func TestConnectionClientPathResponseOnHandshakePath(t *testing.T) {
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()
	handshakeConn := &countingPacketConn{PacketConn: newUDPConnLocalhost(t)}
	tr1 := &Transport{Conn: handshakeConn}
	defer tr1.Close()
	pathConn := &holdingPacketConn{countingPacketConn: countingPacketConn{PacketConn: newUDPConnLocalhost(t)}}
	tr2 := &Transport{Conn: pathConn}
	defer tr2.Close()

	var recorder events.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr1.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), &Config{Tracer: multipathTestTracer(&recorder)})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	// wait for the client to answer the server's PATH_CHALLENGE on the new path
	pathResponses := func(evs []qlogwriter.Event) int {
		var n int
		for _, ev := range evs {
			for _, f := range ev.(qlog.PacketSent).Frames {
				if _, ok := f.Frame.(*qlog.PathResponseFrame); ok {
					n++
				}
			}
		}
		return n
	}
	require.Eventually(t, func() bool { return pathResponses(recorder.Events(qlog.PacketSent{})) > 0 }, time.Second, time.Millisecond)

	// Hold back the packets sent on the new path, so that the server only switches to the path
	// once the client completed switching.
	pathConn.hold.Store(true)
	require.NoError(t, path.Switch())
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	// The client only sends on the new path after it sent all packets queued for the previous path.
	require.Eventually(t, func() bool { return pathConn.numHeld() > 0 }, time.Second, time.Millisecond)
	written := handshakeConn.written.Load()
	sentEvents := len(recorder.Events(qlog.PacketSent{}))
	pathConn.release()

	// The server switches to the new path once it receives the stream data, and validates the previous path.
	rstr, err := sconn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(rstr)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
	// The PATH_RESPONSE frames are sent from the Transport used for the handshake.
	// The packet is logged before it is sent.
	require.Eventually(t, func() bool {
		responses := pathResponses(recorder.Events(qlog.PacketSent{})[sentEvents:])
		return responses > 0 && int(handshakeConn.written.Load()-written) >= responses
	}, 2*time.Second, time.Millisecond)
}

// After switching to a path added with AddPath, the client recognizes a stateless reset that the server sends on that
// path (section 10.3.1 of RFC 9000).
func TestConnectionClientStatelessResetOnNewPath(t *testing.T) {
	var serverKey StatelessResetKey
	rand.Read(serverKey[:])
	udpConn := newUDPConnLocalhost(t)
	serverConn := &droppingPacketConn{PacketConn: udpConn}
	serverTr := &Transport{Conn: serverConn, StatelessResetKey: &serverKey}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()
	tr1 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr1.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), nil)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	// the server switches to the path once it receives a non-probing packet on it
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return sconn.RemoteAddr().String() == tr2.Conn.LocalAddr().String()
	}, time.Second, time.Millisecond)

	// The server loses its state. A new Transport on the same address sends a stateless reset
	// when it receives a packet for the connection.
	serverConn.drop.Store(true)
	require.NoError(t, serverTr.Close())
	require.NoError(t, udpConn.Close())
	udpConn2, err := net.ListenUDP("udp", udpConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	serverTr2 := &Transport{Conn: udpConn2, StatelessResetKey: &serverKey}
	defer serverTr2.Close()
	ln2, err := serverTr2.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln2.Close()

	_, err = str.Write(make([]byte, 100))
	require.NoError(t, err)
	select {
	case <-conn.Context().Done():
		require.ErrorIs(t, context.Cause(conn.Context()), &StatelessResetError{})
	case <-ctx.Done():
		t.Fatal("the client didn't recognize the stateless reset")
	}
}

// holdingPacketConn holds back the datagrams written while hold is set, until release is called.
type holdingPacketConn struct {
	countingPacketConn
	hold atomic.Bool

	mx   sync.Mutex
	held []heldDatagram
}

type heldDatagram struct {
	data []byte
	addr net.Addr
}

func (c *holdingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mx.Lock()
	if c.hold.Load() {
		c.held = append(c.held, heldDatagram{data: slices.Clone(b), addr: addr})
		c.mx.Unlock()
		return len(b), nil
	}
	c.mx.Unlock()
	return c.countingPacketConn.WriteTo(b, addr)
}

func (c *holdingPacketConn) numHeld() int {
	c.mx.Lock()
	defer c.mx.Unlock()
	return len(c.held)
}

func (c *holdingPacketConn) release() {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.hold.Store(false)
	for _, d := range c.held {
		c.countingPacketConn.WriteTo(d.data, d.addr)
	}
	c.held = nil
}

// When switching to a new path, the client uses the connection ID it used for probing the path, which wasn't used on
// any other path, and retires the connection ID used so far (section 9.5 of RFC 9000).
func TestConnectionClientPathSwitchConnectionID(t *testing.T) {
	tc := newClientTestConnection(t, nil, nil, false, connectionOptHandshakeConfirmed(), connectionOptSender(&recordingSendQueue{}))
	require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
	}))
	c := tc.conn
	c.applyTransportParameters()
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().RemoveResetToken(gomock.Any()).AnyTimes()
	connIDs := []protocol.ConnectionID{
		protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
		protocol.ParseConnectionID([]byte{2, 2, 2, 2}),
		protocol.ParseConnectionID([]byte{3, 3, 3, 3}),
	}
	for i, connID := range connIDs {
		_, err := c.handleFrame(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(i + 1),
			ConnectionID:        connID,
			StatelessResetToken: protocol.StatelessResetToken{byte(i + 1)},
		}, protocol.Encryption1RTT, tc.destConnID, monotime.Now())
		require.NoError(t, err)
	}
	require.Equal(t, tc.destConnID, c.connIDManager.Get())
	queuedFrames(c)

	// probe and validate a path, as Path.Probe does
	addValidatedPath := func() *Path {
		t.Helper()
		tr := &Transport{Conn: newUDPConnLocalhost(t)}
		t.Cleanup(func() { tr.Close() })
		path, err := c.AddPath(tr)
		require.NoError(t, err)
		pm := c.pathManagerOutgoing.Load()
		pm.addPath(path, func() {})
		pm.enqueueProbe(path)
		_, f, _, ok := pm.NextPathToProbe()
		require.True(t, ok)
		pm.HandlePathResponseFrame(&wire.PathResponseFrame{Data: f.Frame.(*wire.PathChallengeFrame).Data})
		return path
	}
	switchToPath := func(path *Path) {
		t.Helper()
		require.NoError(t, path.Switch())
		tr, id, ok := c.pathManagerOutgoing.Load().ShouldSwitchPath(c.connIDManager.HasConnIDForPath)
		require.True(t, ok)
		// switching to a new path closes the send queue of the previous path
		c.switchToNewPath(tr, id, monotime.Now())
		require.Equal(t, path.tr.Conn.LocalAddr(), c.LocalAddr())
	}
	defer func() { c.sendQueue.Close() }()

	path1 := addValidatedPath()
	switchToPath(path1)
	require.Equal(t, connIDs[0], c.connIDManager.Get())
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 0}}}, queuedFrames(c))

	path2 := addValidatedPath()
	switchToPath(path2)
	require.Equal(t, connIDs[1], c.connIDManager.Get())
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 1}}}, queuedFrames(c))

	// Switching back to the first path uses a new connection ID:
	// the one used for probing that path was used on that path.
	switchToPath(path1)
	require.Equal(t, connIDs[2], c.connIDManager.Get())
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 2}}}, queuedFrames(c))

	// No unused connection ID is left. Switching back to the second path is delayed,
	// since the connection ID used on the first path must not be used from another local address.
	require.NoError(t, path2.Switch())
	pm := c.pathManagerOutgoing.Load()
	_, _, ok := pm.ShouldSwitchPath(c.connIDManager.HasConnIDForPath)
	require.False(t, ok)
	require.Equal(t, connIDs[2], c.connIDManager.Get())
	_, err := c.handleFrame(&wire.NewConnectionIDFrame{
		SequenceNumber:      4,
		ConnectionID:        protocol.ParseConnectionID([]byte{4, 4, 4, 4}),
		StatelessResetToken: protocol.StatelessResetToken{4},
	}, protocol.Encryption1RTT, tc.destConnID, monotime.Now())
	require.NoError(t, err)
	tr, id, ok := pm.ShouldSwitchPath(c.connIDManager.HasConnIDForPath)
	require.True(t, ok)
	c.switchToNewPath(tr, id, monotime.Now())
	require.Equal(t, path2.tr.Conn.LocalAddr(), c.LocalAddr())
	require.Equal(t, protocol.ParseConnectionID([]byte{4, 4, 4, 4}), c.connIDManager.Get())
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 3}}}, queuedFrames(c))
}

// The client answers the PATH_CHALLENGE that the server sends when the client probes a new path on that path.
func TestConnectionClientPathResponseOnProbedPath(t *testing.T) {
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()
	tr1 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	pathConn := &countingPacketConn{PacketConn: newUDPConnLocalhost(t)}
	tr2 := &Transport{Conn: pathConn}
	defer tr2.Close()

	var recorder events.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr1.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), &Config{Tracer: multipathTestTracer(&recorder)})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))

	// All packets sent on the path are probe packets: those with the client's PATH_CHALLENGE frames,
	// and those with the PATH_RESPONSE frames.
	probePackets := func() (challenges, responses int) {
		for _, ev := range recorder.Events(qlog.PacketSent{}) {
			for _, f := range ev.(qlog.PacketSent).Frames {
				switch f.Frame.(type) {
				case *qlog.PathChallengeFrame:
					challenges++
				case *qlog.PathResponseFrame:
					responses++
				}
			}
		}
		return challenges, responses
	}
	require.Eventually(t, func() bool {
		challenges, responses := probePackets()
		return responses > 0 && int(pathConn.written.Load()) == challenges+responses
	}, time.Second, time.Millisecond)
}

// countingPacketConn counts the datagrams written.
type countingPacketConn struct {
	net.PacketConn
	written atomic.Int64
}

func (c *countingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.written.Add(1)
	return c.PacketConn.WriteTo(b, addr)
}

// LocalAddr, RemoteAddr and ConnectionState can be called while the connection switches to a new path.
// This test is only meaningful with the race detector.
func TestConnectionMigrationConcurrentAddressAccess(t *testing.T) {
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()
	tr1 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr1.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), nil)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))

	done := make(chan struct{})
	switched := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = conn.RemoteAddr().String()
			_ = conn.ConnectionState()
			if conn.LocalAddr().String() == tr2.Conn.LocalAddr().String() {
				close(switched)
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	require.NoError(t, path.Switch())
	select {
	case <-switched:
	case <-ctx.Done():
		t.Fatal("timeout waiting for the connection to switch to the new path")
	}
	<-done
	require.Equal(t, ln.Addr().String(), conn.RemoteAddr().String())
}

// AddPath can be called while the connection switches to a new path.
// This test is only meaningful with the race detector.
func TestConnectionMigrationConcurrentAddPath(t *testing.T) {
	serverTr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), nil)
	require.NoError(t, err)
	defer ln.Close()
	tr1 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()
	tr3 := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr3.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr1.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), nil)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))

	done := make(chan struct{})
	switched := make(chan struct{})
	go func() {
		defer close(done)
		for {
			p, err := conn.AddPath(tr3)
			if err != nil {
				t.Errorf("adding path failed: %v", err)
				return
			}
			if p == nil {
				t.Error("expected a path")
				return
			}
			if conn.LocalAddr().String() == tr2.Conn.LocalAddr().String() {
				close(switched)
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	require.NoError(t, path.Switch())
	select {
	case <-switched:
	case <-ctx.Done():
		t.Fatal("timeout waiting for the connection to switch to the new path")
	}
	<-done
}

func TestConnectionDatagrams(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		testConnectionDatagrams(t, false)
	})
	t.Run("enabled", func(t *testing.T) {
		testConnectionDatagrams(t, true)
	})
}

func testConnectionDatagrams(t *testing.T, enabled bool) {
	tc := newServerTestConnection(t, nil, &Config{EnableDatagrams: enabled}, false)

	data, err := (&wire.DatagramFrame{Data: []byte("foo"), DataLenPresent: true}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	data, err = (&wire.DatagramFrame{Data: []byte("bar")}).Append(data, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())

	if !enabled {
		// section 3 of RFC 9221
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypeDatagramWithLength)})
		return
	}

	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d, err := tc.conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), d)
	d, err = tc.conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), d)
}

// The ACK Delay only includes delays that the endpoint controls (section 13.2.5 of RFC 9000).
// The time that a packet spent in the queue of received packets is part of the RTT.
func TestConnectionAckDelayExcludesQueueingDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false,
			connectionOptHandshakeConfirmed(),
			connectionOptUnpacker(unpacker),
		)
		c := tc.conn
		rcvTime := monotime.Now()
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{1} /* PING */, nil,
		)
		p := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 1, []byte("foobar"))
		p.rcvTime = rcvTime
		c.handlePacket(p)
		// the packet waits in the queue for 20ms before the connection processes it
		time.Sleep(20 * time.Millisecond)
		processed, err := c.handlePackets()
		require.NoError(t, err)
		require.True(t, processed)
		// the idle timeout is still based on the time the packet was received
		require.Equal(t, rcvTime, c.lastPacketReceivedTime)

		time.Sleep(5 * time.Millisecond)
		ack := c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), false, 0)
		require.NotNil(t, ack)
		require.Equal(t, 5*time.Millisecond, ack.DelayTime)
	})
}

// Packets that were queued because their keys weren't available yet include the buffering delay
// in the ACK Delay (section 13.2.5 of RFC 9000).
func TestConnectionAckTime(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	c := tc.conn
	now := monotime.Now()
	require.Equal(t, now, c.ackTime(now))
	c.processingStartTime = now.Add(time.Millisecond)
	require.Equal(t, now.Add(time.Millisecond), c.ackTime(now))
	require.Equal(t, now.Add(2*time.Millisecond), c.ackTime(now.Add(2*time.Millisecond)))
	// packets taken from the queue of undecryptable packets
	c.processingStartTime = 0
	require.Equal(t, now, c.ackTime(now))
}
