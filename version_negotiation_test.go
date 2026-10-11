package quic

import (
	"slices"
	"testing"

	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/mocks"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// composeInitialPacket composes an Initial packet sent by sentBy, protected with the Initial keys derived from keyConnID.
// The payload consists of a PING frame, followed by PADDING.
func composeInitialPacket(
	t *testing.T,
	sentBy protocol.Perspective,
	keyConnID protocol.ConnectionID,
	version protocol.Version,
	src, dest protocol.ConnectionID,
	pn protocol.PacketNumber,
) receivedPacket {
	t.Helper()
	payload := make([]byte, 100) // PADDING
	payload[0] = 0x1             // PING
	extHdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			SrcConnectionID:  src,
			DestConnectionID: dest,
			Length:           protocol.ByteCount(len(payload)+int(protocol.PacketNumberLen4)) + 16,
			Version:          version,
		},
		PacketNumber:    pn,
		PacketNumberLen: protocol.PacketNumberLen4,
	}
	b, err := extHdr.Append(nil, version)
	require.NoError(t, err)
	n := len(b)
	b = append(b, payload...)
	sealer, _ := handshake.NewInitialAEAD(keyConnID, sentBy, version)
	b = slices.Grow(b, 16)
	_ = sealer.Seal(b[n:n], b[n:], pn, b[:n])
	b = b[:len(b)+16]
	sealer.EncryptHeader(b[n:n+16], &b[0], b[n-int(extHdr.PacketNumberLen):n])
	return receivedPacket{
		data:    b,
		buffer:  getPacketBuffer(),
		rcvTime: monotime.Now(),
	}
}

func TestConnectionClientCompatibleVersions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		versions   []protocol.Version
		chosen     protocol.Version
		compatible []protocol.Version
	}{
		{
			name:       "default",
			chosen:     protocol.Version1,
			compatible: []protocol.Version{protocol.Version2},
		},
		{
			name:       "preferring version 2",
			versions:   []protocol.Version{protocol.Version2, protocol.Version1},
			chosen:     protocol.Version2,
			compatible: []protocol.Version{protocol.Version1},
		},
		{
			name:     "only version 1",
			versions: []protocol.Version{protocol.Version1},
			chosen:   protocol.Version1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tconn := newClientTestConnection(t, nil, &Config{Versions: tc.versions}, false)
			conn := tconn.conn
			// newClientTestConnection always uses version 1
			require.Equal(t, protocol.Version1, conn.version)
			require.Equal(t, protocol.Version1, conn.chosenVersion)
			if tc.chosen == protocol.Version1 {
				require.Equal(t, tc.compatible, conn.compatibleVersions)
			}
		})
	}
}

func TestConnectionClientSwitchesVersion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))
	require.Equal(t, []protocol.Version{protocol.Version2}, tc.conn.compatibleVersions)
	serverConnID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})

	// An Initial packet that can't be decrypted doesn't switch the version.
	p := composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version2, serverConnID, tc.srcConnID, 0)
	p.data[len(p.data)-1] ^= 0xff
	wasProcessed, err := tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t, protocol.Version1, tc.conn.version)
	require.False(t, tc.conn.knowsNegotiatedVersion)
	eventRecorder.Clear()

	// The first Initial packet using version 2 switches the version.
	p = composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version2, serverConnID, tc.srcConnID, 0)
	wasProcessed, err = tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.Equal(t, protocol.Version2, tc.conn.version)
	require.Equal(t, protocol.Version1, tc.conn.chosenVersion)
	require.True(t, tc.conn.knowsNegotiatedVersion)
	require.Equal(t, protocol.Version2, tc.conn.ConnectionState().Version)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.VersionInformation{
				ClientVersions: []qlog.Version{protocol.Version1, protocol.Version2},
				ChosenVersion:  protocol.Version2,
			},
		},
		eventRecorder.Events(qlog.VersionInformation{}),
	)
	received := eventRecorder.Events(qlog.PacketReceived{})
	require.Len(t, received, 1)
	require.Equal(t, protocol.Version2, received[0].(qlog.PacketReceived).Header.Version)
	eventRecorder.Clear()

	// Initial packets using version 2 are now processed with the new keys...
	p = composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version2, serverConnID, tc.srcConnID, 1)
	wasProcessed, err = tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	// ... and packets using version 1 are dropped.
	p = composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version1, serverConnID, tc.srcConnID, 2)
	wasProcessed, err = tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Raw:     qlog.RawInfo{Length: len(p.data)},
				Trigger: qlog.PacketDropUnexpectedVersion,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func TestConnectionClientDropsOtherVersions(t *testing.T) {
	serverConnID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})

	t.Run("version not offered", func(t *testing.T) {
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t, nil, &Config{Versions: []protocol.Version{protocol.Version1}}, false, connectionOptTracer(&eventRecorder))
		require.Empty(t, tc.conn.compatibleVersions)
		p := composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version2, serverConnID, tc.srcConnID, 0)
		wasProcessed, err := tc.conn.handleOnePacket(p, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t, protocol.Version1, tc.conn.version)
		require.Equal(t,
			[]qlogwriter.Event{qlog.PacketDropped{Raw: qlog.RawInfo{Length: len(p.data)}, Trigger: qlog.PacketDropUnexpectedVersion}},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("Negotiated Version already known", func(t *testing.T) {
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t, nil, nil, false, connectionOptTracer(&eventRecorder))
		// a CRYPTO frame received in an Initial packet using the Chosen Version fixes the version
		require.NoError(t, tc.conn.handleCryptoFrame(&wire.CryptoFrame{}, protocol.EncryptionInitial, monotime.Now()))
		require.True(t, tc.conn.knowsNegotiatedVersion)
		p := composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version2, serverConnID, tc.srcConnID, 0)
		wasProcessed, err := tc.conn.handleOnePacket(p, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t, protocol.Version1, tc.conn.version)
		require.Len(t, eventRecorder.Events(qlog.PacketDropped{}), 1)
	})

	t.Run("Handshake packet", func(t *testing.T) {
		var eventRecorder events.Recorder
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder), connectionOptUnpacker(unpacker))
		b, err := (&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  serverConnID,
				DestConnectionID: tc.srcConnID,
				Length:           100,
				Version:          protocol.Version2,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}).Append(nil, protocol.Version2)
		require.NoError(t, err)
		b = append(b, make([]byte, 98)...)
		wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{data: b, buffer: getPacketBuffer(), rcvTime: monotime.Now()}, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{qlog.PacketDropped{Raw: qlog.RawInfo{Length: len(b)}, Trigger: qlog.PacketDropUnexpectedVersion}},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("Retry", func(t *testing.T) {
		var eventRecorder events.Recorder
		tc := newClientTestConnection(t, nil, nil, false, connectionOptTracer(&eventRecorder))
		hdr := wire.Header{
			Type:             protocol.PacketTypeRetry,
			SrcConnectionID:  serverConnID,
			DestConnectionID: tc.srcConnID,
			Token:            []byte("foobar"),
			Version:          protocol.Version2,
		}
		b, err := (&wire.ExtendedHeader{Header: hdr}).Append(nil, protocol.Version2)
		require.NoError(t, err)
		tag := handshake.GetRetryIntegrityTag(b, tc.destConnID, protocol.Version2)
		b = append(b, tag[:]...)
		wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{data: b, buffer: getPacketBuffer(), rcvTime: monotime.Now()}, 0)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.False(t, tc.conn.receivedRetry)
		require.Equal(t,
			[]qlogwriter.Event{qlog.PacketDropped{Raw: qlog.RawInfo{Length: len(b)}, Trigger: qlog.PacketDropUnexpectedVersion}},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})
}

func TestConnectionServerVersionNegotiated(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		&Config{Versions: []protocol.Version{protocol.Version2, protocol.Version1}},
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptCryptoSetup(cs),
		connectionOptUnpacker(unpacker),
	)
	require.Equal(t, protocol.Version1, tc.conn.version)
	// the server switches the version when processing the client's first packet
	tc.conn.receivedFirstPacket = true

	gomock.InOrder(
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventVersionNegotiated, Version: protocol.Version2}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
	)
	require.NoError(t, tc.conn.handleHandshakeEvents(monotime.Now()))
	require.Equal(t, protocol.Version2, tc.conn.version)
	require.Equal(t, protocol.Version1, tc.conn.chosenVersion)
	cs.EXPECT().ConnectionState().Return(handshake.ConnectionState{}).AnyTimes()
	require.Equal(t, protocol.Version2, tc.conn.ConnectionState().Version)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.VersionInformation{
				ServerVersions: []qlog.Version{protocol.Version2, protocol.Version1},
				ChosenVersion:  protocol.Version2,
			},
		},
		eventRecorder.Events(qlog.VersionInformation{}),
	)

	clientConnID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
	tc.conn.handshakeDestConnID = clientConnID
	longHeaderPacket := func(typ protocol.PacketType, v protocol.Version) receivedPacket {
		b, err := (&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             typ,
				SrcConnectionID:  clientConnID,
				DestConnectionID: tc.srcConnID,
				Length:           100,
				Version:          v,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}).Append(nil, v)
		require.NoError(t, err)
		return receivedPacket{data: append(b, make([]byte, 98)...), buffer: getPacketBuffer(), rcvTime: monotime.Now()}
	}

	for _, p := range []struct {
		typ       protocol.PacketType
		version   protocol.Version
		processed bool
	}{
		// the client might still use its Chosen Version for Initial packets
		{typ: protocol.PacketTypeInitial, version: protocol.Version1, processed: true},
		{typ: protocol.PacketTypeInitial, version: protocol.Version2, processed: true},
		// 0-RTT packets always use the Chosen Version
		{typ: protocol.PacketType0RTT, version: protocol.Version1, processed: true},
		{typ: protocol.PacketType0RTT, version: protocol.Version2},
		// Handshake packets must use the Negotiated Version
		{typ: protocol.PacketTypeHandshake, version: protocol.Version2, processed: true},
		{typ: protocol.PacketTypeHandshake, version: protocol.Version1},
	} {
		if p.processed {
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
				func(hdr *wire.Header, _ []byte) (*unpackedPacket, error) {
					require.Equal(t, p.typ, hdr.Type)
					require.Equal(t, p.version, hdr.Version)
					return nil, handshake.ErrDecryptionFailed
				},
			)
		}
		eventRecorder.Clear()
		_, err := tc.conn.handleOnePacket(longHeaderPacket(p.typ, p.version), 0)
		require.NoError(t, err)
		require.True(t, mockCtrl.Satisfied())
		drops := eventRecorder.Events(qlog.PacketDropped{})
		require.Len(t, drops, 1)
		if p.processed {
			require.Equal(t, qlog.PacketDropPayloadDecryptError, drops[0].(qlog.PacketDropped).Trigger)
		} else {
			require.Equal(t, qlog.PacketDropUnexpectedVersion, drops[0].(qlog.PacketDropped).Trigger)
		}
	}
}

func TestConnectionAcceptsOtherVersion(t *testing.T) {
	hdr := func(typ protocol.PacketType, v protocol.Version) *wire.Header {
		return &wire.Header{Type: typ, Version: v}
	}

	t.Run("server, before switching", func(t *testing.T) {
		c := &Conn{perspective: protocol.PerspectiveServer, version: protocol.Version1, chosenVersion: protocol.Version1}
		for _, typ := range []protocol.PacketType{protocol.PacketTypeInitial, protocol.PacketTypeHandshake, protocol.PacketType0RTT} {
			require.True(t, c.acceptsVersion(hdr(typ, protocol.Version1)))
			require.False(t, c.acceptsVersion(hdr(typ, protocol.Version2)))
		}
	})

	t.Run("client", func(t *testing.T) {
		c := &Conn{
			perspective:        protocol.PerspectiveClient,
			version:            protocol.Version1,
			chosenVersion:      protocol.Version1,
			compatibleVersions: []protocol.Version{protocol.Version2},
		}
		require.True(t, c.acceptsVersion(hdr(protocol.PacketTypeInitial, protocol.Version1)))
		require.True(t, c.acceptsVersion(hdr(protocol.PacketTypeHandshake, protocol.Version1)))
		require.True(t, c.acceptsVersion(hdr(protocol.PacketTypeInitial, protocol.Version2)))
		require.False(t, c.acceptsVersion(hdr(protocol.PacketTypeInitial, 0x1234)))
		require.False(t, c.acceptsVersion(hdr(protocol.PacketTypeHandshake, protocol.Version2)))
		require.False(t, c.acceptsVersion(hdr(protocol.PacketTypeRetry, protocol.Version2)))
		require.False(t, c.acceptsVersion(hdr(protocol.PacketType0RTT, protocol.Version2)))
		c.knowsNegotiatedVersion = true
		require.False(t, c.acceptsVersion(hdr(protocol.PacketTypeInitial, protocol.Version2)))
	})
}

type recordingTokenStore struct {
	pops []string
	puts []string
}

func (s *recordingTokenStore) Pop(key string) *ClientToken {
	s.pops = append(s.pops, key)
	return nil
}

func (s *recordingTokenStore) Put(key string, _ *ClientToken) { s.puts = append(s.puts, key) }

// Tokens are specific to the QUIC version of the connection that received them (section 5 of RFC 9369).
func TestConnectionClientTokenStoreKeys(t *testing.T) {
	require.Equal(t, "quic-go.net", versionedTokenStoreKey("quic-go.net", protocol.Version1))
	require.Equal(t, "quic-go.net|quic-version=0x6b3343cf", versionedTokenStoreKey("quic-go.net", protocol.Version2))

	store := &recordingTokenStore{}
	tc := newClientTestConnection(t, nil, &Config{TokenStore: store}, false)
	// the connection is started using version 1
	require.Equal(t, []string{"quic-go.net"}, store.pops)
	require.NoError(t, tc.conn.handleNewTokenFrame(&wire.NewTokenFrame{Token: []byte("foo")}))
	// after switching to version 2, tokens are stored for version 2
	serverConnID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
	p := composeInitialPacket(t, protocol.PerspectiveServer, tc.destConnID, protocol.Version2, serverConnID, tc.srcConnID, 0)
	wasProcessed, err := tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.NoError(t, tc.conn.handleNewTokenFrame(&wire.NewTokenFrame{Token: []byte("bar")}))
	require.Equal(t, []string{"quic-go.net", "quic-go.net|quic-version=0x6b3343cf"}, store.puts)
}
