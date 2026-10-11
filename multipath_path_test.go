package quic

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// A sentTestPacket is a packet sent by an mpPathTestConn.
type sentTestPacket struct {
	conn    sendConn // nil if sent on the connection's sendConn
	size    protocol.ByteCount
	gsoSize uint16
	ecn     protocol.ECN
}

// A pathPacketCall is a call to PackPathPacket.
type pathPacketCall struct {
	pathID       protocol.PathID
	pn           protocol.PacketNumber
	frames       []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame
}

// A probeCall is a call to PackMultipathProbePacket.
type probeCall struct {
	time           monotime.Time
	pathID         protocol.PathID
	connID         protocol.ConnectionID
	frames         []ackhandler.Frame
	maxSize, padTo protocol.ByteCount
	size           protocol.ByteCount
}

// An mpPathTestConn is a connection for which IETF Multipath QUIC is active and the handshake is confirmed.
// Packets are unpacked using a mock unpacker, packed using a mock packer, and sent using a mock sender.
type mpPathTestConn struct {
	*testConnection
	mockCtrl *gomock.Controller
	unpacker *MockUnpacker
	sent     []sentTestPacket
	probes   []probeCall
	// the packets packed by PackPathPacket
	pathPackets []pathPacketCall
	// the packet number of the next packet received on a path
	nextPN map[protocol.PathID]protocol.PacketNumber
	// called by AppendPacket, if set
	appendPacket func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error)
	// returned by the WouldBlock method of the sender
	wouldBlock bool
}

type mpPathTestConnOpts struct {
	// the capabilities of the connection's sendConn
	capabilities connCapabilities
	// enables Path MTU Discovery
	pmtud bool
}

func newMPPathTestConn(t *testing.T, pers protocol.Perspective, localMaxPathID, peerMaxPathID protocol.PathID) *mpPathTestConn {
	t.Helper()
	return newMPPathTestConnWithOpts(t, pers, localMaxPathID, peerMaxPathID, mpPathTestConnOpts{})
}

func newMPPathTestConnWithOpts(t *testing.T, pers protocol.Perspective, localMaxPathID, peerMaxPathID protocol.PathID, opts mpPathTestConnOpts) *mpPathTestConn {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	sender := NewMockSender(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := &mpPathTestConn{mockCtrl: mockCtrl, unpacker: unpacker}
	tc.testConnection = newIETFMultipathTestConnection(t, pers, localMaxPathID, peerMaxPathID, false,
		connectionOptSender(sender),
		connectionOptUnpacker(unpacker),
		connectionOptHandshakeConfirmed(),
	)
	c := tc.conn
	if pers == protocol.PerspectiveClient {
		tc.remoteAddr = &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	}
	if opts.capabilities != (connCapabilities{}) {
		conn := newMockPathConn(mockCtrl, tc.remoteAddr, opts.capabilities)
		c.conn = conn
		tc.sendConn = conn
		c.sentPacketHandler = ackhandler.NewSentPacketHandler(
			0,
			protocol.ByteCount(c.config.InitialPacketSize),
			c.rttStats,
			&c.connStats,
			true,
			opts.capabilities.ECN,
			c.receivedPacketHandler.IgnorePacketsBelow,
			pers,
			nil,
			c.logger,
		)
	}
	if opts.pmtud {
		c.config.DisablePathMTUDiscovery = false
		c.mtuDiscoverer = newMTUDiscoverer(c.rttStats, protocol.ByteCount(c.config.InitialPacketSize), protocol.MaxPacketBufferSize, nil)
	}
	// the handshake is confirmed
	c.sentPacketHandler.DropPackets(protocol.EncryptionInitial, monotime.Now())
	c.sentPacketHandler.DropPackets(protocol.EncryptionHandshake, monotime.Now())
	activateMultipathTestConnection(t, tc.testConnection)
	sender.EXPECT().WouldBlock().DoAndReturn(func() bool { return tc.wouldBlock }).AnyTimes()
	sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(b *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
		tc.sent = append(tc.sent, sentTestPacket{size: b.Len(), gsoSize: gsoSize, ecn: ecn})
		b.Release()
	}).AnyTimes()
	sender.EXPECT().SendOnConn(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(b *packetBuffer, gsoSize uint16, ecn protocol.ECN, conn sendConn) {
		tc.sent = append(tc.sent, sentTestPacket{conn: conn, size: b.Len(), gsoSize: gsoSize, ecn: ecn})
		b.Release()
	}).AnyTimes()
	tc.packer.EXPECT().PackMultipathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(pathID protocol.PathID, connID protocol.ConnectionID, frames []ackhandler.Frame, maxSize, padTo protocol.ByteCount, now monotime.Time, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			size := tc.conn.shortHeaderPacketOverhead(tc.conn.mp.paths[pathID], connID)
			for _, f := range frames {
				size += f.Frame.Length(v)
			}
			if size > maxSize {
				return shortHeaderPacket{}, nil, errNothingToPack
			}
			size = max(size, min(padTo, maxSize))
			tc.probes = append(tc.probes, probeCall{time: now, pathID: pathID, connID: connID, frames: frames, maxSize: maxSize, padTo: padTo, size: size})
			return tc.packPacket(pathID, frames, size, true), getTestPacketBuffer(size), nil
		},
	).AnyTimes()
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(buf *packetBuffer, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version, pathID protocol.PathID) (shortHeaderPacket, error) {
			if tc.appendPacket == nil {
				return shortHeaderPacket{}, errNothingToPack
			}
			return tc.appendPacket(buf, maxSize, pathID)
		},
	).AnyTimes()
	tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, nil, errNothingToPack).AnyTimes()
	tc.packer.EXPECT().PackPathPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(pathID protocol.PathID, frames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame, maxSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			size := tc.conn.shortHeaderPacketOverhead(tc.conn.mp.paths[pathID], tc.connIDForTestPath(pathID))
			for _, f := range frames {
				size += f.Frame.Length(v)
			}
			for _, f := range streamFrames {
				size += f.Frame.Length(v)
			}
			require.LessOrEqual(t, size, maxSize)
			sph := tc.conn.sentPacketHandler
			pn, pnLen := sph.PeekPacketNumber(pathID, protocol.Encryption1RTT)
			sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
			tc.pathPackets = append(tc.pathPackets, pathPacketCall{pathID: pathID, pn: pn, frames: frames, streamFrames: streamFrames})
			return shortHeaderPacket{
				PacketNumber:    pn,
				PacketNumberLen: pnLen,
				Frames:          frames,
				StreamFrames:    streamFrames,
				Length:          size,
				PathID:          uint64(pathID),
			}, getTestPacketBuffer(size), nil
		},
	).AnyTimes()
	return tc
}

// connIDForTestPath returns the connection ID used to send on a path.
func (tc *mpPathTestConn) connIDForTestPath(pathID protocol.PathID) protocol.ConnectionID {
	connID, _ := tc.conn.pathDestConnID(tc.conn.mp.paths[pathID])
	return connID
}

// appendDataPacket appends a packet of the given size, containing a PING frame, to the buffer.
func (tc *mpPathTestConn) appendDataPacket(buf *packetBuffer, size protocol.ByteCount, pathID protocol.PathID) shortHeaderPacket {
	buf.Data = append(buf.Data, make([]byte, size)...)
	return tc.packPacket(pathID, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, size, false)
}

// packPacket emulates the packer: it takes the next packet number of the path from the sent packet handler.
func (tc *mpPathTestConn) packPacket(pathID protocol.PathID, frames []ackhandler.Frame, size protocol.ByteCount, isPathProbe bool) shortHeaderPacket {
	sph := tc.conn.sentPacketHandler
	pn, pnLen := sph.PeekPacketNumber(pathID, protocol.Encryption1RTT)
	sph.PopPacketNumber(pathID, protocol.Encryption1RTT)
	for i := range frames {
		if frames[i].Handler == nil {
			frames[i].Handler = emptyHandler{}
		}
	}
	return shortHeaderPacket{
		PacketNumber:      pn,
		PacketNumberLen:   pnLen,
		Frames:            frames,
		Length:            size,
		IsPathProbePacket: isPathProbe,
		PathID:            uint64(pathID),
	}
}

func getTestPacketBuffer(size protocol.ByteCount) *packetBuffer {
	buf := getPacketBuffer()
	buf.Data = append(buf.Data, make([]byte, size)...)
	return buf
}

// connIDForPath returns a connection ID that the connection issued for a path.
func (tc *mpPathTestConn) connIDForPath(t *testing.T, pathID protocol.PathID) protocol.ConnectionID {
	t.Helper()
	p := tc.conn.connIDGenerator.path(pathID)
	require.NotNil(t, p)
	for _, connID := range p.active {
		return connID
	}
	t.Fatalf("no connection ID for path %d", pathID)
	return protocol.ConnectionID{}
}

// receivePacket receives a datagram of the given size, containing a 1-RTT packet with the frames, on a path.
func (tc *mpPathTestConn) receivePacket(t *testing.T, pathID protocol.PathID, remoteAddr net.Addr, info packetInfo, size int, frames ...wire.Frame) (bool, error) {
	t.Helper()
	return tc.receivePacketWithConnID(t, pathID, tc.connIDForPath(t, pathID), remoteAddr, info, size, frames...)
}

func (tc *mpPathTestConn) receivePacketWithConnID(t *testing.T, pathID protocol.PathID, connID protocol.ConnectionID, remoteAddr net.Addr, info packetInfo, size int, frames ...wire.Frame) (bool, error) {
	t.Helper()
	var data []byte
	for _, f := range frames {
		var err error
		data, err = f.Append(data, protocol.Version1)
		require.NoError(t, err)
	}
	if tc.nextPN == nil {
		tc.nextPN = make(map[protocol.PathID]protocol.PacketNumber)
	}
	pn := tc.nextPN[pathID]
	tc.nextPN[pathID]++
	tc.unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), pathID).Return(pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil)
	p := getShortHeaderPacket(t, remoteAddr, connID, pn, nil)
	p.data = append(p.data, make([]byte, size-len(p.data))...)
	p.info = info
	return tc.conn.handleOnePacket(p, 0)
}

// newMockPathConn returns a mock sendConn for a path.
func newMockPathConn(mockCtrl *gomock.Controller, remoteAddr net.Addr, capabilities connCapabilities) *MockSendConn {
	conn := NewMockSendConn(mockCtrl)
	conn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}).AnyTimes()
	conn.EXPECT().capabilities().Return(capabilities).AnyTimes()
	return conn
}

// sentProbeFrames returns the PATH_CHALLENGE and PATH_RESPONSE frames sent on a path.
func sentProbeFrames(probes []probeCall, pathID protocol.PathID) (challenges []*wire.PathChallengeFrame, responses []*wire.PathResponseFrame) {
	for _, p := range probes {
		if p.pathID != pathID {
			continue
		}
		for _, f := range p.frames {
			switch f := f.Frame.(type) {
			case *wire.PathChallengeFrame:
				challenges = append(challenges, f)
			case *wire.PathResponseFrame:
				responses = append(responses, f)
			}
		}
	}
	return challenges, responses
}

// Section 3.1 of draft-ietf-quic-multipath-21: the server creates the state of a new path
// when it receives a packet for an unused path ID that can be decrypted.
func TestMultipathServerNewPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}

		// a packet that can't be decrypted doesn't create any state
		tc.unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), protocol.PathID(1)).Return(
			protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, handshake.ErrDecryptionFailed,
		)
		bytesReceived := c.connStats.BytesReceived.Load()
		processed, err := c.handleOnePacket(getShortHeaderPacket(t, clientAddr, tc.connIDForPath(t, 1), 0, make([]byte, 1200)), 0)
		require.NoError(t, err)
		require.False(t, processed)
		require.NotContains(t, c.mp.paths, protocol.PathID(1))
		require.Equal(t, []protocol.PathID{0}, c.mp.pathIDs)
		require.Nil(t, c.sentPacketHandler.GetPathRTTStats(1))
		require.Empty(t, c.receivedPacketHandler.AckDuePaths(monotime.Now()))
		require.Nil(t, c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), false, 1))
		// the bytes are counted nevertheless
		require.Greater(t, c.connStats.BytesReceived.Load(), bytesReceived)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Empty(t, tc.probes)

		// a packet that can be decrypted creates the path
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		processed, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3}})
		require.NoError(t, err)
		require.True(t, processed)
		require.Contains(t, c.mp.paths, protocol.PathID(1))
		require.Equal(t, mpPathValidating, c.mp.paths[1].state)
		require.NotNil(t, c.sentPacketHandler.GetPathRTTStats(1))

		// The server responds, and validates the path itself.
		// The datagram is expanded to 1200 bytes, and sent on the path.
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, protocol.PathID(1), tc.probes[0].pathID)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[0].padTo)
		challenges, responses := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{1, 2, 3}}}, responses)
		require.Len(t, tc.sent, 1)
		require.Equal(t, sendConn(pathConn), tc.sent[0].conn)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.sent[0].size)
		// ECN is not used on unvalidated paths, and the connection doesn't support ECN anyway
		require.Equal(t, protocol.ECNUnsupported, tc.sent[0].ecn)
		// no data is sent on the path before it is validated
		require.Equal(t, mpPathValidating, c.mp.paths[1].state)

		// the PATH_RESPONSE validates the path
		processed, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)
		require.Equal(t, protocol.MaxByteCount, c.sentPacketHandler.AmplificationBudgetForPath(1))
	})
}

// bytesSentOnConn returns the number of bytes sent using a sendConn.
func (tc *mpPathTestConn) bytesSentOnConn(conn sendConn) protocol.ByteCount {
	var n protocol.ByteCount
	for _, p := range tc.sent {
		if p.conn == conn {
			n += p.size
		}
	}
	return n
}

// advanceToNextMultipathTimeout advances the time to the next timeout of IETF Multipath QUIC,
// and handles the expired timers.
func (tc *mpPathTestConn) advanceToNextMultipathTimeout(t *testing.T) {
	t.Helper()
	deadline := tc.conn.mp.nextTimeout()
	require.False(t, deadline.IsZero(), "no timer set")
	time.Sleep(monotime.Until(deadline))
	require.NoError(t, tc.conn.handleMultipathEvents(monotime.Now()))
}

func pathAbandonFramesFor(frames []ackhandler.Frame, pathID protocol.PathID) []*wire.PathAbandonFrame {
	var abandons []*wire.PathAbandonFrame
	for _, f := range pathAbandonFrames(frames) {
		if f.PathID == pathID {
			abandons = append(abandons, f)
		}
	}
	return abandons
}

// Until the client's address on a new path is validated, the server sends at most 3 times the number of bytes
// received on that path (section 3.1 of draft-ietf-quic-multipath-21).
// If this doesn't allow expanding the datagram with the PATH_CHALLENGE to 1200 bytes, a second path validation
// with an expanded datagram is performed, and the path is only used once the second validation succeeded
// (section 8.2.3 of RFC 9000).
func TestMultipathServerNewPathAmplificationLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		// Make the PTO of path 0 large, such that PATH_CHALLENGE frames are retransmitted a few times
		// before the validation times out.
		c.rttStats.UpdateRTT(time.Second, 0)
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)

		// The path is opened with a small packet that doesn't contain a PATH_CHALLENGE frame.
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 25, &wire.PingFrame{})
		require.NoError(t, err)
		received := protocol.ByteCount(25)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Zero(t, tc.probes[0].padTo)
		require.Equal(t, 3*received, tc.probes[0].maxSize)

		// The PATH_CHALLENGE is retransmitted, as long as the anti-amplification limit allows it.
		for range 2 {
			tc.advanceToNextMultipathTimeout(t)
			require.NoError(t, c.triggerSending(monotime.Now()))
			require.LessOrEqual(t, tc.bytesSentOnConn(pathConn), 3*received)
		}
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 2)
		require.True(t, c.mp.paths[1].challengeDue)

		// Receiving more bytes on the path allows sending the next PATH_CHALLENGE.
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 25, &wire.PingFrame{})
		require.NoError(t, err)
		received += 25
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.LessOrEqual(t, tc.bytesSentOnConn(pathConn), 3*received)
		challenges, _ = sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 3)
		for _, p := range tc.probes {
			require.Less(t, p.size, protocol.ByteCount(protocol.MinInitialPacketSize))
		}

		// The PATH_RESPONSE validates the client's address, but not the path MTU.
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 25, &wire.PathResponseFrame{Data: challenges[1].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathValidating, c.mp.paths[1].state)
		require.Equal(t, protocol.MaxByteCount, c.sentPacketHandler.AmplificationBudgetForPath(1))
		numProbes := len(tc.probes)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, numProbes+1)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[numProbes].padTo)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[numProbes].size)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.sent[len(tc.sent)-1].size)
		challenges, _ = sentProbeFrames(tc.probes[numProbes:], 1)
		require.Len(t, challenges, 1)

		// Responses to the PATH_CHALLENGE frames of the first validation don't validate the path MTU.
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 25, &wire.PathResponseFrame{Data: tc.probes[0].frames[0].Frame.(*wire.PathChallengeFrame).Data})
		require.NoError(t, err)
		require.Equal(t, mpPathValidating, c.mp.paths[1].state)

		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)
	})
}

// Section 3.1 of draft-ietf-quic-multipath-21: if the server doesn't have a connection ID for the path,
// it delays the PATH_RESPONSE. If it doesn't receive one in time, it abandons the path.
func TestMultipathServerNewPathWithoutConnectionID(t *testing.T) {
	setup := func(t *testing.T) (*mpPathTestConn, *MockSendConn) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{4, 2}})
		require.NoError(t, err)
		require.Equal(t, mpPathValidating, tc.conn.mp.paths[1].state)
		require.NoError(t, tc.conn.triggerSending(monotime.Now()))
		require.Empty(t, tc.probes)
		return tc, pathConn
	}

	t.Run("connection ID received in time", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc, pathConn := setup(t)
			c := tc.conn
			time.Sleep(monotime.Until(c.mp.paths[1].validationDeadline) - time.Millisecond)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.NoError(t, c.triggerSending(monotime.Now()))
			require.Empty(t, tc.probes)

			require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 0), protocol.Encryption1RTT))
			require.NoError(t, c.triggerSending(monotime.Now()))
			challenges, responses := sentProbeFrames(tc.probes, 1)
			require.Len(t, challenges, 1)
			require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{4, 2}}}, responses)
			require.Equal(t, sendConn(pathConn), tc.sent[0].conn)
		})
	})

	t.Run("no connection ID received", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc, _ := setup(t)
			c := tc.conn
			deadline := c.mp.paths[1].validationDeadline
			queuedFrames(c)
			tc.advanceToNextMultipathTimeout(t)
			require.Equal(t, deadline, monotime.Now())
			require.Equal(t, mpPathAbandoned, c.mp.paths[1].state)
			require.Equal(t,
				[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoCIDAvailableForPath}},
				pathAbandonFramesFor(queuedFrames(c), 1),
			)
			// connection IDs for the path are ignored now
			require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 0), protocol.Encryption1RTT))
			require.NoError(t, c.triggerSending(monotime.Now()))
			require.Empty(t, tc.probes)
		})
	})
}

// Section 3.1 of draft-ietf-quic-multipath-21: the PATH_RESPONSE is sent on the path that the PATH_CHALLENGE
// was received on, using a connection ID of this path.
// If the PATH_CHALLENGE was received from another 4-tuple than the one the path uses,
// the PATH_RESPONSE is sent to that 4-tuple. It uses another connection ID of the path than the path's 4-tuple:
// a connection ID must not be used towards more than one remote address (section 9.5 of RFC 9000).
func TestMultipathPathResponseOnOtherTuple(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 1)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		pathConnID := newTestPathNewConnectionIDFrame(1, 0).ConnectionID
		require.Equal(t, pathConnID, tc.probes[0].connID)
		tc.probes = nil

		// A PATH_CHALLENGE from another address of the client.
		// The server responds, and validates the new address (section 3.1.2 of draft-ietf-quic-multipath-21).
		otherAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 9999}
		var written []byte
		pathConn.EXPECT().WriteTo(gomock.Any(), otherAddr, packetInfo{}).DoAndReturn(func(b []byte, _ net.Addr, _ packetInfo) error {
			written = b
			return nil
		})
		_, err = tc.receivePacket(t, 1, otherAddr, packetInfo{}, 300, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, protocol.PathID(1), tc.probes[0].pathID)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)
		require.Len(t, tc.probes[0].frames, 2)
		require.IsType(t, &wire.PathChallengeFrame{}, tc.probes[0].frames[0].Frame)
		require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1}}, tc.probes[0].frames[1].Frame)
		// the address is not validated, so the anti-amplification limit applies
		require.Equal(t, protocol.ByteCount(900), tc.probes[0].maxSize)
		require.Zero(t, tc.probes[0].padTo)
		require.Len(t, written, int(tc.probes[0].size))
		// the PATH_RESPONSE is not sent on the 4-tuple of the path, which keeps using its connection ID
		require.NoError(t, c.triggerSending(monotime.Now()))
		_, responses := sentProbeFrames(tc.probes[1:], 1)
		require.Empty(t, responses)
		connID, ok := c.pathDestConnID(c.mp.paths[1])
		require.True(t, ok)
		require.Equal(t, pathConnID, connID)

		// The responses to multiple PATH_CHALLENGE frames share the anti-amplification budget.
		// The 4-tuple keeps using its connection ID.
		tc.probes = nil
		pathConn.EXPECT().WriteTo(gomock.Any(), otherAddr, packetInfo{}).Times(2)
		_, err = tc.receivePacket(t, 1, otherAddr, packetInfo{}, 25,
			&wire.PathChallengeFrame{Data: [8]byte{2}},
			&wire.PathChallengeFrame{Data: [8]byte{3}},
		)
		require.NoError(t, err)
		require.Len(t, tc.probes, 2)
		require.Equal(t, protocol.ByteCount(75), tc.probes[0].maxSize)
		require.Equal(t, 75-tc.probes[0].size, tc.probes[1].maxSize)
		for _, p := range tc.probes {
			require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, p.connID)
		}

		// There's no unused connection ID for a third 4-tuple.
		tc.probes = nil
		_, err = tc.receivePacket(t, 1, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1234}, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{4}})
		require.NoError(t, err)
		require.Empty(t, tc.probes)
	})
}

// Section 3.1 of draft-ietf-quic-multipath-21: a PATH_RESPONSE uses a connection ID of the path that the PATH_CHALLENGE
// was received on. If the client didn't provide a connection ID for the path, a PATH_CHALLENGE from another 4-tuple
// is not answered.
func TestMultipathPathResponseOnOtherTupleWithoutConnectionID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.False(t, c.peerConnIDs.HasConnID(1))

		// no calls to WriteTo expected
		otherAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 9999}
		_, err = tc.receivePacket(t, 1, otherAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Empty(t, tc.probes)

		// With a single connection ID, the path's 4-tuple uses it, and the other 4-tuple still doesn't get a response.
		require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 0), protocol.Encryption1RTT))
		_, err = tc.receivePacket(t, 1, otherAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{2}})
		require.NoError(t, err)
		require.Empty(t, tc.probes)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, tc.probes[0].connID)
		_, responses := sentProbeFrames(tc.probes, 1)
		require.Empty(t, responses)

		// once the client provides another connection ID, the other 4-tuple gets a response
		tc.probes = nil
		require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 1), protocol.Encryption1RTT))
		pathConn.EXPECT().WriteTo(gomock.Any(), otherAddr, packetInfo{})
		_, err = tc.receivePacket(t, 1, otherAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{3}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)
		_, responses = sentProbeFrames(tc.probes, 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{3}}}, responses)
	})
}

// A connection ID must not be used from more than one local address (section 9.5 of RFC 9000).
// A PATH_CHALLENGE received on another local address than the one the path uses is answered from that local address,
// using another connection ID of the path.
func TestMultipathPathResponseFromOtherLocalAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		for seq := range uint64(3) {
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, seq)))
		}
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, tc.probes[0].connID)
		tc.probes = nil

		// the path's sendConn sends from 127.0.0.1
		otherLocal := packetInfo{addr: netip.MustParseAddr("10.0.0.2")}
		pathConn.EXPECT().WriteTo(gomock.Any(), clientAddr, otherLocal).Times(2)
		_, err = tc.receivePacket(t, 1, clientAddr, otherLocal, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)
		_, err = tc.receivePacket(t, 1, clientAddr, otherLocal, 1200, &wire.PathChallengeFrame{Data: [8]byte{2}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 2)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[1].connID)

		// yet another local address
		thirdLocal := packetInfo{addr: netip.MustParseAddr("10.0.0.3")}
		pathConn.EXPECT().WriteTo(gomock.Any(), clientAddr, thirdLocal)
		_, err = tc.receivePacket(t, 1, clientAddr, thirdLocal, 1200, &wire.PathChallengeFrame{Data: [8]byte{3}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 3)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, tc.probes[2].connID)

		// a PATH_CHALLENGE on the path's own 4-tuple is answered on the path, using the path's connection ID
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{4}})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 4)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, tc.probes[3].connID)
		_, responses := sentProbeFrames(tc.probes[3:], 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{4}}}, responses)
	})
}

// Every 4-tuple of a path that the server validates uses up a connection ID of the path.
// If the PATH_CHALLENGE sent to a 4-tuple is lost, its connection ID is retired, so that the client
// provides a new connection ID, which can then be used for another 4-tuple.
func TestMultipathPathResponseTupleReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 1)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)
		tc.probes = nil
		queuedFrames(c)

		addrA := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1001}
		addrB := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1002}
		pathConn.EXPECT().WriteTo(gomock.Any(), addrA, packetInfo{})
		_, err = tc.receivePacket(t, 1, addrA, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)

		// there's no connection ID left for address B
		_, err = tc.receivePacket(t, 1, addrB, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{2}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Empty(t, queuedFrames(c))

		// The PATH_CHALLENGE sent to address A is lost: address A is not validated.
		// Its connection ID is retired.
		time.Sleep(time.Until(c.sentPacketHandler.GetLossDetectionTimeout().ToTime()))
		require.NoError(t, c.sentPacketHandler.OnLossDetectionTimeout(monotime.Now()))
		require.Equal(t,
			[]ackhandler.Frame{{Frame: &wire.PathRetireConnectionIDFrame{PathID: 1, SequenceNumber: 1}}},
			queuedFrames(c),
		)
		require.False(t, c.peerConnIDs.IsActiveStatelessResetToken(newTestPathNewConnectionIDFrame(1, 1).StatelessResetToken))

		// the client provides a new connection ID, which is used for address B
		require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 2), protocol.Encryption1RTT))
		pathConn.EXPECT().WriteTo(gomock.Any(), addrB, packetInfo{})
		_, err = tc.receivePacket(t, 1, addrB, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{4}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 2)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 2).ConnectionID, tc.probes[1].connID)
		_, responses := sentProbeFrames(tc.probes[1:], 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{4}}}, responses)
		// the path keeps using its connection ID
		connID, ok := c.pathDestConnID(c.mp.paths[1])
		require.True(t, ok)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, connID)
	})
}

// Until the client's address on a path is validated, only datagrams received on the path's 4-tuple
// increase the anti-amplification limit for sending to that 4-tuple (section 8 of RFC 9000).
func TestMultipathServerAmplificationLimitOtherTuple(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 100, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, protocol.ByteCount(300), c.sentPacketHandler.AmplificationBudgetForPath(1))

		// datagrams from another remote address, and on another local address
		bytesReceived := c.connStats.BytesReceived.Load()
		otherAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1111}
		for range 3 {
			_, err = tc.receivePacket(t, 1, otherAddr, packetInfo{}, 1200, &wire.PingFrame{})
			require.NoError(t, err)
		}
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{addr: netip.MustParseAddr("10.0.0.2")}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, protocol.ByteCount(300), c.sentPacketHandler.AmplificationBudgetForPath(1))
		// they count for the connection statistics
		require.Equal(t, bytesReceived+4*1200, c.connStats.BytesReceived.Load())

		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, protocol.ByteCount(300), tc.probes[0].maxSize)
		require.Zero(t, tc.probes[0].padTo)
		require.LessOrEqual(t, tc.bytesSentOnConn(pathConn), protocol.ByteCount(300))

		// datagrams received on the path's 4-tuple increase the limit
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, 3*(100+1200)-tc.bytesSentOnConn(pathConn), c.sentPacketHandler.AmplificationBudgetForPath(1))
	})
}

// receiveDroppedPacket receives a 1-RTT packet on a path that is dropped before it is decrypted.
func (tc *mpPathTestConn) receiveDroppedPacket(t *testing.T, pathID protocol.PathID, remoteAddr net.Addr) {
	t.Helper()
	// no call to the unpacker expected
	p := getShortHeaderPacket(t, remoteAddr, tc.connIDForPath(t, pathID), 42, make([]byte, 100))
	processed, err := tc.conn.handleOnePacket(p, 0)
	require.NoError(t, err)
	require.False(t, processed)
}

// A client MUST discard packets from unknown server addresses (section 9 of RFC 9000).
// With IETF Multipath QUIC, every path has its own server address.
func TestMultipathClientUnknownServerAddressPerPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		serverAddr2 := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 4321}
		pathConn := newMockPathConn(tc.mockCtrl, serverAddr2, connCapabilities{})
		p := tc.newTestPath(pathConn)
		errChan := probeMultipathPath(t.Context(), p)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		_, err := tc.receivePacket(t, 1, serverAddr2, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		requireProbeResult(t, errChan, nil)
		tc.probes = nil

		// packets on path 1 from the server address of path 0, and vice versa, are dropped
		tc.receiveDroppedPacket(t, 1, tc.remoteAddr)
		tc.receiveDroppedPacket(t, 0, serverAddr2)
		tc.receiveDroppedPacket(t, 1, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 4321})
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Empty(t, tc.probes)

		// a PATH_CHALLENGE from the server address of the path is answered
		_, err = tc.receivePacket(t, 1, serverAddr2, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{2}})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		_, responses := sentProbeFrames(tc.probes, 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{2}}}, responses)
	})
}

// Once path 0 was abandoned, packets received on it don't cause an RFC 9000 connection migration.
func TestMultipathServerAbandonedPath0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)

		connID := tc.connIDForPath(t, 0)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 0}, protocol.Encryption1RTT))
		require.Equal(t, mpPathAbandoned, c.mp.paths[0].state)
		tc.probes = nil
		// A packet on path 0 from a new address. Packets on abandoned paths are processed, but never answered.
		processed, err := tc.receivePacketWithConnID(t, 0, connID, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 1234}, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.True(t, processed)
		require.Nil(t, c.pathManager)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Empty(t, tc.probes)
	})
}

// probe calls Probe on the path in a new goroutine.
// Probe posts a request to the connection's run loop, which is handled by handleMultipathEvents.
func probeMultipathPath(ctx context.Context, p *Path) <-chan error {
	errChan := make(chan error, 1)
	go func() { errChan <- p.Probe(ctx) }()
	synctest.Wait()
	return errChan
}

// newTestPath returns a Path that is opened using the sendConn.
func (tc *mpPathTestConn) newTestPath(conn sendConn) *Path {
	return tc.conn.newMultipathPath(func() sendConn { return conn })
}

// openTestPath opens a path and validates it. It returns the path ID.
func (tc *mpPathTestConn) openTestPath(t *testing.T, p *Path) protocol.PathID {
	t.Helper()
	c := tc.conn
	errChan := probeMultipathPath(t.Context(), p)
	require.NoError(t, c.handleMultipathEvents(monotime.Now()))
	id, ok := p.mp.pathID()
	require.True(t, ok)
	numProbes := len(tc.probes)
	require.NoError(t, c.triggerSending(monotime.Now()))
	challenges, _ := sentProbeFrames(tc.probes[numProbes:], id)
	require.NotEmpty(t, challenges)
	_, err := tc.receivePacket(t, id, tc.remoteAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
	require.NoError(t, err)
	require.Equal(t, mpPathActive, c.mp.paths[id].state)
	synctest.Wait()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	default:
		t.Fatal("Probe should have returned")
	}
	return id
}

func requireProbeResult(t *testing.T, errChan <-chan error, expected error) {
	t.Helper()
	synctest.Wait()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, expected)
	default:
		t.Fatal("Probe should have returned")
	}
}

func requireProbeBlocked(t *testing.T, errChan <-chan error) {
	t.Helper()
	synctest.Wait()
	select {
	case err := <-errChan:
		t.Fatalf("Probe returned: %v", err)
	default:
	}
}

func multipathFramesOfType[T wire.Frame](frames []ackhandler.Frame) []T {
	var fs []T
	for _, f := range frames {
		if f, ok := f.Frame.(T); ok {
			fs = append(fs, f)
		}
	}
	return fs
}

// The client opens the smallest path ID for which both endpoints issued connection IDs
// (sections 3 and 3.2.1 of draft-ietf-quic-multipath-21). If the server didn't issue a connection ID for an
// unused path ID, the client sends a PATH_CIDS_BLOCKED frame (section 3.2.2).
// It doesn't open more paths than Config.MaxPaths.
func TestMultipathClientOpenPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		// the server provided connection IDs for the path IDs 2 and 3, but not for path ID 1
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(3, 0)))
		queuedFrames(c)

		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p1 := tc.newTestPath(pathConn)
		errChan1 := probeMultipathPath(t.Context(), p1)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		id, ok := p1.mp.pathID()
		require.True(t, ok)
		require.Equal(t, protocol.PathID(2), id)
		require.Equal(t, mpPathValidating, c.mp.paths[2].state)
		require.Empty(t, queuedFrames(c))

		// The first packet sent on the path contains a PATH_CHALLENGE, and is expanded to 1200 bytes.
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, protocol.PathID(2), tc.probes[0].pathID)
		require.Len(t, tc.probes[0].frames, 1)
		require.IsType(t, &wire.PathChallengeFrame{}, tc.probes[0].frames[0].Frame)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[0].padTo)
		require.Len(t, tc.sent, 1)
		require.Equal(t, sendConn(pathConn), tc.sent[0].conn)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.sent[0].size)
		requireProbeBlocked(t, errChan1)

		// the next path uses path ID 3
		errChan2 := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Contains(t, c.mp.paths, protocol.PathID(3))
		require.Empty(t, queuedFrames(c))

		// path ID 1 can't be used yet
		p3 := tc.newTestPath(pathConn)
		errChan3 := probeMultipathPath(t.Context(), p3)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		_, ok = p3.mp.pathID()
		require.False(t, ok)
		require.Equal(t,
			[]*wire.PathCIDsBlockedFrame{{PathID: 1, NextSequenceNumber: 0}},
			multipathFramesOfType[*wire.PathCIDsBlockedFrame](queuedFrames(c)),
		)
		// the frame is only sent once
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Empty(t, queuedFrames(c))
		requireProbeBlocked(t, errChan3)

		// the server provides a connection ID for path ID 1
		require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 0), protocol.Encryption1RTT))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		id, ok = p3.mp.pathID()
		require.True(t, ok)
		require.Equal(t, protocol.PathID(1), id)

		// MaxPaths is 4, so no more paths can be opened
		errChan4 := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		requireProbeResult(t, errChan4, ErrTooManyPaths)
		require.Empty(t, multipathFramesOfType[*wire.PathsBlockedFrame](queuedFrames(c)))

		requireProbeBlocked(t, errChan1)
		requireProbeBlocked(t, errChan2)
		requireProbeBlocked(t, errChan3)
	})
}

// Section 3.2.1 of draft-ietf-quic-multipath-21: if the peer's maximum path ID prevents opening a path,
// a PATHS_BLOCKED frame is sent.
func TestMultipathClientPathsBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 1)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		queuedFrames(c)
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		tc.openTestPath(t, tc.newTestPath(pathConn))

		p2 := tc.newTestPath(pathConn)
		errChan2 := probeMultipathPath(t.Context(), p2)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		frames := queuedFrames(c)
		blocked := multipathFramesOfType[*wire.PathsBlockedFrame](frames)
		require.Equal(t, []*wire.PathsBlockedFrame{{MaximumPathID: 1}}, blocked)
		// the frame is only sent once for every maximum path ID
		p3 := tc.newTestPath(pathConn)
		errChan3 := probeMultipathPath(t.Context(), p3)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Empty(t, queuedFrames(c))
		requireProbeBlocked(t, errChan2)
		requireProbeBlocked(t, errChan3)
		// a lost PATHS_BLOCKED frame is retransmitted, as long as it's still blocked by the same maximum path ID
		var handler ackhandler.FrameHandler
		for _, f := range frames {
			if _, ok := f.Frame.(*wire.PathsBlockedFrame); ok {
				handler = f.Handler
			}
		}
		require.NotNil(t, handler)
		handler.OnLost(blocked[0])
		require.Equal(t, []*wire.PathsBlockedFrame{{MaximumPathID: 1}}, multipathFramesOfType[*wire.PathsBlockedFrame](queuedFrames(c)))

		// the server increases its maximum path ID
		require.NoError(t, handleTestFrame(t, c, &wire.MaxPathIDFrame{MaximumPathID: 2}, protocol.Encryption1RTT))
		handler.OnLost(blocked[0])
		require.Empty(t, multipathFramesOfType[*wire.PathsBlockedFrame](queuedFrames(c)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		id, ok := p2.mp.pathID()
		require.True(t, ok)
		require.Equal(t, protocol.PathID(2), id)
		require.Equal(t,
			[]*wire.PathsBlockedFrame{{MaximumPathID: 2}},
			multipathFramesOfType[*wire.PathsBlockedFrame](queuedFrames(c)),
		)
		requireProbeBlocked(t, errChan3)
	})
}

// PATH_CHALLENGE frames are retransmitted with exponential backoff.
// If the path isn't validated in time, it is abandoned with PATH_UNSTABLE_OR_POOR (section 3.1 of
// draft-ietf-quic-multipath-21), using the timeout recommended in section 8.2.4 of RFC 9000.
func TestMultipathClientPathValidationTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		c.rttStats.UpdateRTT(time.Second, 0)
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		queuedFrames(c)
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		errChan := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		start := monotime.Now()
		require.NoError(t, c.handleMultipathEvents(start))
		require.NoError(t, c.triggerSending(start))
		expectedTimeout := 3 * c.sentPacketHandler.MaxPTO(true)
		require.Equal(t, 3*c.rttStats.PTO(true), expectedTimeout)

		for monotime.Since(start) < expectedTimeout {
			tc.advanceToNextMultipathTimeout(t)
			require.NoError(t, c.triggerSending(monotime.Now()))
		}
		require.Equal(t, expectedTimeout, monotime.Since(start))
		requireProbeResult(t, errChan, errPathValidationFailed)
		require.Equal(t, mpPathAbandoned, c.mp.paths[1].state)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor}},
			pathAbandonFramesFor(queuedFrames(c), 1),
		)

		// every PATH_CHALLENGE contains new data, and is expanded to 1200 bytes
		var times []time.Duration
		seen := make(map[[8]byte]struct{})
		for _, p := range tc.probes {
			require.Equal(t, protocol.PathID(1), p.pathID)
			require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), p.size)
			challenge := p.frames[0].Frame.(*wire.PathChallengeFrame)
			require.NotContains(t, seen, challenge.Data)
			seen[challenge.Data] = struct{}{}
			times = append(times, p.time.Sub(start))
		}
		// starting with the PTO of the new path, the interval is doubled for every retransmission
		pto := utils.NewRTTStats().PTO(true)
		require.Equal(t, []time.Duration{0, pto, 3 * pto, 7 * pto, 15 * pto, 31 * pto}, times)
		// no packets are sent on the abandoned path
		numSent := len(tc.sent)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.sent, numSent)
	})
}

// If the context passed to Probe is canceled, the path is abandoned with APPLICATION_ABANDON_PATH
// (section 3.4 of draft-ietf-quic-multipath-21).
func TestMultipathClientProbeCanceled(t *testing.T) {
	t.Run("before the path is opened", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
			c := tc.conn
			queuedFrames(c)
			ctx, cancel := context.WithCancel(context.Background())
			// The server didn't provide any connection IDs.
			p := tc.newTestPath(nil)
			errChan := probeMultipathPath(ctx, p)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Len(t, c.mp.pendingOpens, 1)
			cancel()
			requireProbeResult(t, errChan, context.Canceled)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Empty(t, c.mp.pendingOpens)
			// no path ID was used
			require.Empty(t, pathAbandonFrames(queuedFrames(c)))
			require.ErrorIs(t, p.Probe(context.Background()), ErrPathClosed)
		})
	})

	t.Run("after the path was opened", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
			c := tc.conn
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
			queuedFrames(c)
			pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
			ctx, cancel := context.WithCancel(context.Background())
			p := tc.newTestPath(pathConn)
			errChan := probeMultipathPath(ctx, p)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.NoError(t, c.triggerSending(monotime.Now()))
			require.Equal(t, mpPathValidating, c.mp.paths[1].state)
			cancel()
			requireProbeResult(t, errChan, context.Canceled)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Equal(t, mpPathAbandoned, c.mp.paths[1].state)
			require.Equal(t,
				[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}},
				pathAbandonFramesFor(queuedFrames(c), 1),
			)
			require.Equal(t, ackhandler.SendNone, c.sentPacketHandler.SendModeForPath(1, monotime.Now()))
			require.ErrorIs(t, p.Probe(context.Background()), ErrPathClosed)
		})
	})
}

// Paths are added by the client after completion of the handshake.
// Section 2.2 of draft-ietf-quic-multipath-21: if the server sent the disable_active_migration transport parameter,
// no paths to the server's handshake address can be opened. Paths to other server addresses can.
func TestMultipathAddPath(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		close(tc.conn.handshakeCompleteChan)
		_, err := tc.conn.AddPath(&Transport{})
		require.Error(t, err)
		_, err = tc.conn.AddPathFromAddr(nil, nil)
		require.EqualError(t, err, "server cannot open paths")
	})

	// Whether a path added before completion of the handshake is a path of IETF Multipath QUIC depends on the
	// server's transport parameters. The path is created when it is probed, once the handshake completed.
	t.Run("before handshake completion", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
			c := tc.conn
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
			p, err := c.AddPathFromAddr(nil, nil)
			require.NoError(t, err)
			_, ok := p.ID()
			require.False(t, ok)
			require.ErrorIs(t, p.Switch(), ErrPathNotValidated)
			require.Error(t, p.SetStatus(PathStatusUnknown))
			require.NoError(t, p.SetStatus(PathStatusBackup))
			errChan := probeMultipathPath(t.Context(), p)
			requireProbeBlocked(t, errChan)
			// a path closed before it was created
			closed, err := c.AddPathFromAddr(nil, nil)
			require.NoError(t, err)
			require.NoError(t, closed.Close())
			require.ErrorIs(t, closed.Switch(), ErrPathClosed)
			require.ErrorIs(t, closed.SetStatus(PathStatusBackup), ErrPathClosed)

			pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
			tc.sendConn.EXPECT().newPathConn(tc.remoteAddr, packetInfo{}).Return(pathConn)
			close(c.handshakeCompleteChan)
			synctest.Wait()
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Equal(t, sendConn(pathConn), c.mp.paths[1].conn)
			// the status set before is used
			require.Equal(t, PathStatusBackup, c.mp.paths[1].status)
			id, ok := p.ID()
			require.True(t, ok)
			require.Equal(t, protocol.PathID(1), id)
			requireProbeBlocked(t, errChan)
			require.ErrorIs(t, closed.Probe(t.Context()), ErrPathClosed)
		})
	})

	t.Run("before handshake completion, multipath not negotiated", func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		c.mp = nil
		p, err := c.AddPathFromAddr(nil, nil)
		require.NoError(t, err)
		migrationPath, err := c.AddPath(&Transport{Conn: newUDPConnLocalhost(t)})
		require.NoError(t, err)
		close(c.handshakeCompleteChan)
		require.EqualError(t, p.Probe(t.Context()), "IETF Multipath QUIC was not negotiated")
		// AddPath creates a path for RFC 9000 connection migration
		path, err := migrationPath.deferred.resolve(t.Context())
		require.NoError(t, err)
		require.Nil(t, path.mp)
		require.NotNil(t, path.pathManager)
		_, ok := migrationPath.ID()
		require.False(t, ok)
	})

	t.Run("multipath not negotiated", func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		tc.conn.mp = nil
		close(tc.conn.handshakeCompleteChan)
		_, err := tc.conn.AddPathFromAddr(nil, nil)
		require.EqualError(t, err, "IETF Multipath QUIC was not negotiated")
		// AddPath creates a path for RFC 9000 connection migration
		p, err := tc.conn.AddPath(&Transport{Conn: newUDPConnLocalhost(t)})
		require.NoError(t, err)
		require.Nil(t, p.mp)
	})

	t.Run("without disable_active_migration", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
			c := tc.conn
			close(c.handshakeCompleteChan)
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
			p, err := c.AddPathFromAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}, nil)
			require.NoError(t, err)
			require.NotNil(t, p.mp)
			// the path uses the connection's underlying connection, from another local address
			pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
			tc.sendConn.EXPECT().newPathConn(tc.remoteAddr, packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}})).Return(pathConn)
			errChan := probeMultipathPath(t.Context(), p)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Equal(t, sendConn(pathConn), c.mp.paths[1].conn)
			requireProbeBlocked(t, errChan)
		})
	})

	t.Run("with disable_active_migration", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
			c := tc.conn
			c.peerParams.DisableActiveMigration = true
			close(c.handshakeCompleteChan)
			_, err := c.AddPath(&Transport{})
			require.EqualError(t, err, "server disabled active migration to its handshake address")
			_, err = c.AddPathFromAddr(nil, nil)
			require.EqualError(t, err, "server disabled active migration to its handshake address")
			_, err = c.AddPathFromAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}, tc.remoteAddr)
			require.EqualError(t, err, "server disabled active migration to its handshake address")

			// another address of the server
			otherAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 4321}
			p, err := c.AddPathFromAddr(nil, otherAddr)
			require.NoError(t, err)
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
			pathConn := newMockPathConn(tc.mockCtrl, otherAddr, connCapabilities{})
			tc.sendConn.EXPECT().newPathConn(otherAddr, packetInfo{}).Return(pathConn)
			errChan := probeMultipathPath(t.Context(), p)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Equal(t, sendConn(pathConn), c.mp.paths[1].conn)
			requireProbeBlocked(t, errChan)
		})
	})

	// Section 2.2 of draft-ietf-quic-multipath-21: disable_active_migration only forbids paths to the server's
	// handshake address. Once path 0 migrated to the server's preferred address, paths to that address can be opened.
	t.Run("with disable_active_migration, after migrating to the preferred address", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
			c := tc.conn
			c.peerParams.DisableActiveMigration = true
			close(c.handshakeCompleteChan)
			handshakeAddr := tc.remoteAddr
			preferredAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 9), Port: 443}
			conn := newMigratingMockPathConn(tc.mockCtrl, handshakeAddr)
			c.conn = conn
			tc.sendConn = conn
			c.migrateMultipathPath(c.mp.paths[0], preferredAddr, packetInfo{}, monotime.Now())
			require.Equal(t, preferredAddr, c.conn.RemoteAddr())

			// paths to the handshake address are still forbidden
			_, err := c.AddPathFromAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}, handshakeAddr)
			require.EqualError(t, err, "server disabled active migration to its handshake address")
			// paths to the preferred address can be opened, this is the default
			_, err = c.AddPathFromAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}, preferredAddr)
			require.NoError(t, err)
			p, err := c.AddPathFromAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}, nil)
			require.NoError(t, err)
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
			pathConn := newMockPathConn(tc.mockCtrl, preferredAddr, connCapabilities{})
			conn.EXPECT().newPathConn(preferredAddr, packetInfoFromPathInfo(PathInfo{LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}})).Return(pathConn)
			errChan := probeMultipathPath(t.Context(), p)
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			require.Equal(t, sendConn(pathConn), c.mp.paths[1].conn)
			requireProbeBlocked(t, errChan)
			// AddPath opens a path to the server address of path 0, i.e. the preferred address
			p, err = c.AddPath(&Transport{Conn: newUDPConnLocalhost(t)})
			require.NoError(t, err)
			require.NotNil(t, p.mp)
		})
	})
}

// PTO probe packets are sent on the path whose PTO expired (section 5.7 of draft-ietf-quic-multipath-21).
func TestMultipathPTOProbesOnExpiringPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		tc.openTestPath(t, tc.newTestPath(pathConn))

		// send an ack-eliciting packet on path 1
		c.registerPackedShortHeaderPacket(tc.packPacket(1, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 1000, false), protocol.ECNNon, monotime.Now())
		timeout := c.sentPacketHandler.GetLossDetectionTimeout()
		require.False(t, timeout.IsZero())
		time.Sleep(monotime.Until(timeout))
		require.NoError(t, c.sentPacketHandler.OnLossDetectionTimeout(monotime.Now()))
		require.Equal(t, ackhandler.SendPTOAppData, c.sentPacketHandler.SendModeForPath(1, monotime.Now()))
		require.Equal(t, ackhandler.SendAny, c.sentPacketHandler.SendModeForPath(0, monotime.Now()))

		var probePaths []protocol.PathID
		tc.packer.EXPECT().PackPTOProbePacket(protocol.Encryption1RTT, gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(_ protocol.EncryptionLevel, maxSize protocol.ByteCount, _ bool, _ monotime.Time, _ protocol.Version, pathID protocol.PathID) (*coalescedPacket, error) {
				probePaths = append(probePaths, pathID)
				p := tc.packPacket(pathID, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 100, false)
				return &coalescedPacket{buffer: getTestPacketBuffer(100), shortHdrPacket: &p}, nil
			},
		).Times(2)
		numSent := len(tc.sent)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, []protocol.PathID{1, 1}, probePaths)
		require.Len(t, tc.sent, numSent+2)
		for _, p := range tc.sent[numSent:] {
			require.Equal(t, sendConn(pathConn), p.conn)
		}
		require.Equal(t, ackhandler.SendAny, c.sentPacketHandler.SendModeForPath(1, monotime.Now()))
	})
}

// Generic Segmentation Offload is only used if a single path can be used for sending.
func TestMultipathGSOWithSinglePath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConnWithOpts(t, protocol.PerspectiveClient, 3, 3, mpPathTestConnOpts{capabilities: connCapabilities{GSO: true}})
		c := tc.conn
		appendPackets := func(n int) {
			var count int
			tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
				if count == n {
					return shortHeaderPacket{}, errNothingToPack
				}
				count++
				return tc.appendDataPacket(buf, maxSize, pathID), nil
			}
		}

		appendPackets(3)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.sent, 1)
		maxSize := c.maxPacketSize()
		require.Nil(t, tc.sent[0].conn)
		require.Equal(t, uint16(maxSize), tc.sent[0].gsoSize)
		require.Equal(t, 3*maxSize, tc.sent[0].size)

		// a validating path is not used for sending
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{GSO: true})
		errChan := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		tc.sent = nil
		appendPackets(2)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.sent, 2)
		require.Equal(t, sendConn(pathConn), tc.sent[0].conn) // the path probe packet
		require.Nil(t, tc.sent[1].conn)
		require.Equal(t, uint16(maxSize), tc.sent[1].gsoSize)
		require.Equal(t, 2*maxSize, tc.sent[1].size)

		// once the path is validated, two paths can be used, and GSO is not used any more
		challenges, _ := sentProbeFrames(tc.probes, 1)
		_, err := tc.receivePacket(t, 1, tc.remoteAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		requireProbeResult(t, errChan, nil)
		tc.sent = nil
		appendPackets(4)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.sent, 4)
		var onPath1 int
		for _, p := range tc.sent {
			require.Zero(t, p.gsoSize)
			if p.conn == pathConn {
				onPath1++
			}
		}
		require.Equal(t, 2, onPath1)
	})
}

// DATAGRAM frames can be sent on any path, so their size is limited by the smallest MTU of all active paths
// (section 5.8 of draft-ietf-quic-multipath-21).
func TestMultipathDatagramSizeLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConnWithOpts(t, protocol.PerspectiveClient, 3, 3, mpPathTestConnOpts{pmtud: true})
		c := tc.conn
		c.mtuDiscoverer = newMTUDiscoverer(c.rttStats, 1400, protocol.MaxPacketBufferSize, nil)
		c.updateMaxPayloadSizeEstimate()
		require.Equal(t, uint32(estimateMaxPayloadSize(1400)), c.maxPayloadSizeEstimate.Load())

		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		// validating paths are not used for DATAGRAM frames
		errChan := probeMultipathPath(t.Context(), p)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, uint32(estimateMaxPayloadSize(1400)), c.maxPayloadSizeEstimate.Load())
		challenges, _ := sentProbeFrames(tc.probes, 1)
		_, err := tc.receivePacket(t, 1, tc.remoteAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		requireProbeResult(t, errChan, nil)
		// path 1 starts with the initial packet size
		require.Equal(t, protocol.ByteCount(c.config.InitialPacketSize), c.pathMaxPacketSize(c.mp.paths[1]))
		require.Equal(t, uint32(estimateMaxPayloadSize(protocol.ByteCount(c.config.InitialPacketSize))), c.maxPayloadSizeEstimate.Load())

		// the MTU of path 1 increases
		ping, size := c.mp.paths[1].mtuDiscoverer.GetPing(monotime.Now())
		require.Greater(t, size, protocol.ByteCount(c.config.InitialPacketSize))
		ping.Handler.OnAcked(ping.Frame)
		c.maybeUpdatePathMTU(c.mp.paths[1])
		require.Equal(t, size, c.mp.paths[1].maxDatagramSize)
		require.Equal(t, uint32(estimateMaxPayloadSize(min(size, 1400))), c.maxPayloadSizeEstimate.Load())

		// abandoned paths don't limit the size
		c.abandonPath(c.mp.paths[1], qerr.ApplicationAbandonPath, monotime.Now(), ErrPathClosed)
		require.Equal(t, uint32(estimateMaxPayloadSize(1400)), c.maxPayloadSizeEstimate.Load())
	})
}

// Path MTU Discovery and ECN validation are performed for every path, once it is validated.
func TestMultipathPathMTUDiscoveryAndECN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		capabilities := connCapabilities{ECN: true, DF: true}
		tc := newMPPathTestConnWithOpts(t, protocol.PerspectiveClient, 3, 3, mpPathTestConnOpts{capabilities: capabilities, pmtud: true})
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, capabilities)
		p := tc.newTestPath(pathConn)
		errChan := probeMultipathPath(t.Context(), p)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Nil(t, c.mp.paths[1].mtuDiscoverer)
		// ECN is not used for path validation
		require.Len(t, tc.sent, 1)
		require.Equal(t, protocol.ECNNon, tc.sent[0].ecn)

		time.Sleep(10 * time.Millisecond)
		challenges, _ := sentProbeFrames(tc.probes, 1)
		_, err := tc.receivePacket(t, 1, tc.remoteAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		requireProbeResult(t, errChan, nil)
		path := c.mp.paths[1]
		require.NotNil(t, path.mtuDiscoverer)
		// the PATH_CHALLENGE / PATH_RESPONSE exchange provides an RTT sample
		require.Equal(t, 10*time.Millisecond, c.sentPacketHandler.GetPathRTTStats(1).SmoothedRTT())

		// data packets sent on the path use ECN
		tc.sent = nil
		var count int
		tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
			if count == 2 {
				return shortHeaderPacket{}, errNothingToPack
			}
			count++
			return tc.appendDataPacket(buf, 1000, pathID), nil
		}
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.sent, 2)
		for _, s := range tc.sent {
			require.Equal(t, protocol.ECT0, s.ecn)
		}

		// an MTU probe is sent on the path after 5 RTTs
		var mtuProbePaths []protocol.PathID
		tc.packer.EXPECT().PackMTUProbePacket(gomock.Any(), gomock.Any(), protocol.Version1, gomock.Any()).DoAndReturn(
			func(ping ackhandler.Frame, size protocol.ByteCount, _ protocol.Version, pathID protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
				mtuProbePaths = append(mtuProbePaths, pathID)
				p := tc.packPacket(pathID, []ackhandler.Frame{ping}, size, false)
				p.IsPathMTUProbePacket = true
				return p, getTestPacketBuffer(size), nil
			},
		).AnyTimes()
		time.Sleep(5 * c.sentPacketHandler.GetPathRTTStats(1).SmoothedRTT())
		tc.sent = nil
		tc.appendPacket = nil
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, []protocol.PathID{1}, mtuProbePaths)
		require.Len(t, tc.sent, 1)
		require.Equal(t, sendConn(pathConn), tc.sent[0].conn)
		require.Greater(t, tc.sent[0].size, protocol.ByteCount(c.config.InitialPacketSize))
	})
}

// ackRangesFor returns the ACK ranges acknowledging the packet numbers, which must be sorted in ascending order.
func ackRangesFor(pns []protocol.PacketNumber) []wire.AckRange {
	var ranges []wire.AckRange
	for _, pn := range pns {
		if len(ranges) > 0 && ranges[0].Largest+1 == pn {
			ranges[0].Largest = pn
			continue
		}
		ranges = append([]wire.AckRange{{Smallest: pn, Largest: pn}}, ranges...)
	}
	return ranges
}

// Every path performs its own ECN validation (section 13.4.2 of RFC 9000).
// A CONNECTION_CLOSE sent on a path uses the ECN marking of that path.
func TestMultipathConnectionCloseECN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		capabilities := connCapabilities{ECN: true}
		tc := newMPPathTestConnWithOpts(t, protocol.PerspectiveClient, 3, 3, mpPathTestConnOpts{capabilities: capabilities})
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, capabilities)
		tc.openTestPath(t, tc.newTestPath(pathConn))

		// Send all ECN testing packets on path 1, and fewer than that on path 0.
		pns := make(map[protocol.PathID][]protocol.PacketNumber)
		tc.appendPacket = func(buf *packetBuffer, maxSize protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
			if len(pns[1]) == 10 {
				return shortHeaderPacket{}, errNothingToPack
			}
			p := tc.appendDataPacket(buf, 1000, pathID)
			pns[pathID] = append(pns[pathID], p.PacketNumber)
			return p, nil
		}
		for len(pns[1]) < 10 {
			require.NoError(t, c.triggerSending(monotime.Now()))
			if len(pns[1]) < 10 {
				require.False(t, c.pacingDeadline.IsZero(), "no packet can be sent")
				time.Sleep(monotime.Until(c.pacingDeadline))
			}
		}
		require.Less(t, len(pns[0]), 10)
		// ECN validation fails on path 1: the PATH_ACK doesn't contain ECN counts
		_, err := tc.receivePacket(t, 1, tc.remoteAddr, packetInfo{}, 1200, &wire.AckFrame{PathID: 1, HasPathID: true, AckRanges: ackRangesFor(pns[1])})
		require.NoError(t, err)
		require.Equal(t, protocol.ECNNon, c.sentPacketHandler.ECNModeForPath(1))
		// path 0 is still testing ECN
		require.Equal(t, protocol.ECT0, c.sentPacketHandler.ECNMode(true))

		connClose := func(pathID protocol.PathID) {
			tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1, pathID).DoAndReturn(
				func(*qerr.TransportError, protocol.ByteCount, protocol.Version, protocol.PathID) (*coalescedPacket, error) {
					buf := getPacketBuffer()
					buf.Data = append(buf.Data, []byte("connection close")...)
					return &coalescedPacket{buffer: buf, shortHdrPacket: &shortHeaderPacket{PathID: uint64(pathID), Length: buf.Len()}}, nil
				},
			)
			_, err := c.sendConnectionClose(&qerr.TransportError{ErrorCode: qerr.NoError})
			require.NoError(t, err)
		}
		// the CONNECTION_CLOSE is sent on path 1, the path that the last packet was received on
		pathConn.EXPECT().Write([]byte("connection close"), uint16(0), protocol.ECNNon)
		connClose(1)

		// on path 0, it is sent with ECT(0)
		c.mp.lastRcvdPathID = 0
		tc.sendConn.EXPECT().Write([]byte("connection close"), uint16(0), protocol.ECT0)
		connClose(0)
	})
}

// A write error on the sendConn of a path abandons the path, if another path can be used.
// Otherwise, the connection is closed.
func TestMultipathPathWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		conn1 := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		conn2 := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p1 := tc.newTestPath(conn1)
		tc.openTestPath(t, p1)
		tc.openTestPath(t, tc.newTestPath(conn2))
		queuedFrames(c)

		// errors for sendConns that don't belong to a path are ignored
		c.handlePathWriteError(newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{}), errors.New("unrelated"))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))

		writeErr := errors.New("network unreachable")
		c.handlePathWriteError(conn1, writeErr)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Equal(t, mpPathAbandoned, c.mp.paths[1].state)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.PathUnstableOrPoor}},
			pathAbandonFramesFor(queuedFrames(c), 1),
		)
		require.ErrorIs(t, p1.Probe(context.Background()), writeErr)

		// If no other path can be used, the error closes the connection.
		c.markPathAbandoned(c.mp.paths[0], monotime.Now(), nil)
		c.handlePathWriteError(conn2, writeErr)
		require.ErrorIs(t, c.handleMultipathEvents(monotime.Now()), writeErr)
	})
}

// Section 3.4 of draft-ietf-quic-multipath-21: when the peer abandons a path, it is abandoned, and a PATH_ABANDON frame
// is sent in response. A path that is being validated is open as well. If it is the only other open path,
// the connection is closed if its validation fails.
func TestMultipathPeerAbandonsPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		p := tc.newTestPath(pathConn)
		tc.openTestPath(t, p)
		queuedFrames(c)

		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}, protocol.Encryption1RTT))
		require.Equal(t, mpPathAbandoned, c.mp.paths[1].state)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.NoError}},
			pathAbandonFramesFor(queuedFrames(c), 1),
		)
		require.ErrorIs(t, p.Probe(context.Background()), ErrPathClosed)
		// the peer's connection IDs for the path are retired
		require.False(t, c.peerConnIDs.HasConnID(1))
		// a repeated PATH_ABANDON frame is ignored
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 1}, protocol.Encryption1RTT))
		require.Empty(t, queuedFrames(c))

		// A path that is still being validated can't be used for sending, but it is open.
		// The PATH_ABANDON frame for path 0 is sent once it can be used.
		errChan := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Equal(t, mpPathValidating, c.mp.paths[2].state)
		require.NoError(t, handleTestFrame(t, c, &wire.PathAbandonFrame{PathID: 0}, protocol.Encryption1RTT))
		require.Equal(t, mpPathAbandoned, c.mp.paths[0].state)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 0, ErrorCode: qerr.NoError}},
			pathAbandonFramesFor(queuedFrames(c), 0),
		)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		requireProbeBlocked(t, errChan)

		// The validation of path 2 fails. No path is left, and the connection is closed.
		var err error
		for i := 0; err == nil; i++ {
			require.Less(t, i, 20, "the connection should have been closed")
			deadline := c.mp.nextTimeout()
			require.False(t, deadline.IsZero(), "no timer set")
			time.Sleep(monotime.Until(deadline))
			err = c.handleMultipathEvents(monotime.Now())
		}
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.NoViablePathError})
		requireProbeResult(t, errChan, errPathValidationFailed)
	})
}

// A path that the client opened is open, even while the server is still validating it (section 3.4 of
// draft-ietf-quic-multipath-21). When the client abandons path 0, the server abandons it as well, instead of closing
// the connection. It sends its PATH_ABANDON frame once it validated the client's new path.
// The client might abandon path 0 right after it validated the new path, while the PATH_RESPONSE it sent on that path
// was lost.
func TestMultipathServerPeerAbandonsPath0WhileValidatingPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		pathConn := newMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		// records the paths that packets other than path validation packets are packed for
		var dataPaths []protocol.PathID
		tc.appendPacket = func(_ *packetBuffer, _ protocol.ByteCount, pathID protocol.PathID) (shortHeaderPacket, error) {
			dataPaths = append(dataPaths, pathID)
			return shortHeaderPacket{}, errNothingToPack
		}

		// the client opens path 1
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		require.Equal(t, mpPathValidating, c.mp.paths[1].state)

		// The client abandons path 0. The PATH_ABANDON frame is received on path 1.
		dataPaths = nil
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathAbandonFrame{PathID: 0, ErrorCode: qerr.ApplicationAbandonPath})
		require.NoError(t, err)
		require.Equal(t, mpPathAbandoned, c.mp.paths[0].state)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		// no packets other than path validation packets can be sent until path 1 is validated
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Empty(t, dataPaths)

		// Path 1 is validated, and becomes the primary path.
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Equal(t, protocol.PathID(1), c.mp.primaryPathID)
		require.Equal(t, clientAddr, c.RemoteAddr())
		// the PATH_ABANDON frame is sent on path 1
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Equal(t, []protocol.PathID{1}, dataPaths)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 0, ErrorCode: qerr.NoError}},
			pathAbandonFramesFor(queuedFrames(c), 0),
		)
	})
}

// Path.Close abandons a path with APPLICATION_ABANDON_PATH. The last path that can be used for sending can't be closed.
func TestMultipathPathClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		closePath := func(p *Path) <-chan error {
			errChan := make(chan error, 1)
			go func() { errChan <- p.Close() }()
			synctest.Wait()
			require.NoError(t, c.handleMultipathEvents(monotime.Now()))
			synctest.Wait()
			return errChan
		}

		// a path that was never probed can be closed right away
		p := tc.newTestPath(pathConn)
		require.NoError(t, p.Close())
		require.ErrorIs(t, p.Probe(t.Context()), ErrPathClosed)

		p1 := tc.newTestPath(pathConn)
		tc.openTestPath(t, p1)
		p2 := tc.newTestPath(pathConn)
		tc.openTestPath(t, p2)
		queuedFrames(c)
		require.NoError(t, <-closePath(p1))
		require.Equal(t, mpPathAbandoned, c.mp.paths[1].state)
		require.Equal(t,
			[]*wire.PathAbandonFrame{{PathID: 1, ErrorCode: qerr.ApplicationAbandonPath}},
			pathAbandonFramesFor(queuedFrames(c), 1),
		)
		require.ErrorIs(t, p1.Switch(), ErrPathClosed)
		require.NoError(t, p1.Close())

		// path 2 is the last path that can be used for sending
		c.markPathAbandoned(c.mp.paths[0], monotime.Now(), nil)
		require.EqualError(t, <-closePath(p2), "cannot close the last usable path")
		require.Equal(t, mpPathActive, c.mp.paths[2].state)
		require.NoError(t, p2.Switch())
	})
}
