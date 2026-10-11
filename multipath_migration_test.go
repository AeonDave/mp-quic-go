package quic

import (
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newMigratingMockPathConn returns a mock sendConn whose remote address can be changed using ChangeRemoteAddr.
func newMigratingMockPathConn(mockCtrl *gomock.Controller, remoteAddr net.Addr, capabilities ...connCapabilities) *MockSendConn {
	var caps connCapabilities
	if len(capabilities) > 0 {
		caps = capabilities[0]
	}
	conn := NewMockSendConn(mockCtrl)
	conn.EXPECT().RemoteAddr().DoAndReturn(func() net.Addr { return remoteAddr }).AnyTimes()
	conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}).AnyTimes()
	conn.EXPECT().capabilities().Return(caps).AnyTimes()
	conn.EXPECT().ChangeRemoteAddr(gomock.Any(), gomock.Any()).Do(func(addr net.Addr, _ packetInfo) { remoteAddr = addr }).AnyTimes()
	return conn
}

func decodeTestTokens(t *testing.T, frames []*wire.NewTokenFrame) []*handshake.Token {
	t.Helper()
	tokenGen := handshake.NewTokenGenerator(handshake.TokenProtectorKey{})
	var tokens []*handshake.Token
	for _, f := range frames {
		token, err := tokenGen.DecodeToken(f.Token)
		require.NoError(t, err)
		tokens = append(tokens, token)
	}
	return tokens
}

// A packet received on a path from another 4-tuple is a migration of that path (section 3.1.2 of
// draft-ietf-quic-multipath-21). The server validates the new 4-tuple using a connection ID of the path,
// and switches to it in response to the highest-numbered non-probing packet (section 9.3 of RFC 9000).
// This resets the path's congestion controller and RTT estimate. Other paths are not affected.
func TestMultipathServerPathMigration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		c.mp.validatedClientAddrs = []net.Addr{c.conn.RemoteAddr()}
		for seq := range uint64(3) {
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, seq)))
		}
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		pathConn := newMigratingMockPathConn(tc.mockCtrl, clientAddr)
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)
		tokens := decodeTestTokens(t, multipathFramesOfType[*wire.NewTokenFrame](queuedFrames(c)))
		require.Len(t, tokens, 1)
		require.True(t, tokens[0].ValidateRemoteAddr(clientAddr))
		require.True(t, tokens[0].ValidateRemoteAddr(c.conn.RemoteAddr()))

		// Both paths have RTT estimates and send packets.
		c.rttStats.UpdateRTT(30*time.Millisecond, 0)
		c.sentPacketHandler.GetPathRTTStats(1).UpdateRTT(50*time.Millisecond, 0)
		path0RTT := c.rttStats.SmoothedRTT()
		c.registerPackedShortHeaderPacket(tc.packPacket(0, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 1000, false), protocol.ECNNon, monotime.Now())
		c.registerPackedShortHeaderPacket(tc.packPacket(1, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, 1000, false), protocol.ECNNon, monotime.Now())
		path0CWND, path0BytesInFlight, ok := c.sentPacketHandler.PathCongestionState(0)
		require.True(t, ok)
		require.NotZero(t, path0BytesInFlight)
		pathConnID, ok := c.pathDestConnID(c.mp.paths[1])
		require.True(t, ok)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, pathConnID)
		tc.probes = nil
		queuedFrames(c)

		// A NAT rebinding: the client's packets on path 1 arrive from a new address.
		// The server validates the new address, using another connection ID of path 1.
		natAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}
		pathConn.EXPECT().WriteTo(gomock.Any(), natAddr, packetInfo{}).Times(2)
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, protocol.PathID(1), tc.probes[0].pathID)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[0].padTo)
		challenges, _ = sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		// The address is not validated yet. The path keeps using the old address.
		require.Equal(t, clientAddr, pathConn.RemoteAddr())

		// a PATH_CHALLENGE from the new address is answered, but doesn't migrate the path
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())

		// The new address is validated. The path switches to it.
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, natAddr, pathConn.RemoteAddr())
		// the congestion controller and the RTT estimate of path 1 are reset
		require.False(t, c.sentPacketHandler.GetPathRTTStats(1).HasMeasurement())
		cwnd, bytesInFlight, ok := c.sentPacketHandler.PathCongestionState(1)
		require.True(t, ok)
		require.Zero(t, bytesInFlight)
		require.Equal(t, protocol.ByteCount(c.config.InitialPacketSize)*32, cwnd)
		// path 0 is not affected
		require.Equal(t, path0RTT, c.rttStats.SmoothedRTT())
		cwnd, bytesInFlight, ok = c.sentPacketHandler.PathCongestionState(0)
		require.True(t, ok)
		require.Equal(t, path0CWND, cwnd)
		require.Equal(t, path0BytesInFlight, bytesInFlight)

		// The path uses the connection ID that was used to validate the new address.
		// The connection ID used for the old address is kept to validate the old address,
		// see TestMultipathServerPathMigrationValidatesPreviousAddress.
		pathConnID, ok = c.pathDestConnID(c.mp.paths[1])
		require.True(t, ok)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, pathConnID)
		frames := queuedFrames(c)
		require.Empty(t, multipathFramesOfType[*wire.PathRetireConnectionIDFrame](frames))
		// The server sends a token that is valid for the new address, and for the addresses validated before.
		tokens = decodeTestTokens(t, multipathFramesOfType[*wire.NewTokenFrame](frames))
		require.Len(t, tokens, 1)
		for _, addr := range []net.Addr{natAddr, clientAddr, c.conn.RemoteAddr()} {
			require.True(t, tokens[0].ValidateRemoteAddr(addr), "address %s", addr)
		}
	})
}

// acceptMigratingServerPath makes the client open path 1 from clientAddr, and validates it (server only).
// The client provides 3 connection IDs for path 1. The returned sendConn of the path can migrate.
func (tc *mpPathTestConn) acceptMigratingServerPath(t *testing.T, clientAddr net.Addr) *MockSendConn {
	t.Helper()
	c := tc.conn
	for seq := range uint64(3) {
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, seq)))
	}
	pathConn := newMigratingMockPathConn(tc.mockCtrl, clientAddr)
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
	return pathConn
}

// If the anti-amplification limit doesn't allow expanding the datagram containing the PATH_CHALLENGE that validates
// a new 4-tuple of a path to 1200 bytes, the PATH_RESPONSE only validates the client's address.
// The server validates the path MTU using a second PATH_CHALLENGE in an expanded datagram, and the path only migrates
// once that validation succeeded (section 8.2.1 of RFC 9000, section 3.1 of draft-ietf-quic-multipath-21).
func TestMultipathServerPathMigrationValidatesPathMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		pathConn := tc.acceptMigratingServerPath(t, clientAddr)

		// After a NAT rebinding, a small packet arrives from the client's new address.
		// 3 times its size doesn't allow expanding the datagram containing the PATH_CHALLENGE.
		natAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}
		pathConn.EXPECT().WriteTo(gomock.Any(), natAddr, packetInfo{}).Times(3)
		_, err := tc.receivePacket(t, 1, natAddr, packetInfo{}, 100, &wire.PingFrame{})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)
		require.Zero(t, tc.probes[0].padTo)
		require.LessOrEqual(t, tc.probes[0].size, protocol.ByteCount(300))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)

		// The PATH_RESPONSE validates the client's address, but not the path MTU. The path doesn't migrate.
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 100, &wire.PathResponseFrame{Data: challenges[0].Data}, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())
		// The second PATH_CHALLENGE is sent in an expanded datagram, using the same connection ID.
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 2)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[1].connID)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[1].padTo)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[1].size)
		mtuChallenges, _ := sentProbeFrames(tc.probes[1:], 1)
		require.Len(t, mtuChallenges, 1)
		require.NotEqual(t, challenges[0].Data, mtuChallenges[0].Data)
		// it is only sent once
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 2)

		// A repeated response to the first PATH_CHALLENGE doesn't validate the path MTU.
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 100, &wire.PathResponseFrame{Data: challenges[0].Data}, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())
		// The client's address was validated: a PATH_CHALLENGE in a small datagram is answered in an expanded datagram.
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 100, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 3)
		_, responses := sentProbeFrames(tc.probes[2:], 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{1}}}, responses)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[2].size)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())

		// The response to the second PATH_CHALLENGE validates the path. It migrates to the new address.
		_, err = tc.receivePacket(t, 1, natAddr, packetInfo{}, 100, &wire.PathResponseFrame{Data: mtuChallenges[0].Data}, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, natAddr, pathConn.RemoteAddr())
		pathConnID, ok := c.pathDestConnID(c.mp.paths[1])
		require.True(t, ok)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, pathConnID)
	})
}

// After a path migrated to another 4-tuple, the server validates the previously active 4-tuple
// (section 9.3.3 of RFC 9000), using the connection ID it used on that 4-tuple: it was never used towards another
// address (section 9.5 of RFC 9000). If the client is still reachable there, it responds with a non-probing packet,
// which migrates the path back: the migration might have been caused by an attacker forwarding packets.
// If the validation fails, the connection ID is retired.
func TestMultipathServerPathMigrationValidatesPreviousAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		pathConn := tc.acceptMigratingServerPath(t, clientAddr)

		// packets forwarded from another address migrate the path
		attackerAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}
		pathConn.EXPECT().WriteTo(gomock.Any(), attackerAddr, packetInfo{})
		_, err := tc.receivePacket(t, 1, attackerAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		challenges, _ := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		_, err = tc.receivePacket(t, 1, attackerAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data}, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, attackerAddr, pathConn.RemoteAddr())
		tc.probes = nil

		// The server validates the previous address, using the connection ID it used there.
		pathConn.EXPECT().WriteTo(gomock.Any(), clientAddr, packetInfo{})
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, tc.probes[0].connID)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[0].size)
		challenges, _ = sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		require.Empty(t, multipathFramesOfType[*wire.PathRetireConnectionIDFrame](queuedFrames(c)))

		// The client is still reachable at the previous address. It responds with a non-probing packet,
		// which migrates the path back. The path uses the connection ID it used on this address before.
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data}, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())
		pathConnID, ok := c.pathDestConnID(c.mp.paths[1])
		require.True(t, ok)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 0).ConnectionID, pathConnID)
		require.Empty(t, multipathFramesOfType[*wire.PathRetireConnectionIDFrame](queuedFrames(c)))

		// Now the attacker's address is validated, using the connection ID used there.
		tc.probes = nil
		pathConn.EXPECT().WriteTo(gomock.Any(), attackerAddr, packetInfo{})
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(1, 1).ConnectionID, tc.probes[0].connID)
		require.Equal(t, protocol.ByteCount(protocol.MinInitialPacketSize), tc.probes[0].size)

		// The validation fails: the packet containing the PATH_CHALLENGE is declared lost.
		// The connection ID is retired.
		time.Sleep(monotime.Until(tc.probes[0].time.Add(time.Second)))
		for {
			timeout := c.sentPacketHandler.GetLossDetectionTimeout()
			if timeout.IsZero() || timeout.After(monotime.Now()) {
				break
			}
			require.NoError(t, c.sentPacketHandler.OnLossDetectionTimeout(monotime.Now()))
		}
		require.Equal(t,
			[]*wire.PathRetireConnectionIDFrame{{PathID: 1, SequenceNumber: 1}},
			multipathFramesOfType[*wire.PathRetireConnectionIDFrame](queuedFrames(c)),
		)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())
	})
}

// A PATH_CHALLENGE received on an active path is answered with a non-probing packet (section 9.3.3 of RFC 9000):
// if the server migrated the path because an attacker forwarded packets from another address, this packet migrates
// the path back. On a path that is being validated, only probing frames are sent.
func TestMultipathPathResponseOnActivePathIsNonProbing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(2, 0)))
		pathConn := newMockPathConn(tc.mockCtrl, tc.remoteAddr, connCapabilities{})
		tc.openTestPath(t, tc.newTestPath(pathConn))
		isPing := func(f ackhandler.Frame) bool {
			_, ok := f.Frame.(*wire.PingFrame)
			return ok
		}

		tc.probes = nil
		_, err := tc.receivePacket(t, 1, tc.remoteAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		require.Len(t, tc.probes, 1)
		_, responses := sentProbeFrames(tc.probes, 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{1}}}, responses)
		require.True(t, slices.ContainsFunc(tc.probes[0].frames, isPing))

		// path 2 is being validated
		errChan := probeMultipathPath(t.Context(), tc.newTestPath(pathConn))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Equal(t, mpPathValidating, c.mp.paths[2].state)
		tc.probes = nil
		_, err = tc.receivePacket(t, 2, tc.remoteAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{2}})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		_, responses = sentProbeFrames(tc.probes, 2)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{2}}}, responses)
		for _, p := range tc.probes {
			require.False(t, slices.ContainsFunc(p.frames, isPing))
		}
		requireProbeBlocked(t, errChan)
	})
}

// Packets that only contain probing frames don't migrate a path (section 9.3 of RFC 9000).
// Neither do reordered packets.
func TestMultipathServerPathMigrationProbingAndReordering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		for seq := range uint64(3) {
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, seq)))
		}
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		pathConn := newMigratingMockPathConn(tc.mockCtrl, clientAddr)
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		require.Equal(t, mpPathActive, c.mp.paths[1].state)
		c.sentPacketHandler.GetPathRTTStats(1).UpdateRTT(50*time.Millisecond, 0)
		tc.probes = nil

		// The client probes another address, using probing frames only.
		probingAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}
		pathConn.EXPECT().WriteTo(gomock.Any(), probingAddr, packetInfo{}).AnyTimes()
		_, err = tc.receivePacket(t, 1, probingAddr, packetInfo{}, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		challenges, responses := sentProbeFrames(tc.probes, 1)
		require.Len(t, challenges, 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{1}}}, responses)
		_, err = tc.receivePacket(t, 1, probingAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		// the address was validated, but the path doesn't migrate
		require.Equal(t, clientAddr, pathConn.RemoteAddr())
		require.True(t, c.sentPacketHandler.GetPathRTTStats(1).HasMeasurement())

		// A reordered non-probing packet from the probed address doesn't migrate the path either:
		// it is not the highest-numbered packet received on the path.
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		tc.nextPN[1] -= 2
		_, err = tc.receivePacket(t, 1, probingAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, clientAddr, pathConn.RemoteAddr())

		// a non-probing packet from the probed address with the highest packet number migrates the path
		tc.nextPN[1] += 2
		_, err = tc.receivePacket(t, 1, probingAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, probingAddr, pathConn.RemoteAddr())
	})
}

// The connection ID provided in the preferred_address transport parameter is the connection ID of path 0
// with sequence number 1 (section 2.2 of draft-ietf-quic-multipath-21).
// When path 0 migrates to the preferred address, the client accepts packets from that address on path 0.
func TestMultipathPreferredAddressPath0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		preferredConnID := protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc, 0xd})
		preferredToken := protocol.StatelessResetToken{0xa}
		require.NoError(t, c.connIDManager.AddFromPreferredAddress(preferredConnID, preferredToken))
		// the same connection ID for path 0, with sequence number 1, is not a conflict
		require.NoError(t, handleTestFrame(t, c, &wire.PathNewConnectionIDFrame{
			PathID:              0,
			SequenceNumber:      1,
			ConnectionID:        preferredConnID,
			StatelessResetToken: preferredToken,
		}, protocol.Encryption1RTT))
		// a different one is
		err := handleTestFrame(t, c, &wire.PathNewConnectionIDFrame{
			PathID:              0,
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 1, 1, 1}),
			StatelessResetToken: preferredToken,
		}, protocol.Encryption1RTT)
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		// path 1 has its own sequence number space
		require.NoError(t, handleTestFrame(t, c, newTestPathNewConnectionIDFrame(1, 1), protocol.Encryption1RTT))

		preferredAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 9), Port: 443}
		tc.receiveDroppedPacket(t, 0, preferredAddr)
		c.mp.allowServerAddr(0, preferredAddr)
		processed, err := tc.receivePacket(t, 0, preferredAddr, packetInfo{}, 100, &wire.PingFrame{})
		require.NoError(t, err)
		require.True(t, processed)

		// path 0 migrates to the preferred address
		c.rttStats.UpdateRTT(50*time.Millisecond, 0)
		tc.sendConn.EXPECT().ChangeRemoteAddr(preferredAddr, packetInfo{})
		c.migrateMultipathPath(c.mp.paths[0], preferredAddr, packetInfo{}, monotime.Now())
		require.False(t, c.rttStats.HasMeasurement())
	})
}

// The server sends a token after validating a new address of the client. The token is valid for the
// most recently validated addresses, up to 4 addresses (section 3.1.3 of draft-ietf-quic-multipath-21).
func TestMultipathTokensForValidatedAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 5, 5)
		c := tc.conn
		handshakeAddr := c.conn.RemoteAddr()
		c.mp.validatedClientAddrs = []net.Addr{handshakeAddr}
		queuedFrames(c)

		addrs := []net.Addr{handshakeAddr}
		for i := range 4 {
			addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(i+1)), Port: 1234}
			tc.acceptServerPath(t, protocol.PathID(i+1), addr)
			addrs = append(addrs, addr)
			tokens := decodeTestTokens(t, multipathFramesOfType[*wire.NewTokenFrame](queuedFrames(c)))
			require.Len(t, tokens, 1)
			for j, a := range addrs {
				valid := j >= len(addrs)-handshake.MaxTokenAddrs
				require.Equal(t, valid, tokens[0].ValidateRemoteAddr(a), "path %d, address %s", i+1, a)
			}
		}

		// a new path from an address that was validated before doesn't lead to a new token
		tc.acceptServerPath(t, 5, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5555})
		require.Empty(t, multipathFramesOfType[*wire.NewTokenFrame](queuedFrames(c)))
	})
}

// After a path migrated, Path MTU Discovery starts again on that path (section 9.2 of RFC 9000).
// The DATAGRAM size limit is updated accordingly.
func TestMultipathMigrationResetsPathMTU(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConnWithOpts(t, protocol.PerspectiveServer, 3, 3, mpPathTestConnOpts{pmtud: true})
		c := tc.conn
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(1, 0)))
		clientAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}
		pathConn := newMigratingMockPathConn(tc.mockCtrl, clientAddr, connCapabilities{DF: true})
		tc.sendConn.EXPECT().newPathConn(clientAddr, packetInfo{}).Return(pathConn)
		_, err := tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.NoError(t, c.triggerSending(monotime.Now()))
		challenges, _ := sentProbeFrames(tc.probes, 1)
		_, err = tc.receivePacket(t, 1, clientAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
		require.NoError(t, err)
		path := c.mp.paths[1]
		require.Equal(t, mpPathActive, path.state)
		require.NotNil(t, path.mtuDiscoverer)
		initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)

		// pretend that Path MTU Discovery found a larger MTU on path 1
		path.mtuDiscoverer.min = 1400
		c.maybeUpdatePathMTU(path)
		require.Equal(t, protocol.ByteCount(1400), path.maxDatagramSize)
		path0Size := c.pathMaxPacketSize(c.mp.paths[0])

		newAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}
		c.migrateMultipathPath(path, newAddr, packetInfo{}, monotime.Now())
		require.Equal(t, newAddr, pathConn.RemoteAddr())
		require.Equal(t, initialPacketSize, path.mtuDiscoverer.CurrentSize())
		require.Equal(t, initialPacketSize, path.maxDatagramSize)
		require.Equal(t, path0Size, c.pathMaxPacketSize(c.mp.paths[0]))
		require.Equal(t, uint32(estimateMaxPayloadSize(initialPacketSize)), c.maxPayloadSizeEstimate.Load())
		// Path MTU Discovery starts again
		require.False(t, path.mtuDiscoverer.ShouldSendProbe(monotime.Now()))
		time.Sleep(time.Minute)
		require.True(t, path.mtuDiscoverer.ShouldSendProbe(monotime.Now()))
	})
}
