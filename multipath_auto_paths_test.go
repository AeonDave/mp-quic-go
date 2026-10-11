package quic

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newAutoPathsTestConn returns a client connection using IETF Multipath QUIC, with Config.MultipathAutoPaths set.
// Its socket is bound to localAddr. The paths opened send from the local address in the packet info.
func newAutoPathsTestConn(t *testing.T, localAddr net.Addr, disableActiveMigration bool) (*mpPathTestConn, *[]packetInfo) {
	t.Helper()
	tc := newMPPathTestConn(t, protocol.PerspectiveClient, 2, 2)
	c := tc.conn
	c.config.MultipathAutoPaths = true
	c.config.MultipathAutoAddrs = []net.IP{
		net.IPv4(127, 0, 0, 1),
		net.IPv4(127, 0, 0, 2),
		net.IPv6loopback,
		net.IPv4(127, 0, 0, 3),
		net.IPv4(127, 0, 0, 4),
	}
	c.primaryLocalIP = net.IPv4(127, 0, 0, 1)
	c.peerHandshakeAddr = tc.remoteAddr
	c.peerParams.DisableActiveMigration = disableActiveMigration
	var infos []packetInfo
	conn := NewMockSendConn(tc.mockCtrl)
	conn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	conn.EXPECT().RemoteAddr().Return(tc.remoteAddr).AnyTimes()
	conn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
	conn.EXPECT().newPathConn(tc.remoteAddr, gomock.Any()).DoAndReturn(func(remote net.Addr, info packetInfo) sendConn {
		infos = append(infos, info)
		return newMockPathConnWithLocalAddr(tc.mockCtrl, remote, &net.UDPAddr{IP: info.addr.AsSlice(), Port: 1234})
	}).AnyTimes()
	c.conn = conn
	tc.sendConn = conn
	for id := protocol.PathID(1); id <= 2; id++ {
		require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(id, 0)))
	}
	return tc, &infos
}

// With IETF Multipath QUIC, the client opens a path from every local address other than the one of path 0,
// as long as Config.MaxPaths allows it. The paths are opened like paths opened using AddPathFromAddr.
func TestMultipathAutoPathsIETF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc, infos := newAutoPathsTestConn(t, &net.UDPAddr{IP: net.IPv4zero, Port: 1234}, false)
		c := tc.conn
		c.maybeStartAutoPaths()
		c.maybeStartAutoPaths()
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))

		// Config.MaxPaths is 3: 2 paths are opened
		require.Len(t, *infos, 2)
		require.Equal(t, netip.AddrFrom4([4]byte{127, 0, 0, 2}), (*infos)[0].addr)
		require.Equal(t, netip.AddrFrom4([4]byte{127, 0, 0, 3}), (*infos)[1].addr)
		paths := c.Paths()
		require.Len(t, paths, 3)
		for i, path := range paths[1:] {
			require.Equal(t, protocol.PathID(i+1), path.ID)
			require.Equal(t, PathStateValidating, path.State)
			require.Equal(t, fmt.Sprintf("127.0.0.%d:1234", i+2), path.LocalAddr.String())
			require.Equal(t, tc.remoteAddr, path.RemoteAddr)
		}
		// the paths are validated
		numProbes := len(tc.probes)
		require.NoError(t, c.triggerSending(monotime.Now()))
		for _, id := range []protocol.PathID{1, 2} {
			challenges, _ := sentProbeFrames(tc.probes[numProbes:], id)
			require.Len(t, challenges, 1)
			_, err := tc.receivePacket(t, id, tc.remoteAddr, packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
			require.NoError(t, err)
			require.Equal(t, mpPathActive, c.mp.paths[id].state)
		}
	})
}

// No paths are opened automatically if the socket is bound to a specific address, since it doesn't receive packets
// sent to other addresses, and if the server disabled active migration (section 2.2 of draft-ietf-quic-multipath-21).
func TestMultipathAutoPathsIETFNotOpened(t *testing.T) {
	t.Run("socket bound to an address", func(t *testing.T) {
		tc, infos := newAutoPathsTestConn(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, false)
		tc.conn.maybeStartAutoPaths()
		require.NoError(t, tc.conn.handleMultipathEvents(monotime.Now()))
		require.Empty(t, *infos)
		require.Len(t, tc.conn.Paths(), 1)
	})

	t.Run("active migration disabled", func(t *testing.T) {
		tc, infos := newAutoPathsTestConn(t, &net.UDPAddr{IP: net.IPv4zero, Port: 1234}, true)
		tc.conn.maybeStartAutoPaths()
		require.NoError(t, tc.conn.handleMultipathEvents(monotime.Now()))
		require.Empty(t, *infos)
		require.Len(t, tc.conn.Paths(), 1)
	})

	t.Run("server", func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 2, 2)
		tc.conn.config.MultipathAutoPaths = true
		tc.conn.config.MultipathAutoAdvertise = true
		tc.conn.config.MultipathAutoAddrs = []net.IP{net.IPv4(127, 0, 0, 2)}
		for tc.conn.framer.HasData() {
			tc.conn.framer.Append(nil, nil, protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1)
		}
		tc.conn.maybeStartAutoPaths()
		require.NoError(t, tc.conn.handleMultipathEvents(monotime.Now()))
		require.Empty(t, tc.conn.mp.pendingOpens)
		// MultipathAutoAdvertise has no effect without the address advertisement extension
		tc.conn.maybeAdvertiseLocalAddrs()
		require.False(t, tc.conn.framer.HasData())
	})
}
