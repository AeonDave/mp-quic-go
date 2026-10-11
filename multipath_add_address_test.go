package quic

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// addressObserverController is a multipath controller that records the addresses advertised by the peer.
type addressObserverController struct {
	*PathSchedulerWrapper

	mx    sync.Mutex
	addrs []AdvertisedAddress
}

var _ MultipathAddressObserver = &addressObserverController{}

func newAddressObserverController() *addressObserverController {
	return &addressObserverController{PathSchedulerWrapper: NewMultipathScheduler(SchedulingPolicyRoundRobin)}
}

func (c *addressObserverController) OnAddressAdvertised(a AdvertisedAddress) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.addrs = append(c.addrs, a)
}

func (c *addressObserverController) observed() []AdvertisedAddress {
	c.mx.Lock()
	defer c.mx.Unlock()
	return slices.Clone(c.addrs)
}

// sentAddAddressFrames returns the ADD_ADDRESS frames sent, and fails the test if one of them wasn't sent
// in a 1-RTT packet.
func sentAddAddressFrames(t *testing.T, r *events.Recorder) []qlog.AddAddressFrame {
	t.Helper()
	var frames []qlog.AddAddressFrame
	for _, ev := range r.Events(qlog.PacketSent{}) {
		ps := ev.(qlog.PacketSent)
		for _, f := range ps.Frames {
			if f, ok := f.Frame.(*qlog.AddAddressFrame); ok {
				require.Equal(t, qlog.PacketType1RTT, ps.Header.PacketType)
				frames = append(frames, *f)
			}
		}
	}
	return frames
}

// The address advertisement extension is negotiated using the add_address transport parameter.
// It is only sent together with the initial_max_path_id transport parameter, and only used if both endpoints
// use IETF Multipath QUIC.
func TestAddAddressNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		clientEnabled, serverEnabled           bool
		clientMultipath, serverMultipath       bool
		clientSendsParam, serverSendsParam     bool
		expectNegotiated                       bool
		expectMultipath                        bool
		clientAdvertiseErr, serverAdvertiseErr error
	}{
		{
			name:          "both enabled",
			clientEnabled: true, serverEnabled: true, clientMultipath: true, serverMultipath: true,
			clientSendsParam: true, serverSendsParam: true, expectNegotiated: true, expectMultipath: true,
		},
		{
			name:          "only the client",
			clientEnabled: true, clientMultipath: true, serverMultipath: true,
			clientSendsParam: true, expectMultipath: true,
		},
		{
			name:          "only the server",
			serverEnabled: true, clientMultipath: true, serverMultipath: true,
			serverSendsParam: true, expectMultipath: true,
		},
		{
			name:          "server without multipath",
			clientEnabled: true, serverEnabled: true, clientMultipath: true,
			clientSendsParam: true,
		},
		{
			name:          "client without multipath",
			clientEnabled: true, serverEnabled: true, serverMultipath: true,
			serverSendsParam: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var clientEvents, serverEvents events.Recorder
				clientConf := multipathTestConfig(tc.clientMultipath, protocol.PerspectiveClient, &clientEvents)
				clientConf.EnableAddressAdvertisement = tc.clientEnabled
				serverConf := multipathTestConfig(tc.serverMultipath, protocol.PerspectiveServer, &serverEvents)
				serverConf.EnableAddressAdvertisement = tc.serverEnabled
				p := dialMultipathTestConnPair(t, &Transport{}, clientConf, serverConf, &clientEvents, &serverEvents)

				require.Equal(t, tc.clientSendsParam, localTransportParameters(t, &clientEvents).EnableAddAddress)
				require.Equal(t, tc.serverSendsParam, localTransportParameters(t, &serverEvents).EnableAddAddress)
				for _, conn := range []*Conn{p.client, p.server} {
					require.Equal(t, tc.expectMultipath, conn.ConnectionState().SupportsMultipath)
					require.Equal(t, tc.expectNegotiated, conn.ConnectionState().SupportsAddressAdvertisement)
					err := conn.AdvertiseAddress(netip.MustParseAddrPort("127.0.0.1:7000"))
					if tc.expectNegotiated {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, ErrAddressAdvertisementNotNegotiated)
					}
				}
				p.transfer(t, []byte("foobar"))
				if !tc.expectNegotiated {
					require.Empty(t, sentAddAddressFrames(t, &clientEvents))
					require.Empty(t, sentAddAddressFrames(t, &serverEvents))
				}
				p.close(t)
			})
		})
	}
}

// The client advertises an address. The server only records it: only clients open paths.
func TestAddAddressServerRecordsClientAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		serverCtrl := newAddressObserverController()
		p := newMultipathPathTestPair(t, multipathPathTestOpts{
			clientConf: func(c *Config) { c.EnableAddressAdvertisement = true },
			serverConf: func(c *Config) {
				c.EnableAddressAdvertisement = true
				c.MultipathAutoPaths = true // has no effect for servers
				c.MultipathControllerFactory = func() MultipathController { return serverCtrl }
			},
		})
		require.True(t, p.client.ConnectionState().SupportsAddressAdvertisement)
		require.True(t, p.server.ConnectionState().SupportsAddressAdvertisement)

		addr := netip.MustParseAddrPort("127.0.0.1:7000")
		require.NoError(t, p.client.AdvertiseAddress(addr))
		// advertising the same address again doesn't send another frame
		require.NoError(t, p.client.AdvertiseAddress(netip.MustParseAddrPort("[::ffff:127.0.0.1]:7000")))
		time.Sleep(time.Second)
		synctest.Wait()

		expected := []AdvertisedAddress{{ID: 0, Addr: addr}}
		require.Equal(t, expected, p.server.PeerAdvertisedAddresses())
		require.Equal(t, expected, serverCtrl.observed())
		require.Empty(t, p.client.PeerAdvertisedAddresses())
		frames := sentAddAddressFrames(t, p.clientEvents)
		require.Len(t, frames, 1)
		require.Equal(t, uint64(0), frames[0].AddressID)
		// the server didn't open a path
		require.Len(t, p.server.Paths(), 1)
		require.Len(t, p.client.Paths(), 1)
		p.transfer(t, []byte("foobar"))
	})
}

// The server advertises an address. A client with Config.MultipathAutoPaths opens a path to it.
func TestAddAddressClientOpensPathToServerAddress(t *testing.T) {
	for _, autoPaths := range []bool{false, true} {
		name := "without MultipathAutoPaths"
		if autoPaths {
			name = "with MultipathAutoPaths"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientCtrl := newAddressObserverController()
				p := newMultipathPathTestPair(t, multipathPathTestOpts{
					clientConf: func(c *Config) {
						c.EnableAddressAdvertisement = true
						c.MultipathAutoPaths = autoPaths
						c.MultipathControllerFactory = func() MultipathController { return clientCtrl }
					},
					serverConf: func(c *Config) { c.EnableAddressAdvertisement = true },
				})
				// Unusable addresses are ignored, they are not recorded.
				for _, addr := range []string{"224.0.0.1:443", "0.0.0.0:443", "127.0.0.1:0"} {
					require.Error(t, p.server.AdvertiseAddress(netip.MustParseAddrPort(addr)))
				}
				serverAddr := netip.MustParseAddrPort("127.0.0.1:9004")
				require.NoError(t, p.server.AdvertiseAddress(serverAddr))
				time.Sleep(time.Second)
				synctest.Wait()

				expected := []AdvertisedAddress{{ID: 0, Addr: serverAddr}}
				require.Equal(t, expected, p.client.PeerAdvertisedAddresses())
				require.Equal(t, expected, clientCtrl.observed())
				require.Len(t, sentAddAddressFrames(t, p.serverEvents), 1)

				paths := p.client.Paths()
				if !autoPaths {
					require.Len(t, paths, 1)
					return
				}
				require.Len(t, paths, 2)
				require.Equal(t, PathID(1), paths[1].ID)
				require.Equal(t, net.UDPAddrFromAddrPort(serverAddr).String(), paths[1].RemoteAddr.String())
				// The client validates the path. Nothing listens on this address in this test.
				var challenges int
				for _, p := range sentPathPackets(p.clientEvents, 1) {
					if hasFrame[*qlog.PathChallengeFrame](p) {
						challenges++
					}
				}
				require.NotZero(t, challenges)
				require.Positive(t, p.router.Delivered(multipathTestClientAddr, net.UDPAddrFromAddrPort(serverAddr)))
			})
		})
	}
}

func newAddAddressTestConn(t *testing.T, pers protocol.Perspective) *mpPathTestConn {
	t.Helper()
	tc := newMPPathTestConn(t, pers, 2, 2)
	c := tc.conn
	c.advertisedAddAddress = true
	c.maybeNegotiateAddressAdvertisement(&wire.TransportParameters{EnableAddAddress: true})
	require.NotNil(t, c.addrAdv)
	c.peerHandshakeAddr = c.conn.RemoteAddr()
	return tc
}

func newTestAddAddressFrame(id, seq uint64, addr string) *wire.AddAddressFrame {
	ap := netip.MustParseAddrPort(addr)
	f := &wire.AddAddressFrame{AddressID: id, SequenceNumber: seq, Port: ap.Port()}
	if ap.Addr().Is4() {
		ip := ap.Addr().As4()
		f.IPVersion = 4
		f.Address = ip[:]
	} else {
		ip := ap.Addr().As16()
		f.IPVersion = 6
		f.Address = ip[:]
	}
	return f
}

// Without the extension, the ADD_ADDRESS frame type is unknown (section 12.4 of RFC 9000).
// With the extension, the frame is only allowed in 1-RTT packets.
func TestAddAddressFrameHandling(t *testing.T) {
	f := newTestAddAddressFrame(0, 0, "192.0.2.1:443")

	t.Run("not negotiated", func(t *testing.T) {
		for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
			tc := newIETFMultipathTestConnection(t, pers, 2, 2, true)
			c := tc.conn
			// we advertised the extension, but the peer didn't
			c.advertisedAddAddress = true
			c.maybeNegotiateAddressAdvertisement(&wire.TransportParameters{})
			require.Nil(t, c.addrAdv)
			err := handleTestFrame(t, c, f, protocol.Encryption1RTT)
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.FrameEncodingError, FrameType: uint64(wire.FrameTypeAddAddress)})

			close(c.handshakeCompleteChan)
			require.ErrorIs(t, c.AdvertiseAddress(netip.MustParseAddrPort("192.0.2.1:443")), ErrAddressAdvertisementNotNegotiated)
			require.Nil(t, c.PeerAdvertisedAddresses())
		}
	})

	t.Run("without multipath", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tc := newClientTestConnection(t, mockCtrl, &Config{EnableAddressAdvertisement: true}, false)
		c := tc.conn
		require.False(t, c.advertisedAddAddress)
		c.maybeNegotiateAddressAdvertisement(&wire.TransportParameters{EnableAddAddress: true})
		require.Nil(t, c.addrAdv)
	})

	t.Run("negotiated", func(t *testing.T) {
		tc := newAddAddressTestConn(t, protocol.PerspectiveServer)
		c := tc.conn
		for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT} {
			err := handleTestFrame(t, c, f, encLevel)
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, FrameType: uint64(wire.FrameTypeAddAddress)}, "encryption level %s", encLevel)
		}
		require.Empty(t, c.addrAdv.peerAddresses())
		require.NoError(t, handleTestFrame(t, c, f, protocol.Encryption1RTT))
		require.Equal(t, []AdvertisedAddress{{ID: 0, Addr: netip.MustParseAddrPort("192.0.2.1:443")}}, c.addrAdv.peerAddresses())
	})
}

// AdvertiseAddress can only be used once the handshake completed, and rejects addresses the peer would ignore.
func TestAddAddressAdvertiseAddress(t *testing.T) {
	tc := newAddAddressTestConn(t, protocol.PerspectiveServer)
	c := tc.conn
	for c.framer.HasData() {
		c.framer.Append(nil, nil, protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1)
	}
	require.EqualError(t, c.AdvertiseAddress(netip.MustParseAddrPort("192.0.2.1:443")), "handshake not complete")
	require.Nil(t, c.PeerAdvertisedAddresses())
	close(c.handshakeCompleteChan)
	require.True(t, c.ConnectionState().SupportsAddressAdvertisement)
	require.Empty(t, c.PeerAdvertisedAddresses())

	for _, addr := range []netip.AddrPort{
		{},
		netip.MustParseAddrPort("192.0.2.1:0"),
		netip.MustParseAddrPort("0.0.0.0:443"),
		netip.MustParseAddrPort("[ff02::1]:443"),
		netip.MustParseAddrPort("255.255.255.255:443"),
	} {
		require.ErrorContains(t, c.AdvertiseAddress(addr), "invalid address")
	}
	require.False(t, c.framer.HasData())

	require.NoError(t, c.AdvertiseAddress(netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")))
	require.NoError(t, c.AdvertiseAddress(netip.MustParseAddrPort("[2001:db8::1]:443")))
	require.NoError(t, c.AdvertiseAddress(netip.MustParseAddrPort("192.0.2.1:443")))
	frames := queuedFrames(c)
	require.Len(t, frames, 2)
	var addFrames []*wire.AddAddressFrame
	for _, f := range frames {
		addFrames = append(addFrames, f.Frame.(*wire.AddAddressFrame))
	}
	slices.SortFunc(addFrames, func(a, b *wire.AddAddressFrame) int { return int(a.AddressID) - int(b.AddressID) })
	require.Equal(t, newTestAddAddressFrame(0, 0, "192.0.2.1:443"), addFrames[0])
	require.Equal(t, newTestAddAddressFrame(1, 0, "[2001:db8::1]:443"), addFrames[1])
}

// The peer's addresses are validated. Addresses that can't be used for a path are ignored.
func TestAddAddressPeerAddressValidation(t *testing.T) {
	tc := newAddAddressTestConn(t, protocol.PerspectiveServer)
	c := tc.conn
	ctrl := newAddressObserverController()
	c.multipathController = ctrl
	// the client's address is not a loopback address
	_, isUDPAddr := c.conn.RemoteAddr().(*net.UDPAddr)
	require.True(t, isUDPAddr)
	require.False(t, netip.MustParseAddrPort(c.conn.RemoteAddr().String()).Addr().IsLoopback())

	for i, addr := range []string{
		"0.0.0.0:443",
		"[::]:443",
		"224.0.0.1:443",
		"[ff02::1]:443",
		"255.255.255.255:443",
		"192.0.2.1:0",
		"127.0.0.1:443",
		"[::1]:443",
		"169.254.1.1:443",
		"[fe80::1]:443",
	} {
		require.NoError(t, handleTestFrame(t, c, newTestAddAddressFrame(uint64(i), 0, addr), protocol.Encryption1RTT))
	}
	require.Empty(t, c.addrAdv.peerAddresses())
	require.Empty(t, ctrl.observed())

	// IPv4-mapped IPv6 addresses are recorded as IPv4 addresses
	require.NoError(t, handleTestFrame(t, c, newTestAddAddressFrame(1, 0, "[::ffff:192.0.2.1]:443"), protocol.Encryption1RTT))
	require.NoError(t, handleTestFrame(t, c, newTestAddAddressFrame(2, 0, "192.0.2.1:443"), protocol.Encryption1RTT))
	expected := []AdvertisedAddress{{ID: 1, Addr: netip.MustParseAddrPort("192.0.2.1:443")}}
	require.Equal(t, expected, c.addrAdv.peerAddresses())
	require.Equal(t, expected, ctrl.observed())

	// the number of addresses is limited
	for i := range 2 * protocol.MaxAdvertisedAddresses {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		f := newTestAddAddressFrame(uint64(10+i), 0, netip.AddrPortFrom(ip, 443).String())
		require.NoError(t, handleTestFrame(t, c, f, protocol.Encryption1RTT))
	}
	require.Len(t, c.addrAdv.peerAddresses(), protocol.MaxAdvertisedAddresses)
	require.Len(t, ctrl.observed(), protocol.MaxAdvertisedAddresses)
	// the server doesn't open paths
	require.Empty(t, c.mp.pendingOpens)
}

// A client with Config.MultipathAutoPaths opens paths to the addresses advertised by the server,
// up to Config.MaxPaths paths in total.
func TestAddAddressClientOpensPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newAddAddressTestConn(t, protocol.PerspectiveClient)
		c := tc.conn
		c.config.MultipathAutoPaths = true
		require.Equal(t, 3, c.config.MaxPaths)
		for id := protocol.PathID(1); id <= 2; id++ {
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(id, 0)))
		}
		var remotes []net.Addr
		conn := NewMockSendConn(tc.mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 100), Port: 1234}).AnyTimes()
		conn.EXPECT().RemoteAddr().Return(tc.remoteAddr).AnyTimes()
		conn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
		conn.EXPECT().newPathConn(gomock.Any(), packetInfo{}).DoAndReturn(func(remote net.Addr, _ packetInfo) sendConn {
			remotes = append(remotes, remote)
			return newMockPathConn(tc.mockCtrl, remote, connCapabilities{})
		}).AnyTimes()
		c.conn = conn
		tc.sendConn = conn

		serverAddr1 := netip.MustParseAddrPort("1.2.3.5:443")
		serverAddr2 := netip.MustParseAddrPort("1.2.3.6:443")
		for _, f := range []*wire.AddAddressFrame{
			// the server's handshake address: path 0 uses it already
			newTestAddAddressFrame(0, 0, tc.remoteAddr.String()),
			// another address family than the server address of path 0
			newTestAddAddressFrame(1, 0, "[2001:db8::1]:443"),
			newTestAddAddressFrame(2, 0, serverAddr1.String()),
			// a retransmission
			newTestAddAddressFrame(2, 0, serverAddr1.String()),
			newTestAddAddressFrame(3, 0, serverAddr2.String()),
			// Config.MaxPaths is reached
			newTestAddAddressFrame(4, 0, "1.2.3.7:443"),
		} {
			require.NoError(t, handleTestFrame(t, c, f, protocol.Encryption1RTT))
		}
		require.Len(t, c.addrAdv.peerAddresses(), 5)
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Equal(t, []net.Addr{net.UDPAddrFromAddrPort(serverAddr1), net.UDPAddrFromAddrPort(serverAddr2)}, remotes)
		paths := c.Paths()
		require.Len(t, paths, 3)
		for i, addr := range []netip.AddrPort{serverAddr1, serverAddr2} {
			require.Equal(t, PathID(i+1), paths[i+1].ID)
			require.Equal(t, PathStateValidating, paths[i+1].State)
			require.Equal(t, net.UDPAddrFromAddrPort(addr), paths[i+1].RemoteAddr)
		}

		// the paths are validated by the server addresses
		numProbes := len(tc.probes)
		require.NoError(t, c.triggerSending(monotime.Now()))
		for i, addr := range []netip.AddrPort{serverAddr1, serverAddr2} {
			id := protocol.PathID(i + 1)
			challenges, _ := sentProbeFrames(tc.probes[numProbes:], id)
			require.Len(t, challenges, 1)
			_, err := tc.receivePacket(t, id, net.UDPAddrFromAddrPort(addr), packetInfo{}, 1200, &wire.PathResponseFrame{Data: challenges[0].Data})
			require.NoError(t, err)
			require.Equal(t, mpPathActive, c.mp.paths[id].state)
		}

		// a new address for an address ID doesn't open more paths
		require.NoError(t, handleTestFrame(t, c, newTestAddAddressFrame(2, 1, "1.2.3.8:443"), protocol.Encryption1RTT))
		require.NoError(t, c.handleMultipathEvents(monotime.Now()))
		require.Len(t, remotes, 2)
	})
}

// A server with Config.MultipathAutoAdvertise advertises its local addresses once the handshake completed,
// except for the address the client sent its packets to. This requires a socket bound to an unspecified address.
func TestAddAddressAutoAdvertise(t *testing.T) {
	newTestConn := func(t *testing.T, pers protocol.Perspective, socketAddr net.Addr, autoAdvertise bool) *Conn {
		tc := newAddAddressTestConn(t, pers)
		c := tc.conn
		c.config.MultipathAutoAdvertise = autoAdvertise
		c.config.MultipathAutoAddrs = []net.IP{
			net.IPv4(192, 0, 2, 1),
			net.IPv4(192, 0, 2, 2),
			net.IPv4zero,
			net.ParseIP("2001:db8::1"),
			net.IPv4(192, 0, 2, 2),
		}
		c.primaryLocalIP = net.IPv4(192, 0, 2, 1)
		conn := NewMockSendConn(tc.mockCtrl)
		conn.EXPECT().LocalAddr().Return(socketAddr).AnyTimes()
		conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1234}).AnyTimes()
		conn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
		c.conn = conn
		for c.framer.HasData() {
			c.framer.Append(nil, nil, protocol.MaxPacketBufferSize, monotime.Now(), protocol.Version1)
		}
		return c
	}

	t.Run("socket bound to an unspecified address", func(t *testing.T) {
		c := newTestConn(t, protocol.PerspectiveServer, &net.UDPAddr{IP: net.IPv4zero, Port: 443}, true)
		c.maybeAdvertiseLocalAddrs()
		var frames []*wire.AddAddressFrame
		for _, f := range queuedFrames(c) {
			frames = append(frames, f.Frame.(*wire.AddAddressFrame))
		}
		slices.SortFunc(frames, func(a, b *wire.AddAddressFrame) int { return int(a.AddressID) - int(b.AddressID) })
		require.Equal(t, []*wire.AddAddressFrame{
			newTestAddAddressFrame(0, 0, "192.0.2.2:443"),
			newTestAddAddressFrame(1, 0, "[2001:db8::1]:443"),
		}, frames)
	})

	t.Run("socket bound to an address", func(t *testing.T) {
		c := newTestConn(t, protocol.PerspectiveServer, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, true)
		c.maybeAdvertiseLocalAddrs()
		require.False(t, c.framer.HasData())
	})

	t.Run("MultipathAutoAdvertise not set", func(t *testing.T) {
		c := newTestConn(t, protocol.PerspectiveServer, &net.UDPAddr{IP: net.IPv4zero, Port: 443}, false)
		c.maybeAdvertiseLocalAddrs()
		require.False(t, c.framer.HasData())
	})

	t.Run("client", func(t *testing.T) {
		c := newTestConn(t, protocol.PerspectiveClient, &net.UDPAddr{IP: net.IPv4zero, Port: 443}, true)
		c.maybeAdvertiseLocalAddrs()
		require.False(t, c.framer.HasData())
	})
}
