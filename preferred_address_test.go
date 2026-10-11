package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/ackhandler"
	"github.com/AeonDave/mp-quic-go/internal/monotime"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/qerr"
	"github.com/AeonDave/mp-quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type zeroLengthConnIDGenerator struct{}

func (zeroLengthConnIDGenerator) GenerateConnectionID() (ConnectionID, error) {
	return ConnectionID{}, nil
}
func (zeroLengthConnIDGenerator) ConnectionIDLen() int { return 0 }

func TestPreferredAddressConfig(t *testing.T) {
	ipv4 := netip.MustParseAddrPort("192.0.2.1:443")
	ipv6 := netip.MustParseAddrPort("[2001:db8::1]:443")

	for _, tt := range []struct {
		name        string
		pa          func(listener *Transport) *PreferredAddress
		transport   func() *Transport // the listener's Transport, defaults to a Transport on a new UDP socket
		expectedErr string
	}{
		{
			name:        "no address",
			pa:          func(*Transport) *PreferredAddress { return &PreferredAddress{} },
			expectedErr: "without an IPv4 and an IPv6 address",
		},
		{
			name:        "IPv6 address as IPv4 address",
			pa:          func(*Transport) *PreferredAddress { return &PreferredAddress{IPv4: ipv6} },
			expectedErr: "invalid IPv4 address",
		},
		{
			name:        "IPv4 address as IPv6 address",
			pa:          func(*Transport) *PreferredAddress { return &PreferredAddress{IPv6: ipv4} },
			expectedErr: "invalid IPv6 address",
		},
		{
			name: "IPv4-mapped IPv6 address as IPv6 address",
			pa: func(*Transport) *PreferredAddress {
				return &PreferredAddress{IPv6: netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")}
			},
			expectedErr: "invalid IPv6 address",
		},
		{
			name: "port 0",
			pa: func(*Transport) *PreferredAddress {
				return &PreferredAddress{IPv4: netip.MustParseAddrPort("192.0.2.1:0")}
			},
			expectedErr: "invalid address",
		},
		{
			name: "unspecified address",
			pa: func(*Transport) *PreferredAddress {
				return &PreferredAddress{IPv6: netip.MustParseAddrPort("[::]:443")}
			},
			expectedErr: "invalid address",
		},
		{
			name: "Transport without address",
			pa: func(*Transport) *PreferredAddress {
				return &PreferredAddress{IPv4: ipv4, IPv6Transport: &Transport{Conn: newUDPConnLocalhost(t)}}
			},
			expectedErr: "IPv6 Transport without IPv6 address",
		},
		{
			name:        "listener's Transport",
			pa:          func(tr *Transport) *PreferredAddress { return &PreferredAddress{IPv4: ipv4, IPv4Transport: tr} },
			expectedErr: "Transport is the listener's Transport",
		},
		{
			name: "different connection ID length",
			pa: func(*Transport) *PreferredAddress {
				return &PreferredAddress{IPv4: ipv4, IPv4Transport: &Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 8}}
			},
			expectedErr: "different connection ID length",
		},
		{
			name: "different stateless reset key",
			pa: func(*Transport) *PreferredAddress {
				return &PreferredAddress{IPv4: ipv4, IPv4Transport: &Transport{Conn: newUDPConnLocalhost(t), StatelessResetKey: &StatelessResetKey{2}}}
			},
			expectedErr: "different stateless reset key",
		},
		{
			name: "zero-length connection IDs",
			pa:   func(*Transport) *PreferredAddress { return &PreferredAddress{IPv4: ipv4} },
			transport: func() *Transport {
				return &Transport{Conn: newUDPConnLocalhost(t), ConnectionIDGenerator: zeroLengthConnIDGenerator{}}
			},
			expectedErr: "requires connection IDs of non-zero length",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Transport{Conn: newUDPConnLocalhost(t), StatelessResetKey: &StatelessResetKey{1}}
			if tt.transport != nil {
				tr = tt.transport()
			}
			defer tr.Close()
			tr.PreferredAddress = tt.pa(tr)
			_, err := tr.Listen(generateTLSConfig(), nil)
			require.ErrorContains(t, err, tt.expectedErr)
		})
	}

	t.Run("received by the listener's Transport", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
		require.NoError(t, err)
		port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
		pa := &PreferredAddress{IPv4: netip.AddrPortFrom(ipv4.Addr(), port), IPv6: netip.AddrPortFrom(ipv6.Addr(), port)}
		tr := &Transport{Conn: conn, PreferredAddress: pa}
		defer tr.Close()
		ln, err := tr.Listen(generateTLSConfig(), nil)
		require.NoError(t, err)
		defer ln.Close()
		require.Equal(t, &serverPreferredAddr{ipv4: pa.IPv4, ipv6: pa.IPv6}, ln.baseServer.preferredAddr)
		require.Equal(t, tr.conn, ln.baseServer.conn)
	})

	// The listener's socket needs to receive the packets sent to the preferred address.
	t.Run("not received by the listener's Transport", func(t *testing.T) {
		newWildcardConn := func(t *testing.T) (*net.UDPConn, uint16) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
			require.NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			return conn, uint16(conn.LocalAddr().(*net.UDPAddr).Port)
		}
		for _, tt := range []struct {
			name string
			conf func(t *testing.T) (net.PacketConn, *PreferredAddress)
		}{
			{
				name: "socket bound to a specific address",
				conf: func(t *testing.T) (net.PacketConn, *PreferredAddress) {
					return newUDPConnLocalhost(t), &PreferredAddress{IPv4: ipv4}
				},
			},
			{
				name: "another port",
				conf: func(t *testing.T) (net.PacketConn, *PreferredAddress) {
					conn, port := newWildcardConn(t)
					return conn, &PreferredAddress{IPv4: netip.AddrPortFrom(ipv4.Addr(), port+1)}
				},
			},
			{
				name: "IPv6 address on an IPv4 socket",
				conf: func(t *testing.T) (net.PacketConn, *PreferredAddress) {
					conn, port := newWildcardConn(t)
					return conn, &PreferredAddress{IPv6: netip.AddrPortFrom(ipv6.Addr(), port)}
				},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				conn, pa := tt.conf(t)
				tr := &Transport{Conn: conn, PreferredAddress: pa}
				defer tr.Close()
				_, err := tr.Listen(generateTLSConfig(), nil)
				require.ErrorContains(t, err, "doesn't receive the packets sent to")
			})
		}
	})

	t.Run("received by another Transport", func(t *testing.T) {
		// the same Transport receives the packets sent to both addresses
		prefTr := &Transport{Conn: newUDPConnLocalhost(t), StatelessResetKey: &StatelessResetKey{1}}
		defer prefTr.Close()
		tr := &Transport{
			Conn:              newUDPConnLocalhost(t),
			StatelessResetKey: &StatelessResetKey{1},
			PreferredAddress: &PreferredAddress{
				// IPv4-mapped IPv6 addresses are IPv4 addresses
				IPv4:          netip.AddrPortFrom(netip.AddrFrom16(ipv4.Addr().As16()), ipv4.Port()),
				IPv4Transport: prefTr,
				IPv6:          ipv6,
				IPv6Transport: prefTr,
			},
		}
		defer tr.Close()
		ln, err := tr.Listen(generateTLSConfig(), nil)
		require.NoError(t, err)
		defer ln.Close()
		require.Equal(t, &serverPreferredAddr{
			ipv4:       ipv4,
			ipv6:       ipv6,
			transports: []preferredAddrTransport{{tr: prefTr, ipv4: ipv4.Addr(), ipv6: ipv6.Addr()}},
		}, ln.baseServer.preferredAddr)
		conn, ok := ln.baseServer.conn.(*preferredAddrConn)
		require.True(t, ok)
		require.Equal(t, tr.conn, conn.rawConn)
		require.Equal(t, map[netip.Addr]rawConn{ipv4.Addr(): prefTr.conn, ipv6.Addr(): prefTr.conn}, conn.conns)
	})
}

func TestPreferredAddressConn(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	base := NewMockRawConn(mockCtrl)
	preferred := NewMockRawConn(mockCtrl)
	preferredIP := netip.MustParseAddr("192.0.2.1")
	c := &preferredAddrConn{rawConn: base, conns: map[netip.Addr]rawConn{preferredIP: preferred}}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}

	// packets sent from the preferred address are sent on the preferred address' connection
	info := packetInfo{addr: netip.AddrFrom16(preferredIP.As16()), ifIndex: 2}
	preferred.EXPECT().WritePacket([]byte("foo"), remoteAddr, info.OOB(), uint16(10), protocol.ECT1).Return(3, nil)
	n, err := c.WritePacketWithInfo([]byte("foo"), remoteAddr, info, 10, protocol.ECT1)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	// all other packets are sent on the listener's connection
	info = packetInfo{addr: netip.MustParseAddr("192.0.2.2")}
	base.EXPECT().WritePacket([]byte("bar"), remoteAddr, info.OOB(), uint16(0), protocol.ECNNon).Return(3, nil)
	_, err = c.WritePacketWithInfo([]byte("bar"), remoteAddr, info, 0, protocol.ECNNon)
	require.NoError(t, err)
	base.EXPECT().WritePacket([]byte("baz"), remoteAddr, []byte(nil), uint16(0), protocol.ECNNon).Return(3, nil)
	_, err = c.WritePacketWithInfo([]byte("baz"), remoteAddr, packetInfo{}, 0, protocol.ECNNon)
	require.NoError(t, err)

	// the local address is the one of the connection that the packet is sent on
	base.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4zero, Port: 443}).AnyTimes()
	preferred.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 8443}).AnyTimes()
	require.Equal(t, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1).To4(), Port: 8443}, c.localAddrFor(packetInfo{addr: preferredIP}))
	require.Equal(t, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2).To4(), Port: 443}, c.localAddrFor(packetInfo{addr: netip.MustParseAddr("192.0.2.2")}))
	sc := newSendConn(c, remoteAddr, packetInfo{addr: netip.MustParseAddr("192.0.2.2")}, nil)
	require.Equal(t, "192.0.2.2:443", sc.LocalAddr().String())
	sc.ChangeRemoteAddr(remoteAddr, packetInfo{addr: preferredIP})
	require.Equal(t, "192.0.2.1:8443", sc.LocalAddr().String())

	// only the capabilities that all connections have are used
	base.EXPECT().capabilities().Return(connCapabilities{DF: true, GSO: true, ECN: true}).Times(2)
	preferred.EXPECT().capabilities().Return(connCapabilities{DF: true, ECN: true})
	require.Equal(t, connCapabilities{DF: true, ECN: true}, c.capabilities())
	preferred.EXPECT().capabilities().Return(connCapabilities{GSO: true})
	require.Equal(t, connCapabilities{GSO: true}, c.capabilities())
}

func TestPreferredAddressPacketHandler(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	v4Client := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	v4MappedClient := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4).To16(), Port: 1234}
	v6Client := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1234}

	for _, tt := range []struct {
		name       string
		ipv4, ipv6 netip.Addr
		remoteAddr net.Addr
		expected   netip.Addr
	}{
		{name: "IPv4 only", ipv4: ipv4, remoteAddr: v4Client, expected: ipv4},
		{name: "IPv6 only", ipv6: ipv6, remoteAddr: v6Client, expected: ipv6},
		{name: "both, IPv4 client", ipv4: ipv4, ipv6: ipv6, remoteAddr: v4Client, expected: ipv4},
		{name: "both, IPv4-mapped client", ipv4: ipv4, ipv6: ipv6, remoteAddr: v4MappedClient, expected: ipv4},
		{name: "both, IPv6 client", ipv4: ipv4, ipv6: ipv6, remoteAddr: v6Client, expected: ipv6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := newServerTestConnection(t, nil, nil, false)
			h := &preferredAddrPacketHandler{Conn: tc.conn, ipv4: tt.ipv4, ipv6: tt.ipv6}
			h.handlePacket(receivedPacket{remoteAddr: tt.remoteAddr, info: packetInfo{ifIndex: 3}, data: []byte{0x40}})
			require.Equal(t, 1, tc.conn.receivedPackets.Len())
			p := tc.conn.receivedPackets.PopFront()
			require.Equal(t, packetInfo{addr: tt.expected, ifIndex: 3}, p.info)
		})
	}
}

func TestChoosePreferredAddr(t *testing.T) {
	pa := &wire.PreferredAddress{
		IPv4: netip.MustParseAddrPort("192.0.2.1:443"),
		IPv6: netip.MustParseAddrPort("[2001:db8::1]:443"),
	}
	v4Only := &wire.PreferredAddress{IPv4: pa.IPv4}
	v6Only := &wire.PreferredAddress{IPv6: pa.IPv6}
	v4Server := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	v4MappedServer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1).To16(), Port: 443}
	v6Server := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}
	v4Local := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	v4Unspecified := &net.UDPAddr{IP: net.IPv4zero, Port: 1234}
	v6Unspecified := &net.UDPAddr{IP: net.IPv6unspecified, Port: 1234}
	v6Local := &net.UDPAddr{IP: net.ParseIP("2001:db8::3"), Port: 1234}

	for _, tt := range []struct {
		name          string
		pa            *wire.PreferredAddress
		local, remote net.Addr
		expected      netip.AddrPort
	}{
		{name: "IPv4", pa: pa, local: v4Local, remote: v4Server, expected: pa.IPv4},
		{name: "IPv4-mapped server address", pa: pa, local: v6Unspecified, remote: v4MappedServer, expected: pa.IPv4},
		{name: "IPv6", pa: pa, local: v6Local, remote: v6Server, expected: pa.IPv6},
		{name: "IPv6 only, from IPv4 socket", pa: v6Only, local: v4Local, remote: v4Server},
		{name: "IPv6 only, from IPv4 unspecified socket", pa: v6Only, local: v4Unspecified, remote: v4Server},
		{name: "IPv6 only, from dual-stack socket", pa: v6Only, local: v6Unspecified, remote: v4MappedServer, expected: pa.IPv6},
		{name: "IPv4 only, from dual-stack socket", pa: v4Only, local: v6Unspecified, remote: v6Server, expected: pa.IPv4},
		{name: "IPv4 only, from IPv6 socket", pa: v4Only, local: v6Local, remote: v6Server},
		{name: "no address", pa: &wire.PreferredAddress{}, local: v4Local, remote: v4Server},
		{name: "current address", pa: v4Only, local: v4Local, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}},
		// section 21.5.6 of RFC 9000
		{
			name:   "loopback address from a non-loopback server",
			pa:     &wire.PreferredAddress{IPv4: netip.MustParseAddrPort("127.0.0.2:443")},
			local:  v4Local,
			remote: v4Server,
		},
		{
			name:     "loopback address from a loopback server",
			pa:       &wire.PreferredAddress{IPv4: netip.MustParseAddrPort("127.0.0.2:443")},
			local:    v4Local,
			remote:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
			expected: netip.MustParseAddrPort("127.0.0.2:443"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addr := choosePreferredAddr(tt.pa, tt.local, tt.remote)
			if !tt.expected.IsValid() {
				require.Nil(t, addr)
				return
			}
			require.Equal(t, net.UDPAddrFromAddrPort(tt.expected), addr)
		})
	}
}

// receiveTestPacket makes the connection receive a 1-RTT packet with the frames.
func receiveTestPacket(t *testing.T, c *Conn, unpacker *MockUnpacker, remoteAddr net.Addr, info packetInfo, pn protocol.PacketNumber, frames ...wire.Frame) bool {
	t.Helper()
	var data []byte
	for _, f := range frames {
		var err error
		data, err = f.Append(data, protocol.Version1)
		require.NoError(t, err)
	}
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
	)
	processed, err := c.handleShortHeaderPacket(receivedPacket{
		remoteAddr: remoteAddr,
		info:       info,
		data:       make([]byte, 10),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}, false, 0)
	require.NoError(t, err)
	return processed
}

// The server sends the preferred_address transport parameter with the connection ID with sequence number 1,
// and adds the connection IDs to the Transports that receive the packets sent to the preferred address.
func TestConnectionServerPreferredAddressTransportParameter(t *testing.T) {
	ipv4 := netip.MustParseAddrPort("192.0.2.1:443")
	ipv6 := netip.MustParseAddrPort("[2001:db8::1]:443")

	t.Run("IPv4 and IPv6", func(t *testing.T) {
		prefTr := &Transport{Conn: newUDPConnLocalhost(t)}
		require.NoError(t, prefTr.init(false))
		tc := newServerTestConnection(t, nil, nil, false)
		c := tc.conn
		c.connIDGenerator.generator = &protocol.DefaultConnectionIDGenerator{ConnLen: c.srcConnIDLen}
		var added []protocol.ConnectionID
		tc.connRunner.EXPECT().Add(gomock.Any(), c).Do(func(connID protocol.ConnectionID, _ packetHandler) bool {
			added = append(added, connID)
			return true
		})
		params := &wire.TransportParameters{}
		c.maybeAdvertisePreferredAddress(params, &serverPreferredAddr{
			ipv4:       ipv4,
			ipv6:       ipv6,
			transports: []preferredAddrTransport{{tr: prefTr, ipv6: ipv6.Addr()}},
		})
		require.NotNil(t, params.PreferredAddress)
		pa := params.PreferredAddress
		require.Equal(t, ipv4, pa.IPv4)
		require.Equal(t, ipv6, pa.IPv6)
		require.Equal(t, []protocol.ConnectionID{pa.ConnectionID}, added)
		require.Equal(t, c.connIDGenerator.statelessResetter.GetStatelessResetToken(pa.ConnectionID), pa.StatelessResetToken)
		// the connection ID has sequence number 1, and belongs to path 0
		require.Equal(t, pa.ConnectionID, c.connIDGenerator.path0.active[1])
		id, ok := c.connIDGenerator.PathForConnID(pa.ConnectionID)
		require.True(t, ok)
		require.Zero(t, id)
		require.Equal(t, &preferredAddrServer{ipv4: ipv4.Addr(), ipv6: ipv6.Addr()}, c.prefAddr)
		// No NEW_CONNECTION_ID frame is sent for it.
		// The peer's active_connection_id_limit includes it.
		require.Empty(t, queuedFrames(c))
		tc.connRunner.EXPECT().Add(gomock.Any(), c).Times(2)
		require.NoError(t, c.connIDGenerator.SetMaxActiveConnIDs(4))
		var seqs []uint64
		for _, f := range queuedFrames(c) {
			seqs = append(seqs, f.Frame.(*wire.NewConnectionIDFrame).SequenceNumber)
		}
		require.ElementsMatch(t, []uint64{2, 3}, seqs)

		// All connection IDs are added to the other Transport,
		// with a handler that marks the packets as received on the preferred address.
		for _, connID := range append(c.connIDGenerator.allConnIDs(), pa.ConnectionID) {
			h, ok := (*packetHandlerMap)(prefTr).Get(connID)
			require.True(t, ok, "connection ID %s", connID)
			require.Equal(t, &preferredAddrPacketHandler{Conn: c, ipv6: ipv6.Addr()}, h)
		}
		// the connection IDs are removed from both Transports
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		c.connIDGenerator.RemoveAll()
		_, ok = (*packetHandlerMap)(prefTr).Get(pa.ConnectionID)
		require.False(t, ok)
		require.NoError(t, prefTr.Close())
	})

	// The client connected to the preferred address of an address family.
	t.Run("connected to a preferred address", func(t *testing.T) {
		tc := newServerTestConnection(t, nil, nil, false)
		c := tc.conn
		localAddr := netip.MustParseAddr(c.conn.LocalAddr().(*net.UDPAddr).IP.String())
		params := &wire.TransportParameters{}
		tc.connRunner.EXPECT().Add(gomock.Any(), c)
		c.maybeAdvertisePreferredAddress(params, &serverPreferredAddr{ipv4: netip.AddrPortFrom(localAddr, 443), ipv6: ipv6})
		require.NotNil(t, params.PreferredAddress)
		require.False(t, params.PreferredAddress.IPv4.IsValid())
		require.Equal(t, ipv6, params.PreferredAddress.IPv6)

		tc = newServerTestConnection(t, nil, nil, false)
		params = &wire.TransportParameters{}
		tc.conn.maybeAdvertisePreferredAddress(params, &serverPreferredAddr{ipv4: netip.AddrPortFrom(localAddr, 443)})
		require.Nil(t, params.PreferredAddress)
		require.Nil(t, tc.conn.prefAddr)
		require.Equal(t, uint64(1), tc.conn.connIDGenerator.path0.nextSeq)
	})

	t.Run("zero-length connection ID", func(t *testing.T) {
		tc := newServerTestConnection(t, nil, nil, false)
		tc.conn.srcConnIDLen = 0
		params := &wire.TransportParameters{}
		tc.conn.maybeAdvertisePreferredAddress(params, &serverPreferredAddr{ipv4: ipv4})
		require.Nil(t, params.PreferredAddress)
	})
}

// The server validates the path from its preferred address, and only migrates after it validated the path,
// and received a non-probing packet on it (section 9.6.2 of RFC 9000).
func TestConnectionServerPreferredAddressMigration(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	sendQueue := &recordingSendQueue{}
	preferredIP := netip.MustParseAddr("192.0.2.1")
	tc := newServerTestConnectionWithPreferredAddr(t, mockCtrl, nil, false,
		&serverPreferredAddr{ipv4: netip.AddrPortFrom(preferredIP, 443)},
		connectionOptHandshakeConfirmed(),
		connectionOptSender(sendQueue),
		connectionOptUnpacker(unpacker),
	)
	c := tc.conn
	require.NotNil(t, c.prefAddr)
	require.NoError(t, c.handleTransportParameters(&wire.TransportParameters{MaxUDPPayloadSize: 1456}))
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any()).AnyTimes()
	// the client provides connection IDs
	c.connIDManager.ChangeInitialConnID(protocol.ParseConnectionID([]byte{0, 0, 0, 0}))
	for seq := range uint64(3) {
		_, err := c.handleFrame(&wire.NewConnectionIDFrame{
			SequenceNumber:      seq + 1,
			ConnectionID:        protocol.ParseConnectionID([]byte{byte(seq + 1), 1, 1, 1}),
			StatelessResetToken: protocol.StatelessResetToken{byte(seq + 1)},
		}, protocol.Encryption1RTT, protocol.ConnectionID{}, monotime.Now())
		require.NoError(t, err)
	}
	queuedFrames(c)

	preferredInfo := packetInfo{addr: preferredIP, ifIndex: 2}
	var probes [][]ackhandler.Frame
	var probeConnIDs []protocol.ConnectionID
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, protocol.PathID(0)).DoAndReturn(
		func(connID protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			probes = append(probes, frames)
			probeConnIDs = append(probeConnIDs, connID)
			return newTestProbePacket(c, frames), getPacketBuffer(), nil
		},
	).AnyTimes()

	// The client probes the preferred address.
	// The server responds, and validates the path from the preferred address, although the client's address
	// didn't change.
	require.True(t, receiveTestPacket(t, c, unpacker, tc.remoteAddr, preferredInfo, 1, &wire.PathChallengeFrame{Data: [8]byte{1}}))
	require.Len(t, probes, 1)
	require.Len(t, probes[0], 2)
	challenge, ok := probes[0][0].Frame.(*wire.PathChallengeFrame)
	require.True(t, ok)
	require.Equal(t, &wire.PathResponseFrame{Data: [8]byte{1}}, probes[0][1].Frame)
	// a connection ID that wasn't used before is used for the new path
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), probeConnIDs[0])
	require.Equal(t, []net.Addr{tc.remoteAddr}, sendQueue.sent)
	require.Equal(t, []packetInfo{preferredInfo}, sendQueue.infos)

	// A non-probing packet doesn't make the server migrate before the path is validated.
	// Non-probing packets are still sent from the original address.
	require.True(t, receiveTestPacket(t, c, unpacker, tc.remoteAddr, preferredInfo, 2, &wire.PingFrame{}))
	require.Len(t, probes, 1)
	require.False(t, c.prefAddr.currentLocalAddr().IsValid())

	// Packets received on the original address are processed as usual.
	require.True(t, receiveTestPacket(t, c, unpacker, tc.remoteAddr, packetInfo{}, 3, &wire.PingFrame{}))
	require.Len(t, probes, 1)

	// The path is validated. The server migrates.
	c.rttStats.UpdateRTT(time.Second, 0)
	tc.sendConn.EXPECT().ChangeRemoteAddr(tc.remoteAddr, preferredInfo)
	require.True(t, receiveTestPacket(t, c, unpacker, tc.remoteAddr, preferredInfo, 4, &wire.PathResponseFrame{Data: challenge.Data}, &wire.PingFrame{}))
	require.Equal(t, preferredIP, c.prefAddr.currentLocalAddr())
	// the RTT estimate is reset
	require.False(t, c.rttStats.HasMeasurement())
	// The server uses the connection ID used to validate the path, and retires the old one.
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 1, 1, 1}), c.connIDManager.Get())
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 0}}}, stripHandlers(queuedFrames(c)))

	// The client's address changes on the preferred address (e.g. a NAT rebinding).
	// This is a normal migration.
	newAddr := &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999}
	require.True(t, receiveTestPacket(t, c, unpacker, newAddr, preferredInfo, 5, &wire.PingFrame{}))
	require.Len(t, probes, 2)
	require.Equal(t, []net.Addr{tc.remoteAddr, newAddr}, sendQueue.sent)
	require.Equal(t, []packetInfo{preferredInfo, preferredInfo}, sendQueue.infos)
	require.Equal(t, preferredIP, c.prefAddr.currentLocalAddr())

	// Packets received on the original address are dropped, both newer and delayed packets.
	require.False(t, receiveTestPacket(t, c, unpacker, tc.remoteAddr, packetInfo{}, 10, &wire.PathChallengeFrame{Data: [8]byte{2}}))
	require.False(t, receiveTestPacket(t, c, unpacker, tc.remoteAddr, packetInfo{}, 0, &wire.PingFrame{}))
	require.False(t, receiveTestPacket(t, c, unpacker, newAddr, packetInfo{addr: netip.MustParseAddr("198.51.100.1")}, 11, &wire.PingFrame{}))
	require.Len(t, probes, 2)
	require.Empty(t, queuedFrames(c))
	require.Len(t, sendQueue.sent, 2)
}

// newTestProbePacket emulates the packer packing a path probe packet on path 0.
func newTestProbePacket(c *Conn, frames []ackhandler.Frame) shortHeaderPacket {
	pn, pnLen := c.sentPacketHandler.PeekPacketNumber(0, protocol.Encryption1RTT)
	c.sentPacketHandler.PopPacketNumber(0, protocol.Encryption1RTT)
	return shortHeaderPacket{
		PacketNumber:      pn,
		PacketNumberLen:   pnLen,
		Frames:            frames,
		Length:            protocol.MinInitialPacketSize,
		IsPathProbePacket: true,
	}
}

// stripHandlers removes the handlers of the frames.
func stripHandlers(frames []ackhandler.Frame) []ackhandler.Frame {
	for i := range frames {
		frames[i].Handler = nil
	}
	return frames
}

type preferredAddrTestClient struct {
	*testConnection
	unpacker *MockUnpacker
	addr     *net.UDPAddr
	connID   protocol.ConnectionID
	token    protocol.StatelessResetToken
	// the frames of the path probe packets sent
	probes [][]ackhandler.Frame
	// the connection IDs that the path probe packets were sent to
	probeConnIDs []protocol.ConnectionID
}

// newPreferredAddrTestClient creates a client connection that received the server's preferred address
// in the transport parameters. The handshake is complete, but not confirmed.
func newPreferredAddrTestClient(t *testing.T, disableActiveMigration bool, opts ...testConnectionOpt) *preferredAddrTestClient {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	opts = append(opts, connectionOptUnpacker(unpacker))
	tc := &preferredAddrTestClient{
		testConnection: newClientTestConnection(t, mockCtrl, nil, false, opts...),
		unpacker:       unpacker,
		addr:           &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1).To4(), Port: 443},
		connID:         protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc, 0xd}),
		token:          protocol.StatelessResetToken{0xa, 0xb},
	}
	c := tc.conn
	c.handshakeComplete = true
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, protocol.PathID(0)).DoAndReturn(
		func(connID protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
			tc.probes = append(tc.probes, frames)
			tc.probeConnIDs = append(tc.probeConnIDs, connID)
			return newTestProbePacket(c, frames), getPacketBuffer(), nil
		},
	).AnyTimes()
	// the connection ID from the preferred_address transport parameter is used for the preferred address
	tc.connRunner.EXPECT().AddResetToken(tc.token, c)
	require.NoError(t, c.handleTransportParameters(&wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		InitialSourceConnectionID:       tc.destConnID,
		DisableActiveMigration:          disableActiveMigration,
		PreferredAddress: &wire.PreferredAddress{
			IPv4:                tc.addr.AddrPort(),
			IPv6:                netip.MustParseAddrPort("[2001:db8::1]:443"),
			ConnectionID:        tc.connID,
			StatelessResetToken: tc.token,
		},
	}))
	c.applyTransportParameters()
	require.NotNil(t, c.prefAddrMigration)
	require.Equal(t, tc.addr, c.prefAddrMigration.addr)
	require.False(t, c.prefAddrMigration.validating())
	require.Zero(t, c.prefAddrMigration.timeout())
	return tc
}

// The client validates the preferred address once the handshake is confirmed, and migrates to it.
func TestConnectionClientPreferredAddressMigration(t *testing.T) {
	tc := newPreferredAddrTestClient(t, true)
	c := tc.conn
	// disable_active_migration applies until the client migrated to the preferred address
	_, err := c.AddPath(&Transport{})
	require.ErrorContains(t, err, "server disabled connection migration")

	now := monotime.Now()
	require.NoError(t, c.handleHandshakeConfirmed(now))
	require.True(t, c.prefAddrMigration.validating())
	require.Equal(t, now, c.prefAddrMigration.timeout())

	// A PATH_CHALLENGE is sent to the preferred address, using the connection ID from the transport parameter.
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.addr, packetInfo{}).Times(2)
	require.NoError(t, c.handlePreferredAddrTimers(now))
	require.Len(t, tc.probes, 1)
	require.Len(t, tc.probes[0], 1)
	challenge, ok := tc.probes[0][0].Frame.(*wire.PathChallengeFrame)
	require.True(t, ok)
	require.Equal(t, []protocol.ConnectionID{tc.connID}, tc.probeConnIDs)
	require.Equal(t, now.Add(c.rttStats.PTO(true)), c.prefAddrMigration.timeout())
	require.NoError(t, c.handlePreferredAddrTimers(now))
	require.Len(t, tc.probes, 1)

	// The PATH_CHALLENGE that the server sends from the preferred address is answered on that path
	// (section 8.2.2 of RFC 9000).
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 1, &wire.PathChallengeFrame{Data: [8]byte{9}}))
	require.Len(t, tc.probes, 2)
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{9}}}}, stripHandlers(tc.probes[1]))
	require.Equal(t, tc.connID, tc.probeConnIDs[1])
	require.Empty(t, queuedFrames(c))

	// The PATH_RESPONSE validates the preferred address. The client migrates.
	c.rttStats.UpdateRTT(time.Second, 0)
	tc.sendConn.EXPECT().ChangeRemoteAddr(tc.addr, packetInfo{})
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 2, &wire.PathResponseFrame{Data: challenge.Data}))
	require.Equal(t, preferredAddrMigrated, c.prefAddrMigration.state)
	require.Zero(t, c.prefAddrMigration.timeout())
	require.False(t, c.rttStats.HasMeasurement())
	// The client uses the connection ID, and retires the connection ID used so far.
	require.Equal(t, tc.connID, c.connIDManager.Get())
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 0}}}, stripHandlers(queuedFrames(c)))

	// a late PATH_RESPONSE is ignored
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 3, &wire.PathResponseFrame{Data: challenge.Data}))
	// a PATH_CHALLENGE on the current path is answered as usual
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 4, &wire.PathChallengeFrame{Data: [8]byte{10}}))
	require.Equal(t, [][8]byte{{10}}, queuedPathResponses(c))
	require.Len(t, tc.probes, 2)

	// disable_active_migration doesn't apply anymore
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()
	_, err = c.AddPath(tr)
	require.NoError(t, err)
}

// If the validation of the preferred address fails, the client keeps using the original address.
func TestConnectionClientPreferredAddressValidationFailure(t *testing.T) {
	tc := newPreferredAddrTestClient(t, false)
	c := tc.conn
	start := monotime.Now()
	pto := c.rttStats.PTO(true)
	require.NoError(t, c.handleHandshakeConfirmed(start))

	var probeTimes []monotime.Time
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.addr, packetInfo{}).DoAndReturn(func([]byte, net.Addr, packetInfo) error {
		return &net.OpError{Op: "write", Err: errors.New("network is unreachable")}
	}).AnyTimes()
	tc.connRunner.EXPECT().RemoveResetToken(tc.token)
	for c.prefAddrMigration.validating() {
		now := c.prefAddrMigration.timeout()
		numProbes := len(tc.probes)
		require.NoError(t, c.handlePreferredAddrTimers(now))
		if len(tc.probes) > numProbes {
			probeTimes = append(probeTimes, now)
		}
	}
	require.Equal(t, preferredAddrFailed, c.prefAddrMigration.state)
	// PATH_CHALLENGE frames are sent with exponential backoff, for 3 PTOs
	require.Equal(t, []monotime.Time{start, start.Add(pto)}, probeTimes)
	require.Zero(t, c.prefAddrMigration.timeout())
	// the connection ID is retired
	require.Equal(t, []ackhandler.Frame{{Frame: &wire.RetireConnectionIDFrame{SequenceNumber: 1}}}, stripHandlers(queuedFrames(c)))
	// a PATH_RESPONSE received after the validation failed doesn't make the client migrate
	challenge := tc.probes[0][0].Frame.(*wire.PathChallengeFrame)
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 1, &wire.PathResponseFrame{Data: challenge.Data}))
	require.Equal(t, preferredAddrFailed, c.prefAddrMigration.state)
}

// After a migration to a new local address, the preferred address is validated from that address
// (section 9.6.3 of RFC 9000).
func TestConnectionClientPreferredAddressValidationAfterMigration(t *testing.T) {
	tc := newPreferredAddrTestClient(t, false, connectionOptSender(&recordingSendQueue{}))
	c := tc.conn
	start := monotime.Now()
	require.NoError(t, c.handleHandshakeConfirmed(start))
	tc.sendConn.EXPECT().WriteTo(gomock.Any(), tc.addr, packetInfo{})
	require.NoError(t, c.handlePreferredAddrTimers(start))
	require.Len(t, tc.probes, 1)
	oldChallenge := tc.probes[0][0].Frame.(*wire.PathChallengeFrame)

	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	require.NoError(t, tr.init(false))
	defer tr.Close()
	now := start.Add(10 * time.Millisecond)
	c.switchToNewPath(tr, 1, now)
	defer c.sendQueue.Close()
	require.True(t, c.prefAddrMigration.validating())
	require.Equal(t, now, c.prefAddrMigration.timeout())

	// the PATH_RESPONSE to the PATH_CHALLENGE sent from the old local address doesn't validate the preferred address
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 1, &wire.PathResponseFrame{Data: oldChallenge.Data}))
	require.True(t, c.prefAddrMigration.validating())

	// a new PATH_CHALLENGE is sent from the new local address
	require.NoError(t, c.handlePreferredAddrTimers(now))
	require.Len(t, tc.probes, 2)
	challenge := tc.probes[1][0].Frame.(*wire.PathChallengeFrame)
	require.True(t, receiveTestPacket(t, c, tc.unpacker, tc.addr, packetInfo{}, 2, &wire.PathResponseFrame{Data: challenge.Data}))
	require.Equal(t, preferredAddrMigrated, c.prefAddrMigration.state)
	require.Equal(t, tc.addr.String(), c.RemoteAddr().String())
	require.Equal(t, tr.Conn.LocalAddr().String(), c.LocalAddr().String())
}

// A server that uses a zero-length connection ID must not send a preferred address (section 18.2 of RFC 9000).
func TestConnectionClientPreferredAddressZeroLengthConnID(t *testing.T) {
	tc := newClientTestConnection(t, nil, nil, false)
	c := tc.conn
	c.handshakeDestConnID = protocol.ConnectionID{}
	err := c.handleTransportParameters(&wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		PreferredAddress: &wire.PreferredAddress{
			IPv4:         netip.MustParseAddrPort("192.0.2.1:443"),
			ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		},
	})
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
	require.ErrorContains(t, err, "received preferred_address, although the server uses a zero-length connection ID")
}

// If the client can't use any of the preferred addresses, the connection ID is used like any other one.
func TestConnectionClientPreferredAddressNotUsable(t *testing.T) {
	tc := newClientTestConnection(t, nil, nil, false, connectionOptHandshakeConfirmed())
	c := tc.conn
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	require.NoError(t, c.handleTransportParameters(&wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		InitialSourceConnectionID:       tc.destConnID,
		// the client's local address is an IPv4 address
		PreferredAddress: &wire.PreferredAddress{
			IPv6:         netip.MustParseAddrPort("[2001:db8::1]:443"),
			ConnectionID: connID,
		},
	}))
	c.applyTransportParameters()
	require.NoError(t, c.handleHandshakeConfirmed(monotime.Now()))
	require.Nil(t, c.prefAddrMigration)
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), c)
	c.connIDManager.SetHandshakeComplete()
	require.Equal(t, connID, c.connIDManager.Get())
}

// With IETF Multipath QUIC, path 0 migrates to the preferred address (section 2.2 of draft-ietf-quic-multipath-21).
// The server validates the 4-tuple from the preferred address using a connection ID of path 0.
func TestMultipathServerPreferredAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveServer, 3, 3)
		c := tc.conn
		preferredIP := netip.MustParseAddr("192.0.2.1")
		preferredInfo := packetInfo{addr: preferredIP}
		c.prefAddr = &preferredAddrServer{ipv4: preferredIP}
		c.connIDManager.ChangeInitialConnID(newTestPathNewConnectionIDFrame(0, 0).ConnectionID)
		for seq := range uint64(3) {
			require.NoError(t, c.peerConnIDs.Add(newTestPathNewConnectionIDFrame(0, seq+1)))
		}
		queuedFrames(c)
		clientAddr := c.conn.RemoteAddr()

		// The client probes the preferred address. The server responds from the preferred address,
		// and validates the 4-tuple.
		tc.sendConn.EXPECT().WriteTo(gomock.Any(), clientAddr, preferredInfo)
		_, err := tc.receivePacket(t, 0, clientAddr, preferredInfo, 1200, &wire.PathChallengeFrame{Data: [8]byte{1}})
		require.NoError(t, err)
		require.Len(t, tc.probes, 1)
		require.Equal(t, newTestPathNewConnectionIDFrame(0, 1).ConnectionID, tc.probes[0].connID)
		challenges, responses := sentProbeFrames(tc.probes, 0)
		require.Len(t, challenges, 1)
		require.Equal(t, []*wire.PathResponseFrame{{Data: [8]byte{1}}}, responses)
		require.False(t, c.prefAddr.currentLocalAddr().IsValid())

		// A non-probing packet from the preferred address migrates path 0, once the 4-tuple is validated.
		tc.sendConn.EXPECT().ChangeRemoteAddr(clientAddr, preferredInfo)
		_, err = tc.receivePacket(t, 0, clientAddr, preferredInfo, 1200, &wire.PathResponseFrame{Data: challenges[0].Data}, &wire.PingFrame{})
		require.NoError(t, err)
		require.Equal(t, preferredIP, c.prefAddr.currentLocalAddr())
		// The path uses the connection ID used for validating the 4-tuple, and retires the old one.
		// The original 4-tuple is not validated: packets received on the original address are dropped.
		connID, ok := c.pathDestConnID(c.mp.paths[0])
		require.True(t, ok)
		require.Equal(t, newTestPathNewConnectionIDFrame(0, 1).ConnectionID, connID)
		require.Equal(t,
			[]*wire.PathRetireConnectionIDFrame{{PathID: 0, SequenceNumber: 0}},
			multipathFramesOfType[*wire.PathRetireConnectionIDFrame](queuedFrames(c)),
		)
		require.NoError(t, c.sendDueTupleChallenges(c.mp.paths[0], monotime.Now()))
		require.Len(t, tc.probes, 1)

		processed, err := tc.receivePacket(t, 0, clientAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.False(t, processed)
		// other paths are not affected
		tc.acceptServerPath(t, 1, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678})
		processed, err = tc.receivePacket(t, 1, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 5), Port: 5678}, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.True(t, processed)
	})
}

// With IETF Multipath QUIC, the client migrates path 0 to the preferred address, using the connection ID
// from the transport parameter, which is a connection ID of path 0 (section 2.2 of draft-ietf-quic-multipath-21).
// Paths are opened automatically once the migration completed.
func TestMultipathClientPreferredAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		c.config.MultipathAutoPaths = true
		preferredAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1).To4(), Port: 443}
		pa := &wire.PreferredAddress{
			IPv4:                preferredAddr.AddrPort(),
			ConnectionID:        protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc, 0xd}),
			StatelessResetToken: protocol.StatelessResetToken{0xa},
		}
		c.peerParams.PreferredAddress = pa
		c.handlePreferredAddress(pa)
		var probes [][]ackhandler.Frame
		var probeConnIDs []protocol.ConnectionID
		tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1, protocol.PathID(0)).DoAndReturn(
			func(connID protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.ByteCount, _ protocol.Version, _ protocol.PathID) (shortHeaderPacket, *packetBuffer, error) {
				probes = append(probes, frames)
				probeConnIDs = append(probeConnIDs, connID)
				return newTestProbePacket(c, frames), getPacketBuffer(), nil
			},
		).AnyTimes()

		// before the migration, the client drops packets from the preferred address
		tc.receiveDroppedPacket(t, 0, preferredAddr)
		c.maybeMigrateToPreferredAddr(monotime.Now())
		require.True(t, c.prefAddrMigration.validating())
		c.maybeStartAutoPaths()
		require.False(t, c.autoPathsStarted)

		tc.sendConn.EXPECT().WriteTo(gomock.Any(), preferredAddr, packetInfo{}).Times(2)
		require.NoError(t, c.handlePreferredAddrTimers(monotime.Now()))
		require.Len(t, probes, 1)
		require.Equal(t, pa.ConnectionID, probeConnIDs[0])
		challenge := probes[0][0].Frame.(*wire.PathChallengeFrame)

		// The server validates the path from the preferred address, and responds to the client's PATH_CHALLENGE.
		// Path 0 migrates.
		tc.sendConn.EXPECT().ChangeRemoteAddr(preferredAddr, packetInfo{})
		processed, err := tc.receivePacket(t, 0, preferredAddr, packetInfo{}, 1200,
			&wire.PathChallengeFrame{Data: [8]byte{9}},
			&wire.PathResponseFrame{Data: challenge.Data},
		)
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, preferredAddrMigrated, c.prefAddrMigration.state)
		// the PATH_RESPONSE is sent to the preferred address
		require.Len(t, probes, 2)
		require.Equal(t, []ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: [8]byte{9}}}}, stripHandlers(probes[1]))
		require.Equal(t, pa.ConnectionID, probeConnIDs[1])
		connID, ok := c.pathDestConnID(c.mp.paths[0])
		require.True(t, ok)
		require.Equal(t, pa.ConnectionID, connID)
		require.Equal(t,
			[]*wire.PathRetireConnectionIDFrame{{PathID: 0, SequenceNumber: 0}},
			multipathFramesOfType[*wire.PathRetireConnectionIDFrame](queuedFrames(c)),
		)
		require.True(t, c.migratedToPreferredAddr.Load())
		require.True(t, c.autoPathsStarted)
		// packets that the server sent from its original address are still accepted
		processed, err = tc.receivePacket(t, 0, tc.remoteAddr, packetInfo{}, 1200, &wire.PingFrame{})
		require.NoError(t, err)
		require.True(t, processed)
	})
}

// With IETF Multipath QUIC, the validation of the preferred address fails if path 0 is abandoned.
func TestMultipathClientPreferredAddressPath0Abandoned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tc := newMPPathTestConn(t, protocol.PerspectiveClient, 3, 3)
		c := tc.conn
		pa := &wire.PreferredAddress{
			IPv4:         netip.MustParseAddrPort("192.0.2.1:443"),
			ConnectionID: protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc, 0xd}),
		}
		c.peerParams.PreferredAddress = pa
		c.handlePreferredAddress(pa)
		c.maybeMigrateToPreferredAddr(monotime.Now())
		require.True(t, c.prefAddrMigration.validating())

		c.mp.paths[0].state = mpPathAbandoned
		require.NoError(t, c.handlePreferredAddrTimers(monotime.Now()))
		require.Equal(t, preferredAddrFailed, c.prefAddrMigration.state)
		require.Equal(t,
			[]*wire.PathRetireConnectionIDFrame{{PathID: 0, SequenceNumber: 1}},
			multipathFramesOfType[*wire.PathRetireConnectionIDFrame](queuedFrames(c)),
		)
	})
}

// The client accepts packets from the server's preferred address once it started validating it.
// Before, the preferred address is an unknown server address (section 9 of RFC 9000).
func TestConnectionClientPreferredAddressIsKnownServerAddr(t *testing.T) {
	tc := newPreferredAddrTestClient(t, false, connectionOptSender(&recordingSendQueue{}))
	c := tc.conn
	require.True(t, c.isKnownServerAddr0(c.peerHandshakeAddr))
	require.False(t, c.isKnownServerAddr0(tc.addr))
	wasProcessed, err := c.handleOnePacket(getShortHeaderPacket(t, tc.addr, tc.srcConnID, 1, []byte("foobar")), 0)
	require.NoError(t, err)
	require.False(t, wasProcessed)

	require.NoError(t, c.handleHandshakeConfirmed(monotime.Now()))
	require.True(t, c.prefAddrMigration.validating())
	require.True(t, c.isKnownServerAddr0(tc.addr))
	require.True(t, c.isKnownServerAddr0(c.peerHandshakeAddr))
}

// droppingPacketConn drops all datagrams sent and received once drop is set.
type droppingPacketConn struct {
	net.PacketConn
	drop atomic.Bool
}

func (c *droppingPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.drop.Load() {
			return n, addr, err
		}
	}
}

func (c *droppingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.drop.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// A client that lost its state after migrating to the preferred address sends a stateless reset to the preferred
// address. The Transport receiving the packets sent to the preferred address recognizes it
// (section 10.3.1 of RFC 9000).
func TestPreferredAddressStatelessResetOnOtherTransport(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		t.Run(fmt.Sprintf("multipath: %t", multipath), func(t *testing.T) {
			testPreferredAddressStatelessResetOnOtherTransport(t, multipath)
		})
	}
}

func testPreferredAddressStatelessResetOnOtherTransport(t *testing.T, multipath bool) {
	prefConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 not available: %s", err)
	}
	var serverKey StatelessResetKey
	rand.Read(serverKey[:])
	prefTr := &Transport{Conn: prefConn, StatelessResetKey: &serverKey}
	defer prefTr.Close()
	preferred := prefConn.LocalAddr().(*net.UDPAddr).AddrPort()
	tr := &Transport{
		Conn:              newUDPConnLocalhost(t),
		StatelessResetKey: &serverKey,
		PreferredAddress:  &PreferredAddress{IPv6: preferred, IPv6Transport: prefTr},
	}
	defer tr.Close()
	newConfig := func() *Config {
		if !multipath {
			return nil
		}
		return &Config{MultipathControllerFactory: func() MultipathController { return NewDefaultMultipathController(nil) }}
	}
	ln, err := tr.Listen(generateTLSConfig(), newConfig())
	require.NoError(t, err)
	defer ln.Close()

	var clientKey StatelessResetKey
	rand.Read(clientKey[:])
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	require.NoError(t, err)
	clientConn := &droppingPacketConn{PacketConn: udpConn}
	clientTr := &Transport{Conn: clientConn, StatelessResetKey: &clientKey}
	defer clientTr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, ln.Addr(), generateTLSConfigWithServerName("localhost"), newConfig())
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	require.Equal(t, multipath, conn.ConnectionState().SupportsMultipath)

	// The server migrates to the preferred address once it received a non-probing packet on it.
	preferredAddr := net.UDPAddrFromAddrPort(preferred).String()
	cstr, err := conn.OpenUniStream()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		if _, err := cstr.Write([]byte("foobar")); err != nil {
			return false
		}
		return conn.RemoteAddr().String() == preferredAddr && sconn.LocalAddr().String() == preferredAddr
	}, 5*time.Second, 10*time.Millisecond)

	// The client loses its state. A new Transport on the same address sends a stateless reset
	// when it receives a packet for the connection.
	clientConn.drop.Store(true)
	clientAddr := udpConn.LocalAddr().(*net.UDPAddr)
	require.NoError(t, clientTr.Close())
	require.NoError(t, udpConn.Close())
	udpConn2, err := net.ListenUDP("udp", clientAddr)
	require.NoError(t, err)
	clientTr2 := &Transport{Conn: udpConn2, StatelessResetKey: &clientKey}
	defer clientTr2.Close()
	require.NoError(t, clientTr2.init(false))

	str, err := sconn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(make([]byte, 100))
	require.NoError(t, err)
	select {
	case <-sconn.Context().Done():
		require.ErrorIs(t, context.Cause(sconn.Context()), &StatelessResetError{})
	case <-ctx.Done():
		t.Fatal("the server didn't recognize the stateless reset")
	}
}
