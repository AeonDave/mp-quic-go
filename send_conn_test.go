package quic

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/utils"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Only if appendUDPSegmentSizeMsg actually appends a message (and isn't only a stub implementation),
// GSO is actually supported on this platform.
var platformSupportsGSO = len(appendUDPSegmentSizeMsg([]byte{}, 1337)) > 0

func TestSendConnLocalAndRemoteAddress(t *testing.T) {
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	rawConn := NewMockRawConn(gomock.NewController(t))
	rawConn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(10, 11, 12, 13), Port: 14}).Times(2)
	c := newSendConn(
		rawConn,
		remoteAddr,
		packetInfo{addr: netip.AddrFrom4([4]byte{127, 0, 0, 42})},
		utils.DefaultLogger,
	)
	require.Equal(t, "127.0.0.42:14", c.LocalAddr().String())
	require.Equal(t, remoteAddr, c.RemoteAddr())

	// the local raw conn's local address is only used if we don't an address from the packet info
	c = newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
	require.Equal(t, "10.11.12.13:14", c.LocalAddr().String())
}

func TestSendConnOOB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("we don't OOB conn on windows, and no packet info will be available")
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	rawConn := NewMockRawConn(gomock.NewController(t))
	rawConn.EXPECT().LocalAddr()
	rawConn.EXPECT().capabilities().AnyTimes()
	pi := packetInfo{addr: netip.IPv6Loopback()}
	rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, pi.OOB(), uint16(0), protocol.ECT1)
	require.NotEmpty(t, pi.OOB())
	c := newSendConn(rawConn, remoteAddr, pi, utils.DefaultLogger)
	require.NoError(t, c.Write([]byte("foobar"), 0, protocol.ECT1))
}

func TestSendConnDetectGSOFailure(t *testing.T) {
	if !platformSupportsGSO {
		t.Skip("GSO is not supported on this platform")
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	rawConn := NewMockRawConn(gomock.NewController(t))
	rawConn.EXPECT().LocalAddr()
	rawConn.EXPECT().capabilities().Return(connCapabilities{GSO: true}).MinTimes(1)
	c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
	gomock.InOrder(
		rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), uint16(4), protocol.ECNCE).Return(0, errGSO),
		rawConn.EXPECT().WritePacket([]byte("foob"), remoteAddr, gomock.Any(), uint16(0), protocol.ECNCE).Return(4, nil),
		rawConn.EXPECT().WritePacket([]byte("ar"), remoteAddr, gomock.Any(), uint16(0), protocol.ECNCE).Return(2, nil),
	)
	require.NoError(t, c.Write([]byte("foobar"), 4, protocol.ECNCE))
	require.False(t, c.capabilities().GSO)
}

func TestSendConnSendmsgFailures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux exhibits this bug, we don't need to work around it on other platforms")
	}

	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}

	t.Run("first call to sendmsg fails", func(t *testing.T) {
		rawConn := NewMockRawConn(gomock.NewController(t))
		rawConn.EXPECT().LocalAddr()
		rawConn.EXPECT().capabilities().AnyTimes()
		c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
		gomock.InOrder(
			rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), gomock.Any(), protocol.ECNCE).Return(0, errNotPermitted),
			rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), uint16(0), protocol.ECNCE).Return(6, nil),
		)
		require.NoError(t, c.Write([]byte("foobar"), 0, protocol.ECNCE))
	})

	t.Run("later call to sendmsg fails", func(t *testing.T) {
		rawConn := NewMockRawConn(gomock.NewController(t))
		rawConn.EXPECT().LocalAddr()
		rawConn.EXPECT().capabilities().AnyTimes()
		c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
		rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), gomock.Any(), protocol.ECNCE).Return(0, errNotPermitted).Times(2)
		require.Error(t, c.Write([]byte("foobar"), 0, protocol.ECNCE))
	})
}

func TestSendConnRemoteAddrChange(t *testing.T) {
	ln1 := newUDPConnLocalhost(t)
	ln2 := newUDPConnLocalhost(t)

	c := newSendConn(
		&basicConn{PacketConn: newUDPConnLocalhost(t)},
		ln1.LocalAddr(),
		packetInfo{},
		utils.DefaultLogger,
	)

	require.NoError(t, c.Write([]byte("foobar"), 0, protocol.ECNUnsupported))
	ln1.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1024)
	n, err := ln1.Read(b)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(b[:n]))

	require.NoError(t, c.WriteTo([]byte("foobaz"), ln2.LocalAddr(), packetInfo{}))
	ln2.SetReadDeadline(time.Now().Add(time.Second))
	b = make([]byte, 1024)
	n, err = ln2.Read(b)
	require.NoError(t, err)
	require.Equal(t, "foobaz", string(b[:n]))

	c.ChangeRemoteAddr(ln2.LocalAddr(), packetInfo{})
	require.NoError(t, c.Write([]byte("lorem ipsum"), 0, protocol.ECNUnsupported))
	ln2.SetReadDeadline(time.Now().Add(time.Second))
	b = make([]byte, 1024)
	n, err = ln2.Read(b)
	require.NoError(t, err)
	require.Equal(t, "lorem ipsum", string(b[:n]))
}

// A sendConn for a path of IETF Multipath QUIC sends on the same underlying connection,
// to another remote address and from another local address.
func TestSendConnNewPathConn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("we don't OOB conn on windows, and no packet info will be available")
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	pathRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 201), Port: 1338}
	rawConn := NewMockRawConn(gomock.NewController(t))
	rawConn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4zero, Port: 14}).AnyTimes()
	rawConn.EXPECT().capabilities().AnyTimes()
	c := newSendConn(rawConn, remoteAddr, packetInfo{addr: netip.MustParseAddr("127.0.0.1")}, utils.DefaultLogger)

	pi := packetInfo{addr: netip.MustParseAddr("127.0.0.2")}
	pc := c.newPathConn(pathRemoteAddr, pi)
	require.Equal(t, pathRemoteAddr, pc.RemoteAddr())
	require.Equal(t, "127.0.0.2:14", pc.LocalAddr().String())
	rawConn.EXPECT().WritePacket([]byte("foobar"), pathRemoteAddr, pi.OOB(), uint16(0), protocol.ECT0)
	require.NoError(t, pc.Write([]byte("foobar"), 0, protocol.ECT0))
	// the original sendConn is not affected
	require.Equal(t, remoteAddr, c.RemoteAddr())
	require.Equal(t, "127.0.0.1:14", c.LocalAddr().String())
}

// packetInfoRawConn is a rawConn that sends packets from the local address in the packet info,
// like the MultiSocketManager.
type packetInfoRawConn struct {
	rawConn
	writes []packetInfoWrite
}

type packetInfoWrite struct {
	data    []byte
	addr    net.Addr
	info    packetInfo
	gsoSize uint16
	ecn     protocol.ECN
}

func (c *packetInfoRawConn) WritePacketWithInfo(b []byte, addr net.Addr, info packetInfo, gsoSize uint16, ecn protocol.ECN) (int, error) {
	c.writes = append(c.writes, packetInfoWrite{data: append([]byte(nil), b...), addr: addr, info: info, gsoSize: gsoSize, ecn: ecn})
	return len(b), nil
}

// If the underlying connection selects the socket based on the packet info, Write and WriteTo pass the packet info.
func TestSendConnWritePacketInfo(t *testing.T) {
	mockRawConn := NewMockRawConn(gomock.NewController(t))
	mockRawConn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4zero, Port: 14}).AnyTimes()
	mockRawConn.EXPECT().capabilities().AnyTimes()
	rawConn := &packetInfoRawConn{rawConn: mockRawConn}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	info := packetInfo{addr: netip.MustParseAddr("127.0.0.1")}
	c := newSendConn(rawConn, remoteAddr, info, utils.DefaultLogger)
	require.NoError(t, c.Write([]byte("foobar"), 0, protocol.ECT1))

	pathInfo := packetInfo{addr: netip.MustParseAddr("127.0.0.2")}
	pc := c.newPathConn(remoteAddr, pathInfo)
	require.NoError(t, pc.Write([]byte("lorem"), 5, protocol.ECNNon))
	// probe packets are sent from the local address in the packet info, to another remote address
	probeAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 201), Port: 1338}
	probeInfo := packetInfo{addr: netip.MustParseAddr("127.0.0.3")}
	require.NoError(t, c.WriteTo([]byte("ipsum"), probeAddr, probeInfo))
	require.Equal(t, []packetInfoWrite{
		{data: []byte("foobar"), addr: remoteAddr, info: info, gsoSize: 0, ecn: protocol.ECT1},
		{data: []byte("lorem"), addr: remoteAddr, info: pathInfo, gsoSize: 5, ecn: protocol.ECNNon},
		{data: []byte("ipsum"), addr: probeAddr, info: probeInfo, gsoSize: 0, ecn: protocol.ECNUnsupported},
	}, rawConn.writes)
	// WriteTo doesn't change the remote address
	require.Equal(t, remoteAddr, c.RemoteAddr())
}

// The local address follows the packet info passed to ChangeRemoteAddr, e.g. when a server migrates to its
// preferred address.
func TestSendConnLocalAddrChange(t *testing.T) {
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
	rawConn := NewMockRawConn(gomock.NewController(t))
	rawConn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4zero, Port: 443}).AnyTimes()
	c := newSendConn(rawConn, remoteAddr, packetInfo{addr: netip.MustParseAddr("10.0.0.1")}, utils.DefaultLogger)
	require.Equal(t, "10.0.0.1:443", c.LocalAddr().String())

	newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 201), Port: 1337}
	c.ChangeRemoteAddr(newRemoteAddr, packetInfo{addr: netip.MustParseAddr("10.0.0.2")})
	require.Equal(t, "10.0.0.2:443", c.LocalAddr().String())
	require.Equal(t, newRemoteAddr, c.RemoteAddr())
	// without a local address in the packet info, the local address doesn't change
	c.ChangeRemoteAddr(remoteAddr, packetInfo{})
	require.Equal(t, "10.0.0.2:443", c.LocalAddr().String())
	require.Equal(t, remoteAddr, c.RemoteAddr())
}
