//go:build linux

package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// sourceRecordingConn records the addresses that packets are received from, and the number of bytes received.
type sourceRecordingConn struct {
	net.PacketConn

	mx      sync.Mutex
	sources map[string]int
}

func (c *sourceRecordingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.mx.Lock()
		c.sources[addr.String()] += n
		c.mx.Unlock()
	}
	return n, addr, err
}

func (c *sourceRecordingConn) bytesReceivedFrom(addr net.Addr) int {
	c.mx.Lock()
	defer c.mx.Unlock()
	return c.sources[addr.String()]
}

// multipathUDPTestServer runs a server using IETF Multipath QUIC on 127.0.0.1.
// It echoes the data of every stream, once the client closed the stream.
// It records the addresses it receives packets from.
func multipathUDPTestServer(t *testing.T) (*sourceRecordingConn, net.Addr) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverConn := &sourceRecordingConn{PacketConn: udpConn, sources: make(map[string]int)}
	tr := &Transport{Conn: serverConn}
	t.Cleanup(func() { tr.Close() })
	ln, err := tr.Listen(generateTLSConfig(), &Config{
		MultipathControllerFactory: func() MultipathController { return NewDefaultMultipathController(nil) },
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go echoStreams(ln)
	return serverConn, udpConn.LocalAddr()
}

// echoStreams accepts connections, and echoes the data of every stream, once the client closed the stream.
func echoStreams(ln *Listener) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		go func() {
			for {
				str, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					defer str.Close()
					// Read all data before echoing it. Otherwise, both endpoints might be blocked by flow control.
					data, err := io.ReadAll(str)
					if err != nil {
						return
					}
					str.Write(data)
				}()
			}
		}()
	}
}

// echoTestData sends data on a new stream, and checks that the server echoes it.
func echoTestData(t *testing.T, conn *Conn, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	data := make([]byte, size)
	rand.Read(data)
	_, err = str.Write(data)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	echoed, err := io.ReadAll(str)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, echoed))
}

// With IETF Multipath QUIC, a client with Config.MultipathAutoPaths opens a path from every local address.
// The client's socket is bound to an unspecified address. It uses the packet info to send from 127.0.0.2.
func TestMultipathAutoPathsUDP(t *testing.T) {
	serverConn, serverAddr := multipathUDPTestServer(t)
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(t, err)
	clientTr := &Transport{Conn: clientConn}
	defer clientTr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, serverAddr, generateTLSConfigWithServerName("localhost"), &Config{
		MaxPaths:            2,
		MultipathController: NewDefaultMultipathController(NewRoundRobinScheduler()),
		MultipathAutoPaths:  true,
		MultipathAutoAddrs:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)},
	})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	require.Eventually(t, func() bool {
		paths := conn.Paths()
		return len(paths) == 2 && paths[1].State == PathStateActive
	}, 5*time.Second, 10*time.Millisecond)
	path := conn.Paths()[1]
	require.Equal(t, PathID(1), path.ID)
	localAddr, ok := path.LocalAddr.(*net.UDPAddr)
	require.True(t, ok)
	require.Equal(t, net.IPv4(127, 0, 0, 2).To4(), localAddr.IP.To4())
	echoTestData(t, conn, 1<<20)
	// data was sent on both paths
	port := clientConn.LocalAddr().(*net.UDPAddr).Port
	require.Greater(t, serverConn.bytesReceivedFrom(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}), 100<<10)
	require.Greater(t, serverConn.bytesReceivedFrom(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}), 100<<10)
}

// A MultiSocketManager sends the packets of a path opened using AddPathFromAddr from the socket bound to the path's
// local address.
func TestMultipathMultiSocketManagerPath(t *testing.T) {
	serverConn, serverAddr := multipathUDPTestServer(t)
	baseConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{BaseConn: baseConn})
	require.NoError(t, err)
	managedAddr, err := mgr.AddLocalAddr(net.IPv4(127, 0, 0, 2))
	require.NoError(t, err)
	clientTr := &Transport{Conn: mgr}
	defer clientTr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, serverAddr, generateTLSConfigWithServerName("localhost"), &Config{
		MultipathController: NewDefaultMultipathController(nil),
	})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	path, err := conn.AddPathFromAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}, nil)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	// only send data on the new path
	require.NoError(t, path.Switch())
	echoTestData(t, conn, 1<<20)
	require.Greater(t, serverConn.bytesReceivedFrom(managedAddr), 1<<20)
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.Equal(t, net.IPv4(127, 0, 0, 2).To4(), localAddr.IP.To4())
}

// A server using a MultiSocketManager sends the PATH_RESPONSE of RFC 9000 connection migration from the socket that
// received the PATH_CHALLENGE (section 8.2.2 of RFC 9000). Here, this socket uses a different port than the base socket.
// The client would discard packets received from any other server address (section 9 of RFC 9000).
func TestMultiSocketManagerConnectionMigration(t *testing.T) {
	baseConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	mgr, err := NewMultiSocketManager(MultiSocketManagerConfig{BaseConn: baseConn})
	require.NoError(t, err)
	managedAddr, err := mgr.AddLocalAddr(net.IPv4(127, 0, 0, 2))
	require.NoError(t, err)
	// the kernel might have chosen the port of the base socket
	for managedAddr.Port == baseConn.LocalAddr().(*net.UDPAddr).Port {
		require.True(t, mgr.RemoveLocalAddr(net.IPv4(127, 0, 0, 2)))
		managedAddr, err = mgr.AddLocalAddr(net.IPv4(127, 0, 0, 2))
		require.NoError(t, err)
	}
	serverTr := &Transport{Conn: mgr}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), &Config{})
	require.NoError(t, err)
	defer ln.Close()
	go echoStreams(ln)

	// Both client sockets are wrapped, so that neither of them is used with ECN:
	// the connection doesn't stop using ECN when it migrates to a socket that doesn't support it.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	clientTr := &Transport{Conn: &sourceRecordingConn{PacketConn: udpConn, sources: make(map[string]int)}}
	defer clientTr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, managedAddr, generateTLSConfigWithServerName("localhost"), &Config{})
	require.NoError(t, err)
	require.False(t, conn.ConnectionState().SupportsMultipath)

	udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	newConn := &sourceRecordingConn{PacketConn: udpConn, sources: make(map[string]int)}
	newTr := &Transport{Conn: newConn}
	// The connection is closed first, since closing the Transport destroys the connection.
	defer func() {
		conn.CloseWithError(0, "")
		newTr.Close()
	}()
	path, err := conn.AddPath(newTr)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	echoTestData(t, conn, 100<<10)

	newConn.mx.Lock()
	defer newConn.mx.Unlock()
	require.Equal(t, []string{managedAddr.String()}, slices.Sorted(maps.Keys(newConn.sources)))
}

// A server with Config.MultipathAutoAdvertise advertises its local addresses using the address advertisement
// extension. Its socket is bound to an unspecified address, and it uses the packet info to send from 127.0.0.2.
// A client with Config.MultipathAutoPaths opens a path to the advertised address, and data is sent on both paths.
func TestMultipathAutoAdvertiseUDP(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(t, err)
	serverTr := &Transport{Conn: serverConn}
	defer serverTr.Close()
	ln, err := serverTr.Listen(generateTLSConfig(), &Config{
		MultipathControllerFactory: func() MultipathController { return NewDefaultMultipathController(NewRoundRobinScheduler()) },
		EnableAddressAdvertisement: true,
		MultipathAutoAdvertise:     true,
		MultipathAutoAddrs:         []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)},
	})
	require.NoError(t, err)
	defer ln.Close()
	go echoStreams(ln)
	port := serverConn.LocalAddr().(*net.UDPAddr).Port

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	clientConn := &sourceRecordingConn{PacketConn: udpConn, sources: make(map[string]int)}
	clientTr := &Transport{Conn: clientConn}
	defer clientTr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, generateTLSConfigWithServerName("localhost"), &Config{
		MaxPaths:                   2,
		MultipathController:        NewDefaultMultipathController(NewRoundRobinScheduler()),
		EnableAddressAdvertisement: true,
		MultipathAutoPaths:         true,
	})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	require.True(t, conn.ConnectionState().SupportsAddressAdvertisement)

	advertisedAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}
	require.Eventually(t, func() bool {
		paths := conn.Paths()
		return len(paths) == 2 && paths[1].State == PathStateActive
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []AdvertisedAddress{{ID: 0, Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 2}), uint16(port))}}, conn.PeerAdvertisedAddresses())
	path := conn.Paths()[1]
	require.Equal(t, PathID(1), path.ID)
	require.Equal(t, advertisedAddr.String(), path.RemoteAddr.String())
	echoTestData(t, conn, 1<<20)
	// data was received on both paths
	require.Greater(t, clientConn.bytesReceivedFrom(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}), 100<<10)
	require.Greater(t, clientConn.bytesReceivedFrom(advertisedAddr), 100<<10)
}
