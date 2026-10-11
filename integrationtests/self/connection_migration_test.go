package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	quicproxy "github.com/AeonDave/mp-quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestConnectionMigration(t *testing.T) {
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()

	var packetsPath1, packetsPath2 atomic.Int64
	// the Destination Connection IDs of the 1-RTT packets sent on each path, by the client and by the server
	var connIDsMx sync.Mutex
	clientConnIDsPath1 := make(map[string]struct{})
	clientConnIDsPath2 := make(map[string]struct{})
	serverConnIDsPath1 := make(map[string]struct{})
	serverConnIDsPath2 := make(map[string]struct{})
	// client and server use connection IDs of the default length
	const connIDLen = 4

	const rtt = 5 * time.Millisecond
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, from, to net.Addr, data []byte) time.Duration {
			var port int
			switch dir {
			case quicproxy.DirectionIncoming:
				port = from.(*net.UDPAddr).Port
			case quicproxy.DirectionOutgoing:
				port = to.(*net.UDPAddr).Port
			}
			var connIDs map[string]struct{}
			switch port {
			case tr1.Conn.LocalAddr().(*net.UDPAddr).Port:
				packetsPath1.Add(1)
				connIDs = clientConnIDsPath1
				if dir == quicproxy.DirectionOutgoing {
					connIDs = serverConnIDsPath1
				}
			case tr2.Conn.LocalAddr().(*net.UDPAddr).Port:
				packetsPath2.Add(1)
				connIDs = clientConnIDsPath2
				if dir == quicproxy.DirectionOutgoing {
					connIDs = serverConnIDsPath2
				}
			default:
				fmt.Println("address not found", from)
			}
			if connIDs != nil && len(data) > connIDLen && data[0]&0x80 == 0 {
				connIDsMx.Lock()
				connIDs[string(data[1:1+connIDLen])] = struct{}{}
				connIDsMx.Unlock()
			}
			return rtt / 2
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tr1.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	sendAndReceiveFile := func(t *testing.T) {
		t.Helper()
		str, err := conn.OpenUniStream()
		require.NoError(t, err)

		errChan := make(chan error, 1)
		go func() {
			defer close(errChan)
			sstr, err := sconn.AcceptUniStream(ctx)
			if err != nil {
				errChan <- fmt.Errorf("accepting stream: %w", err)
				return
			}
			data, err := io.ReadAll(sstr)
			if err != nil {
				errChan <- fmt.Errorf("reading stream data: %w", err)
				return
			}
			if !bytes.Equal(data, PRData) {
				errChan <- errors.New("unexpected data")
			}
		}()

		_, err = str.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str.Close())

		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	}

	sendAndReceiveFile(t) // stream 2
	require.NotZero(t, packetsPath1.Load())
	require.Zero(t, packetsPath2.Load())

	// probing the path causes a few packets to be sent on path 2
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.ErrorIs(t, path.Switch(), quic.ErrPathNotValidated)
	require.NoError(t, path.Probe(ctx))
	require.Less(t, int(packetsPath2.Load()), 5)
	if !multipathConfigured() {
		// The client answers the server's PATH_CHALLENGE on path 2 (section 8.2.2 of RFC 9000),
		// possibly after Probe returned: the client's and the server's probe packets, and the PATH_RESPONSE.
		require.Eventually(t, func() bool { return packetsPath2.Load() >= 3 }, time.Second, time.Millisecond)
	}

	// Make sure that no more packets are sent on path 2 before switching to the path.
	// With IETF Multipath QUIC, all validated paths are used for sending, until the application switches to a path.
	c2 := packetsPath2.Load()
	sendAndReceiveFile(t) // stream 6
	if !multipathConfigured() {
		require.Equal(t, packetsPath2.Load(), c2)
	}
	c2 = packetsPath2.Load()

	time.Sleep(3 * rtt) // wait for ACKs

	// now switch and make sure that no packets are sent on path 1
	require.NoError(t, path.Switch())
	sendAndReceiveFile(t) // stream 10
	c1 := packetsPath1.Load()
	require.Equal(t, c1, packetsPath1.Load())
	require.Greater(t, packetsPath2.Load(), c2)
	require.Equal(t, tr2.Conn.LocalAddr(), conn.LocalAddr())

	// switch back to the handshake path
	time.Sleep(3 * rtt) // wait for ACKs
	c1BeforeSwitch := packetsPath1.Load()
	c2BeforeSwitch := packetsPath2.Load()
	path2, err := conn.AddPath(tr1)
	require.NoError(t, err)
	require.NoError(t, path2.Probe(ctx))
	time.Sleep(3 * rtt) // wait for ACKs
	require.NoError(t, path2.Switch())
	sendAndReceiveFile(t) // stream 14
	require.Greater(t, packetsPath1.Load(), c1BeforeSwitch)
	// some path probing might have happened
	require.Less(t, int(packetsPath2.Load()-c2BeforeSwitch), 20)
	require.Equal(t, tr1.Conn.LocalAddr(), conn.LocalAddr())

	// A connection ID must not be used for sending from more than one local address,
	// or to more than one remote address, see section 9.5 of RFC 9000.
	connIDsMx.Lock()
	defer connIDsMx.Unlock()
	for _, connIDs := range []map[string]struct{}{clientConnIDsPath1, clientConnIDsPath2, serverConnIDsPath1, serverConnIDsPath2} {
		require.NotEmpty(t, connIDs)
	}
	for connID := range clientConnIDsPath2 {
		require.NotContains(t, clientConnIDsPath1, connID)
	}
	for connID := range serverConnIDsPath2 {
		require.NotContains(t, serverConnIDsPath1, connID)
	}
}

// The client migrates to a Transport whose connection can't set the ECN bits, since it isn't a *net.UDPConn.
// The packets sent on the new path don't use ECN.
func TestConnectionMigrationToConnWithoutECN(t *testing.T) {
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	// hide the methods of the *net.UDPConn that are used to set the ECN bits
	tr2 := &quic.Transport{Conn: struct{ net.PacketConn }{newUDPConnLocalhost(t)}}
	defer tr2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
	defer cancel()
	conn, err := tr1.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	transfer := func(t *testing.T) {
		t.Helper()
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str.Close())
		sstr, err := sconn.AcceptUniStream(ctx)
		require.NoError(t, err)
		data, err := io.ReadAll(sstr)
		require.NoError(t, err)
		require.Equal(t, PRData, data)
	}

	transfer(t)
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	transfer(t)
	require.Equal(t, tr2.Conn.LocalAddr(), conn.LocalAddr())
	transfer(t)
}
