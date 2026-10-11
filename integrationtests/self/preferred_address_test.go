package self_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"

	"github.com/stretchr/testify/require"
)

// preferredAddressConfig returns the config used by the client and the server, with or without IETF Multipath QUIC,
// independently of the -multipath flag.
func preferredAddressConfig(multipath bool) *quic.Config {
	conf := &quic.Config{}
	if multipath {
		conf.MaxPaths = 2
		conf.MultipathControllerFactory = newMultipathControllerFactory()
	}
	conf = getQuicConfig(conf)
	if !multipath {
		conf.MultipathControllerFactory = nil
		conf.GetConfigForClient = nil
	}
	return conf
}

// echoPreferredAddressData opens a stream, sends data on it, and checks that the server echoes it.
func echoPreferredAddressData(t *testing.T, conn, sconn *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		str, err := sconn.AcceptStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		_, err = io.Copy(str, str)
		if err == nil {
			err = str.Close()
		}
		errChan <- err
	}()
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	data := GeneratePRData(50_000)
	_, err = str.Write(data)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	str.SetReadDeadline(time.Now().Add(scaleDuration(5 * time.Second)))
	received, err := io.ReadAll(str)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, received))
	require.NoError(t, <-errChan)
}

// testPreferredAddressMigration dials the listener, and checks that the connection migrates to the
// preferred address: the client sends to it, and the server sends from it.
// With IETF Multipath QUIC, path 0 migrates.
func testPreferredAddressMigration(t *testing.T, ln *quic.Listener, clientTr *quic.Transport, serverAddr net.Addr, preferred netip.AddrPort, multipath bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
	defer cancel()

	conn, err := clientTr.Dial(ctx, serverAddr, getTLSClientConfig(), preferredAddressConfig(multipath))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	require.Equal(t, multipath, conn.ConnectionState().SupportsMultipath)

	// The client migrates once the handshake is confirmed. The server migrates once it validated the path
	// from its preferred address, and received a non-probing packet on it.
	preferredAddr := net.UDPAddrFromAddrPort(preferred)
	migrated := func() bool {
		echoPreferredAddressData(t, conn, sconn)
		return conn.RemoteAddr().String() == preferredAddr.String() && sconn.LocalAddr().String() == preferredAddr.String()
	}
	require.Eventually(t, migrated, scaleDuration(5*time.Second), scaleDuration(10*time.Millisecond))
	require.Equal(t, clientTr.Conn.LocalAddr().(*net.UDPAddr).Port, conn.LocalAddr().(*net.UDPAddr).Port)
	if multipath {
		paths := conn.Paths()
		require.NotEmpty(t, paths)
		require.Equal(t, quic.PathID(0), paths[0].ID)
		require.Equal(t, preferredAddr.String(), paths[0].RemoteAddr.String())
	}
	echoPreferredAddressData(t, conn, sconn)
	require.Equal(t, preferredAddr.String(), conn.RemoteAddr().String())
	require.Equal(t, preferredAddr.String(), sconn.LocalAddr().String())
}

// The server receives the packets sent to its preferred address on another Transport.
// The client connects to the server's IPv4 address, and migrates to its IPv6 address: the server didn't send a
// preferred IPv4 address, and the client's socket can send to IPv6 addresses.
func TestPreferredAddressOtherTransport(t *testing.T) {
	for _, multipath := range []bool{false, true} {
		name := "without multipath"
		if multipath {
			name = "with multipath"
		}
		t.Run(name, func(t *testing.T) {
			prefConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
			if err != nil {
				t.Skipf("IPv6 not available: %s", err)
			}
			prefTr := &quic.Transport{Conn: prefConn}
			addTracer(prefTr)
			defer prefTr.Close()
			preferred := prefConn.LocalAddr().(*net.UDPAddr).AddrPort()

			tr := &quic.Transport{
				Conn:             newUDPConnLocalhost(t),
				PreferredAddress: &quic.PreferredAddress{IPv6: preferred, IPv6Transport: prefTr},
			}
			addTracer(tr)
			defer tr.Close()
			ln, err := tr.Listen(getTLSConfig(), preferredAddressConfig(multipath))
			require.NoError(t, err)
			defer ln.Close()

			clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0})
			require.NoError(t, err)
			clientTr := &quic.Transport{Conn: clientConn}
			addTracer(clientTr)
			defer clientTr.Close()

			testPreferredAddressMigration(t, ln, clientTr, ln.Addr(), preferred, multipath)
		})
	}
}

// If the client can't send to the preferred address, it keeps using the server's original address.
func TestPreferredAddressNotUsable(t *testing.T) {
	prefConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 not available: %s", err)
	}
	prefTr := &quic.Transport{Conn: prefConn}
	defer prefTr.Close()
	tr := &quic.Transport{
		Conn: newUDPConnLocalhost(t),
		PreferredAddress: &quic.PreferredAddress{
			IPv6:          prefConn.LocalAddr().(*net.UDPAddr).AddrPort(),
			IPv6Transport: prefTr,
		},
	}
	defer tr.Close()
	ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	// the client's socket is an IPv4 socket
	clientTr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer clientTr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
	defer cancel()
	conn, err := clientTr.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	for range 3 {
		echoPreferredAddressData(t, conn, sconn)
	}
	require.Equal(t, ln.Addr().String(), conn.RemoteAddr().String())
	require.Equal(t, ln.Addr().String(), sconn.LocalAddr().String())
}
