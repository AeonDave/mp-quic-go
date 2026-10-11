//go:build picoquic

package multipath

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/qlog"

	"github.com/stretchr/testify/require"
)

// picoquicdemo's server (-4) sends 127.0.0.2, with another port, as its preferred address. Our client connects to
// 127.0.0.1, and migrates to the preferred address (section 9.6 of RFC 9000).
// With multipath, path 0 migrates (section 2.2 of draft-ietf-quic-multipath-21).
func testClientPreferredAddress(t *testing.T, multipath bool) {
	setup(t)
	dir := testDir(t)
	port := freeUDPPort(t)
	preferred := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: freeUDPPort(t)}
	server, addr := startPreferredAddressServer(t, dir, port, preferred, multipath)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := dial(ctx, t, newTransport(t, net.IPv4(127, 0, 0, 1)), addr, tr)
	require.Equal(t, multipath, conn.ConnectionState().SupportsMultipath)
	require.Eventually(t, func() bool {
		download(ctx, t, conn, 10000)
		return conn.RemoteAddr().String() == preferred.String()
	}, 5*time.Second, 10*time.Millisecond)
	download(ctx, t, conn, downloadSize/4)
	require.Equal(t, preferred.String(), conn.RemoteAddr().String())
	if multipath {
		paths := conn.Paths()
		t.Logf("paths: %+v", paths)
		require.Equal(t, preferred.String(), paths[0].RemoteAddr.String())
	}
	require.NoError(t, conn.CloseWithError(0, ""))
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)

	recorder := tr.all()[0]
	stats := getPathStats(recorder)
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
	var sentPreferredAddr bool
	for _, ev := range recorder.Events(qlog.ParametersSet{}) {
		if ps := ev.(qlog.ParametersSet); ps.Initiator == qlog.InitiatorRemote && ps.PreferredAddress != nil {
			require.Equal(t, netip.MustParseAddrPort(preferred.String()), ps.PreferredAddress.IPv4)
			sentPreferredAddr = true
		}
	}
	require.True(t, sentPreferredAddr)
}

func TestPicoquicServerPreferredAddress(t *testing.T) { testClientPreferredAddress(t, false) }

func TestPicoquicServerPreferredAddressMultipath(t *testing.T) { testClientPreferredAddress(t, true) }

// startPreferredAddressServer starts picoquicdemo's server on a port, with a preferred IPv4 address, see startServer.
// With -p <port>:<local port>, picoquicdemo listens on both ports, and uses the local port as the port of the
// preferred address.
func startPreferredAddressServer(t *testing.T, dir string, port int, preferred *net.UDPAddr, multipath bool) (*container, *net.UDPAddr) {
	t.Helper()
	args := []string{
		"-p", fmt.Sprintf("%d:%d", port, preferred.Port), "-4", preferred.IP.String(),
		"-c", "/certs/cert.pem", "-k", "/certs/key.pem", "-q", "/work", "-1",
	}
	if multipath {
		args = append(args, "-M")
	}
	server := runPicoquic(t, dir, "server", args...)
	server.waitForOutput(t, "Waiting for packets")
	return server, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

// Our server sends 127.0.0.2 as its preferred address. Its socket is bound to the unspecified address, and receives
// the packets sent to both addresses. picoquicdemo's client connects to 127.0.0.1, and migrates to the preferred
// address. With multipath, path 0 migrates.
func testServerPreferredAddress(t *testing.T, multipath bool) {
	setup(t)
	dir := testDir(t)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(t, err)
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	preferred := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 2}), uint16(port))
	serverTr := &quic.Transport{Conn: udpConn, PreferredAddress: &quic.PreferredAddress{IPv4: preferred}}
	defer serverTr.Close()
	conf := multipathConfig(false, tr)
	if !multipath {
		conf.MultipathControllerFactory = nil
	}
	ln, err := serverTr.Listen(&tls.Config{
		Certificates: []tls.Certificate{loadCertificate(t)},
		NextProtos:   []string{alpn},
	}, conf)
	require.NoError(t, err)
	defer ln.Close()
	connChan := make(chan *quic.Conn, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		connChan <- conn
		serveHQ(conn)
	}()

	args := []string{"-n", "localhost", "-a", alpn, "-t", "/certs/ca.pem", "-D", "-q", "/work"}
	if multipath {
		args = append(args, "-M")
	}
	args = append(args, "127.0.0.1", strconv.Itoa(port), fmt.Sprintf("/%d", downloadSize))
	client := runPicoquic(t, dir, "client", args...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code, err := client.wait(ctx)
	require.NoError(t, err)
	logs := client.logs()
	require.Zerof(t, code, "picoquicdemo failed:\n%s", logs)
	require.Contains(t, logs, "Client exit with code = 0")
	if multipath {
		require.Contains(t, logs, "Enable multipath: Success")
	}

	var conn *quic.Conn
	select {
	case conn = <-connChan:
	case <-ctx.Done():
		t.Fatal("no connection accepted")
	}
	require.Equal(t, multipath, conn.ConnectionState().SupportsMultipath)
	// The server migrated: it sends from the preferred address.
	require.Equal(t, net.UDPAddrFromAddrPort(preferred).String(), conn.LocalAddr().String())
	recorders := tr.all()
	require.Len(t, recorders, 1)
	require.Eventually(t, func() bool { return len(recorders[0].Events(qlog.ConnectionClosed{})) > 0 }, 5*time.Second, 10*time.Millisecond)
	stats := getPathStats(recorders[0])
	t.Logf("data packets sent per path: %v, received: %v", stats.sentData, stats.rcvdData)
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
}

func TestPicoquicClientPreferredAddress(t *testing.T) { testServerPreferredAddress(t, false) }

func TestPicoquicClientPreferredAddressMultipath(t *testing.T) { testServerPreferredAddress(t, true) }

// serveHQ serves HTTP/0.9 requests for /<n> on a connection, answering with n bytes.
func serveHQ(conn *quic.Conn) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			req, err := io.ReadAll(str)
			if err != nil {
				return
			}
			size, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(string(req)), "GET /"))
			if err != nil {
				str.CancelWrite(42)
				return
			}
			_, _ = io.Copy(str, io.LimitReader(zeroReader{}, int64(size)))
			str.Close()
		}()
	}
}
