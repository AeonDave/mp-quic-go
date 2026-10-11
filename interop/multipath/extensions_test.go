//go:build picoquic

package multipath

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/interop/http09"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

// quicBitConn counts the datagrams sent and received whose first byte has the QUIC Bit (0x40) set to 0.
type quicBitConn struct {
	net.PacketConn

	sent, sentGreased, rcvd, rcvdGreased atomic.Int64
}

func (c *quicBitConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if n > 0 {
		c.rcvd.Add(1)
		if b[0]&0x40 == 0 {
			c.rcvdGreased.Add(1)
		}
	}
	return n, addr, err
}

func (c *quicBitConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > 0 {
		c.sent.Add(1)
		if b[0]&0x40 == 0 {
			c.sentGreased.Add(1)
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *quicBitConn) String() string {
	return fmt.Sprintf("sent %d datagrams (%d with the QUIC Bit set to 0), received %d (%d with the QUIC Bit set to 0)",
		c.sent.Load(), c.sentGreased.Load(), c.rcvd.Load(), c.rcvdGreased.Load())
}

func newQUICBitConn(t *testing.T) *quicBitConn {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	return &quicBitConn{PacketConn: udpConn}
}

// sentResetStreamAt says if a RESET_STREAM_AT frame with the given reliable size was sent.
func sentResetStreamAt(r *events.Recorder, reliableSize int64) bool {
	for _, ev := range r.Events(qlog.PacketSent{}) {
		for _, f := range ev.(qlog.PacketSent).Frames {
			if rs, ok := f.Frame.(*qlog.ResetStreamFrame); ok && int64(rs.ReliableSize) == reliableSize {
				return true
			}
		}
	}
	return false
}

// TestPicoquicServerGreaseQUICBitResetStreamAt runs our client, with greasing the QUIC Bit (RFC 9287) and Stream
// Resets with Partial Delivery enabled, against picoquicdemo's server:
//   - picoquicdemo's server only sends the grease_quic_bit transport parameter if the client sent it, and then
//     greases the QUIC Bit. Both endpoints set the QUIC Bit of their packets to 0 at random.
//   - picoquic sends the reset_stream_at transport parameter with the code point of draft-07 (0x17f7586d2cb571).
//     The client resets a stream with a RESET_STREAM_AT frame.
func TestPicoquicServerGreaseQUICBitResetStreamAt(t *testing.T) {
	setup(t)
	dir := testDir(t)
	server, addr := startServer(t, dir, false)
	tracer := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pconn := newQUICBitConn(t)
	tr := &quic.Transport{Conn: pconn}
	defer tr.Close()
	conn := dial(ctx, t, tr, addr, tracer, func(conf *quic.Config) {
		conf.EnableQUICBitGreasing = true
		conf.EnableStreamResetPartialDelivery = true
	})
	require.True(t, conn.ConnectionState().SupportsQUICBitGreasing.Remote)
	require.True(t, conn.ConnectionState().SupportsStreamResetPartialDelivery.Remote)

	// a request that is reset after it was sent reliably
	const request = "GET /1000\r\n"
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write([]byte(request))
	require.NoError(t, err)
	str.SetReliableBoundary()
	str.CancelWrite(42)
	str.CancelRead(42)

	download(ctx, t, conn, downloadSize)
	require.NoError(t, conn.CloseWithError(0, ""))
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)

	t.Log(pconn)
	require.NotZero(t, pconn.sentGreased.Load())
	require.Less(t, pconn.sentGreased.Load(), pconn.sent.Load())
	require.NotZero(t, pconn.rcvdGreased.Load())
	require.Less(t, pconn.rcvdGreased.Load(), pconn.rcvd.Load())
	require.True(t, sentResetStreamAt(tracer.all()[0], int64(len(request))))
	stats := getPathStats(tracer.all()[0])
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
}

// TestPicoquicClientGreaseQUICBitResetStreamAt runs picoquicdemo's client against our server, with greasing the QUIC
// Bit and Stream Resets with Partial Delivery enabled. picoquicdemo's client doesn't send the grease_quic_bit
// transport parameter, so our server doesn't grease the QUIC Bit. It sends the reset_stream_at transport parameter
// with the code point of draft-07, which our server accepts.
func TestPicoquicClientGreaseQUICBitResetStreamAt(t *testing.T) {
	setup(t)
	dir := testDir(t)
	tracer := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	pconn := newQUICBitConn(t)
	serverTr := &quic.Transport{Conn: pconn}
	defer serverTr.Close()
	conf := multipathConfig(false, tracer)
	conf.EnableQUICBitGreasing = true
	conf.EnableStreamResetPartialDelivery = true
	ln, err := serverTr.ListenEarly(&tls.Config{
		Certificates: []tls.Certificate{loadCertificate(t)},
		NextProtos:   []string{alpn},
	}, conf)
	require.NoError(t, err)
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		size, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			return
		}
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, int64(size)))
	})
	go (&http09.Server{Handler: mux}).ServeListener(ln)

	client := runPicoquic(t, dir, "client",
		"-n", "localhost", "-a", alpn, "-t", "/certs/ca.pem", "-D", "-q", "/work",
		"127.0.0.1", strconv.Itoa(pconn.PacketConn.LocalAddr().(*net.UDPAddr).Port), fmt.Sprintf("/%d", downloadSize),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code, err := client.wait(ctx)
	require.NoError(t, err)
	logs := client.logs()
	require.Zerof(t, code, "picoquicdemo failed:\n%s", logs)
	require.Contains(t, logs, "Client exit with code = 0")
	require.Contains(t, logs, "Quic Bit was NOT greased by the server")

	recorders := tracer.all()
	require.Len(t, recorders, 1)
	require.Eventually(t, func() bool { return len(recorders[0].Events(qlog.ConnectionClosed{})) > 0 }, 5*time.Second, 10*time.Millisecond)
	var remoteParams *qlog.ParametersSet
	for _, ev := range recorders[0].Events(qlog.ParametersSet{}) {
		if ev := ev.(qlog.ParametersSet); ev.Initiator == qlog.InitiatorRemote {
			remoteParams = &ev
		}
	}
	require.NotNil(t, remoteParams)
	require.True(t, remoteParams.EnableResetStreamAt)
	require.False(t, remoteParams.GreaseQUICBit)
	t.Log(pconn)
	require.Zero(t, pconn.sentGreased.Load())
	require.Zero(t, pconn.rcvdGreased.Load())
}
