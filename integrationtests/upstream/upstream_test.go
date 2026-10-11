// Package upstream tests that mp-quic-go interoperates with upstream quic-go, using standard (single-path) QUIC.
// The mp-quic-go endpoints are configured for IETF Multipath QUIC. Upstream quic-go doesn't support the extension,
// so it must not be used (section 2 of draft-ietf-quic-multipath-21).
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	mpquic "github.com/AeonDave/mp-quic-go"
	mphttp3 "github.com/AeonDave/mp-quic-go/http3"
	"github.com/AeonDave/mp-quic-go/integrationtests/tools"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

var (
	serverTLSConf *tls.Config
	clientTLSConf *tls.Config
)

func init() {
	ca, caKey, err := tools.GenerateCA()
	if err != nil {
		panic(err)
	}
	leaf, leafKey, err := tools.GenerateLeafCert(ca, caKey)
	if err != nil {
		panic(err)
	}
	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}},
		NextProtos:   []string{tools.ALPN},
	}
	root := x509.NewCertPool()
	root.AddCert(ca)
	clientTLSConf = &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{tools.ALPN},
	}
}

func newUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// mpConfig returns a config for mp-quic-go with a multipath controller.
// Greasing the QUIC Bit is enabled, but not used, since upstream quic-go doesn't support it.
// The connections record their qlog events in the returned recorders.
func mpConfig(recorders chan<- *events.Recorder) *mpquic.Config {
	return &mpquic.Config{
		Allow0RTT:                        true,
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		EnableQUICBitGreasing:            true,
		MultipathControllerFactory: func() mpquic.MultipathController {
			return mpquic.NewDefaultMultipathController(nil)
		},
		Tracer: func(context.Context, bool, mpquic.ConnectionID) qlogwriter.Trace {
			r := &events.Recorder{}
			recorders <- r
			return &events.Trace{Recorder: r}
		},
	}
}

func upstreamConfig() *quic.Config {
	return &quic.Config{Allow0RTT: true, EnableDatagrams: true, EnableStreamResetPartialDelivery: true}
}

// A stream is a bidirectional stream of either implementation.
// Close closes the send direction.
type stream interface {
	io.ReadWriteCloser
}

// A conn is a connection of either implementation.
type conn interface {
	OpenStream(context.Context) (stream, error)
	AcceptStream(context.Context) (stream, error)
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Used0RTT() bool
	HandshakeComplete() <-chan struct{}
	CloseWithError(uint64, string) error
	Done() <-chan struct{}
}

type mpConn struct{ *mpquic.Conn }

func (c mpConn) OpenStream(ctx context.Context) (stream, error) { return c.OpenStreamSync(ctx) }

func (c mpConn) AcceptStream(ctx context.Context) (stream, error) { return c.Conn.AcceptStream(ctx) }

func (c mpConn) Used0RTT() bool        { return c.ConnectionState().Used0RTT }
func (c mpConn) Done() <-chan struct{} { return c.Context().Done() }

func (c mpConn) CloseWithError(code uint64, msg string) error {
	return c.Conn.CloseWithError(mpquic.ApplicationErrorCode(code), msg)
}

type upConn struct{ *quic.Conn }

func (c upConn) OpenStream(ctx context.Context) (stream, error) { return c.OpenStreamSync(ctx) }

func (c upConn) AcceptStream(ctx context.Context) (stream, error) { return c.Conn.AcceptStream(ctx) }

func (c upConn) Used0RTT() bool        { return c.ConnectionState().Used0RTT }
func (c upConn) Done() <-chan struct{} { return c.Context().Done() }

func (c upConn) CloseWithError(code uint64, msg string) error {
	return c.Conn.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// echo echoes the data of every stream, and every datagram, until the connection is closed.
func echo(c conn) {
	go func() {
		for {
			b, err := c.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			_ = c.SendDatagram(b)
		}
	}()
	for {
		str, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer str.Close()
			_, _ = io.Copy(str, str)
		}()
	}
}

// A server is a server of either implementation, that echoes streams and datagrams.
type server struct {
	addr  net.Addr
	conns chan conn
}

func runMPServer(t *testing.T, recorders chan<- *events.Recorder) *server {
	t.Helper()
	tr := &mpquic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr.Close() })
	ln, err := tr.ListenEarly(serverTLSConf, mpConfig(recorders))
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	s := &server{addr: ln.Addr(), conns: make(chan conn, 10)}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			s.conns <- mpConn{c}
			go echo(mpConn{c})
		}
	}()
	return s
}

func runUpstreamServer(t *testing.T) *server {
	t.Helper()
	tr := &quic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr.Close() })
	ln, err := tr.ListenEarly(serverTLSConf, upstreamConfig())
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	s := &server{addr: ln.Addr(), conns: make(chan conn, 10)}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			s.conns <- upConn{c}
			go echo(upConn{c})
		}
	}()
	return s
}

type dialFunc func(ctx context.Context, t *testing.T, addr net.Addr, tlsConf *tls.Config) (conn, error)

func dialMP(recorders chan<- *events.Recorder) dialFunc {
	return func(ctx context.Context, t *testing.T, addr net.Addr, tlsConf *tls.Config) (conn, error) {
		tr := &mpquic.Transport{Conn: newUDPConn(t)}
		t.Cleanup(func() { tr.Close() })
		c, err := tr.DialEarly(ctx, addr, tlsConf, mpConfig(recorders))
		if err != nil {
			return nil, err
		}
		return mpConn{c}, nil
	}
}

func dialUpstream(ctx context.Context, t *testing.T, addr net.Addr, tlsConf *tls.Config) (conn, error) {
	tr := &quic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr.Close() })
	c, err := tr.DialEarly(ctx, addr, tlsConf, upstreamConfig())
	if err != nil {
		return nil, err
	}
	return upConn{c}, nil
}

// echoData sends data on a new stream, and checks that it's echoed.
func echoData(ctx context.Context, c conn, data []byte) error {
	str, err := c.OpenStream(ctx)
	if err != nil {
		return err
	}
	errChan := make(chan error, 1)
	go func() {
		_, err := str.Write(data)
		if err == nil {
			err = str.Close()
		}
		errChan <- err
	}()
	echoed, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	if err := <-errChan; err != nil {
		return err
	}
	if !bytes.Equal(data, echoed) {
		return errors.New("echoed data doesn't match")
	}
	return nil
}

// resetStreamAt sends data on a new stream, marks it as reliable and resets the stream (RESET_STREAM_AT,
// draft-ietf-quic-reliable-stream-reset). It checks that the reliable data is echoed.
func resetStreamAt(ctx context.Context, c conn, data []byte) error {
	str, err := c.OpenStream(ctx)
	if err != nil {
		return err
	}
	if _, err := str.Write(data); err != nil {
		return err
	}
	switch str := str.(type) {
	case *mpquic.Stream:
		if !c.(mpConn).ConnectionState().SupportsStreamResetPartialDelivery.Remote {
			return errors.New("peer doesn't support RESET_STREAM_AT")
		}
		str.SetReliableBoundary()
		str.CancelWrite(42)
	case *quic.Stream:
		if !c.(upConn).ConnectionState().SupportsStreamResetPartialDelivery.Remote {
			return errors.New("peer doesn't support RESET_STREAM_AT")
		}
		str.SetReliableBoundary()
		str.CancelWrite(42)
	default:
		return fmt.Errorf("unexpected stream type %T", str)
	}
	// The echo server reads the reliable data, and closes the stream when it reads the reset error.
	echoed, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, echoed) {
		return fmt.Errorf("echoed data doesn't match (%d bytes, expected %d)", len(echoed), len(data))
	}
	return nil
}

// echoDatagram sends a datagram until it is echoed.
func echoDatagram(ctx context.Context, c conn, data []byte) error {
	for {
		if err := c.SendDatagram(data); err != nil {
			return err
		}
		rctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		b, err := c.ReceiveDatagram(rctx)
		cancel()
		if err == nil {
			if !bytes.Equal(b, data) {
				return fmt.Errorf("unexpected datagram: %q", b)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func countKeyUpdates(r *events.Recorder) int {
	var n int
	for _, ev := range r.Events(qlog.KeyUpdated{}) {
		if ev := ev.(qlog.KeyUpdated); ev.KeyType == qlog.KeyTypeClient1RTT && ev.Trigger != qlog.KeyUpdateTLS {
			n++
		}
	}
	return n
}

// requireStandardQUIC checks that an mp-quic-go connection advertised IETF Multipath QUIC,
// but didn't use it: no frames of the extension were sent or received.
// It also advertised greasing the QUIC Bit, which upstream quic-go doesn't support.
func requireStandardQUIC(t *testing.T, r *events.Recorder) {
	t.Helper()
	var advertised bool
	for _, ev := range r.Events() {
		var frames []qlog.Frame
		switch ev := ev.(type) {
		case qlog.ParametersSet:
			if ev.Initiator == qlog.InitiatorLocal && !ev.Restore {
				advertised = ev.InitialMaxPathID != nil
				require.True(t, ev.GreaseQUICBit)
			}
			if ev.Initiator == qlog.InitiatorRemote {
				require.Nil(t, ev.InitialMaxPathID)
				require.False(t, ev.GreaseQUICBit)
			}
			continue
		case qlog.PacketSent:
			require.False(t, ev.Header.HasPathID)
			frames = ev.Frames
		case qlog.PacketReceived:
			require.False(t, ev.Header.HasPathID)
			frames = ev.Frames
		default:
			continue
		}
		for _, f := range frames {
			switch f := f.Frame.(type) {
			case *qlog.AckFrame:
				require.False(t, f.HasPathID)
			case *qlog.PathAbandonFrame, *qlog.PathStatusFrame, *qlog.PathNewConnectionIDFrame,
				*qlog.PathRetireConnectionIDFrame, *qlog.MaxPathIDFrame, *qlog.PathsBlockedFrame, *qlog.PathCIDsBlockedFrame:
				t.Fatalf("multipath frame: %#v", f)
			}
		}
	}
	require.True(t, advertised, "initial_max_path_id not sent")
}

// testInterop runs a handshake, a transfer with key updates and datagrams, and then resumes the session using 0-RTT.
func testInterop(t *testing.T, s *server, dial dialFunc, recorders <-chan *events.Recorder) {
	reset := handshake.SetKeyUpdateInterval(100)
	t.Cleanup(reset)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsConf := clientTLSConf.Clone()
	tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(10)

	c, err := dial(ctx, t, s.addr, tlsConf)
	require.NoError(t, err)
	select {
	case <-c.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("handshake timed out")
	}
	require.False(t, c.Used0RTT())
	if mc, ok := c.(mpConn); ok {
		require.False(t, mc.ConnectionState().SupportsMultipath)
		require.Nil(t, mc.Paths())
	}
	data := make([]byte, 2<<20)
	for i := range data {
		data[i] = byte(i % 251)
	}
	require.NoError(t, echoData(ctx, c, data))
	require.NoError(t, resetStreamAt(ctx, c, data[:100<<10]))
	require.NoError(t, echoDatagram(ctx, c, []byte("datagram")))
	require.NoError(t, c.CloseWithError(0, ""))
	var serverConn conn
	select {
	case serverConn = <-s.conns:
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	select {
	case <-serverConn.Done():
	case <-ctx.Done():
		t.Fatal("timeout waiting for the server to close the connection")
	}

	// resume the session, sending data in 0-RTT packets
	c, err = dial(ctx, t, s.addr, tlsConf)
	require.NoError(t, err)
	require.NoError(t, echoData(ctx, c, []byte("0-RTT data")))
	require.True(t, c.Used0RTT())
	require.NoError(t, echoDatagram(ctx, c, []byte("datagram")))
	require.NoError(t, c.CloseWithError(0, ""))
	select {
	case serverConn = <-s.conns:
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	select {
	case <-serverConn.Done():
	case <-ctx.Done():
		t.Fatal("timeout waiting for the server to close the connection")
	}

	// the mp-quic-go endpoint didn't use IETF Multipath QUIC
	for i := range 2 {
		var r *events.Recorder
		select {
		case r = <-recorders:
		case <-ctx.Done():
			t.Fatal("missing qlog recorder")
		}
		requireStandardQUIC(t, r)
		if i == 0 {
			t.Logf("%d key updates", countKeyUpdates(r))
			require.GreaterOrEqual(t, countKeyUpdates(r), 2)
		}
	}
}

func TestUpstreamServer(t *testing.T) {
	recorders := make(chan *events.Recorder, 10)
	testInterop(t, runUpstreamServer(t), dialMP(recorders), recorders)
}

func TestUpstreamClient(t *testing.T) {
	recorders := make(chan *events.Recorder, 10)
	testInterop(t, runMPServer(t, recorders), dialUpstream, recorders)
}

const httpBody = "Hello, HTTP/3!"

func httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, httpBody)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	})
	return mux
}

func testHTTP3(t *testing.T, addr net.Addr, client *http.Client) {
	t.Helper()
	resp, err := client.Get(fmt.Sprintf("https://localhost:%d/hello", addr.(*net.UDPAddr).Port))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, httpBody, string(body))
	require.Equal(t, "HTTP/3.0", resp.Proto)

	data := bytes.Repeat([]byte("upload"), 100<<10)
	resp, err = client.Post(fmt.Sprintf("https://localhost:%d/echo", addr.(*net.UDPAddr).Port), "application/octet-stream", bytes.NewReader(data))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, data, body)
}

func h3TLSConfigs() (server, client *tls.Config) {
	server = serverTLSConf.Clone()
	server.NextProtos = []string{http3.NextProtoH3}
	client = clientTLSConf.Clone()
	client.NextProtos = []string{http3.NextProtoH3}
	return server, client
}

// An HTTP/3 client of mp-quic-go sends requests to an HTTP/3 server of upstream quic-go.
func TestUpstreamHTTP3Server(t *testing.T) {
	serverTLS, clientTLS := h3TLSConfigs()
	conn := newUDPConn(t)
	srv := &http3.Server{Handler: httpHandler(), TLSConfig: serverTLS}
	go srv.Serve(conn)
	defer srv.Close()

	recorders := make(chan *events.Recorder, 10)
	tr := &mphttp3.Transport{TLSClientConfig: clientTLS, QUICConfig: mpConfig(recorders)}
	defer tr.Close()
	testHTTP3(t, conn.LocalAddr(), &http.Client{Transport: tr, Timeout: 10 * time.Second})
	requireStandardQUIC(t, <-recorders)
}

// An HTTP/3 client of upstream quic-go sends requests to an HTTP/3 server of mp-quic-go.
func TestUpstreamHTTP3Client(t *testing.T) {
	serverTLS, clientTLS := h3TLSConfigs()
	conn := newUDPConn(t)
	recorders := make(chan *events.Recorder, 10)
	srv := &mphttp3.Server{Handler: httpHandler(), TLSConfig: serverTLS, QUICConfig: mpConfig(recorders)}
	go srv.Serve(conn)
	defer srv.Close()

	tr := &http3.Transport{TLSClientConfig: clientTLS, QUICConfig: upstreamConfig()}
	defer tr.Close()
	testHTTP3(t, conn.LocalAddr(), &http.Client{Transport: tr, Timeout: 10 * time.Second})
	requireStandardQUIC(t, <-recorders)
}

// Upstream quic-go clients ignore the preferred_address transport parameter: they keep using the server address
// they connected to.
func TestUpstreamClientPreferredAddress(t *testing.T) {
	prefConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 not available: %s", err)
	}
	prefTr := &mpquic.Transport{Conn: prefConn}
	t.Cleanup(func() { prefTr.Close() })
	preferred := prefConn.LocalAddr().(*net.UDPAddr).AddrPort()
	tr := &mpquic.Transport{
		Conn:             newUDPConn(t),
		PreferredAddress: &mpquic.PreferredAddress{IPv6: preferred, IPv6Transport: prefTr},
	}
	t.Cleanup(func() { tr.Close() })
	recorders := make(chan *events.Recorder, 10)
	ln, err := tr.Listen(serverTLSConf, mpConfig(recorders))
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go echo(mpConn{c})
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientTr := &quic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { clientTr.Close() })
	c, err := clientTr.Dial(ctx, ln.Addr(), clientTLSConf, upstreamConfig())
	require.NoError(t, err)
	defer c.CloseWithError(0, "")
	require.NoError(t, echoData(ctx, upConn{c}, make([]byte, 1<<20)))
	require.Equal(t, ln.Addr().String(), c.RemoteAddr().String())

	var r *events.Recorder
	select {
	case r = <-recorders:
	case <-ctx.Done():
		t.Fatal("missing qlog recorder")
	}
	var sentPreferredAddr bool
	for _, ev := range r.Events(qlog.ParametersSet{}) {
		if ps := ev.(qlog.ParametersSet); ps.Initiator == qlog.InitiatorLocal && ps.PreferredAddress != nil {
			require.Equal(t, preferred, ps.PreferredAddress.IPv6)
			sentPreferredAddr = true
		}
	}
	require.True(t, sentPreferredAddr)
}

// lastSentDestConnID returns the destination connection ID of the last 1-RTT packet that was sent.
func lastSentDestConnID(t *testing.T, r *events.Recorder) mpquic.ConnectionID {
	t.Helper()
	evs := r.Events(qlog.PacketSent{})
	for i := len(evs) - 1; i >= 0; i-- {
		if ev := evs[i].(qlog.PacketSent); ev.Header.PacketType == qlog.PacketType1RTT {
			return ev.Header.DestConnectionID
		}
	}
	t.Fatal("no 1-RTT packet sent")
	return mpquic.ConnectionID{}
}

// An upstream quic-go client migrates to a new path (RFC 9000 connection migration).
// The mp-quic-go server follows it, and uses a new connection ID on the new path.
func TestUpstreamClientMigration(t *testing.T) {
	recorders := make(chan *events.Recorder, 10)
	s := runMPServer(t, recorders)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr1 := &quic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr1.Close() })
	c, err := tr1.Dial(ctx, s.addr, clientTLSConf, upstreamConfig())
	require.NoError(t, err)
	defer c.CloseWithError(0, "")
	data := make([]byte, 1<<20)
	require.NoError(t, echoData(ctx, upConn{c}, data))
	sconn := (<-s.conns).(mpConn)
	r := <-recorders
	connIDBefore := lastSentDestConnID(t, r)

	tr2 := &quic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr2.Close() })
	path, err := c.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	require.NoError(t, echoData(ctx, upConn{c}, data))
	require.Equal(t, tr2.Conn.LocalAddr().String(), sconn.RemoteAddr().String())
	require.NotEqual(t, connIDBefore, lastSentDestConnID(t, r))
	requireStandardQUIC(t, r)
}

// An mp-quic-go client migrates to a new path, with an upstream quic-go server.
func TestUpstreamServerMigration(t *testing.T) {
	s := runUpstreamServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recorders := make(chan *events.Recorder, 10)
	tr1 := &mpquic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr1.Close() })
	c, err := tr1.Dial(ctx, s.addr, clientTLSConf, mpConfig(recorders))
	require.NoError(t, err)
	defer c.CloseWithError(0, "")
	data := make([]byte, 1<<20)
	require.NoError(t, echoData(ctx, mpConn{c}, data))
	sconn := (<-s.conns).(upConn)
	r := <-recorders
	connIDBefore := lastSentDestConnID(t, r)

	tr2 := &mpquic.Transport{Conn: newUDPConn(t)}
	t.Cleanup(func() { tr2.Close() })
	path, err := c.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	require.NoError(t, echoData(ctx, mpConn{c}, data))
	require.Equal(t, tr2.Conn.LocalAddr().String(), sconn.RemoteAddr().String())
	require.NotEqual(t, connIDBefore, lastSentDestConnID(t, r))
	requireStandardQUIC(t, r)
}
