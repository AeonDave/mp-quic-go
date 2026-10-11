package versionnegotiation

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func tracerFor(r *events.Recorder) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	return func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return &events.Trace{Recorder: r}
	}
}

func containsCryptoFrame(frames []qlog.Frame) bool {
	for _, f := range frames {
		if _, ok := f.Frame.(*qlog.CryptoFrame); ok {
			return true
		}
	}
	return false
}

type sentLongHeaderPacket struct {
	Type    qlog.PacketType
	Version protocol.Version
	Crypto  bool
}

func sentLongHeaderPackets(r *events.Recorder) []sentLongHeaderPacket {
	var packets []sentLongHeaderPacket
	for _, ev := range r.Events(qlog.PacketSent{}) {
		p := ev.(qlog.PacketSent)
		switch p.Header.PacketType {
		case qlog.PacketTypeInitial, qlog.PacketTypeHandshake, qlog.PacketType0RTT:
			packets = append(packets, sentLongHeaderPacket{
				Type:    p.Header.PacketType,
				Version: p.Header.Version,
				Crypto:  containsCryptoFrame(p.Frames),
			})
		}
	}
	return packets
}

// requireEcho opens a stream, and checks that the peer echoes the data.
func requireEcho(t *testing.T, conn *quic.Conn) {
	t.Helper()
	str, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
}

// closeConnsOnCleanup closes the connections when the test ends, and waits until they are closed.
// Some tests modify protocol.SupportedVersions, so no connection must outlive the test.
func closeConnsOnCleanup(t *testing.T) func(*quic.Conn) {
	t.Helper()
	var mx sync.Mutex
	var conns []*quic.Conn
	t.Cleanup(func() {
		mx.Lock()
		defer mx.Unlock()
		for _, conn := range conns {
			conn.CloseWithError(0, "")
			select {
			case <-conn.Context().Done():
			case <-time.After(5 * time.Second):
				t.Error("timeout waiting for the connection to close")
			}
		}
	})
	return func(conn *quic.Conn) {
		mx.Lock()
		defer mx.Unlock()
		conns = append(conns, conn)
	}
}

// runEchoServer accepts connections and echoes the data of all streams.
// It returns the server-side connections.
func runEchoServer(t *testing.T, ln *quic.Listener) <-chan *quic.Conn {
	t.Helper()
	track := closeConnsOnCleanup(t)
	conns := make(chan *quic.Conn, 10)
	done := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			track(conn)
			conns <- conn
			go func() {
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						defer str.Close()
						_, _ = io.Copy(str, str)
					}()
				}
			}()
		}
	}()
	return conns
}

func TestCompatibleVersionNegotiation(t *testing.T) {
	t.Run("from version 1 to version 2", func(t *testing.T) {
		testCompatibleVersionNegotiation(t, quic.Version1, quic.Version2)
	})
	t.Run("from version 2 to version 1", func(t *testing.T) {
		testCompatibleVersionNegotiation(t, quic.Version2, quic.Version1)
	})
}

func testCompatibleVersionNegotiation(t *testing.T, chosen, negotiated quic.Version) {
	var serverEvents, clientEvents events.Recorder
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{negotiated, chosen},
		Tracer:   tracerFor(&serverEvents),
	}))
	require.NoError(t, err)
	defer ln.Close()
	serverConns := runEchoServer(t, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{chosen, negotiated},
		Tracer:   tracerFor(&clientEvents),
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	requireEcho(t, conn)

	require.Equal(t, negotiated, conn.ConnectionState().Version)
	var sconn *quic.Conn
	select {
	case sconn = <-serverConns:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Equal(t, negotiated, sconn.ConnectionState().Version)
	require.NoError(t, conn.CloseWithError(0, ""))
	select {
	case <-sconn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// no round trip was needed for version negotiation
	require.Empty(t, clientEvents.Events(qlog.VersionNegotiationReceived{}))
	// The client's first flight uses the Chosen Version.
	clientPackets := sentLongHeaderPackets(&clientEvents)
	require.NotEmpty(t, clientPackets)
	require.Equal(t, sentLongHeaderPacket{Type: qlog.PacketTypeInitial, Version: chosen, Crypto: true}, clientPackets[0])
	var clientSentNegotiated bool
	for _, p := range clientPackets {
		switch p.Type {
		case qlog.PacketTypeHandshake:
			require.Equal(t, negotiated, p.Version)
			clientSentNegotiated = true
		case qlog.PacketTypeInitial:
			if p.Version == negotiated {
				clientSentNegotiated = true
			} else {
				// once the client learned the Negotiated Version, it sends all packets using that version
				require.False(t, clientSentNegotiated, "client sent Initial packet using the Chosen Version after switching")
			}
		}
	}
	require.True(t, clientSentNegotiated)
	// The server sends all CRYPTO frames and all Handshake packets using the Negotiated Version.
	serverPackets := sentLongHeaderPackets(&serverEvents)
	require.NotEmpty(t, serverPackets)
	for _, p := range serverPackets {
		if p.Crypto || p.Type == qlog.PacketTypeHandshake {
			require.Equal(t, negotiated, p.Version)
		}
	}
	// the Version Information events
	clientVersionInfo := clientEvents.Events(qlog.VersionInformation{})
	require.Equal(t, qlog.VersionInformation{ClientVersions: []quic.Version{chosen, negotiated}, ChosenVersion: negotiated}, clientVersionInfo[len(clientVersionInfo)-1])
	serverVersionInfo := serverEvents.Events(qlog.VersionInformation{})
	require.Equal(t, qlog.VersionInformation{ServerVersions: []quic.Version{negotiated, chosen}, ChosenVersion: negotiated}, serverVersionInfo[len(serverVersionInfo)-1])
}

func TestCompatibleVersionNegotiationServerDefaultConfig(t *testing.T) {
	// If the server's versions are not configured, the server uses the client's Chosen Version.
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(nil))
	require.NoError(t, err)
	defer ln.Close()
	serverConns := runEchoServer(t, ln)

	for _, versions := range [][]quic.Version{
		{quic.Version1, quic.Version2},
		{quic.Version2, quic.Version1},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{Versions: versions}))
		cancel()
		require.NoError(t, err)
		requireEcho(t, conn)
		require.Equal(t, versions[0], conn.ConnectionState().Version)
		sconn := <-serverConns
		require.Equal(t, versions[0], sconn.ConnectionState().Version)
		require.NoError(t, conn.CloseWithError(0, ""))
	}
}

func TestCompatibleVersionNegotiationWithRetry(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{
		Conn:                udpConn,
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	defer tr.Close()
	var serverEvents, clientEvents events.Recorder
	ln, err := tr.Listen(getTLSConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
		Tracer:   tracerFor(&serverEvents),
	}))
	require.NoError(t, err)
	defer ln.Close()
	runEchoServer(t, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, udpConn.LocalAddr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version1, quic.Version2},
		Tracer:   tracerFor(&clientEvents),
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	requireEcho(t, conn)
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)

	// The Retry is sent using the Chosen Version (section 4.1 of RFC 9369),
	// and the Initial carrying the Retry token uses the Chosen Version as well.
	var receivedRetry, checkedInitial bool
	for _, ev := range clientEvents.Events() {
		switch ev := ev.(type) {
		case qlog.PacketReceived:
			if ev.Header.PacketType == qlog.PacketTypeRetry {
				require.False(t, receivedRetry)
				receivedRetry = true
				require.Equal(t, quic.Version1, ev.Header.Version)
			}
		case qlog.PacketSent:
			if receivedRetry && !checkedInitial && ev.Header.PacketType == qlog.PacketTypeInitial {
				checkedInitial = true
				require.Equal(t, quic.Version1, ev.Header.Version)
			}
		}
	}
	require.True(t, receivedRetry)
	require.True(t, checkedInitial)
}

func TestCompatibleVersionNegotiationWith0RTT(t *testing.T) {
	tlsConf := getTLSConfig().Clone()
	var mx sync.Mutex
	serverVersions := []quic.Version{quic.Version1, quic.Version2}
	ln, err := quic.ListenAddrEarly("localhost:0", tlsConf, maybeAddQLOGTracer(&quic.Config{
		Allow0RTT: true,
		GetConfigForClient: func(*quic.ClientInfo) (*quic.Config, error) {
			mx.Lock()
			defer mx.Unlock()
			return maybeAddQLOGTracer(&quic.Config{Allow0RTT: true, Versions: serverVersions}), nil
		},
	}))
	require.NoError(t, err)
	defer ln.Close()
	track := closeConnsOnCleanup(t)
	serverConns := make(chan *quic.Conn, 2)
	acceptDone := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-acceptDone
	})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			track(conn)
			serverConns <- conn
		}
	}()

	clientTLSConf := getTLSClientConfig().Clone()
	sessionCache := newNotifyingSessionCache()
	clientTLSConf.ClientSessionCache = sessionCache
	clientConf := &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}}

	// The first connection uses version 1, and obtains a session ticket.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), clientTLSConf, maybeAddQLOGTracer(clientConf))
	require.NoError(t, err)
	require.Equal(t, quic.Version1, conn.ConnectionState().Version)
	<-serverConns
	// wait for the session ticket to arrive
	select {
	case <-sessionCache.puts:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for the session ticket")
	}
	require.NoError(t, conn.CloseWithError(0, ""))

	// The second connection resumes the session, sends 0-RTT data, and is switched to version 2.
	mx.Lock()
	serverVersions = []quic.Version{quic.Version2, quic.Version1}
	mx.Unlock()
	var clientEvents events.Recorder
	conf := clientConf.Clone()
	conf.Tracer = tracerFor(&clientEvents)
	conn, err = quic.DialAddrEarly(ctx, ln.Addr().String(), clientTLSConf, maybeAddQLOGTracer(conf))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("0-RTT data"))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	sconn := <-serverConns
	sstr, err := sconn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(sstr)
	require.NoError(t, err)
	require.Equal(t, []byte("0-RTT data"), data)
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.True(t, conn.ConnectionState().Used0RTT)
	require.True(t, sconn.ConnectionState().Used0RTT)
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)
	require.Equal(t, quic.Version2, sconn.ConnectionState().Version)

	// 0-RTT packets are always sent using the Chosen Version (section 4.1 of RFC 9369).
	var num0RTT int
	for _, p := range sentLongHeaderPackets(&clientEvents) {
		if p.Type == qlog.PacketType0RTT {
			num0RTT++
			require.Equal(t, quic.Version1, p.Version)
		}
	}
	require.NotZero(t, num0RTT)
}

type notifyingSessionCache struct {
	tls.ClientSessionCache
	puts chan struct{}
}

func newNotifyingSessionCache() *notifyingSessionCache {
	return &notifyingSessionCache{
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
		puts:               make(chan struct{}, 10),
	}
}

func (c *notifyingSessionCache) Put(key string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	select {
	case c.puts <- struct{}{}:
	default:
	}
}

// Incompatible version negotiation followed by compatible version negotiation,
// see figure 1 of RFC 9368.
func TestIncompatibleFollowedByCompatibleVersionNegotiation(t *testing.T) {
	const unsupportedVersion protocol.Version = 0x1a1a1a1b // not a reserved version
	supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
	protocol.SupportedVersions = append(protocol.SupportedVersions, unsupportedVersion)
	defer func() { protocol.SupportedVersions = supportedVersions }()

	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
	}))
	require.NoError(t, err)
	defer ln.Close()
	runEchoServer(t, ln)

	var clientEvents events.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{unsupportedVersion, quic.Version1, quic.Version2},
		Tracer:   tracerFor(&clientEvents),
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	requireEcho(t, conn)
	require.Len(t, clientEvents.Events(qlog.VersionNegotiationReceived{}), 1)
	// The client selects version 1 from the Version Negotiation packet,
	// and the server then switches to version 2.
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)
	versionInfo := clientEvents.Events(qlog.VersionInformation{})
	require.Len(t, versionInfo, 2)
	require.Equal(t, quic.Version1, versionInfo[0].(qlog.VersionInformation).ChosenVersion)
	require.Equal(t, quic.Version2, versionInfo[1].(qlog.VersionInformation).ChosenVersion)
}

// downgradeRelay relays packets between a client and a server.
// It drops the client's first packet, and responds with a forged Version Negotiation packet.
type downgradeRelay struct {
	conn       *net.UDPConn
	serverConn *net.UDPConn
	versions   []protocol.Version

	mx         sync.Mutex
	clientAddr net.Addr
}

func newDowngradeRelay(t *testing.T, serverAddr net.Addr, versions []protocol.Version) *downgradeRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverConn, err := net.DialUDP("udp", nil, serverAddr.(*net.UDPAddr))
	require.NoError(t, err)
	r := &downgradeRelay{conn: conn, serverConn: serverConn, versions: versions}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.runClientSide()
	}()
	go func() {
		defer wg.Done()
		r.runServerSide()
	}()
	t.Cleanup(func() {
		conn.Close()
		serverConn.Close()
		wg.Wait()
	})
	return r
}

func (r *downgradeRelay) runClientSide() {
	var forged bool
	b := make([]byte, 2000)
	for {
		n, addr, err := r.conn.ReadFrom(b)
		if err != nil {
			return
		}
		if !forged {
			forged = true
			r.mx.Lock()
			r.clientAddr = addr
			r.mx.Unlock()
			_, dest, src, err := wire.ParseArbitraryLenConnectionIDs(b[:n])
			if err != nil {
				panic(err)
			}
			// the Version Negotiation packet echoes the connection IDs
			r.conn.WriteTo(wire.ComposeVersionNegotiation(src, dest, r.versions), addr)
			continue
		}
		r.serverConn.Write(b[:n])
	}
}

func (r *downgradeRelay) runServerSide() {
	b := make([]byte, 2000)
	for {
		n, err := r.serverConn.Read(b)
		if err != nil {
			return
		}
		r.mx.Lock()
		addr := r.clientAddr
		r.mx.Unlock()
		r.conn.WriteTo(b[:n], addr)
	}
}

func TestVersionDowngradePrevention(t *testing.T) {
	for _, tc := range []struct {
		name           string
		serverVersions []quic.Version
	}{
		{name: "server keeps the version", serverVersions: []quic.Version{quic.Version1, quic.Version2}},
		{name: "server switches the version", serverVersions: []quic.Version{quic.Version2, quic.Version1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(&quic.Config{Versions: tc.serverVersions}))
			require.NoError(t, err)
			defer ln.Close()
			runEchoServer(t, ln)

			// The client prefers version 2, which is supported by the server.
			// An attacker forges a Version Negotiation packet that only lists version 1.
			relay := newDowngradeRelay(t, ln.Addr(), []protocol.Version{quic.Version1})
			var clientEvents events.Recorder
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = quic.DialAddr(ctx, relay.conn.LocalAddr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
				Versions: []quic.Version{quic.Version2, quic.Version1},
				Tracer:   tracerFor(&clientEvents),
			}))
			require.Error(t, err)
			var transportErr *quic.TransportError
			require.True(t, errors.As(err, &transportErr), "unexpected error: %v", err)
			require.Equal(t, quic.VersionNegotiationErrorCode, transportErr.ErrorCode)
			require.False(t, transportErr.Remote)
			require.Len(t, clientEvents.Events(qlog.VersionNegotiationReceived{}), 1)
		})
	}
}

// Without an attacker, a Version Negotiation packet listing only version 1 is legitimate,
// as long as the server's Available Versions confirm it.
func TestVersionNegotiationToVersion1(t *testing.T) {
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version1},
	}))
	require.NoError(t, err)
	defer ln.Close()
	runEchoServer(t, ln)

	var clientEvents events.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
		Tracer:   tracerFor(&clientEvents),
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	requireEcho(t, conn)
	require.Equal(t, quic.Version1, conn.ConnectionState().Version)
	require.Len(t, clientEvents.Events(qlog.VersionNegotiationReceived{}), 1)
}

// Session tickets are specific to a QUIC version (section 5 of RFC 9369).
// After compatible version negotiation, a ticket belongs to the Negotiated Version.
func TestSessionResumptionScopedToVersion(t *testing.T) {
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
	}))
	require.NoError(t, err)
	defer ln.Close()
	runEchoServer(t, ln)

	tlsConf := getTLSClientConfig().Clone()
	sessionCache := newNotifyingSessionCache()
	tlsConf.ClientSessionCache = sessionCache
	dial := func(versions ...quic.Version) *quic.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, ln.Addr().String(), tlsConf, maybeAddQLOGTracer(&quic.Config{Versions: versions}))
		require.NoError(t, err)
		requireEcho(t, conn)
		return conn
	}

	// The first connection starts with version 1, and is switched to version 2.
	conn := dial(quic.Version1, quic.Version2)
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)
	require.False(t, conn.ConnectionState().TLS.DidResume)
	select {
	case <-sessionCache.puts:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for the session ticket")
	}
	require.NoError(t, conn.CloseWithError(0, ""))

	// The ticket is not used for a connection starting with version 1...
	conn = dial(quic.Version1, quic.Version2)
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)
	require.False(t, conn.ConnectionState().TLS.DidResume)
	require.NoError(t, conn.CloseWithError(0, ""))

	// ... but for a connection starting with version 2.
	conn = dial(quic.Version2, quic.Version1)
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)
	require.True(t, conn.ConnectionState().TLS.DidResume)
	require.NoError(t, conn.CloseWithError(0, ""))
}

// The server selects the Negotiated Version using the client's first ClientHello,
// and sends the HelloRetryRequest using the Negotiated Version.
func TestCompatibleVersionNegotiationWithHelloRetryRequest(t *testing.T) {
	tlsConf := getTLSConfig().Clone()
	// the client doesn't send a key share for P-384
	tlsConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
	cert := tlsConf.Certificates[0]
	tlsConf.Certificates = nil
	var helloRetryRequest atomic.Bool
	tlsConf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		helloRetryRequest.Store(info.HelloRetryRequest)
		return &cert, nil
	}
	var serverEvents events.Recorder
	ln, err := quic.ListenAddr("localhost:0", tlsConf, maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
		Tracer:   tracerFor(&serverEvents),
	}))
	require.NoError(t, err)
	defer ln.Close()
	serverConns := runEchoServer(t, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
		Versions: []quic.Version{quic.Version1, quic.Version2},
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	requireEcho(t, conn)
	require.True(t, helloRetryRequest.Load())
	require.Equal(t, quic.Version2, conn.ConnectionState().Version)
	var sconn *quic.Conn
	select {
	case sconn = <-serverConns:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Equal(t, quic.Version2, sconn.ConnectionState().Version)
	require.NoError(t, conn.CloseWithError(0, ""))
	select {
	case <-sconn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// The server sends all CRYPTO frames, including the HelloRetryRequest, using the Negotiated Version.
	serverPackets := sentLongHeaderPackets(&serverEvents)
	require.NotEmpty(t, serverPackets)
	for _, p := range serverPackets {
		if p.Crypto || p.Type == qlog.PacketTypeHandshake {
			require.Equal(t, quic.Version2, p.Version)
		}
	}
}

// With Config.InitialVersion, the client sends its first flight using QUIC version 1,
// while preferring QUIC version 2.
func TestCompatibleVersionNegotiationInitialVersion(t *testing.T) {
	for _, tc := range []struct {
		name           string
		serverVersions []quic.Version
		negotiated     quic.Version
	}{
		{name: "server preferring version 2", serverVersions: []quic.Version{quic.Version2, quic.Version1}, negotiated: quic.Version2},
		{name: "server with the default config", negotiated: quic.Version1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), maybeAddQLOGTracer(&quic.Config{Versions: tc.serverVersions}))
			require.NoError(t, err)
			defer ln.Close()
			runEchoServer(t, ln)

			var clientEvents events.Recorder
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, ln.Addr().String(), getTLSClientConfig(), maybeAddQLOGTracer(&quic.Config{
				Versions:       []quic.Version{quic.Version2, quic.Version1},
				InitialVersion: quic.Version1,
				Tracer:         tracerFor(&clientEvents),
			}))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			requireEcho(t, conn)
			require.Equal(t, tc.negotiated, conn.ConnectionState().Version)
			require.NoError(t, conn.CloseWithError(0, ""))

			require.Empty(t, clientEvents.Events(qlog.VersionNegotiationReceived{}))
			clientPackets := sentLongHeaderPackets(&clientEvents)
			require.NotEmpty(t, clientPackets)
			require.Equal(t, sentLongHeaderPacket{Type: qlog.PacketTypeInitial, Version: quic.Version1, Crypto: true}, clientPackets[0])
		})
	}
}
