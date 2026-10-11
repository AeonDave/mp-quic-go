package self_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/internal/handshake"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

const (
	// Packets of at least this size are counted as data packets.
	dataPacketMinSize = 1000
	// The chunk size used by the senders of a multipath transfer.
	transferChunkSize = 32 << 10
)

// A lossyConn is a net.PacketConn that drops every n-th packet it sends, and every n-th packet it receives.
// It counts the packets it sends and receives.
// It is not a net.UDPConn, so the connection doesn't use GSO, ECN or packet info on it.
type lossyConn struct {
	net.PacketConn
	conn      *net.UDPConn
	dropEvery uint64 // 0 means that no packets are dropped

	sent, rcvd               atomic.Uint64 // all packets, including the dropped packets
	sentData, rcvdData       atomic.Uint64 // data packets that were not dropped
	droppedSent, droppedRcvd atomic.Uint64
}

// newLossyConn creates a lossyConn on a new UDP socket bound to ip.
func newLossyConn(t *testing.T, ip net.IP, dropEvery uint64) *lossyConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return &lossyConn{PacketConn: conn, conn: conn, dropEvery: dropEvery}
}

func (c *lossyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if num := c.rcvd.Add(1); c.dropEvery > 0 && num%c.dropEvery == 0 {
			c.droppedRcvd.Add(1)
			continue
		}
		if n >= dataPacketMinSize {
			c.rcvdData.Add(1)
		}
		return n, addr, nil
	}
}

func (c *lossyConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if num := c.sent.Add(1); c.dropEvery > 0 && num%c.dropEvery == 0 {
		c.droppedSent.Add(1)
		return len(b), nil
	}
	if len(b) >= dataPacketMinSize {
		c.sentData.Add(1)
	}
	return c.PacketConn.WriteTo(b, addr)
}

// SetReadBuffer, SetWriteBuffer and SyscallConn allow the Transport to increase the socket buffers,
// and to set the DF bit for path MTU discovery.
func (c *lossyConn) SetReadBuffer(n int) error             { return c.conn.SetReadBuffer(n) }
func (c *lossyConn) SetWriteBuffer(n int) error            { return c.conn.SetWriteBuffer(n) }
func (c *lossyConn) SyscallConn() (syscall.RawConn, error) { return c.conn.SyscallConn() }

func (c *lossyConn) String() string { return c.conn.LocalAddr().String() }

// dataPackets returns the number of data packets sent and received, excluding the dropped packets.
func (c *lossyConn) dataPackets() (sent, rcvd uint64) { return c.sentData.Load(), c.rcvdData.Load() }

// droppedPackets returns the number of packets dropped when sending and receiving.
func (c *lossyConn) droppedPackets() (sent, rcvd uint64) {
	return c.droppedSent.Load(), c.droppedRcvd.Load()
}

// resetCounters resets the data packet counters.
func (c *lossyConn) resetCounters() {
	c.sentData.Store(0)
	c.rcvdData.Store(0)
}

func newMultipathController() quic.MultipathController {
	return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
}

func newMultipathControllerFactory() func() quic.MultipathController { return newMultipathController }

type pathPacketKey struct {
	sent     bool
	pathID   quic.PathID
	keyPhase qlog.KeyPhaseBit
}

type recordedPathFrame struct {
	seq    int // the position of the packet in the sequence of 1-RTT packets sent and received
	sent   bool
	pathID quic.PathID // the path that the packet was sent on
	frame  qlog.Frame
}

// A multipathRecorder is a qlog recorder for connections that send a lot of packets.
// It counts the 1-RTT packets sent and received per path and key phase,
// and keeps the frames used to manage paths.
type multipathRecorder struct {
	mx sync.Mutex

	seq int
	// number of 1-RTT packets, and number of 1-RTT packets carrying STREAM frames
	packets, dataPackets map[pathPacketKey]int
	// the position of the last 1-RTT packet sent on a path
	lastSent map[quic.PathID]int
	// PATH_CHALLENGE, PATH_RESPONSE, PATH_ABANDON and PATH_STATUS frames
	pathFrames []recordedPathFrame
	// number of frames of the multipath extension sent and received, including PATH_ACK frames
	multipathFrames int
	// number of packets that were logged with a path ID
	packetsWithPathID int
	// number of 1-RTT key updates
	keyUpdates     int
	paramsSent     []qlog.ParametersSet
	paramsReceived []qlog.ParametersSet
	closed         *qlog.ConnectionClosed
}

var _ qlogwriter.Recorder = &multipathRecorder{}

func newMultipathRecorder() *multipathRecorder {
	return &multipathRecorder{
		packets:     make(map[pathPacketKey]int),
		dataPackets: make(map[pathPacketKey]int),
		lastSent:    make(map[quic.PathID]int),
	}
}

func isMultipathFrame(f qlog.Frame) bool {
	switch f := f.Frame.(type) {
	case *qlog.AckFrame:
		return f.HasPathID
	case *qlog.PathAbandonFrame, *qlog.PathStatusFrame, *qlog.PathNewConnectionIDFrame,
		*qlog.PathRetireConnectionIDFrame, *qlog.MaxPathIDFrame, *qlog.PathsBlockedFrame, *qlog.PathCIDsBlockedFrame:
		return true
	}
	return false
}

func (r *multipathRecorder) recordPacket(sent bool, hdr qlog.PacketHeader, frames []qlog.Frame) {
	if hdr.HasPathID {
		r.packetsWithPathID++
	}
	for _, f := range frames {
		if isMultipathFrame(f) {
			r.multipathFrames++
		}
	}
	if hdr.PacketType != qlog.PacketType1RTT {
		return
	}
	r.seq++
	key := pathPacketKey{sent: sent, pathID: hdr.PathID, keyPhase: hdr.KeyPhaseBit}
	r.packets[key]++
	if sent {
		r.lastSent[hdr.PathID] = r.seq
	}
	for _, f := range frames {
		switch f.Frame.(type) {
		case *qlog.StreamFrame:
			r.dataPackets[key]++
		case *qlog.PathChallengeFrame, *qlog.PathResponseFrame, *qlog.PathAbandonFrame, *qlog.PathStatusFrame:
			r.pathFrames = append(r.pathFrames, recordedPathFrame{seq: r.seq, sent: sent, pathID: hdr.PathID, frame: f})
		}
	}
}

func (r *multipathRecorder) RecordEvent(ev qlogwriter.Event) {
	r.mx.Lock()
	defer r.mx.Unlock()

	switch ev := ev.(type) {
	case qlog.PacketSent:
		r.recordPacket(true, ev.Header, ev.Frames)
	case qlog.PacketReceived:
		r.recordPacket(false, ev.Header, ev.Frames)
	case qlog.KeyUpdated:
		if ev.KeyType == qlog.KeyTypeClient1RTT && ev.Trigger != qlog.KeyUpdateTLS {
			r.keyUpdates++
		}
	case qlog.ParametersSet:
		if ev.Restore {
			return
		}
		if ev.Initiator == qlog.InitiatorLocal {
			r.paramsSent = append(r.paramsSent, ev)
		} else {
			r.paramsReceived = append(r.paramsReceived, ev)
		}
	case qlog.ConnectionClosed:
		r.closed = &ev
	}
}

func (r *multipathRecorder) Close() error { return nil }

// packetCount returns the number of 1-RTT packets sent or received on a path.
// If dataOnly is set, only packets carrying STREAM frames are counted.
func (r *multipathRecorder) packetCount(sent bool, pathID quic.PathID, dataOnly bool) int {
	r.mx.Lock()
	defer r.mx.Unlock()

	m := r.packets
	if dataOnly {
		m = r.dataPackets
	}
	return m[pathPacketKey{sent, pathID, qlog.KeyPhaseZero}] + m[pathPacketKey{sent, pathID, qlog.KeyPhaseOne}]
}

func (r *multipathRecorder) connectionError() *qlog.ConnectionClosed {
	r.mx.Lock()
	defer r.mx.Unlock()

	return r.closed
}

func (r *multipathRecorder) tracer() func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	return newTracer(r)
}

// sendTransferData writes size bytes of pseudo-random data, generated from seed, to w.
// It calls hook (if set) before writing the data at every multiple of transferChunkSize.
// It returns the SHA-256 checksum of the data.
func sendTransferData(w io.Writer, seed uint64, size int, hook func(offset int)) ([]byte, error) {
	var s [32]byte
	binary.BigEndian.PutUint64(s[:], seed)
	rng := rand.NewChaCha8(s)
	h := sha256.New()
	buf := make([]byte, transferChunkSize)
	for offset := 0; offset < size; offset += transferChunkSize {
		if hook != nil {
			hook(offset)
		}
		b := buf[:min(transferChunkSize, size-offset)]
		_, _ = rng.Read(b)
		h.Write(b)
		if _, err := w.Write(b); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func receiveTransferData(r io.Reader) ([]byte, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	return h.Sum(nil), n, err
}

type transferResult struct {
	sentChecksum, rcvdChecksum []byte
	rcvd                       int64
	err                        error
}

// sendAndReceive sends size bytes on str, while receiving the data that the peer sends on str.
func sendAndReceive(str *quic.Stream, seed uint64, size int, hook func(int)) transferResult {
	rcvdChan := make(chan transferResult, 1)
	go func() {
		checksum, n, err := receiveTransferData(str)
		rcvdChan <- transferResult{rcvdChecksum: checksum, rcvd: n, err: err}
	}()
	sentChecksum, err := sendTransferData(str, seed, size, hook)
	if err != nil {
		str.CancelRead(1)
		<-rcvdChan
		return transferResult{err: fmt.Errorf("sending failed: %w", err)}
	}
	if err := str.Close(); err != nil {
		return transferResult{err: err}
	}
	res := <-rcvdChan
	if res.err != nil {
		res.err = fmt.Errorf("receiving failed: %w", res.err)
	}
	res.sentChecksum = sentChecksum
	return res
}

// transferHooks are called by the senders of runBidiTransfer before they write the data at an offset,
// at every multiple of transferChunkSize. They can block.
type transferHooks struct {
	client, server func(offset int)
}

// runBidiTransfer transfers size bytes in each direction on a bidirectional stream:
// the client uploads data while the server sends data to the client.
// The data received is verified using SHA-256 checksums.
func runBidiTransfer(t *testing.T, client, server *quic.Conn, size int, timeout time.Duration, hooks transferHooks) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	serverRes := make(chan transferResult, 1)
	go func() {
		str, err := server.AcceptStream(ctx)
		if err != nil {
			serverRes <- transferResult{err: err}
			return
		}
		str.SetDeadline(deadline)
		serverRes <- sendAndReceive(str, 2, size, hooks.server)
	}()

	str, err := client.OpenStreamSync(ctx)
	require.NoError(t, err)
	str.SetDeadline(deadline)
	clientRes := sendAndReceive(str, 1, size, hooks.client)
	require.NoError(t, clientRes.err)
	var sres transferResult
	select {
	case sres = <-serverRes:
	case <-ctx.Done():
		t.Fatal("timeout waiting for the server")
	}
	require.NoError(t, sres.err)
	require.EqualValues(t, size, clientRes.rcvd)
	require.EqualValues(t, size, sres.rcvd)
	require.Equal(t, clientRes.sentChecksum, sres.rcvdChecksum, "upload corrupted")
	require.Equal(t, sres.sentChecksum, clientRes.rcvdChecksum, "download corrupted")
}

// A multipathTestConn is a client connection with IETF Multipath QUIC, using one socket per path,
// and the server's connection.
type multipathTestConn struct {
	client, server             *quic.Conn
	clientEvents, serverEvents *multipathRecorder
	// the sockets of path 0 and path 1
	clientConns [2]*lossyConn
	path1       *quic.Path
	// the server's listener, used to accept the connection
	ln *quic.Listener
}

// listenMultipath starts a server with IETF Multipath QUIC on conn.
// The server's connections use the returned recorder.
func listenMultipath(t *testing.T, conn net.PacketConn) (*quic.Listener, *multipathRecorder) {
	t.Helper()
	tr := &quic.Transport{Conn: conn}
	addTracer(tr)
	t.Cleanup(func() { tr.Close() })
	serverEvents := newMultipathRecorder()
	ln, err := tr.Listen(getTLSConfig(), getQuicConfig(&quic.Config{
		MultipathControllerFactory: newMultipathControllerFactory(),
		Tracer:                     serverEvents.tracer(),
	}))
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln, serverEvents
}

// dialMultipath dials a server with IETF Multipath QUIC from conn0, and opens path 1 from conn1.
// It waits until the server validated path 1.
func dialMultipath(t *testing.T, ln *quic.Listener, serverEvents *multipathRecorder, serverAddr net.Addr, conn0, conn1 *lossyConn) *multipathTestConn {
	t.Helper()
	tr0 := &quic.Transport{Conn: conn0}
	addTracer(tr0)
	tr1 := &quic.Transport{Conn: conn1}
	addTracer(tr1)
	clientEvents := newMultipathRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
	defer cancel()
	conn, err := tr0.Dial(ctx, serverAddr, getTLSClientConfig(), getQuicConfig(&quic.Config{
		MultipathController: newMultipathController(),
		Tracer:              clientEvents.tracer(),
	}))
	require.NoError(t, err)
	// The connection is closed before the Transports: closing a Transport destroys the connection.
	t.Cleanup(func() {
		conn.CloseWithError(0, "")
		tr0.Close()
		tr1.Close()
	})
	require.True(t, conn.ConnectionState().SupportsMultipath)
	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { serverConn.CloseWithError(0, "") })

	path, err := conn.AddPath(tr1)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	id, ok := path.ID()
	require.True(t, ok)
	require.Equal(t, quic.PathID(1), id)
	waitForServerPath(t, serverConn, 1)
	return &multipathTestConn{
		client:       conn,
		server:       serverConn,
		clientEvents: clientEvents,
		serverEvents: serverEvents,
		clientConns:  [2]*lossyConn{conn0, conn1},
		path1:        path,
		ln:           ln,
	}
}

// waitForServerPath waits until the server validated a path.
func waitForServerPath(t *testing.T, conn *quic.Conn, id quic.PathID) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, p := range conn.Paths() {
			if p.ID == id && p.State == quic.PathStateActive {
				return true
			}
		}
		return false
	}, scaleDuration(5*time.Second), time.Millisecond)
}

// requireDataShare checks that every socket sent and received at least 10% of the data packets.
func requireDataShare(t *testing.T, conns ...*lossyConn) {
	t.Helper()
	var totalSent, totalRcvd uint64
	for _, c := range conns {
		sent, rcvd := c.dataPackets()
		totalSent += sent
		totalRcvd += rcvd
	}
	for _, c := range conns {
		sent, rcvd := c.dataPackets()
		t.Logf("%s: %d data packets sent, %d received", c, sent, rcvd)
		require.GreaterOrEqual(t, sent*10, totalSent, "%s sent less than 10%% of the data packets", c)
		require.GreaterOrEqual(t, rcvd*10, totalRcvd, "%s received less than 10%% of the data packets", c)
	}
}

// requireNoConnectionError checks that a connection was closed by the application, without an error.
func requireNoConnectionError(t *testing.T, r *multipathRecorder) {
	t.Helper()
	closed := r.connectionError()
	if closed == nil {
		return
	}
	require.Nil(t, closed.ConnectionError, "connection closed with a transport error: %s", closed.Reason)
	if closed.ApplicationError != nil {
		require.Zero(t, *closed.ApplicationError)
	}
}

// testMultipathTransferWithLoss transfers data in both directions, using path 0 from 127.0.0.1 and path 1 from
// path1IP. On both paths, every 20th packet (5%) is dropped in each direction.
func testMultipathTransferWithLoss(t *testing.T, path1IP net.IP, size int) {
	ln, serverEvents := listenMultipath(t, newUDPConnLocalhost(t))
	conn0 := newLossyConn(t, net.IPv4(127, 0, 0, 1), 20)
	conn1 := newLossyConn(t, path1IP, 20)
	c := dialMultipath(t, ln, serverEvents, ln.Addr(), conn0, conn1)
	conn0.resetCounters()
	conn1.resetCounters()

	runBidiTransfer(t, c.client, c.server, size, scaleDuration(30*time.Second), transferHooks{})
	requireDataShare(t, conn0, conn1)
	for _, conn := range c.clientConns {
		sent, rcvd := conn.droppedPackets()
		require.NotZero(t, sent)
		require.NotZero(t, rcvd)
	}
	for _, r := range []*multipathRecorder{c.clientEvents, c.serverEvents} {
		for _, id := range []quic.PathID{0, 1} {
			require.NotZero(t, r.packetCount(true, id, true))
			require.NotZero(t, r.packetCount(false, id, true))
		}
	}
	require.NoError(t, c.client.CloseWithError(0, ""))
	requireNoConnectionError(t, c.clientEvents)
}

// Two paths from two sockets on 127.0.0.1 transfer data in both directions, while 5% of the packets are lost
// on every path in each direction.
func TestMultipathTransferWithLoss(t *testing.T) {
	testMultipathTransferWithLoss(t, net.IPv4(127, 0, 0, 1), 4<<20)
}

// multipathInteropRecorders keeps the recorders of all connections of an endpoint.
type multipathInteropRecorders struct {
	mx        sync.Mutex
	recorders []*events.Recorder
}

func (r *multipathInteropRecorders) tracer(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	r.mx.Lock()
	defer r.mx.Unlock()

	rec := &events.Recorder{}
	r.recorders = append(r.recorders, rec)
	return &events.Trace{Recorder: rec}
}

func (r *multipathInteropRecorders) all() []*events.Recorder {
	r.mx.Lock()
	defer r.mx.Unlock()

	return r.recorders
}

// requireSinglePath checks that a connection didn't use IETF Multipath QUIC: no frames of the extension were sent
// or received, and no packets were logged with a path ID.
// If advertised is false, the endpoint didn't send the initial_max_path_id transport parameter.
func requireSinglePath(t *testing.T, r *events.Recorder, advertised bool) {
	t.Helper()
	var paramsSent int
	for _, ev := range r.Events() {
		var hdr qlog.PacketHeader
		var frames []qlog.Frame
		switch ev := ev.(type) {
		case qlog.PacketSent:
			hdr, frames = ev.Header, ev.Frames
		case qlog.PacketReceived:
			hdr, frames = ev.Header, ev.Frames
		case qlog.ParametersSet:
			if ev.Initiator == qlog.InitiatorLocal && !ev.Restore {
				paramsSent++
				if advertised {
					require.NotNil(t, ev.InitialMaxPathID)
				} else {
					require.Nil(t, ev.InitialMaxPathID, "initial_max_path_id sent")
				}
			}
			continue
		default:
			continue
		}
		require.False(t, hdr.HasPathID)
		for _, f := range frames {
			require.False(t, isMultipathFrame(f), "multipath frame: %#v", f.Frame)
		}
	}
	require.Equal(t, 1, paramsSent)
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

// echoServer echoes the data of every stream of a connection.
func echoServer(conn *quic.Conn) {
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
}

// echo sends data on a new stream, and checks that it is echoed.
func echo(t *testing.T, conn *quic.Conn, data []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
	defer cancel()
	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	str.SetDeadline(time.Now().Add(scaleDuration(10 * time.Second)))
	errChan := make(chan error, 1)
	go func() {
		_, err := str.Write(data)
		if err == nil {
			err = str.Close()
		}
		errChan <- err
	}()
	echoed, err := io.ReadAll(str)
	require.NoError(t, err)
	require.NoError(t, <-errChan)
	require.Equal(t, data, echoed)
}

// An endpoint with a multipath controller interoperates with an endpoint without one, using standard QUIC
// (section 2 of draft-ietf-quic-multipath-21): data transfer, key updates, RFC 9000 connection migration and 0-RTT
// work. No frames of the extension are sent, and the endpoint without a multipath controller doesn't send the
// initial_max_path_id transport parameter.
func TestMultipathSinglePathInterop(t *testing.T) {
	for _, multipathEndpoint := range []string{"client", "server"} {
		t.Run("multipath "+multipathEndpoint, func(t *testing.T) {
			reset := handshake.SetKeyUpdateInterval(50)
			t.Cleanup(reset)

			var serverRecorders, clientRecorders multipathInteropRecorders
			serverConf := &quic.Config{Allow0RTT: true, Tracer: serverRecorders.tracer}
			clientConf := &quic.Config{Tracer: clientRecorders.tracer}
			if multipathEndpoint == "client" {
				clientConf.MultipathControllerFactory = newMultipathControllerFactory()
			} else {
				serverConf.MultipathControllerFactory = newMultipathControllerFactory()
			}
			serverTr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
			defer serverTr.Close()
			ln, err := serverTr.ListenEarly(getTLSConfig(), serverConf)
			require.NoError(t, err)
			defer ln.Close()
			go func() {
				for {
					conn, err := ln.Accept(context.Background())
					if err != nil {
						return
					}
					go echoServer(conn)
				}
			}()

			tlsConf := getTLSClientConfig()
			puts := make(chan string, 10)
			tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
			defer cancel()

			// first connection: data transfer with key updates, and connection migration
			tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
			defer tr1.Close()
			tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
			defer tr2.Close()
			conn, err := tr1.Dial(ctx, ln.Addr(), tlsConf, clientConf)
			require.NoError(t, err)
			require.False(t, conn.ConnectionState().SupportsMultipath)
			require.Nil(t, conn.Paths())
			echo(t, conn, GeneratePRData(500<<10))

			path, err := conn.AddPath(tr2)
			require.NoError(t, err)
			require.NoError(t, path.Probe(ctx))
			_, ok := path.ID()
			require.False(t, ok)
			require.NoError(t, path.Switch())
			// the connection switches to the new path asynchronously
			require.Eventually(t, func() bool {
				return conn.LocalAddr().String() == tr2.Conn.LocalAddr().String()
			}, scaleDuration(time.Second), time.Millisecond)
			echo(t, conn, GeneratePRData(500<<10))
			select {
			case <-puts:
			case <-ctx.Done():
				t.Fatal("timeout waiting for the session ticket")
			}
			require.NoError(t, conn.CloseWithError(0, ""))

			// second connection: 0-RTT
			tr3 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
			defer tr3.Close()
			conn, err = tr3.DialEarly(ctx, ln.Addr(), tlsConf, clientConf)
			require.NoError(t, err)
			data := GeneratePRData(10 << 10)
			str, err := conn.OpenStream()
			require.NoError(t, err)
			_, err = str.Write(data)
			require.NoError(t, err)
			require.NoError(t, str.Close())
			echoed, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, data, echoed)
			require.True(t, conn.ConnectionState().Used0RTT)
			require.False(t, conn.ConnectionState().SupportsMultipath)
			require.NoError(t, conn.CloseWithError(0, ""))

			// wait for the server to close the connections
			require.Eventually(t, func() bool {
				for _, r := range serverRecorders.all() {
					if len(r.Events(qlog.ConnectionClosed{})) == 0 {
						return false
					}
				}
				return true
			}, scaleDuration(5*time.Second), 10*time.Millisecond)

			clients, servers := clientRecorders.all(), serverRecorders.all()
			require.Len(t, clients, 2)
			require.Len(t, servers, 2)
			for i := range 2 {
				requireSinglePath(t, clients[i], multipathEndpoint == "client")
				requireSinglePath(t, servers[i], multipathEndpoint == "server")
			}
			// key updates were initiated, and the peer followed them
			require.GreaterOrEqual(t, countKeyUpdates(clients[0]), 2)
			require.GreaterOrEqual(t, countKeyUpdates(servers[0]), 2)
			// On the first connection, the server answered the client's path validation,
			// and validated the client's new address (section 9.3 of RFC 9000).
			var pathChallenges, pathResponses int
			for _, ev := range servers[0].Events(qlog.PacketSent{}) {
				for _, f := range ev.(qlog.PacketSent).Frames {
					switch f.Frame.(type) {
					case *qlog.PathChallengeFrame:
						pathChallenges++
					case *qlog.PathResponseFrame:
						pathResponses++
					}
				}
			}
			require.NotZero(t, pathResponses)
			require.NotZero(t, pathChallenges)
		})
	}
}
