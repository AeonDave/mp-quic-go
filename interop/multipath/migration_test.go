//go:build picoquic

package multipath

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/qlog"

	"github.com/stretchr/testify/require"
)

// A natRelay forwards the datagrams of the client to the server, like a NAT: every client address is mapped to a
// socket that sends to the server. rebind maps a client address to a new socket, which changes the address that the
// server sees, as a NAT rebinding does (section 9.3 of RFC 9000).
type natRelay struct {
	conn   *net.UDPConn // receives the client's datagrams
	server *net.UDPAddr

	mx       sync.Mutex
	mappings map[string]*net.UDPConn // by client address
	closed   bool

	// the number of bytes received from the server on every socket, by its local address
	rcvdFromServer sync.Map // string -> *atomic.Int64
}

func newNATRelay(t *testing.T, server *net.UDPAddr) *natRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	r := &natRelay{conn: conn, server: server, mappings: make(map[string]*net.UDPConn)}
	go r.run()
	t.Cleanup(r.close)
	return r
}

func (r *natRelay) addr() *net.UDPAddr { return r.conn.LocalAddr().(*net.UDPAddr) }

func (r *natRelay) run() {
	b := make([]byte, 2000)
	for {
		n, clientAddr, err := r.conn.ReadFromUDP(b)
		if err != nil {
			return
		}
		r.mx.Lock()
		out, ok := r.mappings[clientAddr.String()]
		if !ok && !r.closed {
			out, err = r.newMapping(clientAddr)
			if err != nil {
				r.mx.Unlock()
				return
			}
		}
		r.mx.Unlock()
		if out != nil {
			_, _ = out.WriteToUDP(b[:n], r.server)
		}
	}
}

// newMapping creates a socket for a client address. It must be called with the mutex held.
func (r *natRelay) newMapping(clientAddr *net.UDPAddr) (*net.UDPConn, error) {
	out, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	r.mappings[clientAddr.String()] = out
	counter := &atomic.Int64{}
	r.rcvdFromServer.Store(out.LocalAddr().String(), counter)
	go func() {
		b := make([]byte, 2000)
		for {
			n, _, err := out.ReadFromUDP(b)
			if err != nil {
				return
			}
			counter.Add(int64(n))
			_, _ = r.conn.WriteToUDP(b[:n], clientAddr)
		}
	}()
	return out, nil
}

// rebind maps the client address to a new socket. The previous socket keeps forwarding the server's datagrams.
// It returns the address that the server sees from now on.
func (r *natRelay) rebind(clientAddr net.Addr) (*net.UDPAddr, error) {
	r.mx.Lock()
	defer r.mx.Unlock()
	out, err := r.newMapping(clientAddr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	return out.LocalAddr().(*net.UDPAddr), nil
}

// mapping returns the address of the socket that a client address is mapped to.
func (r *natRelay) mapping(clientAddr net.Addr) *net.UDPAddr {
	r.mx.Lock()
	defer r.mx.Unlock()
	out, ok := r.mappings[clientAddr.String()]
	if !ok {
		return nil
	}
	return out.LocalAddr().(*net.UDPAddr)
}

func (r *natRelay) receivedFromServer(addr *net.UDPAddr) int64 {
	c, ok := r.rcvdFromServer.Load(addr.String())
	if !ok {
		return 0
	}
	return c.(*atomic.Int64).Load()
}

func (r *natRelay) close() {
	r.mx.Lock()
	defer r.mx.Unlock()
	r.closed = true
	r.conn.Close()
	for _, out := range r.mappings {
		out.Close()
	}
}

// pathChallengesReceived returns the number of PATH_CHALLENGE frames received on a path.
func pathChallengesReceived(t *testing.T, tr *tracer, id quic.PathID) int {
	t.Helper()
	recorders := tr.all()
	require.Len(t, recorders, 1)
	var n int
	for _, ev := range recorders[0].Events(qlog.PacketReceived{}) {
		ev := ev.(qlog.PacketReceived)
		if ev.Header.PathID != id {
			continue
		}
		for _, f := range ev.Frames {
			if _, ok := f.Frame.(*qlog.PathChallengeFrame); ok {
				n++
			}
		}
	}
	return n
}

// The NAT of our client rebinds during a download from picoquicdemo's server: the server sees the client's
// packets on path 0 coming from a new port. It validates the new address (section 9.3 of RFC 9000; with multipath,
// section 5.1 of draft-ietf-quic-multipath-21), and continues sending to it.
func testClientNATRebinding(t *testing.T, multipath bool) {
	setup(t)
	dir := testDir(t)
	server, serverAddr := startServer(t, dir, multipath)
	relay := newNATRelay(t, serverAddr)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr0 := newTransport(t, net.IPv4(127, 0, 0, 1))
	conn := dial(ctx, t, tr0, relay.addr(), tr, func(conf *quic.Config) {
		if !multipath {
			conf.MultipathController = nil
		}
	})
	require.Equal(t, multipath, conn.ConnectionState().SupportsMultipath)
	if multipath {
		openPath(ctx, t, conn, newTransport(t, net.IPv4(127, 0, 0, 2)), 1)
	}
	challengesBefore := pathChallengesReceived(t, tr, 0)
	oldAddr := relay.mapping(tr0.Conn.LocalAddr())
	require.NotNil(t, oldAddr)
	rcvdBefore := relay.receivedFromServer(oldAddr)

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := get(ctx, conn, fmt.Sprintf("/%d", downloadSize))
		done <- result{n: n, err: err}
	}()
	// rebind once a part of the document was received
	require.Eventually(t, func() bool {
		return relay.receivedFromServer(oldAddr) > rcvdBefore+downloadSize/8
	}, 10*time.Second, time.Millisecond)
	newAddr, err := relay.rebind(tr0.Conn.LocalAddr())
	require.NoError(t, err)
	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	require.NoError(t, res.err)
	require.EqualValues(t, downloadSize, res.n)
	t.Logf("received %d bytes from the server on the old port, %d on the new port", relay.receivedFromServer(oldAddr)-rcvdBefore, relay.receivedFromServer(newAddr))
	// The server continued sending to the client's new address.
	// With multipath, path 1 carries most of the data while path 0 restarts with a new congestion window.
	require.Greater(t, relay.receivedFromServer(newAddr), int64(100_000))
	// the server validated the new address on path 0
	require.Greater(t, pathChallengesReceived(t, tr, 0), challengesBefore)
	t.Logf("paths: %+v", conn.Paths())

	require.NoError(t, conn.CloseWithError(0, ""))
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)
	stats := getPathStats(tr.all()[0])
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
}

func TestPicoquicServerNATRebinding(t *testing.T) { testClientNATRebinding(t, false) }

func TestPicoquicServerNATRebindingMultipath(t *testing.T) { testClientNATRebinding(t, true) }

// countingConn counts the bytes received on a connection.
type countingConn struct {
	net.PacketConn
	rcvd atomic.Int64
}

func (c *countingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	c.rcvd.Add(int64(n))
	return n, addr, err
}

// Our client migrates the connection to a new port (RFC 9000 connection migration, without multipath):
// it probes the new path, switches to it, and continues downloading from picoquicdemo's server.
func TestPicoquicServerConnectionMigration(t *testing.T) {
	setup(t)
	dir := testDir(t)
	server, serverAddr := startServer(t, dir, false)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := dial(ctx, t, newTransport(t, net.IPv4(127, 0, 0, 1)), serverAddr, tr, func(conf *quic.Config) {
		conf.MultipathController = nil
	})
	require.False(t, conn.ConnectionState().SupportsMultipath)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	counting := &countingConn{PacketConn: udpConn}
	newTr := &quic.Transport{Conn: counting}
	t.Cleanup(func() { newTr.Close() })
	path, err := conn.AddPath(newTr)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	download(ctx, t, conn, downloadSize)
	require.Equal(t, udpConn.LocalAddr().String(), conn.LocalAddr().String())
	t.Logf("received %d bytes on the new path", counting.rcvd.Load())
	require.Greater(t, counting.rcvd.Load(), int64(downloadSize))

	require.NoError(t, conn.CloseWithError(0, ""))
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)
	stats := getPathStats(tr.all()[0])
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
}

// picoquicEvent is an event of a picoquic qlog: the time, the path ID, the category, the event name and the data.
type picoquicEvent struct {
	time   int64
	pathID uint64
	name   string
	frames []string // the frame types of packet_sent and packet_received events
}

// readPicoquicQlog reads the qlog of picoquicdemo, after it exited.
func readPicoquicQlog(t *testing.T, c *container) []picoquicEvent {
	t.Helper()
	dir := t.TempDir()
	out, err := exec.Command("docker", "cp", c.name+":/work/.", dir).CombinedOutput()
	require.NoError(t, err, string(out))
	files, err := filepath.Glob(filepath.Join(dir, "*.qlog"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	b, err := os.ReadFile(files[0])
	require.NoError(t, err)
	var doc struct {
		Traces []struct {
			Events [][]json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	require.NoError(t, json.Unmarshal(b, &doc))
	require.Len(t, doc.Traces, 1)
	var evs []picoquicEvent
	for _, raw := range doc.Traces[0].Events {
		if len(raw) != 5 {
			continue
		}
		var ev picoquicEvent
		require.NoError(t, json.Unmarshal(raw[0], &ev.time))
		require.NoError(t, json.Unmarshal(raw[1], &ev.pathID))
		require.NoError(t, json.Unmarshal(raw[3], &ev.name))
		if ev.name == "packet_sent" || ev.name == "packet_received" {
			var data struct {
				Frames []struct {
					FrameType string `json:"frame_type"`
				} `json:"frames"`
			}
			require.NoError(t, json.Unmarshal(raw[4], &data))
			for _, f := range data.Frames {
				ev.frames = append(ev.frames, f.FrameType)
			}
		}
		evs = append(evs, ev)
	}
	return evs
}

// Our server marks path 1, opened by picoquicdemo's client, as a backup path, and later as available again
// (section 3.3 of draft-ietf-quic-multipath-21).
func TestPicoquicClientPathStatus(t *testing.T) {
	setup(t)
	dir := testDir(t)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverTr := &quic.Transport{Conn: udpConn}
	defer serverTr.Close()
	ln, err := serverTr.Listen(&tls.Config{
		Certificates: []tls.Certificate{loadCertificate(t)},
		NextProtos:   []string{alpn},
	}, multipathConfig(false, tr))
	require.NoError(t, err)
	defer ln.Close()

	statusErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			statusErr <- err
			return
		}
		go serveHQ(conn)
		statusErr <- setBackupDuringDownload(conn, tr)
	}()

	args := []string{
		"-n", "localhost", "-a", alpn, "-t", "/certs/ca.pem", "-D", "-q", "/work",
		"-M", "-A", "127.0.0.2/0",
		"127.0.0.1", strconv.Itoa(udpConn.LocalAddr().(*net.UDPAddr).Port), fmt.Sprintf("/%d", 4*downloadSize),
	}
	client := runPicoquic(t, dir, "client", args...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code, err := client.wait(ctx)
	require.NoError(t, err)
	logs := client.logs()
	require.Zerof(t, code, "picoquicdemo failed:\n%s", logs)
	require.Contains(t, logs, "Client exit with code = 0")
	require.Contains(t, logs, "Enable multipath: Success")
	select {
	case err := <-statusErr:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("timeout")
	}

	recorders := tr.all()
	require.Len(t, recorders, 1)
	require.Eventually(t, func() bool { return len(recorders[0].Events(qlog.ConnectionClosed{})) > 0 }, 5*time.Second, 10*time.Millisecond)
	stats := getPathStats(recorders[0])
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}

	// picoquic received both PATH_STATUS frames
	evs := readPicoquicQlog(t, client)
	var statusFrames []string
	var backupTime, availableTime int64
	for _, ev := range evs {
		if ev.name != "packet_received" {
			continue
		}
		for _, f := range ev.frames {
			switch f {
			case "path_backup":
				statusFrames = append(statusFrames, "backup")
				backupTime = ev.time
			case "path_available":
				statusFrames = append(statusFrames, "available")
				availableTime = ev.time
			}
		}
	}
	require.Equal(t, []string{"backup", "available"}, statusFrames)
	// picoquic stops sending on path 1 while it is a backup path (the other path can be used), and resumes afterwards
	countSent := func(from, to int64) (all, nonAck int) {
		for _, ev := range evs {
			if ev.name != "packet_sent" || ev.pathID != 1 || ev.time < from || ev.time >= to {
				continue
			}
			all++
			for _, f := range ev.frames {
				if f != "ack" && f != "path_ack" && f != "padding" {
					nonAck++
					break
				}
			}
		}
		return all, nonAck
	}
	backupAll, backupNonAck := countSent(backupTime, availableTime)
	afterAll, afterNonAck := countSent(availableTime, 1<<62)
	t.Logf("picoquic's packets on path 1: while backup: %d (%d not only ACKs), afterwards: %d (%d not only ACKs)", backupAll, backupNonAck, afterAll, afterNonAck)
	// a few packets might already have been scheduled on path 1
	require.LessOrEqual(t, backupAll, 5)
	require.Greater(t, afterAll, 100)
}

// setBackupDuringDownload marks path 1 as a backup path once it is used, and as available again once some data
// was sent on path 0.
func setBackupDuringDownload(conn *quic.Conn, tr *tracer) error {
	ctx, cancel := context.WithTimeout(conn.Context(), 30*time.Second)
	defer cancel()
	waitFor := func(cond func() bool) error {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !cond() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
		return nil
	}
	sentOnPath := func(id quic.PathID) int {
		recorders := tr.all()
		if len(recorders) != 1 {
			return 0
		}
		return getPathStats(recorders[0]).sentData[id]
	}
	if err := waitFor(func() bool { return sentOnPath(1) > 100 }); err != nil {
		return fmt.Errorf("path 1 not used: %w", err)
	}
	if err := conn.SetPathStatus(1, quic.PathStatusBackup); err != nil {
		return err
	}
	sent0 := sentOnPath(0)
	if err := waitFor(func() bool { return sentOnPath(0) > sent0+2000 }); err != nil {
		return err
	}
	return conn.SetPathStatus(1, quic.PathStatusAvailable)
}
