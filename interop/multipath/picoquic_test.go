//go:build picoquic

package multipath

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/internal/utils"
	"github.com/AeonDave/mp-quic-go/interop/http09"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

var logDir = flag.String("logdir", "", "directory for the qlogs and logs of both endpoints (default: a new temporary directory, which is kept)")

const (
	// the number of bytes downloaded by the client
	downloadSize = 10 << 20
	// the ALPN of HTTP/0.9 over QUIC, supported by picoquicdemo
	alpn = http09.NextProto
)

var (
	setupOnce sync.Once
	setupErr  error
	image     string
	certDir   string
	caPool    *x509.CertPool
	resultDir string
)

// setup builds the Docker image, generates the certificates, and creates the directory for the logs.
func setup(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("These tests use the host network of Docker, and 127.0.0.2.")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	setupOnce.Do(func() { setupErr = doSetup() })
	require.NoError(t, setupErr)
}

func doSetup() error {
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`(?m)^ARG PICOQUIC_COMMIT=([0-9a-f]{40})$`).FindSubmatch(dockerfile)
	if m == nil {
		return errors.New("picoquic commit not found in Dockerfile")
	}
	image = "mp-quic-go-picoquic:" + string(m[1][:12])
	if out, err := exec.Command("docker", "build", "-q", "-t", image, ".").CombinedOutput(); err != nil {
		return fmt.Errorf("building the image failed: %w\n%s", err, out)
	}

	resultDir = *logDir
	if resultDir == "" {
		resultDir, err = os.MkdirTemp("", "picoquic-interop-")
		if err != nil {
			return err
		}
	}
	resultDir, err = filepath.Abs(resultDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		return err
	}
	certDir = filepath.Join(resultDir, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return err
	}
	return writeCertificates(certDir)
}

// writeCertificates writes a CA certificate (ca.pem), and a certificate (cert.pem) and private key (key.pem)
// for localhost and 127.0.0.1, signed by the CA.
func writeCertificates(dir string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "multipath interop CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	caPool = x509.NewCertPool()
	caPool.AddCert(ca)
	for name, block := range map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: certDER},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// testDir creates the directory for the logs of a test.
func testDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(resultDir, t.Name())
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "qlog-mp-quic-go"), 0o755))
	t.Logf("logs: %s", dir)
	return dir
}

// A container is a picoquicdemo process running in a Docker container.
type container struct {
	name string
}

// runPicoquic starts picoquicdemo with the given arguments in a container using the host network.
// The certificates are copied to /certs. picoquicdemo writes its logs to /work, which is copied to the test
// directory when the test ends. Files are copied instead of mounted, since the Docker daemon might not have
// access to the test directory.
func runPicoquic(t *testing.T, dir, name string, args ...string) *container {
	t.Helper()
	c := &container{name: fmt.Sprintf("mp-quic-go-picoquic-%s-%d", name, time.Now().UnixNano())}
	createArgs := []string{
		"create", "--name", c.name, "--network", "host",
		// line-buffered output, so that the logs can be read while picoquicdemo is running
		"--entrypoint", "stdbuf", image, "-oL", "-eL", "picoquicdemo",
	}
	out, err := exec.Command("docker", append(createArgs, args...)...).CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "kill", c.name).Run()
		logs := c.logs()
		if err := os.WriteFile(filepath.Join(dir, name+".log"), []byte(logs), 0o644); err != nil {
			t.Log(err)
		}
		if out, err := exec.Command("docker", "cp", c.name+":/work/.", filepath.Join(dir, "picoquic-"+name)).CombinedOutput(); err != nil {
			t.Logf("copying the logs of picoquicdemo failed: %s: %s", err, out)
		}
		_ = exec.Command("docker", "rm", "-f", c.name).Run()
	})
	out, err = exec.Command("docker", "cp", certDir+"/.", c.name+":/certs").CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = exec.Command("docker", "start", c.name).CombinedOutput()
	require.NoError(t, err, string(out))
	return c
}

func (c *container) logs() string {
	out, _ := exec.Command("docker", "logs", c.name).CombinedOutput()
	return string(out)
}

// wait waits for the container to exit, and returns its exit code.
func (c *container) wait(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "docker", "wait", c.name).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// waitForOutput waits until the output of the container contains s.
func (c *container) waitForOutput(t *testing.T, s string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(c.logs(), s) }, 10*time.Second, 50*time.Millisecond,
		"picoquicdemo didn't print %q", s)
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

type multiplexedRecorder []qlogwriter.Recorder

func (r multiplexedRecorder) RecordEvent(ev qlogwriter.Event) {
	for _, rec := range r {
		rec.RecordEvent(ev)
	}
}

func (r multiplexedRecorder) Close() error {
	for _, rec := range r {
		rec.Close()
	}
	return nil
}

type multiplexedTrace []qlogwriter.Trace

func (t multiplexedTrace) AddProducer() qlogwriter.Recorder {
	var r multiplexedRecorder
	for _, tr := range t {
		r = append(r, tr.AddProducer())
	}
	return r
}

func (t multiplexedTrace) SupportsSchemas(string) bool { return true }

// tracer writes a qlog file for every connection to dir, and records the events of the connections.
type tracer struct {
	dir string

	mx        sync.Mutex
	recorders []*events.Recorder
}

func (tr *tracer) trace(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	pers := "server"
	if isClient {
		pers = "client"
	}
	r := &events.Recorder{}
	tr.mx.Lock()
	tr.recorders = append(tr.recorders, r)
	tr.mx.Unlock()
	f, err := os.Create(filepath.Join(tr.dir, fmt.Sprintf("%s_%s.sqlog", connID, pers)))
	if err != nil {
		return &events.Trace{Recorder: r}
	}
	fileSeq := qlogwriter.NewConnectionFileSeq(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), isClient, connID, []string{qlog.EventSchema})
	go fileSeq.Run()
	return multiplexedTrace{&events.Trace{Recorder: r}, fileSeq}
}

func (tr *tracer) all() []*events.Recorder {
	tr.mx.Lock()
	defer tr.mx.Unlock()
	return tr.recorders
}

// pathStats are the number of 1-RTT packets with STREAM frames sent and received on every path,
// the number of frames of the multipath extension sent and received, the number of 1-RTT key updates,
// and the event of the closing of the connection.
type pathStats struct {
	sentData, rcvdData   map[quic.PathID]int
	multipathFrames      int
	keyUpdates           int
	connectionCloseError *qlog.ConnectionClosed
}

func getPathStats(r *events.Recorder) pathStats {
	s := pathStats{sentData: make(map[quic.PathID]int), rcvdData: make(map[quic.PathID]int)}
	for _, ev := range r.Events() {
		var hdr qlog.PacketHeader
		var frames []qlog.Frame
		var m map[quic.PathID]int
		switch ev := ev.(type) {
		case qlog.PacketSent:
			hdr, frames, m = ev.Header, ev.Frames, s.sentData
		case qlog.PacketReceived:
			hdr, frames, m = ev.Header, ev.Frames, s.rcvdData
		case qlog.KeyUpdated:
			if ev.KeyType == qlog.KeyTypeClient1RTT && ev.Trigger != qlog.KeyUpdateTLS {
				s.keyUpdates++
			}
			continue
		case qlog.ConnectionClosed:
			s.connectionCloseError = &ev
			continue
		default:
			continue
		}
		var hasData bool
		for _, f := range frames {
			switch f := f.Frame.(type) {
			case *qlog.StreamFrame:
				hasData = true
			case *qlog.AckFrame:
				if f.HasPathID {
					s.multipathFrames++
				}
			case *qlog.PathAbandonFrame, *qlog.PathStatusFrame, *qlog.PathNewConnectionIDFrame,
				*qlog.PathRetireConnectionIDFrame, *qlog.MaxPathIDFrame, *qlog.PathsBlockedFrame, *qlog.PathCIDsBlockedFrame:
				s.multipathFrames++
			}
		}
		if hasData && hdr.PacketType == qlog.PacketType1RTT {
			m[hdr.PathID]++
		}
	}
	return s
}

func clientTLSConfig() *tls.Config {
	return &tls.Config{ServerName: "localhost", RootCAs: caPool, NextProtos: []string{alpn}}
}

func multipathConfig(isClient bool, tr *tracer) *quic.Config {
	newController := func() quic.MultipathController {
		return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
	}
	conf := &quic.Config{Tracer: tr.trace, MaxIdleTimeout: 10 * time.Second}
	if isClient {
		conf.MultipathController = newController()
	} else {
		conf.MultipathControllerFactory = newController
	}
	return conf
}

// get requests a document using HTTP/0.9 on a new stream, and returns the number of bytes received.
func get(ctx context.Context, conn *quic.Conn, path string) (int64, error) {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		str.SetDeadline(deadline)
	}
	if _, err := str.Write([]byte("GET " + path + "\r\n")); err != nil {
		return 0, err
	}
	if err := str.Close(); err != nil {
		return 0, err
	}
	return io.Copy(io.Discard, str)
}

// startServer starts picoquicdemo's server, and waits until it's ready.
// It exits after the first connection, so that its qlog file is complete.
func startServer(t *testing.T, dir string, multipath bool, extraArgs ...string) (*container, *net.UDPAddr) {
	t.Helper()
	port := freeUDPPort(t)
	args := []string{"-p", strconv.Itoa(port), "-c", "/certs/cert.pem", "-k", "/certs/key.pem", "-q", "/work", "-1"}
	if multipath {
		args = append(args, "-M")
	}
	args = append(args, extraArgs...)
	server := runPicoquic(t, dir, "server", args...)
	server.waitForOutput(t, "Waiting for packets")
	return server, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

// newTransport creates a Transport on a new UDP socket bound to ip.
// The Transport is closed when the test ends, after the connections (closing it destroys the connections).
func newTransport(t *testing.T, ip net.IP) *quic.Transport {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { tr.Close() })
	return tr
}

// dial dials picoquicdemo's server, and sends a first request.
func dial(ctx context.Context, t *testing.T, tr *quic.Transport, addr net.Addr, tracer *tracer, modifyConf ...func(*quic.Config)) *quic.Conn {
	t.Helper()
	conf := multipathConfig(true, tracer)
	for _, f := range modifyConf {
		f(conf)
	}
	conn, err := tr.Dial(ctx, addr, clientTLSConfig(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	// picoquicdemo drops the Handshake and 1-RTT packets coalesced with the client's last Initial packet, if they
	// use a connection ID that the server issued in a NEW_CONNECTION_ID or PATH_NEW_CONNECTION_ID frame
	// (section 5.1.1 of RFC 9000 allows this). The client's PATH_NEW_CONNECTION_ID frames are then only received
	// when they are retransmitted. picoquicdemo crashes if it receives a PATH_CHALLENGE on a path for which it has no
	// connection ID. Opening a path after a request was answered avoids this.
	n, err := get(ctx, conn, "/1000")
	require.NoError(t, err)
	require.EqualValues(t, 1000, n)
	return conn
}

func openPath(ctx context.Context, t *testing.T, conn *quic.Conn, tr *quic.Transport, expectedID quic.PathID) *quic.Path {
	t.Helper()
	path, err := conn.AddPath(tr)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	id, ok := path.ID()
	require.True(t, ok)
	require.Equal(t, expectedID, id)
	return path
}

func download(ctx context.Context, t *testing.T, conn *quic.Conn, size int) {
	t.Helper()
	n, err := get(ctx, conn, fmt.Sprintf("/%d", size))
	require.NoError(t, err)
	require.EqualValues(t, size, n)
}

// testClient runs our client against picoquicdemo's server.
// With multipath, the client opens a second path from 127.0.0.2.
func testClient(t *testing.T, picoquicMultipath bool) {
	setup(t)
	dir := testDir(t)
	server, addr := startServer(t, dir, picoquicMultipath)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := dial(ctx, t, newTransport(t, net.IPv4(127, 0, 0, 1)), addr, tr)
	require.Equal(t, picoquicMultipath, conn.ConnectionState().SupportsMultipath)
	if picoquicMultipath {
		openPath(ctx, t, conn, newTransport(t, net.IPv4(127, 0, 0, 2)), 1)
	}
	n, err := get(ctx, conn, fmt.Sprintf("/%d", downloadSize))
	require.NoError(t, err)
	require.EqualValues(t, downloadSize, n)
	t.Logf("paths: %+v", conn.Paths())
	require.NoError(t, conn.CloseWithError(0, ""))
	// picoquicdemo exits once the connection was closed
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)

	recorders := tr.all()
	require.Len(t, recorders, 1)
	stats := getPathStats(recorders[0])
	t.Logf("data packets received per path: %v, sent: %v, key updates: %d", stats.rcvdData, stats.sentData, stats.keyUpdates)
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
	if picoquicMultipath {
		require.NotZero(t, stats.multipathFrames)
		for _, id := range []quic.PathID{0, 1} {
			require.NotZero(t, stats.rcvdData[id], "no data received on path %d", id)
		}
	} else {
		require.Zero(t, stats.multipathFrames)
	}
	require.NotZero(t, stats.keyUpdates)
}

// Our client downloads a document from picoquicdemo -M, using two paths.
func TestPicoquicServerMultipath(t *testing.T) { testClient(t, true) }

// Our client abandons path 1, opens path 2, and then abandons path 0, downloading a document after every step.
// picoquicdemo responds to every PATH_ABANDON frame with a PATH_ABANDON frame.
func TestPicoquicServerAbandonPaths(t *testing.T) {
	setup(t)
	dir := testDir(t)
	server, addr := startServer(t, dir, true)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := dial(ctx, t, newTransport(t, net.IPv4(127, 0, 0, 1)), addr, tr)
	require.True(t, conn.ConnectionState().SupportsMultipath)
	path1 := openPath(ctx, t, conn, newTransport(t, net.IPv4(127, 0, 0, 2)), 1)
	download(ctx, t, conn, downloadSize/4)

	recorder := tr.all()[0]
	// receivedAbandons returns the paths that picoquicdemo sent a PATH_ABANDON frame for
	receivedAbandons := func() []quic.PathID {
		var ids []quic.PathID
		for _, ev := range recorder.Events(qlog.PacketReceived{}) {
			for _, f := range ev.(qlog.PacketReceived).Frames {
				if f, ok := f.Frame.(*qlog.PathAbandonFrame); ok {
					ids = append(ids, f.PathID)
				}
			}
		}
		return ids
	}
	require.NoError(t, path1.Close())
	download(ctx, t, conn, downloadSize/4)
	require.Eventually(t, func() bool { return len(receivedAbandons()) == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []quic.PathID{1}, receivedAbandons())

	openPath(ctx, t, conn, newTransport(t, net.IPv4(127, 0, 0, 2)), 2)
	download(ctx, t, conn, downloadSize/4)
	require.NoError(t, conn.ClosePath(0))
	download(ctx, t, conn, downloadSize/4)
	require.Eventually(t, func() bool { return len(receivedAbandons()) == 2 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []quic.PathID{1, 0}, receivedAbandons())
	t.Logf("paths: %+v", conn.Paths())
	require.NoError(t, conn.CloseWithError(0, ""))
	code, err := server.wait(ctx)
	require.NoError(t, err)
	require.Zero(t, code)

	stats := getPathStats(recorder)
	t.Logf("data packets received per path: %v, sent: %v, key updates: %d", stats.rcvdData, stats.sentData, stats.keyUpdates)
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
	for _, id := range []quic.PathID{0, 1, 2} {
		require.NotZero(t, stats.rcvdData[id], "no data received on path %d", id)
	}
}

// Our client is configured for multipath, picoquicdemo isn't: the connection uses a single path.
func TestPicoquicServerSinglePath(t *testing.T) { testClient(t, false) }

// testServer runs picoquicdemo's client against our server.
// With multipath, the client adds a second path from 127.0.0.2.
func testServer(t *testing.T, picoquicMultipath bool, extraArgs ...string) *events.Recorder {
	return testServerWithConfig(t, picoquicMultipath, nil, extraArgs...)
}

func testServerWithConfig(t *testing.T, picoquicMultipath bool, modifyConf func(*quic.Config), extraArgs ...string) *events.Recorder {
	setup(t)
	dir := testDir(t)
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverTr := &quic.Transport{Conn: udpConn}
	defer serverTr.Close()
	conf := multipathConfig(false, tr)
	if modifyConf != nil {
		modifyConf(conf)
	}
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

	args := []string{
		"-n", "localhost", "-a", alpn, "-t", "/certs/ca.pem", "-D", "-q", "/work",
		// trigger a key update after receiving 1000 packets
		"-u", "1000",
	}
	if picoquicMultipath {
		// a second path from 127.0.0.2
		args = append(args, "-M", "-A", "127.0.0.2/0")
	}
	args = append(args, extraArgs...)
	args = append(args, "127.0.0.1", strconv.Itoa(udpConn.LocalAddr().(*net.UDPAddr).Port), fmt.Sprintf("/%d", downloadSize))
	client := runPicoquic(t, dir, "client", args...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code, err := client.wait(ctx)
	require.NoError(t, err)
	logs := client.logs()
	require.Zerof(t, code, "picoquicdemo failed:\n%s", logs)
	require.Contains(t, logs, "Client exit with code = 0")
	if picoquicMultipath {
		require.Contains(t, logs, "Enable multipath: Success")
	}

	recorders := tr.all()
	require.Len(t, recorders, 1)
	// wait until the server's connection was closed, so that all events were recorded
	require.Eventually(t, func() bool { return len(recorders[0].Events(qlog.ConnectionClosed{})) > 0 }, 5*time.Second, 10*time.Millisecond)
	stats := getPathStats(recorders[0])
	t.Logf("data packets sent per path: %v, received: %v, key updates: %d", stats.sentData, stats.rcvdData, stats.keyUpdates)
	if stats.connectionCloseError != nil && stats.connectionCloseError.ConnectionError != nil {
		t.Fatalf("connection closed with error: %v (%s)", *stats.connectionCloseError.ConnectionError, stats.connectionCloseError.Reason)
	}
	if picoquicMultipath {
		require.NotZero(t, stats.multipathFrames)
		for _, id := range []quic.PathID{0, 1} {
			require.NotZero(t, stats.sentData[id], "no data sent on path %d", id)
		}
	} else {
		require.Zero(t, stats.multipathFrames)
	}
	require.NotZero(t, stats.keyUpdates)
	return recorders[0]
}

// picoquicdemo -M downloads a document from our server, using two paths.
func TestPicoquicClientMultipath(t *testing.T) { testServer(t, true) }

// Our server is configured for multipath, picoquicdemo isn't: the connection uses a single path.
func TestPicoquicClientSinglePath(t *testing.T) { testServer(t, false) }

// observedAddressFrames returns the OBSERVED_ADDRESS frames sent and received, by the path of the packet.
func observedAddressFrames(r *events.Recorder) (sent, rcvd map[quic.PathID][]qlog.ObservedAddressFrame) {
	sent = make(map[quic.PathID][]qlog.ObservedAddressFrame)
	rcvd = make(map[quic.PathID][]qlog.ObservedAddressFrame)
	for _, ev := range r.Events(qlog.PacketSent{}, qlog.PacketReceived{}) {
		var hdr qlog.PacketHeader
		var frames []qlog.Frame
		m := sent
		switch ev := ev.(type) {
		case qlog.PacketSent:
			hdr, frames = ev.Header, ev.Frames
		case qlog.PacketReceived:
			hdr, frames, m = ev.Header, ev.Frames, rcvd
		}
		for _, f := range frames {
			if f, ok := f.Frame.(*qlog.ObservedAddressFrame); ok {
				m[hdr.PathID] = append(m[hdr.PathID], *f)
			}
		}
	}
	return sent, rcvd
}

func addrPort(t *testing.T, addr net.Addr) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr.String())
	require.NoError(t, err)
	return ap
}

// picoquicdemo's server (-J 0) provides address observations (QUIC Address Discovery), our client requests them.
// With multipath, the client opens a second path from 127.0.0.2. The server reports the client's address on every path.
// The client offers to provide address observations as well, but the server doesn't request them: picoquicdemo's
// HTTP/0.9 server doesn't handle the callback for received address observations, and fails the request on stream 0.
func testClientAddressDiscovery(t *testing.T, multipath bool) {
	setup(t)
	dir := testDir(t)
	server, addr := startServer(t, dir, multipath, "-J", "0")
	tr := &tracer{dir: filepath.Join(dir, "qlog-mp-quic-go")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tr1 := newTransport(t, net.IPv4(127, 0, 0, 1))
	conn := dial(ctx, t, tr1, addr, tr, func(c *quic.Config) {
		c.RequestObservedAddress = true
		c.ProvideObservedAddress = true
	})
	require.False(t, conn.ConnectionState().SupportsAddressDiscovery.Send)
	require.True(t, conn.ConnectionState().SupportsAddressDiscovery.Receive)
	observed, ok := conn.ObservedAddr()
	require.True(t, ok)
	require.Equal(t, addrPort(t, tr1.Conn.LocalAddr()), observed)
	var tr2 *quic.Transport
	if multipath {
		tr2 = newTransport(t, net.IPv4(127, 0, 0, 2))
		openPath(ctx, t, conn, tr2, 1)
	}
	download(ctx, t, conn, downloadSize/4)
	paths := conn.Paths()
	t.Logf("paths: %+v", paths)
	if multipath {
		require.Len(t, paths, 2)
		require.Equal(t, addrPort(t, tr1.Conn.LocalAddr()), paths[0].ObservedAddr)
		require.Equal(t, addrPort(t, tr2.Conn.LocalAddr()), paths[1].ObservedAddr)
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
	sent, rcvd := observedAddressFrames(recorder)
	t.Logf("OBSERVED_ADDRESS frames sent: %v, received: %v", sent, rcvd)
	pathIDs := []quic.PathID{0}
	if multipath {
		pathIDs = append(pathIDs, 1)
	}
	require.Empty(t, sent)
	for _, id := range pathIDs {
		require.NotEmpty(t, rcvd[id], "no OBSERVED_ADDRESS frame received on path %d", id)
	}
}

func TestPicoquicServerAddressDiscovery(t *testing.T) { testClientAddressDiscovery(t, false) }

func TestPicoquicServerAddressDiscoveryMultipath(t *testing.T) { testClientAddressDiscovery(t, true) }

// picoquicdemo's client (-J 2) and our server both request and provide address observations.
// With multipath, picoquicdemo adds a second path from 127.0.0.2.
func testServerAddressDiscovery(t *testing.T, multipath bool) {
	var serverAddr netip.AddrPort
	recorder := testServerWithConfig(t, multipath, func(c *quic.Config) {
		c.RequestObservedAddress = true
		c.ProvideObservedAddress = true
	}, "-J", "2")
	for _, ev := range recorder.Events(qlog.ParametersSet{}) {
		if ps := ev.(qlog.ParametersSet); ps.Initiator == qlog.InitiatorRemote {
			require.NotNil(t, ps.AddressDiscovery)
			require.Equal(t, uint64(2), *ps.AddressDiscovery)
		}
	}
	sent, rcvd := observedAddressFrames(recorder)
	t.Logf("OBSERVED_ADDRESS frames sent: %v, received: %v", sent, rcvd)
	pathIDs := []quic.PathID{0}
	if multipath {
		pathIDs = append(pathIDs, 1)
	}
	for i, id := range pathIDs {
		require.NotEmpty(t, sent[id], "no OBSERVED_ADDRESS frame sent on path %d", id)
		// the client's address on path 1 is on 127.0.0.2
		for _, f := range sent[id] {
			require.Equal(t, netip.AddrFrom4([4]byte{127, 0, 0, byte(i + 1)}), f.Address.Addr())
		}
		require.NotEmpty(t, rcvd[id], "no OBSERVED_ADDRESS frame received on path %d", id)
		for _, f := range rcvd[id] {
			if !serverAddr.IsValid() {
				serverAddr = f.Address
			}
			require.Equal(t, serverAddr, f.Address)
		}
	}
	require.Equal(t, netip.AddrFrom4([4]byte{127, 0, 0, 1}), serverAddr.Addr())
}

func TestPicoquicClientAddressDiscovery(t *testing.T) { testServerAddressDiscovery(t, false) }

func TestPicoquicClientAddressDiscoveryMultipath(t *testing.T) { testServerAddressDiscovery(t, true) }

func loadCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem"))
	require.NoError(t, err)
	return cert
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}
