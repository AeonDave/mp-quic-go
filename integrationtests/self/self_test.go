package self_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3"
	"github.com/AeonDave/mp-quic-go/integrationtests/tools"
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/internal/wire"
	"github.com/AeonDave/mp-quic-go/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

const alpn = tools.ALPN

const (
	dataLen     = 500 * 1024       // 500 KB
	dataLenLong = 50 * 1024 * 1024 // 50 MB
)

var (
	// PRData contains dataLen bytes of pseudo-random data.
	PRData = GeneratePRData(dataLen)
	// PRDataLong contains dataLenLong bytes of pseudo-random data.
	PRDataLong = GeneratePRData(dataLenLong)
)

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func GeneratePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := range l {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

var (
	version    quic.Version
	enableQlog bool
	// The endpoints that IETF Multipath QUIC is configured on, set by the -multipath flag:
	// "both", "client", "server", or "" (none).
	multipathEndpoints string

	tlsConfig                        *tls.Config
	tlsConfigLongChain               *tls.Config
	tlsClientConfig                  *tls.Config
	tlsClientConfigWithoutServerName *tls.Config
)

func init() {
	ca, caPrivateKey, err := tools.GenerateCA()
	if err != nil {
		panic(err)
	}
	leafCert, leafPrivateKey, err := tools.GenerateLeafCert(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{alpn},
	}
	tlsConfLongChain, err := tools.GenerateTLSConfigWithLongCertChain(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfigLongChain = tlsConfLongChain

	root := x509.NewCertPool()
	root.AddCert(ca)
	tlsClientConfig = &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{alpn},
	}
	tlsClientConfigWithoutServerName = &tls.Config{
		RootCAs:    root,
		NextProtos: []string{alpn},
	}
}

func getTLSConfig() *tls.Config                  { return tlsConfig.Clone() }
func getTLSConfigWithLongCertChain() *tls.Config { return tlsConfigLongChain.Clone() }
func getTLSClientConfig() *tls.Config            { return tlsClientConfig.Clone() }
func getTLSClientConfigWithoutServerName() *tls.Config {
	return tlsClientConfigWithoutServerName.Clone()
}

type multiplexedRecorder struct {
	Recorders []qlogwriter.Recorder
}

var _ qlogwriter.Recorder = &multiplexedRecorder{}

func (r *multiplexedRecorder) Close() error {
	for _, recorder := range r.Recorders {
		recorder.Close()
	}
	return nil
}

func (r *multiplexedRecorder) RecordEvent(ev qlogwriter.Event) {
	for _, recorder := range r.Recorders {
		recorder.RecordEvent(ev)
	}
}

type multiplexedTrace struct {
	Traces []qlogwriter.Trace
}

var _ qlogwriter.Trace = &multiplexedTrace{}

func (t *multiplexedTrace) AddProducer() qlogwriter.Recorder {
	recorders := make([]qlogwriter.Recorder, 0, len(t.Traces))
	for _, tr := range t.Traces {
		recorders = append(recorders, tr.AddProducer())
	}
	return &multiplexedRecorder{Recorders: recorders}
}

func (t *multiplexedTrace) SupportsSchemas(schema string) bool {
	return true
}

func getQuicConfig(conf *quic.Config) *quic.Config {
	if conf == nil {
		conf = &quic.Config{}
	} else {
		conf = conf.Clone()
	}
	configureMultipath(conf)
	if !enableQlog {
		return conf
	}
	if conf.Tracer == nil {
		conf.Tracer = func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
			return tools.NewQlogConnectionTracer(os.Stdout)(ctx, isClient, connID)
		}
		return conf
	}
	origTracer := conf.Tracer
	conf.Tracer = func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		tr := origTracer(ctx, isClient, connID)
		qlogger := tools.NewQlogConnectionTracer(os.Stdout)(ctx, isClient, connID)
		if tr == nil {
			return qlogger
		}
		return &multiplexedTrace{Traces: []qlogwriter.Trace{tr, qlogger}}
	}
	return conf
}

// configureMultipath configures a multipath controller, as requested by the -multipath flag.
func configureMultipath(conf *quic.Config) {
	configureMultipathOn(conf, multipathEndpoints)
}

// configureMultipathOn configures a multipath controller on both endpoints (both), the client or the server.
// A config is used by clients and servers. Servers use the config returned by GetConfigForClient for a new
// connection (the default config if it returns nil), so the multipath controller is added (or removed) there
// for the server side. Tests that use GetConfigForClient therefore set it before calling getQuicConfig.
func configureMultipathOn(conf *quic.Config, endpoints string) {
	if endpoints == "" || conf.MultipathController != nil || conf.MultipathControllerFactory != nil {
		return
	}
	factory := func() quic.MultipathController { return quic.NewDefaultMultipathController(nil) }
	if endpoints != "server" {
		conf.MultipathControllerFactory = factory
	}
	getConfigForClient := conf.GetConfigForClient
	if endpoints == "both" && getConfigForClient == nil {
		return
	}
	conf.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
		c := conf
		if getConfigForClient != nil {
			var err error
			c, err = getConfigForClient(info)
			if err != nil {
				return nil, err
			}
			if c == nil {
				c = &quic.Config{}
			}
		}
		c = c.Clone()
		c.GetConfigForClient = nil
		// a controller configured by the test is kept
		if c.MultipathController != nil {
			return c, nil
		}
		if endpoints == "client" {
			c.MultipathControllerFactory = nil
		} else {
			c.MultipathControllerFactory = factory
		}
		return c, nil
	}
}

// multipathConfigured says if IETF Multipath QUIC is configured on both endpoints.
func multipathConfigured() bool {
	return multipathEndpoints == "both"
}

// clientMultipathConfigured says if IETF Multipath QUIC is configured on the client.
func clientMultipathConfigured() bool {
	return multipathEndpoints == "both" || multipathEndpoints == "client"
}

func addTracer(tr *quic.Transport) {
	if !enableQlog {
		return
	}
	if tr.Tracer == nil {
		tr.Tracer = tools.QlogTracer(os.Stdout).AddProducer()
		return
	}
	origTracer := tr.Tracer
	tr.Tracer = &multiplexedRecorder{
		Recorders: []qlogwriter.Recorder{origTracer, tools.QlogTracer(os.Stdout).AddProducer()},
	}
}

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestMain(m *testing.M) {
	var versionParam string
	flag.StringVar(&versionParam, "version", "1", "QUIC version")
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")
	flag.StringVar(&multipathEndpoints, "multipath", "", "configure IETF Multipath QUIC on both endpoints (both), the client or the server")
	flag.Parse()

	switch multipathEndpoints {
	case "", "both", "client", "server":
	default:
		fmt.Printf("invalid value for -multipath: %s\n", multipathEndpoints)
		os.Exit(1)
	}
	if multipathEndpoints != "" {
		fmt.Printf("configuring IETF Multipath QUIC on: %s\n", multipathEndpoints)
	}

	switch versionParam {
	case "1":
		version = quic.Version1
	case "2":
		version = quic.Version2
	default:
		fmt.Printf("unknown QUIC version: %s\n", versionParam)
		os.Exit(1)
	}
	fmt.Printf("using QUIC version: %s\n", version)

	os.Exit(m.Run())
}

func scaleDuration(d time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR is 0")
	}
	return time.Duration(scaleFactor) * d
}

func newTracer(tracer qlogwriter.Recorder) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	return func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return &events.Trace{Recorder: tracer}
	}
}

type packet struct {
	time   time.Time
	hdr    qlog.PacketHeader
	frames []qlog.Frame
	size   int
}

type packetCounter struct {
	recorder *events.Recorder
}

func (t *packetCounter) getSentShortHeaderPackets() []packet {
	var sentShortHdr []packet
	for _, ev := range t.recorder.EventsWithTime(qlog.PacketSent{}) {
		e := ev.Event.(qlog.PacketSent)
		if e.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		sentShortHdr = append(sentShortHdr, packet{time: ev.Time, hdr: e.Header, frames: e.Frames})
	}
	return sentShortHdr
}

func (t *packetCounter) getRcvdLongHeaderPackets() []packet {
	var rcvdLongHdr []packet
	for _, ev := range t.recorder.EventsWithTime(qlog.PacketReceived{}) {
		e := ev.Event.(qlog.PacketReceived)
		if e.Header.PacketType == qlog.PacketType1RTT {
			continue
		}
		rcvdLongHdr = append(rcvdLongHdr, packet{time: ev.Time, hdr: e.Header, frames: e.Frames})
	}
	return rcvdLongHdr
}

func (t *packetCounter) getRcvd0RTTPacketNumbers() []protocol.PacketNumber {
	var zeroRTTPackets []protocol.PacketNumber
	for _, p := range t.getRcvdLongHeaderPackets() {
		if p.hdr.PacketType == qlog.PacketType0RTT {
			zeroRTTPackets = append(zeroRTTPackets, p.hdr.PacketNumber)
		}
	}
	return zeroRTTPackets
}

func (t *packetCounter) getRcvdShortHeaderPackets() []packet {
	var rcvdShortHdr []packet
	for _, ev := range t.recorder.EventsWithTime(qlog.PacketReceived{}) {
		e := ev.Event.(qlog.PacketReceived)
		if e.Header.PacketType != qlog.PacketType1RTT {
			continue
		}
		rcvdShortHdr = append(rcvdShortHdr, packet{time: ev.Time, hdr: e.Header, frames: e.Frames, size: e.Raw.Length})
	}
	return rcvdShortHdr
}

func newPacketTracer() (*packetCounter, qlogwriter.Trace) {
	c := &packetCounter{recorder: &events.Recorder{}}
	return c, &events.Trace{Recorder: c.recorder}
}

type readerWithTimeout struct {
	io.Reader
	Timeout time.Duration
}

func (r *readerWithTimeout) Read(p []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err = r.Reader.Read(p)
	}()

	select {
	case <-done:
		return n, err
	case <-time.After(r.Timeout):
		return 0, fmt.Errorf("read timeout after %s", r.Timeout)
	}
}

func randomDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(rand.IntN(int(max-min)))
}

// containsPacketType checks if a packet contains a long header packet of the specified type.
// It correctly handles coalesced packets.
func containsPacketType(data []byte, packetType protocol.PacketType) bool {
	for len(data) > 0 {
		if !wire.IsLongHeaderPacket(data[0]) {
			return false
		}
		hdr, _, rest, err := wire.ParsePacket(data)
		if err != nil {
			return false
		}
		if hdr.Type == packetType {
			return true
		}
		data = rest
	}
	return false
}

// addDialCallback explicitly adds the http3.Transport's Dial callback.
// This is needed since dialing on dual-stack sockets is flaky on macOS,
// see https://github.com/golang/go/issues/67226.
func addDialCallback(t *testing.T, tr *http3.Transport) {
	t.Helper()

	if runtime.GOOS != "darwin" {
		return
	}

	require.Nil(t, tr.Dial)
	tr.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		return quic.DialEarly(ctx, newUDPConnLocalhost(t), a, tlsConf, conf)
	}
}
