package http3

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
)

// maxByteCount is the maximum value of a ByteCount
const maxByteCount = uint64(1<<62 - 1)

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR is 0")
	}
	return time.Duration(scaleFactor) * t
}

var tlsConfig, tlsClientConfig *tls.Config

func init() {
	ca, caPrivateKey, err := generateCA()
	if err != nil {
		panic(err)
	}
	leafCert, leafPrivateKey, err := generateLeafCert(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{NextProtoH3},
	}

	root := x509.NewCertPool()
	root.AddCert(ca)
	tlsClientConfig = &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{NextProtoH3},
	}
}

func generateCA() (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, priv, nil
}

func generateLeafCert(ca *x509.Certificate, caPriv crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTempl, ca, pub, caPriv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func getTLSConfig() *tls.Config       { return tlsConfig.Clone() }
func getTLSClientConfig() *tls.Config { return tlsClientConfig.Clone() }

type qlogTrace struct {
	recorder qlogwriter.Recorder
}

func (t *qlogTrace) SupportsSchemas(schema string) bool { return true }

func (t *qlogTrace) AddProducer() qlogwriter.Recorder {
	return t.recorder
}

type connPairOpts struct {
	clientRecorder        qlogwriter.Recorder
	serverRecorder        qlogwriter.Recorder
	serverBidiStreamLimit int64
	enableDatagrams       bool
}

type connPairOpt func(*connPairOpts)

func withClientRecorder(r qlogwriter.Recorder) connPairOpt {
	return func(o *connPairOpts) { o.clientRecorder = r }
}

func withServerRecorder(r qlogwriter.Recorder) connPairOpt {
	return func(o *connPairOpts) { o.serverRecorder = r }
}

func withDatagrams() connPairOpt {
	return func(o *connPairOpts) { o.enableDatagrams = true }
}

func withServerBidiStreamLimit(limit int64) connPairOpt {
	return func(o *connPairOpts) { o.serverBidiStreamLimit = limit }
}

func newConnPair(t *testing.T, opts ...connPairOpt) (client, server *quic.Conn) {
	t.Helper()

	var o connPairOpts
	for _, opt := range opts {
		opt(&o)
	}

	ln, err := quic.ListenEarly(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		&quic.Config{
			InitialStreamReceiveWindow:     maxByteCount,
			InitialConnectionReceiveWindow: maxByteCount,
			MaxIncomingStreams:             o.serverBidiStreamLimit,
			EnableDatagrams:                o.enableDatagrams,
			Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
				return &qlogTrace{recorder: o.serverRecorder}
			},
		},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cl, err := quic.DialEarly(
		ctx,
		newUDPConnLocalhost(t),
		ln.Addr(),
		getTLSClientConfig(),
		&quic.Config{
			EnableDatagrams: o.enableDatagrams,
			Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
				return &qlogTrace{recorder: o.clientRecorder}
			},
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { cl.CloseWithError(0, "") })

	conn, err := ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	return cl, conn
}

type quicReceiveStream interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

func expectStreamReadReset(t *testing.T, str quicReceiveStream, errCode quic.StreamErrorCode) {
	t.Helper()

	str.SetReadDeadline(time.Now().Add(time.Second))
	_, err := str.Read([]byte{0})
	require.Error(t, err)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("didn't receive a stream reset")
	}
	var strErr *quic.StreamError
	require.ErrorAs(t, err, &strErr)
	require.Equal(t, errCode, strErr.ErrorCode)
}

type quicSendStream interface {
	io.Writer
	Context() context.Context
}

func expectStreamWriteReset(t *testing.T, str quicSendStream, errCode quic.StreamErrorCode) {
	t.Helper()

	select {
	case <-str.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	_, err := str.Write([]byte{0})
	var strErr *quic.StreamError
	require.ErrorAs(t, err, &strErr)
	require.Equal(t, errCode, strErr.ErrorCode)
}

func encodeRequest(t *testing.T, req *http.Request) []byte {
	t.Helper()

	var buf bytes.Buffer
	rw := newRequestWriter()
	require.NoError(t, rw.WriteRequestHeader(&buf, req, false, 0, nil))
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		buf.Write((&dataFrame{Length: uint64(len(body))}).Append(nil))
		buf.Write(body)
	}
	return buf.Bytes()
}

func decodeHeader(t *testing.T, r io.Reader) map[string][]string {
	t.Helper()

	fields := make(map[string][]string)
	frame, err := (&frameParser{r: r}).ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	headersFrame := frame.(*headersFrame)
	data := make([]byte, headersFrame.Length)
	_, err = io.ReadFull(r, data)
	require.NoError(t, err)
	hfs := decodeQpackHeaderFields(t, data)
	for _, p := range hfs {
		fields[p.Name] = append(fields[p.Name], p.Value)
	}
	return fields
}

func decodeQpackHeaderFields(t *testing.T, data []byte) []qpack.HeaderField {
	t.Helper()

	decoder := qpack.NewDecoder()
	decodeFn := decoder.Decode(data)
	var hfs []qpack.HeaderField
	for {
		hf, err := decodeFn()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		hfs = append(hfs, hf)
	}
	return hfs
}

// filterQlogEventsForFrame filters the events for the given frame type,
// for both FrameCreated and FrameParsed events.
// It returns the events that match the given frame type.
func filterQlogEventsForFrame(events []qlogwriter.Event, frame any) []qlogwriter.Event {
	var filtered []qlogwriter.Event
	for _, ev := range events {
		switch e := ev.(type) {
		case qlog.FrameCreated:
			if reflect.TypeOf(e.Frame.Frame) == reflect.TypeOf(frame) {
				filtered = append(filtered, ev)
			}
		case qlog.FrameParsed:
			if reflect.TypeOf(e.Frame.Frame) == reflect.TypeOf(frame) {
				filtered = append(filtered, ev)
			}
		}
	}
	return filtered
}

func expectedFrameLength(t *testing.T, frame any) (length, payloadLength int) {
	t.Helper()

	switch f := frame.(type) {
	case *dataFrame:
		return len(f.Append(nil)) + int(f.Length), int(f.Length)
	case *headersFrame:
		return len(f.Append(nil)) + int(f.Length), int(f.Length)
	case *goAwayFrame:
		return len(f.Append(nil)), quicvarint.Len(uint64(f.StreamID))
	case *settingsFrame:
		data := f.Append(nil)
		r := bytes.NewReader(data)
		_, err := quicvarint.Read(r) // type
		require.NoError(t, err)
		_, err = quicvarint.Read(r) // length
		require.NoError(t, err)
		return len(data), r.Len()
	default:
		t.Fatalf("unexpected frame type: %T", frame)
	}
	panic("unreachable")
}

// encodeTrailerFrame encodes a HEADERS frame carrying a trailer section.
func encodeTrailerFrame(t *testing.T, fields ...qpack.HeaderField) []byte {
	t.Helper()

	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range fields {
		require.NoError(t, enc.WriteField(f))
	}
	require.NoError(t, enc.Close())
	return append((&headersFrame{Length: uint64(buf.Len())}).Append(nil), buf.Bytes()...)
}

// encodeHeadersFrame encodes a HEADERS frame carrying the given encoded field section.
func encodeHeadersFrame(fieldSection []byte) []byte {
	return append((&headersFrame{Length: uint64(len(fieldSection))}).Append(nil), fieldSection...)
}

// qpackConnectionErrorTests are encoded field sections that must be treated
// as a connection error of type QPACK_DECOMPRESSION_FAILED, see RFC 9204.
var qpackConnectionErrorTests = []struct {
	name         string
	fieldSection []byte
}{
	{name: "non-zero Required Insert Count", fieldSection: []byte{0x01, 0x00, 0xd1}},
	{name: "reference to the dynamic table", fieldSection: []byte{0x00, 0x00, 0x80}},
	{name: "invalid static table index", fieldSection: []byte{0x00, 0x00, 0xff, 0x24}},
}

// expectConnClosedByPeer waits until the peer closes the connection with the given error code.
func expectConnClosedByPeer(t *testing.T, conn *quic.Conn, errCode ErrCode) {
	t.Helper()

	select {
	case <-conn.Context().Done():
		require.ErrorIs(t,
			context.Cause(conn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(errCode)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for the connection to be closed")
	}
}

// A trailerValidationTest is a trailer section that must be rejected,
// and the error code used to reset the stream.
type trailerValidationTest struct {
	name           string
	trailer        []byte
	maxHeaderBytes int
	errCode        ErrCode
}

func trailerValidationTests(t *testing.T) []trailerValidationTest {
	t.Helper()

	// Static table entries are encoded in a single byte,
	// but count with their full name and value length towards the field section size.
	tooLarge := make([]qpack.HeaderField, 0, 100)
	for range 100 {
		tooLarge = append(tooLarge, qpack.HeaderField{Name: "accept-encoding", Value: "gzip, deflate, br"})
	}
	return []trailerValidationTest{
		{
			name:    "uppercase field name",
			trailer: encodeTrailerFrame(t, qpack.HeaderField{Name: "Foo", Value: "bar"}),
			errCode: ErrCodeMessageError,
		},
		{
			name:    "connection-specific field",
			trailer: encodeTrailerFrame(t, qpack.HeaderField{Name: "connection", Value: "close"}),
			errCode: ErrCodeMessageError,
		},
		{
			name:    "pseudo header field",
			trailer: encodeTrailerFrame(t, qpack.HeaderField{Name: ":path", Value: "/"}),
			errCode: ErrCodeMessageError,
		},
		{
			name:    "invalid field value",
			trailer: encodeTrailerFrame(t, qpack.HeaderField{Name: "foo", Value: "bar\r\nbaz"}),
			errCode: ErrCodeMessageError,
		},
		{
			// A truncated field line is a stream error.
			// Other QPACK errors are connection errors, see qpackConnectionErrorTests.
			name:    "invalid QPACK encoding",
			trailer: encodeHeadersFrame([]byte{0x00, 0x00, 0x52}),
			errCode: ErrCodeQPACKDecompressionFailed,
		},
		{
			name:           "field section too large",
			trailer:        encodeTrailerFrame(t, tooLarge...),
			maxHeaderBytes: 1000,
			errCode:        ErrCodeExcessiveLoad,
		},
		{
			name:           "HEADERS frame too large",
			trailer:        (&headersFrame{Length: 1001}).Append(nil),
			maxHeaderBytes: 1000,
			errCode:        ErrCodeExcessiveLoad,
		},
	}
}
