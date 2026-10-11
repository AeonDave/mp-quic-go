package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/internal/testdata"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/AeonDave/mp-quic-go/testutils/events"
	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
)

func TestConfigureTLSConfig(t *testing.T) {
	t.Run("basic config", func(t *testing.T) {
		conf := ConfigureTLSConfig(&tls.Config{})
		require.Equal(t, conf.NextProtos, []string{NextProtoH3})
	})

	t.Run("ALPN set", func(t *testing.T) {
		conf := ConfigureTLSConfig(&tls.Config{NextProtos: []string{"foo", "bar"}})
		require.Equal(t, []string{NextProtoH3}, conf.NextProtos)
	})

	// for configs that define GetConfigForClient, the ALPN is set to h3
	t.Run("GetConfigForClient", func(t *testing.T) {
		staticConf := &tls.Config{NextProtos: []string{"foo", "bar"}}
		conf := ConfigureTLSConfig(&tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return staticConf, nil
			},
		})
		innerConf, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
		require.NoError(t, err)
		require.NotNil(t, innerConf)
		require.Equal(t, []string{NextProtoH3}, innerConf.NextProtos)
		// make sure the original config was not modified
		require.Equal(t, []string{"foo", "bar"}, staticConf.NextProtos)
	})

	// GetConfigForClient might return a nil tls.Config
	t.Run("GetConfigForClient returns nil", func(t *testing.T) {
		conf := ConfigureTLSConfig(&tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
		})
		innerConf, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
		require.NoError(t, err)
		require.Nil(t, innerConf)
	})
}

func TestServerSettings(t *testing.T) {
	t.Run("enable datagrams", func(t *testing.T) {
		testServerSettings(t, true, nil)
	})
	t.Run("additional settings", func(t *testing.T) {
		testServerSettings(t, false, map[uint64]uint64{13: 37})
	})
}

func testServerSettings(t *testing.T, enableDatagrams bool, other map[uint64]uint64) {
	s := Server{
		EnableDatagrams:    enableDatagrams,
		AdditionalSettings: other,
	}
	s.init()

	testDone := make(chan struct{})
	defer close(testDone)

	clientConn, serverConn := newConnPair(t)
	go s.handleConn(serverConn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	settingsStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	settingsStr.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1024)
	n, err := settingsStr.Read(b)
	require.NoError(t, err)
	b = b[:n]

	typ, l, err := quicvarint.Parse(b)
	require.NoError(t, err)
	require.EqualValues(t, streamTypeControlStream, typ)
	fp := (&frameParser{r: bytes.NewReader(b[l:])})
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	settingsFrame := f.(*settingsFrame)
	// Extended CONNECT is always supported
	require.True(t, settingsFrame.ExtendedConnect)
	require.Equal(t, settingsFrame.Datagram, enableDatagrams)
	require.Equal(t, settingsFrame.Other, other)
}

func TestServerRequestHandling(t *testing.T) {
	t.Run("200 with an empty handler", func(t *testing.T) {
		var eventRecorder events.Recorder
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {},
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
			&eventRecorder,
		)
		require.Equal(t, hfs[":status"], []string{"200"})
		require.Empty(t, body)

		require.Len(t, eventRecorder.Events(qlog.FrameParsed{}), 1)
		require.IsType(t, qlog.HeadersFrame{}, eventRecorder.Events(qlog.FrameParsed{})[0].(qlog.FrameParsed).Frame.Frame)
		fp := eventRecorder.Events(qlog.FrameParsed{})[0].(qlog.FrameParsed)
		require.Equal(t, quic.StreamID(0), fp.StreamID)
		require.NotZero(t, fp.Raw.PayloadLength)
		require.Contains(t, fp.Frame.Frame.(qlog.HeadersFrame).HeaderFields, qlog.HeaderField{Name: ":method", Value: "GET"})
		require.Contains(t, fp.Frame.Frame.(qlog.HeadersFrame).HeaderFields, qlog.HeaderField{Name: ":authority", Value: "www.example.com"})

		events := filterQlogEventsForFrame(eventRecorder.Events(qlog.FrameCreated{}), qlog.HeadersFrame{})
		require.Len(t, events, 1)
		fc := events[0].(qlog.FrameCreated)
		require.Equal(t, quic.StreamID(0), fp.StreamID)
		require.NotZero(t, fc.Raw.PayloadLength)
		require.Contains(t, fc.Frame.Frame.(qlog.HeadersFrame).HeaderFields, qlog.HeaderField{Name: ":status", Value: "200"})
	})

	t.Run("content-length", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
				w.Write([]byte("foobar"))
			},
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
			nil,
		)
		require.Equal(t, hfs[":status"], []string{"418"})
		require.Equal(t, hfs["content-length"], []string{"6"})
		require.Equal(t, body, []byte("foobar"))
	})

	t.Run("no content-length when flushed", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foo"))
				w.(http.Flusher).Flush()
				w.Write([]byte("bar"))
			},
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
			nil,
		)
		require.Equal(t, hfs[":status"], []string{"200"})
		require.NotContains(t, hfs, "content-length")
		require.Equal(t, body, []byte("foobar"))
	})

	t.Run("HEAD request", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foobar"))
			},
			httptest.NewRequest(http.MethodHead, "https://www.example.com", nil),
			nil,
		)
		require.Equal(t, hfs[":status"], []string{"200"})
		require.Empty(t, body)
	})

	t.Run("POST request", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
				data, _ := io.ReadAll(r.Body)
				w.Write(data)
			},
			httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			nil,
		)
		require.Equal(t, hfs[":status"], []string{"418"})
		require.Equal(t, []byte("foobar"), body)
	})
}

func testServerRequestHandling(t *testing.T,
	handler http.HandlerFunc,
	req *http.Request,
	rec qlogwriter.Recorder,
) (responseHeaders map[string][]string, body []byte) {
	clientConn, serverConn := newConnPair(t, withServerRecorder(rec))
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, req))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	s := &Server{Handler: handler}
	go s.ServeQUICConn(serverConn)

	hfs := decodeHeader(t, str)
	fp := frameParser{r: str}
	var content []byte
	for {
		frame, err := fp.ParseNext(nil)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		require.IsType(t, &dataFrame{}, frame)
		b := make([]byte, frame.(*dataFrame).Length)
		_, err = io.ReadFull(str, b)
		require.NoError(t, err)
		content = append(content, b...)
	}
	return hfs, content
}

func TestServerFirstFrameNotHeaders(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)

	var buf bytes.Buffer
	buf.Write((&dataFrame{Length: 6}).Append(nil))
	buf.Write([]byte("foobar"))
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, str.Close())

	s := &Server{}
	go s.ServeQUICConn(serverConn)

	select {
	case <-clientConn.Context().Done():
		err := context.Cause(clientConn.Context())
		var appErr *quic.ApplicationError
		require.ErrorAs(t, err, &appErr)
		require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameUnexpected), appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// A request stream that ends in the middle of a frame is a connection error of type H3_FRAME_ERROR
// (section 7.1 of RFC 9114).
func TestServerTruncatedHeadersFrame(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "in the frame header", data: []byte{0x1}},
		{name: "in the payload", data: append((&headersFrame{Length: 10}).Append(nil), 1, 2, 3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := newConnPair(t)
			str, err := clientConn.OpenStream()
			require.NoError(t, err)
			_, err = str.Write(tc.data)
			require.NoError(t, err)
			require.NoError(t, str.Close())

			go (&Server{}).ServeQUICConn(serverConn)

			select {
			case <-clientConn.Context().Done():
				var appErr *quic.ApplicationError
				require.ErrorAs(t, context.Cause(clientConn.Context()), &appErr)
				require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameError), appErr.ErrorCode)
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
		})
	}
}

func TestServerRejectsPriorityUpdateForPush(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	go (&Server{}).ServeQUICConn(serverConn)

	str, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	b = quicvarint.Append(b, 0xf0701)
	b = quicvarint.Append(b, 42)
	b = append(b, make([]byte, 42)...)
	_, err = str.Write(b)
	require.NoError(t, err)

	select {
	case <-clientConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(clientConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeIDError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

func TestServerHandlerBodyNotRead(t *testing.T) {
	t.Run("GET request with a body", func(t *testing.T) {
		testServerHandlerBodyNotRead(t,
			httptest.NewRequest(http.MethodGet, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			func(w http.ResponseWriter, r *http.Request) {},
		)
	})

	t.Run("POST body not read", func(t *testing.T) {
		testServerHandlerBodyNotRead(t,
			httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			func(w http.ResponseWriter, r *http.Request) {},
		)
	})

	t.Run("POST request, with a replaced body", func(t *testing.T) {
		testServerHandlerBodyNotRead(t,
			httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = struct {
					io.Reader
					io.Closer
				}{}
			},
		)
	})
}

func testServerHandlerBodyNotRead(t *testing.T, req *http.Request, handler http.HandlerFunc) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, req))
	require.NoError(t, err)

	done := make(chan struct{})
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(done)
			handler(w, r)
		}),
	}

	go s.ServeQUICConn(serverConn)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServerStreamResetByClient(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	str.CancelWrite(1337)

	var called bool
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}),
	}

	go s.ServeQUICConn(serverConn)

	expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeRequestIncomplete))
	require.False(t, called)
}

func TestServerPanickingHandler(t *testing.T) {
	t.Run("panicking handler", func(t *testing.T) {
		logOutput := testServerPanickingHandler(t, func(w http.ResponseWriter, r *http.Request) {
			panic("foobar")
		})
		require.Contains(t, logOutput, "http3: panic serving")
		require.Contains(t, logOutput, "foobar")
	})

	t.Run("http.ErrAbortHandler", func(t *testing.T) {
		logOutput := testServerPanickingHandler(t, func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		})
		require.NotContains(t, logOutput, "http3: panic serving")
		require.NotContains(t, logOutput, "http.ErrAbortHandler")
	})
}

func testServerPanickingHandler(t *testing.T, handler http.HandlerFunc) (logOutput string) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	var logBuf bytes.Buffer
	s := &Server{
		Handler: handler,
		Logger:  slog.New(slog.NewTextHandler(&logBuf, nil)),
	}

	go s.ServeQUICConn(serverConn)

	expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeInternalError))
	s.Close()

	return logBuf.String()
}

func TestServerRequestHeaderTooLarge(t *testing.T) {
	t.Run("default value", func(t *testing.T) {
		var eventRecorder events.Recorder
		// use 2*DefaultMaxHeaderBytes here. qpack will compress the request,
		// but the request will still end up larger than DefaultMaxHeaderBytes.
		url := bytes.Repeat([]byte{'a'}, http.DefaultMaxHeaderBytes*2)
		testServerRequestHeaderTooLarge(t,
			httptest.NewRequest(http.MethodGet, "https://"+string(url), nil),
			0,
			&eventRecorder,
		)
		events := eventRecorder.Events(qlog.FrameParsed{})
		require.Len(t, events, 1)
		require.Equal(t, qlog.HeadersFrame{}, events[0].(qlog.FrameParsed).Frame.Frame)
		// The request is QPACK-compressed, so it will be smaller than 2*http.DefaultMaxHeaderBytes
		require.Greater(t, events[0].(qlog.FrameParsed).Raw.PayloadLength, http.DefaultMaxHeaderBytes)
		require.Less(t, events[0].(qlog.FrameParsed).Raw.PayloadLength, http.DefaultMaxHeaderBytes*2)
	})

	t.Run("custom value", func(t *testing.T) {
		var eventRecorder events.Recorder
		testServerRequestHeaderTooLarge(t,
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
			20,
			&eventRecorder,
		)
		events := eventRecorder.Events(qlog.FrameParsed{})
		require.Len(t, events, 1)
		require.Equal(t, qlog.HeadersFrame{}, events[0].(qlog.FrameParsed).Frame.Frame)
		require.Greater(t, events[0].(qlog.FrameParsed).Raw.PayloadLength, 20)
		require.Less(t, events[0].(qlog.FrameParsed).Raw.PayloadLength, 40)
	})
}

func testServerRequestHeaderTooLarge(t *testing.T, req *http.Request, maxHeaderBytes int, rec qlogwriter.Recorder) {
	var called bool
	s := &Server{
		MaxHeaderBytes: maxHeaderBytes,
		Handler:        http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
	}
	s.init()

	clientConn, serverConn := newConnPair(t, withServerRecorder(rec))
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, req))
	require.NoError(t, err)

	go s.ServeQUICConn(serverConn)

	hfs := decodeHeader(t, str)
	require.Equal(t, []string{"431"}, hfs[":status"])
	expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeExcessiveLoad))
	require.False(t, called)
}

func TestServerRequestContext(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)))
	require.NoError(t, err)

	ctxChan := make(chan context.Context, 1)
	block := make(chan struct{})
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctxChan <- r.Context()
			<-block
		}),
	}

	go s.ServeQUICConn(serverConn)

	var requestContext context.Context
	select {
	case requestContext = <-ctxChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Equal(t, s, requestContext.Value(ServerContextKey))
	require.Equal(t, serverConn.LocalAddr(), requestContext.Value(http.LocalAddrContextKey))
	require.Equal(t, serverConn.RemoteAddr(), requestContext.Value(RemoteAddrContextKey))
	select {
	case <-requestContext.Done():
		t.Fatal("request context was canceled")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	str.CancelRead(1337)

	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.ErrorIs(t, requestContext.Err(), context.Canceled)
	close(block)
}

func TestServerHTTPStreamHijacking(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			str := w.(HTTPStreamer).HTTPStream()
			str.Write([]byte("foobar"))
			str.Close()
		}),
	}
	go s.ServeQUICConn(serverConn)

	str.SetReadDeadline(time.Now().Add(time.Second))
	rsp, err := io.ReadAll(str)
	require.NoError(t, err)
	r := bytes.NewReader(rsp)
	hfs := decodeHeader(t, r)
	require.Equal(t, hfs[":status"], []string{"200"})
	fp := frameParser{r: r}
	frame, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, frame)
	dataFrame := frame.(*dataFrame)
	require.Equal(t, uint64(6), dataFrame.Length)
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
}

func getAltSvc(s *Server) (string, bool) {
	hdr := http.Header{}
	s.SetQUICHeaders(hdr)
	if altSvc, ok := hdr["Alt-Svc"]; ok {
		return altSvc[0], true
	}
	return "", false
}

func TestServerAltSvcFromListenersAndConns(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		testServerAltSvcFromListenersAndConns(t, []quic.Version{})
	})
	t.Run("v1", func(t *testing.T) {
		testServerAltSvcFromListenersAndConns(t, []quic.Version{quic.Version1})
	})
	t.Run("v1 and v2", func(t *testing.T) {
		testServerAltSvcFromListenersAndConns(t, []quic.Version{quic.Version1, quic.Version2})
	})
}

func testServerAltSvcFromListenersAndConns(t *testing.T, versions []quic.Version) {
	ln1, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), nil)
	require.NoError(t, err)
	port1 := ln1.Addr().(*net.UDPAddr).Port

	s := &Server{
		Addr:       ":1337", // will be ignored since we're using listeners
		TLSConfig:  getTLSConfig(),
		QUICConfig: &quic.Config{Versions: versions},
	}
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		s.ServeListener(ln1)
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))
	altSvc, ok := getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf(`h3=":%d"; ma=2592000`, port1), altSvc)

	udpConn := newUDPConnLocalhost(t)
	port2 := udpConn.LocalAddr().(*net.UDPAddr).Port
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.Serve(udpConn)
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))
	altSvc, ok = getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf(`h3=":%d"; ma=2592000,h3=":%d"; ma=2592000`, port1, port2), altSvc)

	// Close the first listener.
	// This should remove the associated Alt-Svc entry.
	require.NoError(t, ln1.Close())
	select {
	case <-done1:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	altSvc, ok = getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf(`h3=":%d"; ma=2592000`, port2), altSvc)

	// Close the second listener.
	// This should remove the Alt-Svc entry altogether.
	require.NoError(t, udpConn.Close())
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	_, ok = getAltSvc(s)
	require.False(t, ok)
}

func TestServerAltSvcFromPort(t *testing.T) {
	s := &Server{Port: 1337}
	_, ok := getAltSvc(s)
	require.False(t, ok)

	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), nil)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeListener(ln)
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))

	altSvc, ok := getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, `h3=":1337"; ma=2592000`, altSvc)

	require.NoError(t, ln.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	_, ok = getAltSvc(s)
	require.False(t, ok)
}

type unixSocketListener struct {
	*quic.EarlyListener
}

func (l *unixSocketListener) Addr() net.Addr {
	return &net.UnixAddr{Net: "unix", Name: "/tmp/quic.sock"}
}

func TestServerAltSvcFromUnixSocket(t *testing.T) {
	t.Run("with Server.Addr not set", func(t *testing.T) {
		_, ok := testServerAltSvcFromUnixSocket(t, "")
		require.False(t, ok)
	})

	t.Run("with Server.Addr set", func(t *testing.T) {
		altSvc, ok := testServerAltSvcFromUnixSocket(t, ":1337")
		require.True(t, ok)
		require.Equal(t, `h3=":1337"; ma=2592000`, altSvc)
	})
}

func testServerAltSvcFromUnixSocket(t *testing.T, addr string) (altSvc string, ok bool) {
	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), testdata.GetTLSConfig(), nil)
	require.NoError(t, err)

	var logBuf bytes.Buffer
	s := &Server{
		Addr:   addr,
		Logger: slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeListener(&unixSocketListener{EarlyListener: ln})
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))

	altSvc, ok = getAltSvc(s)
	require.NoError(t, ln.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Contains(t, logBuf.String(), "Unable to extract port from listener, will not be announced using SetQUICHeaders")
	return altSvc, ok
}

func TestServerListenAndServeErrors(t *testing.T) {
	require.EqualError(t, (&Server{}).ListenAndServe(), "use of http3.Server without TLSConfig")
	s := &Server{
		Addr:      ":123456",
		TLSConfig: testdata.GetTLSConfig(),
	}
	require.ErrorContains(t, s.ListenAndServe(), "invalid port")
}

func TestServerClosing(t *testing.T) {
	s := &Server{TLSConfig: getTLSConfig()}
	require.NoError(t, s.Close())
	require.NoError(t, s.Close()) // duplicate calls are ok
	require.ErrorIs(t, s.ListenAndServe(), http.ErrServerClosed)
	require.ErrorIs(t, s.ListenAndServeTLS(testdata.GetCertificatePaths()), http.ErrServerClosed)
	require.ErrorIs(t, s.Serve(nil), http.ErrServerClosed)
	require.ErrorIs(t, s.ServeListener(nil), http.ErrServerClosed)
	require.ErrorIs(t, s.ServeQUICConn(nil), http.ErrServerClosed)
}

func TestServerConcurrentServeAndClose(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	c, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	done := make(chan struct{})
	s := &Server{TLSConfig: testdata.GetTLSConfig()}
	go func() {
		defer close(done)
		s.Serve(c)
	}()
	runtime.Gosched()
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServerImmediateGracefulShutdown(t *testing.T) {
	s := &Server{TLSConfig: testdata.GetTLSConfig()}
	errChan := make(chan error, 1)
	go func() { errChan <- s.Shutdown(context.Background()) }()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServerGracefulShutdown(t *testing.T) {
	requestChan := make(chan struct{}, 1)
	s := &Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestChan <- struct{}{}
	})}

	clientConn, serverConn := newConnPair(t)
	go s.ServeQUICConn(serverConn)

	firstStream, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = firstStream.Write(encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)))
	require.NoError(t, err)

	select {
	case <-requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	controlStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	typ, err := quicvarint.Read(quicvarint.NewReader(controlStr))
	require.NoError(t, err)
	require.EqualValues(t, streamTypeControlStream, typ)
	fp := &frameParser{r: controlStr}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	errChan := make(chan error)
	go func() {
		errChan <- s.Shutdown(shutdownCtx)
	}()

	f, err = fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, &goAwayFrame{StreamID: 4}, f)

	select {
	case <-errChan:
		t.Fatal("didn't expect Shutdown to return")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// all further streams are getting rejected
	for range 3 {
		str, err := clientConn.OpenStream()
		require.NoError(t, err)
		_, _ = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)))
		expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeRequestRejected))
		expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeRequestRejected))
	}

	// cancel the context passed to Shutdown
	shutdownCancel()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// Malformed requests MUST be treated as a stream error, see section 4.1.2 of RFC 9114.
// This also applies to malformed trailers.
func TestServerRequestTrailerValidation(t *testing.T) {
	for _, tt := range trailerValidationTests(t) {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := newConnPair(t)
			str, err := clientConn.OpenStream()
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBufferString("foobar"))
			_, err = str.Write(append(encodeRequest(t, req), tt.trailer...))
			require.NoError(t, err)

			handlerErr := make(chan error, 1)
			s := &Server{
				MaxHeaderBytes: tt.maxHeaderBytes,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := io.ReadAll(r.Body)
					handlerErr <- err
				}),
			}
			go s.ServeQUICConn(serverConn)

			select {
			case err := <-handlerErr:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
			expectStreamReadReset(t, str, quic.StreamErrorCode(tt.errCode))
			expectStreamWriteReset(t, str, quic.StreamErrorCode(tt.errCode))
		})
	}
}

// A field section that doesn't reference the dynamic table can use any value for the Base,
// see section 4.5.1.2 of RFC 9204.
func TestServerRequestNonZeroBase(t *testing.T) {
	headers := encodeFieldSection(t,
		qpack.HeaderField{Name: ":method", Value: http.MethodPost},
		qpack.HeaderField{Name: ":scheme", Value: "https"},
		qpack.HeaderField{Name: ":authority", Value: "www.example.com"},
		qpack.HeaderField{Name: ":path", Value: "/foo"},
	)
	trailers := encodeFieldSection(t, qpack.HeaderField{Name: "foo", Value: "bar"})
	require.Equal(t, []byte{0x00, 0x00}, headers[:2])
	require.Equal(t, []byte{0x00, 0x00}, trailers[:2])
	headers[1], trailers[1] = 0x05, 0x2a // Sign 0, Delta Base 5 and 42

	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	b := encodeHeadersFrame(headers)
	b = append(b, getDataFrame([]byte("foobar"))...)
	b = append(b, encodeHeadersFrame(trailers)...)
	_, err = str.Write(b)
	require.NoError(t, err)
	require.NoError(t, str.Close())

	type result struct {
		path    string
		body    []byte
		trailer http.Header
		err     error
	}
	resultChan := make(chan result, 1)
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			resultChan <- result{path: r.URL.Path, body: body, trailer: r.Trailer, err: err}
		}),
	}
	go s.ServeQUICConn(serverConn)

	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, "/foo", res.path)
		require.Equal(t, []byte("foobar"), res.body)
		require.Equal(t, http.Header{"Foo": []string{"bar"}}, res.trailer)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// Some QPACK decoding errors MUST be treated as a connection error,
// see sections 2.2.3, 3.1 and 4.5.1.1 of RFC 9204.
func TestServerRequestHeadersQPACKConnectionError(t *testing.T) {
	for _, tt := range qpackConnectionErrorTests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := newConnPair(t)
			str, err := clientConn.OpenStream()
			require.NoError(t, err)
			_, err = str.Write(encodeHeadersFrame(tt.fieldSection))
			require.NoError(t, err)

			handlerCalled := make(chan struct{})
			s := &Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(handlerCalled) })}
			go s.ServeQUICConn(serverConn)

			expectConnClosedByPeer(t, clientConn, ErrCodeQPACKDecompressionFailed)
			select {
			case <-handlerCalled:
				t.Fatal("handler should not have been called")
			default:
			}
		})
	}
}

func TestServerRequestTrailersQPACKConnectionError(t *testing.T) {
	for _, tt := range qpackConnectionErrorTests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := newConnPair(t)
			str, err := clientConn.OpenStream()
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBufferString("foobar"))
			_, err = str.Write(append(encodeRequest(t, req), encodeHeadersFrame(tt.fieldSection)...))
			require.NoError(t, err)

			handlerErr := make(chan error, 1)
			s := &Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := io.ReadAll(r.Body)
					handlerErr <- err
				}),
			}
			go s.ServeQUICConn(serverConn)

			select {
			case err := <-handlerErr:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
			expectConnClosedByPeer(t, clientConn, ErrCodeQPACKDecompressionFailed)
		})
	}
}

// A DATA or HEADERS frame after the trailing HEADERS frame MUST be treated
// as a connection error of type H3_FRAME_UNEXPECTED, see section 4.1 of RFC 9114.
func TestServerFramesAfterRequestTrailers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{name: "DATA", frame: getDataFrame([]byte("foo"))},
		{name: "HEADERS", frame: encodeTrailerFrame(t, qpack.HeaderField{Name: "bar", Value: "baz"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := newConnPair(t)
			str, err := clientConn.OpenStream()
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBufferString("foobar"))
			b := encodeRequest(t, req)
			b = append(b, encodeTrailerFrame(t, qpack.HeaderField{Name: "foo", Value: "bar"})...)
			b = append(b, tc.frame...)
			_, err = str.Write(b)
			require.NoError(t, err)

			type result struct {
				body    []byte
				trailer http.Header
				err     error
			}
			resultChan := make(chan result, 1)
			s := &Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					resultChan <- result{body: body, trailer: r.Trailer, err: err}
				}),
			}
			go s.ServeQUICConn(serverConn)

			select {
			case res := <-resultChan:
				require.Error(t, res.err)
				require.Equal(t, []byte("foobar"), res.body)
				require.Equal(t, http.Header{"Foo": []string{"bar"}}, res.trailer)
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
			expectConnClosedByPeer(t, clientConn, ErrCodeFrameUnexpected)
		})
	}
}

// On the stream of a CONNECT request, only DATA frames are allowed after the request (section 4.4 of RFC 9114).
func TestServerConnectStreamHeadersFrame(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodConnect, "https://www.example.com", nil)
	b := encodeRequest(t, req)
	b = append(b, getDataFrame([]byte("foo"))...)
	b = append(b, encodeTrailerFrame(t, qpack.HeaderField{Name: "foo", Value: "bar"})...)
	_, err = str.Write(b)
	require.NoError(t, err)

	type result struct {
		body []byte
		err  error
	}
	resultChan := make(chan result, 1)
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodConnect, r.Method)
			w.WriteHeader(http.StatusOK)
			body, err := io.ReadAll(r.Body)
			resultChan <- result{body: body, err: err}
		}),
	}
	go s.ServeQUICConn(serverConn)

	select {
	case res := <-resultChan:
		require.Error(t, res.err)
		require.Equal(t, []byte("foo"), res.body)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	expectConnClosedByPeer(t, clientConn, ErrCodeFrameUnexpected)
}

// testServerControlStreamConnError sends the frames on the control stream, after the SETTINGS frame,
// and expects the server to close the connection.
func testServerControlStreamConnError(t *testing.T, frames []byte, errCode ErrCode) {
	t.Helper()

	clientConn, serverConn := newConnPair(t)
	go (&Server{}).ServeQUICConn(serverConn)

	str, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	_, err = str.Write(append(b, frames...))
	require.NoError(t, err)
	expectConnClosedByPeer(t, clientConn, errCode)
}

func TestServerControlStreamPushFrames(t *testing.T) {
	// The server never sends PUSH_PROMISE frames, so the client can't cancel any push,
	// see section 7.2.3 of RFC 9114.
	t.Run("CANCEL_PUSH", func(t *testing.T) {
		testServerControlStreamConnError(t, (&cancelPushFrame{PushID: 0}).Append(nil), ErrCodeIDError)
	})

	// section 7.2.5 of RFC 9114
	t.Run("PUSH_PROMISE", func(t *testing.T) {
		testServerControlStreamConnError(t, appendPushPromiseFrame(nil, 0), ErrCodeFrameUnexpected)
	})

	// section 7.2.7 of RFC 9114
	t.Run("decreasing MAX_PUSH_ID", func(t *testing.T) {
		b := (&maxPushIDFrame{PushID: 5}).Append(nil)
		b = (&maxPushIDFrame{PushID: 3}).Append(b)
		testServerControlStreamConnError(t, b, ErrCodeIDError)
	})

	// section 5.2 of RFC 9114
	t.Run("increasing push ID in GOAWAY", func(t *testing.T) {
		b := (&goAwayFrame{StreamID: 0}).Append(nil)
		b = (&goAwayFrame{StreamID: 4}).Append(b)
		testServerControlStreamConnError(t, b, ErrCodeIDError)
	})

	// Non-decreasing MAX_PUSH_ID frames and GOAWAY frames with non-increasing push IDs are valid.
	// The PUSH_PROMISE frame at the end shows that the server processed them without closing the connection.
	t.Run("valid frames", func(t *testing.T) {
		b := (&maxPushIDFrame{PushID: 3}).Append(nil)
		b = (&maxPushIDFrame{PushID: 3}).Append(b)
		b = (&maxPushIDFrame{PushID: 5}).Append(b)
		b = (&goAwayFrame{StreamID: 9}).Append(b)
		b = (&goAwayFrame{StreamID: 9}).Append(b)
		b = (&goAwayFrame{StreamID: 1}).Append(b)
		b = appendPushPromiseFrame(b, 0)
		testServerControlStreamConnError(t, b, ErrCodeFrameUnexpected)
	})
}

// PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID and SETTINGS frames are not allowed on request streams,
// see sections 7.2.3, 7.2.4, 7.2.5 and 7.2.7 of RFC 9114.
func TestServerPushFramesOnRequestStream(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{name: "PUSH_PROMISE", frame: appendPushPromiseFrame(nil, 0)},
		{name: "CANCEL_PUSH", frame: (&cancelPushFrame{PushID: 0}).Append(nil)},
		{name: "MAX_PUSH_ID", frame: (&maxPushIDFrame{PushID: 0}).Append(nil)},
		// A frame that is not allowed on the stream is unexpected, even if it is malformed.
		{name: "CANCEL_PUSH without payload", frame: []byte{0x3, 0x0}},
		{name: "SETTINGS ending inside a setting", frame: []byte{0x4, 0x1, 0x1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("before HEADERS", func(t *testing.T) {
				clientConn, serverConn := newConnPair(t)
				str, err := clientConn.OpenStream()
				require.NoError(t, err)
				req := httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)
				_, err = str.Write(append(tc.frame, encodeRequest(t, req)...))
				require.NoError(t, err)

				handlerCalled := make(chan struct{})
				s := &Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(handlerCalled) })}
				go s.ServeQUICConn(serverConn)

				expectConnClosedByPeer(t, clientConn, ErrCodeFrameUnexpected)
				select {
				case <-handlerCalled:
					t.Fatal("handler should not have been called")
				default:
				}
			})

			t.Run("in the body", func(t *testing.T) {
				clientConn, serverConn := newConnPair(t)
				str, err := clientConn.OpenStream()
				require.NoError(t, err)
				req := httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBufferString("foobar"))
				b := encodeRequest(t, req)
				b = append(b, tc.frame...)
				b = append(b, getDataFrame([]byte("baz"))...)
				_, err = str.Write(b)
				require.NoError(t, err)

				type result struct {
					body []byte
					err  error
				}
				resultChan := make(chan result, 1)
				s := &Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						resultChan <- result{body: body, err: err}
					}),
				}
				go s.ServeQUICConn(serverConn)

				select {
				case res := <-resultChan:
					require.Error(t, res.err)
					require.Equal(t, []byte("foobar"), res.body)
				case <-time.After(time.Second):
					t.Fatal("timeout")
				}
				expectConnClosedByPeer(t, clientConn, ErrCodeFrameUnexpected)
			})
		})
	}
}
