package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"

	"github.com/quic-go/qpack"
)

type datagramStream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	StreamID() quic.StreamID
	Context() context.Context
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetPriority(urgency int8, incremental bool)
	TryWriteAll([]byte) error
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	QUICStream() *quic.Stream
}

// A Stream is an HTTP/3 stream.
//
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type Stream struct {
	datagramStream
	conn        *rawConn
	frameParser *frameParser

	buf []byte // used as a temporary buffer when writing the HTTP/3 frame headers

	bytesRemainingInFrame uint64

	qlogger qlogwriter.Recorder

	parseTrailer  func(io.Reader, *headersFrame) error
	parsedTrailer bool
	// Set once the CONNECT method has completed: on the server for the streams of CONNECT requests,
	// on the client when a 2xx response was received. Only DATA frames are allowed then (section 4.4 of RFC 9114).
	isConnect bool
	// Set when a write failed. The last frame might be incomplete, see Close.
	writeFailed atomic.Bool
}

func newStream(
	str datagramStream,
	conn *rawConn,
	trace *httptrace.ClientTrace,
	parseTrailer func(io.Reader, *headersFrame) error,
	qlogger qlogwriter.Recorder,
) *Stream {
	return &Stream{
		datagramStream: str,
		conn:           conn,
		buf:            make([]byte, 16),
		qlogger:        qlogger,
		parseTrailer:   parseTrailer,
		frameParser: &frameParser{
			r:         &tracingReader{Reader: str, trace: trace},
			streamID:  str.StreamID(),
			closeConn: conn.CloseWithError,
		},
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	if s.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := s.frameParser.ParseNext(s.qlogger)
			if err != nil {
				if errors.Is(err, errPriorityUpdateForPush) || isControlStreamFrame(err) {
					s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				}
				if isTruncatedFrame(err) {
					s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "truncated frame")
				}
				return 0, maybeReplaceError(err)
			}
			// A DATA or HEADERS frame after the trailing HEADERS frame is an invalid sequence of frames,
			// see section 4.1 of RFC 9114.
			switch f := frame.(type) {
			case *dataFrame:
				if s.parsedTrailer {
					s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "DATA frame received after trailers")
					return 0, errors.New("DATA frame received after trailers")
				}
				s.bytesRemainingInFrame = f.Length
				break parseLoop
			case *headersFrame:
				if s.isConnect {
					maybeQlogInvalidHeadersFrame(s.qlogger, s.StreamID(), f.Length)
					s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "HEADERS frame on a CONNECT stream")
					return 0, errors.New("HEADERS frame on a CONNECT stream")
				}
				if s.parsedTrailer {
					maybeQlogInvalidHeadersFrame(s.qlogger, s.StreamID(), f.Length)
					s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "additional HEADERS frame received after trailers")
					return 0, errors.New("additional HEADERS frame received after trailers")
				}
				s.parsedTrailer = true
				if err := s.parseTrailer(s.datagramStream, f); err != nil {
					if err == io.EOF || isTruncatedFrame(err) {
						s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "truncated HEADERS frame")
						return 0, io.ErrUnexpectedEOF
					}
					if qpackErr, ok := errors.AsType[*qpackConnectionError](err); ok {
						s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKDecompressionFailed), qpackErr.Error())
					} else if trailerErr, ok := errors.AsType[*trailerError](err); ok {
						s.CancelRead(quic.StreamErrorCode(trailerErr.code))
						s.CancelWrite(quic.StreamErrorCode(trailerErr.code))
					}
					return 0, maybeReplaceError(err)
				}
				return 0, nil
			case *pushPromiseFrame:
				s.conn.CloseWithError(quic.ApplicationErrorCode(s.conn.pushPromiseErrorCode()), "")
				return 0, errors.New("peer sent a PUSH_PROMISE frame")
			default:
				s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if s.bytesRemainingInFrame < uint64(len(b)) {
		n, err = s.datagramStream.Read(b[:s.bytesRemainingInFrame])
	} else {
		n, err = s.datagramStream.Read(b)
	}
	s.bytesRemainingInFrame -= uint64(n)
	// The stream ended in the middle of a DATA frame (section 7.1 of RFC 9114).
	if err == io.EOF && s.bytesRemainingInFrame > 0 {
		s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "truncated DATA frame")
		return n, io.ErrUnexpectedEOF
	}
	return n, maybeReplaceError(err)
}

func (s *Stream) hasMoreData() bool {
	return s.bytesRemainingInFrame > 0
}

func (s *Stream) Write(b []byte) (int, error) {
	s.buf = s.buf[:0]
	s.buf = (&dataFrame{Length: uint64(len(b))}).Append(s.buf)
	if s.qlogger != nil {
		s.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: s.StreamID(),
			Raw: qlog.RawInfo{
				Length:        len(s.buf) + len(b),
				PayloadLength: len(b),
			},
			Frame: qlog.Frame{Frame: qlog.DataFrame{}},
		})
	}
	if _, err := s.writeUnframed(s.buf); err != nil {
		return 0, err
	}
	return s.writeUnframed(b)
}

// TryWriteAll writes b in a DATA frame if the entire frame can be queued immediately.
// It returns [quic.ErrWouldBlock] without queueing anything otherwise.
func (s *Stream) TryWriteAll(b []byte) error {
	data := make([]byte, 0, frameHeaderLen+len(b))
	data = (&dataFrame{Length: uint64(len(b))}).Append(data)
	data = append(data, b...)
	if err := s.datagramStream.TryWriteAll(data); err != nil {
		return maybeReplaceError(err)
	}
	if s.qlogger != nil {
		s.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: s.StreamID(),
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
			Frame: qlog.Frame{Frame: qlog.DataFrame{}},
		})
	}
	return nil
}

func (s *Stream) writeUnframed(b []byte) (int, error) {
	n, err := s.datagramStream.Write(b)
	if err != nil {
		s.writeFailed.Store(true)
	}
	return n, maybeReplaceError(err)
}

// Close closes the stream for sending.
// If a write failed (for example, because the write deadline expired), the last frame might be incomplete.
// A stream ending in the middle of a frame is a connection error (section 7.1 of RFC 9114),
// so the stream is reset with H3_REQUEST_CANCELLED instead.
func (s *Stream) Close() error {
	if s.writeFailed.Load() {
		s.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
		return nil
	}
	return s.datagramStream.Close()
}

func (s *Stream) StreamID() quic.StreamID {
	return s.datagramStream.StreamID()
}

func (s *Stream) SendDatagram(b []byte) error {
	// TODO: reject if datagrams are not negotiated (yet)
	return maybeReplaceError(s.datagramStream.SendDatagram(b))
}

func (s *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// TODO: reject if datagrams are not negotiated (yet)
	b, err := s.datagramStream.ReceiveDatagram(ctx)
	return b, maybeReplaceError(err)
}

// A RequestStream is a low-level abstraction representing an HTTP/3 request stream.
// It decouples sending of the HTTP request from reading the HTTP response, allowing
// the application to optimistically use the stream (and, for example, send datagrams)
// before receiving the response.
//
// This is only needed for advanced use case, e.g. WebTransport and the various
// MASQUE proxying protocols.
// Stream and application errors are returned as *[Error], possibly wrapped.
type RequestStream struct {
	str *Stream

	responseBody io.ReadCloser // set by ReadResponse

	decoder            *qpack.Decoder
	requestWriter      *requestWriter
	maxHeaderBytes     int
	reqDone            chan<- struct{}
	disableCompression bool
	response           *http.Response

	sentRequest   bool
	requestedGzip bool
	isConnect     bool
	isHead        bool
}

func newRequestStream(
	str *Stream,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	decoder *qpack.Decoder,
	disableCompression bool,
	maxHeaderBytes int,
	rsp *http.Response,
) *RequestStream {
	return &RequestStream{
		str:                str,
		requestWriter:      requestWriter,
		reqDone:            reqDone,
		decoder:            decoder,
		disableCompression: disableCompression,
		maxHeaderBytes:     maxHeaderBytes,
		response:           rsp,
	}
}

// Read reads data from the underlying stream.
//
// It can only be used after the request has been sent using [RequestStream.SendRequestHeader]
// and [RequestStream.ReadResponse] has returned the response.
func (s *RequestStream) Read(b []byte) (int, error) {
	if s.responseBody == nil {
		return 0, errors.New("http3: invalid use of RequestStream.Read before ReadResponse")
	}
	return s.responseBody.Read(b)
}

// StreamID returns the QUIC stream ID of the underlying QUIC stream.
func (s *RequestStream) StreamID() quic.StreamID {
	return s.str.StreamID()
}

// Write writes data to the stream.
//
// It can only be used after the request has been sent using [RequestStream.SendRequestHeader].
func (s *RequestStream) Write(b []byte) (int, error) {
	if !s.sentRequest {
		return 0, errors.New("http3: invalid use of RequestStream.Write before SendRequestHeader")
	}
	return s.str.Write(b)
}

// TryWriteAll writes b if the entire DATA frame can be queued immediately.
// It can only be used after the request has been sent using [RequestStream.SendRequestHeader].
func (s *RequestStream) TryWriteAll(b []byte) error {
	if !s.sentRequest {
		return errors.New("http3: invalid use of RequestStream.TryWriteAll before SendRequestHeader")
	}
	return s.str.TryWriteAll(b)
}

// Close closes the send-direction of the stream.
// It does not close the receive-direction of the stream.
func (s *RequestStream) Close() error {
	return s.str.Close()
}

// CancelRead aborts receiving on this stream.
// See [quic.Stream.CancelRead] for more details.
func (s *RequestStream) CancelRead(errorCode quic.StreamErrorCode) {
	s.str.CancelRead(errorCode)
}

// CancelWrite aborts sending on this stream.
// See [quic.Stream.CancelWrite] for more details.
func (s *RequestStream) CancelWrite(errorCode quic.StreamErrorCode) {
	s.str.CancelWrite(errorCode)
}

// Context returns a context derived from the underlying QUIC stream's context.
// See [quic.Stream.Context] for more details.
func (s *RequestStream) Context() context.Context {
	return s.str.Context()
}

// SetReadDeadline sets the deadline for [RequestStream.Read] calls.
func (s *RequestStream) SetReadDeadline(t time.Time) error {
	return s.str.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for [RequestStream.Write] calls.
func (s *RequestStream) SetWriteDeadline(t time.Time) error {
	return s.str.SetWriteDeadline(t)
}

// SetDeadline sets the read and write deadlines associated with the stream.
// It is equivalent to calling both [RequestStream.SetReadDeadline] and [RequestStream.SetWriteDeadline].
func (s *RequestStream) SetDeadline(t time.Time) error {
	return s.str.SetDeadline(t)
}

// SendDatagram sends a new HTTP Datagram (RFC 9297).
//
// It is only possible to send datagrams if the server enabled support for this extension.
// It is recommended (though not required) to send the request before calling this method,
// as the server might drop datagrams which it can't associate with an existing request.
func (s *RequestStream) SendDatagram(b []byte) error {
	return s.str.SendDatagram(b)
}

// ReceiveDatagram receives HTTP Datagrams (RFC 9297).
//
// It is only possible if HTTP Datagram support was enabled using [Transport.EnableDatagrams].
func (s *RequestStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.str.ReceiveDatagram(ctx)
}

// SendRequestHeader sends the HTTP request.
//
// It can only be used for requests that don't have a request body.
// It is invalid to call it more than once.
func (s *RequestStream) SendRequestHeader(req *http.Request) error {
	if req.Body != nil && req.Body != http.NoBody {
		return errors.New("http3: invalid use of RequestStream.SendRequestHeader with a request that has a request body")
	}
	return s.sendRequestHeader(req)
}

func (s *RequestStream) sendRequestHeader(req *http.Request) error {
	if s.sentRequest {
		return errors.New("http3: invalid duplicate use of RequestStream.SendRequestHeader")
	}
	if !s.disableCompression && req.Method != http.MethodHead &&
		req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		s.requestedGzip = true
	}
	s.isConnect = req.Method == http.MethodConnect
	s.isHead = req.Method == http.MethodHead
	s.sentRequest = true
	return maybeReplaceError(s.requestWriter.WriteRequestHeader(s.str.datagramStream, req, s.requestedGzip, s.str.StreamID(), s.str.qlogger))
}

// sendRequestTrailer sends request trailers to the stream.
// It should be called after the request body has been fully written.
func (s *RequestStream) sendRequestTrailer(req *http.Request) error {
	return maybeReplaceError(s.requestWriter.WriteRequestTrailer(s.str.datagramStream, req, s.str.StreamID(), s.str.qlogger))
}

// ReadResponse reads the HTTP response from the stream.
//
// It must be called after sending the request using [RequestStream.SendRequestHeader].
// It is invalid to call it more than once.
// It doesn't set [http.Response.Request] or [http.Response.TLS].
func (s *RequestStream) ReadResponse() (*http.Response, error) {
	if !s.sentRequest {
		return nil, errors.New("http3: invalid use of RequestStream.ReadResponse before SendRequestHeader")
	}
	frame, err := s.str.frameParser.ParseNext(s.str.qlogger)
	if err != nil {
		if errors.Is(err, errPriorityUpdateForPush) || isControlStreamFrame(err) {
			s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return nil, err
		}
		if isTruncatedFrame(err) {
			s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "truncated frame")
			return nil, err
		}
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: parsing frame failed: %w", maybeReplaceError(err))
	}
	if _, ok := frame.(*pushPromiseFrame); ok {
		s.str.conn.CloseWithError(quic.ApplicationErrorCode(s.str.conn.pushPromiseErrorCode()), "")
		return nil, errors.New("http3: peer sent a PUSH_PROMISE frame")
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "expected first frame to be a HEADERS frame")
		return nil, errors.New("http3: expected first frame to be a HEADERS frame")
	}
	if hf.Length > uint64(s.maxHeaderBytes) {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes)
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(s.str.datagramStream, headerBlock); err != nil {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "truncated HEADERS frame")
			return nil, fmt.Errorf("http3: failed to read response headers: %w", io.ErrUnexpectedEOF)
		}
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return nil, fmt.Errorf("http3: failed to read response headers: %w", maybeReplaceError(err))
	}
	headerBlock, err = checkFieldSection(headerBlock)
	if err != nil {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKDecompressionFailed), err.Error())
		return nil, fmt.Errorf("http3: invalid response: %w", err)
	}
	decodeFn := s.decoder.Decode(headerBlock)
	var hfs []qpack.HeaderField
	if s.str.qlogger != nil {
		hfs = make([]qpack.HeaderField, 0, 16)
	}
	res := s.response
	err = updateResponseFromHeaders(res, decodeFn, s.maxHeaderBytes, &hfs)
	if s.str.qlogger != nil {
		qlogParsedHeadersFrame(s.str.qlogger, s.str.StreamID(), hf, hfs)
	}
	if err != nil {
		errCode := ErrCodeMessageError
		if _, ok := errors.AsType[*qpackError](err); ok {
			errCode = ErrCodeQPACKDecompressionFailed
		}
		s.str.CancelRead(quic.StreamErrorCode(errCode))
		s.str.CancelWrite(quic.StreamErrorCode(errCode))
		return nil, fmt.Errorf("http3: invalid response: %w", err)
	}

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == http.StatusNoContent
	isSuccessfulConnect := s.isConnect && res.StatusCode >= 200 && res.StatusCode < 300
	// Once the CONNECT method has completed, only DATA frames are allowed on the stream (section 4.4 of RFC 9114).
	// The response to a CONNECT request that failed can have trailers.
	s.str.isConnect = isSuccessfulConnect

	// Check that the server sends as much data in DATA frames as indicated by the Content-Length header (if set).
	// See section 4.1.2 of RFC 9114. Responses to HEAD requests and 304 responses have no content, but their
	// Content-Length header describes the content of a GET request (section 8.6 of RFC 9110).
	contentLength := res.ContentLength
	if s.isHead || res.StatusCode == http.StatusNotModified || isNoContent || isInformational {
		contentLength = -1
	}
	respBody := newResponseBody(s.str, contentLength, s.reqDone)
	if (isInformational || isNoContent || isSuccessfulConnect) && res.ContentLength == -1 {
		res.ContentLength = 0
	}
	if s.requestedGzip && !isSuccessfulConnect && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		s.responseBody = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		s.responseBody = respBody
	}
	res.Body = s.responseBody
	return res, nil
}

type tracingReader struct {
	io.Reader
	readFirst bool
	trace     *httptrace.ClientTrace
}

func (r *tracingReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 && !r.readFirst {
		traceGotFirstResponseByte(r.trace)
		r.readFirst = true
	}
	return n, err
}
