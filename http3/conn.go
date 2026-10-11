package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

const maxQuarterStreamID = 1<<60 - 1

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

// rawConn is an HTTP/3 connection.
// It provides HTTP/3 specific functionality by wrapping a quic.Conn,
// in particular handling of unidirectional HTTP/3 streams, SETTINGS and datagrams.
type rawConn struct {
	conn *quic.Conn

	logger *slog.Logger

	enableDatagrams bool
	isClient        bool

	streamMx sync.Mutex
	streams  map[quic.StreamID]*stateTrackingStream

	rcvdControlStr      atomic.Bool
	rcvdQPACKEncoderStr atomic.Bool
	rcvdQPACKDecoderStr atomic.Bool
	controlStrHandler   func(*quic.ReceiveStream, *frameParser) // is called *after* the SETTINGS frame was parsed

	onStreamsEmpty func()

	settings         *Settings
	receivedSettings chan struct{}

	qlogger   qlogwriter.Recorder
	qloggerWG sync.WaitGroup // tracks goroutines that may produce qlog events
}

func newRawConn(
	quicConn *quic.Conn,
	enableDatagrams bool,
	onStreamsEmpty func(),
	controlStrHandler func(*quic.ReceiveStream, *frameParser),
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
) *rawConn {
	c := &rawConn{
		conn:              quicConn,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		receivedSettings:  make(chan struct{}),
		streams:           make(map[quic.StreamID]*stateTrackingStream),
		qlogger:           qlogger,
		onStreamsEmpty:    onStreamsEmpty,
		controlStrHandler: controlStrHandler,
	}
	if qlogger != nil {
		context.AfterFunc(quicConn.Context(), c.closeQlogger)
	}
	return c
}

func (c *rawConn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// openControlStream opens the control stream and sends the SETTINGS frame.
// It returns the control stream (needed by the server for sending GOAWAY later).
func (c *rawConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	str, err := c.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	b = settings.Append(b)
	if c.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: settings.MaxFieldSectionSize,
			Other:               maps.Clone(settings.Other),
		}
		if settings.Datagram {
			sf.Datagram = new(true)
		}
		if settings.ExtendedConnect {
			sf.ExtendedConnect = new(true)
		}
		c.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}
	if _, err := str.Write(b); err != nil {
		return nil, err
	}
	return str, nil
}

func (c *rawConn) TrackStream(str *quic.Stream) *stateTrackingStream {
	hstr := newStateTrackingStream(str, c, func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })

	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	c.qloggerWG.Add(1)
	c.streamMx.Unlock()
	return hstr
}

func (c *rawConn) UpdateStreamPriority(id quic.StreamID, urgency int8, incremental bool) {
	c.streamMx.Lock()
	str := c.streams[id]
	c.streamMx.Unlock()
	// A PRIORITY_UPDATE can arrive before its request stream. We deliberately ignore such reordered frames.
	if str != nil {
		str.SetPriority(urgency, incremental)
	}
}

func (c *rawConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *rawConn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *rawConn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	if _, ok := c.streams[id]; ok {
		delete(c.streams, id)
		c.qloggerWG.Done()
	}
	if len(c.streams) == 0 {
		c.onStreamsEmpty()
	}
}

func (c *rawConn) hasActiveStreams() bool {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	return len(c.streams) > 0
}

func (c *rawConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.conn.CloseWithError(code, msg)
}

func (c *rawConn) handleUnidirectionalStream(str *quic.ReceiveStream, isServer bool) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
		}
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
			return
		}
		c.handleQPACKEncoderStream(str)
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
			return
		}
		c.handleQPACKDecoderStream(str)
		return
	case streamTypePushStream:
		if isServer {
			// only the server can push
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		} else {
			// we never increased the Push ID, so we don't expect any push streams
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	c.handleControlStream(str)
}

// isCriticalStreamClosed says if an error returned when reading from a critical stream
// means that the peer closed the stream (section 6.2.1 of RFC 9114 and section 4.2 of RFC 9204).
// minUniStreams is the number of unidirectional streams that both endpoints need to allow:
// the control stream and the two QPACK streams (section 6.2 of RFC 9114).
const minUniStreams = 3

// checkUniStreams checks that the QUIC configuration allows the peer to open enough unidirectional streams.
func checkUniStreams(conf *quic.Config) error {
	if conf.MaxIncomingUniStreams < 0 || (conf.MaxIncomingUniStreams > 0 && conf.MaxIncomingUniStreams < minUniStreams) {
		return fmt.Errorf("http3: QUIC Config.MaxIncomingUniStreams must allow at least %d unidirectional streams", minUniStreams)
	}
	return nil
}

func isCriticalStreamClosed(err error) bool {
	_, isStreamError := errors.AsType[*quic.StreamError](err)
	return err == io.EOF || err == io.ErrUnexpectedEOF || isStreamError
}

// controlStreamErrorCode returns the error code for closing the connection
// when parsing a frame on the control stream failed.
func controlStreamErrorCode(err error) ErrCode {
	if _, ok := errors.AsType[*settingsError](err); ok {
		return ErrCodeSettingsError
	}
	if isCriticalStreamClosed(err) {
		return ErrCodeClosedCriticalStream
	}
	return ErrCodeFrameError
}

func (c *rawConn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID()}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		// The first frame must be a SETTINGS frame (section 6.2.1 of RFC 9114).
		if fe, ok := errors.AsType[*frameError](err); (ok && fe.Type != 0x4) || errors.Is(err, errPriorityUpdateForPush) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(controlStreamErrorCode(err)), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams.Remote {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		c.qloggerWG.Go(func() {
			err := c.receiveDatagrams()
			if c.logger != nil {
				c.logger.Debug("receiving datagrams failed", "error", err)
			}
		})
	}

	c.controlStrHandler(str, fp)
}

// handleQPACKEncoderStream reads the peer's QPACK encoder stream.
// We advertise a dynamic table capacity of 0 (the default value of SETTINGS_QPACK_MAX_TABLE_CAPACITY),
// so the only valid instruction is Set Dynamic Table Capacity with a capacity of 0 (section 4.3.1 of RFC 9204).
// Any other instruction either exceeds this capacity or refers to an entry that can't exist.
func (c *rawConn) handleQPACKEncoderStream(str *quic.ReceiveStream) {
	r := quicvarint.NewReader(str)
	for {
		b, err := r.ReadByte()
		if err != nil {
			c.handleQPACKStreamReadError(err)
			return
		}
		// Set Dynamic Table Capacity is encoded as 001 followed by a 5-bit prefix integer.
		// A capacity of 0 is encoded in a single byte.
		if b == 0b00100000 {
			continue
		}
		if b&0b11100000 == 0b00100000 && b&0b00011111 == 0b00011111 {
			// Read the rest of the capacity, so that a stream that ends inside the instruction
			// is treated as a closed critical stream.
			if err := skipPrefixedIntegerContinuation(r); err != nil && !errors.Is(err, errPrefixedIntegerTooLong) {
				c.handleQPACKStreamReadError(err)
				return
			}
		}
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKEncoderStreamError), "")
		return
	}
}

// handleQPACKDecoderStream reads the peer's QPACK decoder stream.
// Since our encoder never refers to the dynamic table, the only valid instruction is
// Stream Cancellation (section 4.4.2 of RFC 9204).
// A Section Acknowledgment or an Insert Count Increment is a connection error (sections 4.4.1 and 4.4.3).
func (c *rawConn) handleQPACKDecoderStream(str *quic.ReceiveStream) {
	r := quicvarint.NewReader(str)
	for {
		b, err := r.ReadByte()
		if err != nil {
			c.handleQPACKStreamReadError(err)
			return
		}
		// Stream Cancellation is encoded as 01 followed by a 6-bit prefix integer.
		if b&0b11000000 != 0b01000000 {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKDecoderStreamError), "")
			return
		}
		if b&0b00111111 == 0b00111111 {
			if err := skipPrefixedIntegerContinuation(r); err != nil {
				if errors.Is(err, errPrefixedIntegerTooLong) {
					c.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKDecoderStreamError), "")
					return
				}
				c.handleQPACKStreamReadError(err)
				return
			}
		}
	}
}

func (c *rawConn) handleQPACKStreamReadError(err error) {
	// Closure of either QPACK stream is a connection error (section 4.2 of RFC 9204).
	if isCriticalStreamClosed(err) {
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
	}
}

var errPrefixedIntegerTooLong = errors.New("http3: QPACK prefixed integer too long")

// skipPrefixedIntegerContinuation reads the continuation bytes of a prefixed integer
// whose prefix bits are all set (section 4.1.1 of RFC 9204).
// Integers larger than 2^62 are rejected.
func skipPrefixedIntegerContinuation(r io.ByteReader) error {
	for range 9 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b&0x80 == 0 {
			return nil
		}
	}
	return errPrefixedIntegerTooLong
}

func (c *rawConn) sendDatagram(streamID quic.StreamID, b []byte) error {
	// QUIC DATAGRAM frames are only sent once SETTINGS_H3_DATAGRAM was sent and received with a value of 1
	// (section 2.1.1 of RFC 9297).
	if !c.enableDatagrams {
		return errors.New("http3: HTTP datagrams not enabled")
	}
	select {
	case <-c.receivedSettings:
	case <-c.conn.Context().Done():
		return context.Cause(c.conn.Context())
	}
	if !c.settings.EnableDatagrams {
		return errors.New("http3: peer doesn't support HTTP datagrams")
	}
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	quarterStreamID := uint64(streamID / 4)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuarterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
		})
	}
	return c.conn.SendDatagram(data)
}

func (c *rawConn) receiveDatagrams() error {
	for {
		b, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		quarterStreamID, n, err := quicvarint.Parse(b)
		if err != nil {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("could not read quarter stream id: %w", err)
		}
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.DatagramParsed{
				QuarterStreamID: quarterStreamID,
				Raw: qlog.RawInfo{
					Length:        len(b),
					PayloadLength: len(b) - n,
				},
			})
		}
		if quarterStreamID > maxQuarterStreamID {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("invalid quarter stream id: %w", err)
		}
		streamID := quic.StreamID(4 * quarterStreamID)
		c.streamMx.Lock()
		dg, ok := c.streams[streamID]
		c.streamMx.Unlock()
		if !ok {
			continue
		}
		dg.enqueueDatagram(b[n:])
	}
}

// pushPromiseErrorCode is the error code for closing the connection when a PUSH_PROMISE frame is received.
// A server must not receive PUSH_PROMISE frames (section 7.2.5 of RFC 9114).
// A client never sends a MAX_PUSH_ID frame, so the push ID of any PUSH_PROMISE frame is larger than
// the maximum push ID (section 4.6 of RFC 9114).
func (c *rawConn) pushPromiseErrorCode() ErrCode {
	if c.isClient {
		return ErrCodeIDError
	}
	return ErrCodeFrameUnexpected
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *rawConn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *rawConn) Settings() *Settings { return c.settings }

// closeQlogger waits for all goroutines that may produce qlog events to finish,
// then closes the qlogger.
func (c *rawConn) closeQlogger() {
	if c.qlogger == nil {
		return
	}
	c.qloggerWG.Wait()
	c.qlogger.Close()
}
