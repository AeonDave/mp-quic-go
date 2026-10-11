package http3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func nopControlStrHandler(*quic.ReceiveStream, *frameParser) {}

func TestConnReceiveSettings(t *testing.T) {
	var eventRecorder events.Recorder
	clientConn, serverConn := newConnPair(t, withServerRecorder(&eventRecorder))

	conn := newRawConn(serverConn, false, nil, nopControlStrHandler, &eventRecorder, nil)
	b := quicvarint.Append(nil, streamTypeControlStream)
	sf := &settingsFrame{
		MaxFieldSectionSize: 1234,
		Datagram:            true,
		ExtendedConnect:     true,
		Other:               map[uint64]uint64{1337: 42},
	}
	b = sf.Append(b)
	controlStr, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(serverStr, true)
	}()
	select {
	case <-conn.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	settings := conn.Settings()
	require.True(t, settings.EnableDatagrams)
	require.True(t, settings.EnableExtendedConnect)
	require.Equal(t, map[uint64]uint64{1337: 42}, settings.Other)

	expectedLen, expectedPayloadLen := expectedFrameLength(t, sf)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameParsed{
				StreamID: controlStr.StreamID(),
				Raw:      qlog.RawInfo{Length: expectedLen, PayloadLength: expectedPayloadLen},
				Frame: qlog.Frame{
					Frame: qlog.SettingsFrame{
						MaxFieldSectionSize: 1234,
						Datagram:            new(true),
						ExtendedConnect:     new(true),
						Other:               map[uint64]uint64{1337: 42},
					},
				},
			},
		},
		filterQlogEventsForFrame(eventRecorder.Events(qlog.FrameParsed{}), qlog.SettingsFrame{}),
	)
}

func TestConnRejectDuplicateStreams(t *testing.T) {
	t.Run("control stream", func(t *testing.T) {
		testConnRejectDuplicateStreams(t, streamTypeControlStream)
	})
	t.Run("encoder stream", func(t *testing.T) {
		testConnRejectDuplicateStreams(t, streamTypeQPACKEncoderStream)
	})
	t.Run("decoder stream", func(t *testing.T) {
		testConnRejectDuplicateStreams(t, streamTypeQPACKDecoderStream)
	})
}

func testConnRejectDuplicateStreams(t *testing.T, typ uint64) {
	clientConn, serverConn := newConnPair(t)

	conn := newRawConn(serverConn, false, nil, nopControlStrHandler, nil, nil)
	b := quicvarint.Append(nil, typ)
	if typ == streamTypeControlStream {
		b = (&settingsFrame{}).Append(b)
	}
	controlStr1, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr1.Write(b)
	require.NoError(t, err)
	controlStr2, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr2.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr1, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	serverStr2, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		conn.handleUnidirectionalStream(serverStr1, true)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		conn.handleUnidirectionalStream(serverStr2, true)
	}()
	select {
	case <-clientConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(clientConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeStreamCreationError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for duplicate stream")
	}
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
}

func TestConnResetUnknownUniStream(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	conn := newRawConn(serverConn, false, nil, nopControlStrHandler, nil, nil)
	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x1337))
	str, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(serverStr, true)
	}()
	expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeStreamCreationError))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnControlStreamFailures(t *testing.T) {
	t.Run("missing SETTINGS", func(t *testing.T) {
		testConnControlStreamFailures(t, (&dataFrame{}).Append(nil), nil, ErrCodeMissingSettings)
	})
	// section 6.2.1 of RFC 9114
	t.Run("MAX_PUSH_ID before SETTINGS", func(t *testing.T) {
		b := (&maxPushIDFrame{PushID: 1}).Append(nil)
		b = (&settingsFrame{}).Append(b)
		testConnControlStreamFailures(t, b, nil, ErrCodeMissingSettings)
	})
	t.Run("CANCEL_PUSH before SETTINGS", func(t *testing.T) {
		b := (&cancelPushFrame{PushID: 1}).Append(nil)
		b = (&settingsFrame{}).Append(b)
		testConnControlStreamFailures(t, b, nil, ErrCodeMissingSettings)
	})
	t.Run("malformed MAX_PUSH_ID before SETTINGS", func(t *testing.T) {
		b := quicvarint.Append(nil, 0xd)
		b = quicvarint.Append(b, 0)
		b = (&settingsFrame{}).Append(b)
		testConnControlStreamFailures(t, b, nil, ErrCodeMissingSettings)
	})
	t.Run("PUSH_PROMISE before SETTINGS", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x5)
		b = quicvarint.Append(b, 2)
		b = append(b, 0, 0)
		b = (&settingsFrame{}).Append(b)
		testConnControlStreamFailures(t, b, nil, ErrCodeMissingSettings)
	})
	t.Run("settings error", func(t *testing.T) {
		testConnControlStreamFailures(t,
			// 1337 is invalid value for the Extended CONNECT setting
			(&settingsFrame{Other: map[uint64]uint64{settingExtendedConnect: 1337}}).Append(nil),
			nil,
			ErrCodeSettingsError,
		)
	})
	// section 2.1.1 of RFC 9297
	t.Run("invalid SETTINGS_H3_DATAGRAM value", func(t *testing.T) {
		testConnControlStreamFailures(t,
			(&settingsFrame{Other: map[uint64]uint64{settingDatagram: 2}}).Append(nil),
			nil,
			ErrCodeSettingsError,
		)
	})
	// section 7.2.4.1 of RFC 9114
	t.Run("HTTP/2 setting", func(t *testing.T) {
		testConnControlStreamFailures(t,
			(&settingsFrame{Other: map[uint64]uint64{0x5: 1337}}).Append(nil),
			nil,
			ErrCodeSettingsError,
		)
	})
	// section 7.1 of RFC 9114
	t.Run("SETTINGS ending inside a setting", func(t *testing.T) {
		b := quicvarint.Append(nil, 0x4)
		b = quicvarint.Append(b, 1)
		b = quicvarint.Append(b, 0x1)
		testConnControlStreamFailures(t, b, nil, ErrCodeFrameError)
	})
	t.Run("control stream closed before SETTINGS", func(t *testing.T) {
		testConnControlStreamFailures(t, nil, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("control stream reset before SETTINGS", func(t *testing.T) {
		testConnControlStreamFailures(t,
			nil,
			&quic.StreamError{Remote: true, ErrorCode: 42},
			ErrCodeClosedCriticalStream,
		)
	})
}

func testConnControlStreamFailures(t *testing.T, data []byte, readErr error, expectedErr ErrCode) {
	clientConn, serverConn := newConnPair(t)

	conn := newRawConn(clientConn, false, nil, nopControlStrHandler, nil, nil)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(quicvarint.Append(nil, streamTypeControlStream))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(clientStr, false)
	}()

	switch readErr {
	case nil:
		_, err = controlStr.Write(data)
		require.NoError(t, err)
	case io.EOF:
		_, err = controlStr.Write(data)
		require.NoError(t, err)
		require.NoError(t, controlStr.Close())
	default:
		// make sure the stream type is received
		time.Sleep(scaleDuration(10 * time.Millisecond))
		controlStr.CancelWrite(1337)
	}

	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(expectedErr)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnControlStreamHandler(t *testing.T) {
	localConn, peerConn := newConnPair(t)

	handlerCalled := make(chan struct{})
	conn := newRawConn(localConn, false, nil, func(*quic.ReceiveStream, *frameParser) { close(handlerCalled) }, nil, nil)

	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	str, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	go conn.handleUnidirectionalStream(localStr, false)

	select {
	case <-conn.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	select {
	case <-handlerCalled:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler to be called")
	}
}

func TestConnRejectPushStream(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testConnRejectPushStream(t, false, ErrCodeIDError)
	})
	t.Run("server", func(t *testing.T) {
		testConnRejectPushStream(t, true, ErrCodeStreamCreationError)
	})
}

func testConnRejectPushStream(t *testing.T, isServer bool, expectedErr ErrCode) {
	localConn, peerConn := newConnPair(t)

	conn := newRawConn(localConn, false, nil, nopControlStrHandler, nil, nil)
	buf := bytes.NewBuffer(quicvarint.Append(nil, streamTypePushStream))
	str, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(localStr, isServer)
	}()
	select {
	case <-peerConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(peerConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(expectedErr)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnInconsistentDatagramSupport(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	conn := newRawConn(clientConn, true, nil, nopControlStrHandler, nil, nil)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(clientStr, false)
	}()

	select {
	case <-serverConn.Context().Done():
		err := context.Cause(serverConn.Context())
		require.ErrorIs(t, err, &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeSettingsError)})
		require.ErrorContains(t, err, "missing QUIC Datagram support")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

func TestConnSendAndReceiveDatagram(t *testing.T) {
	var eventRecorder events.Recorder
	clientConn, serverConn := newConnPair(t, withDatagrams(), withClientRecorder(&eventRecorder))

	conn := newRawConn(clientConn, true, nil, nopControlStrHandler, &eventRecorder, nil)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(clientStr, false)
	}()

	const strID = 4

	// first deliver a datagram...
	// since the stream is not open yet, it will be dropped
	quarterStreamID := quicvarint.Append([]byte{}, strID/4)

	datagram := append(quarterStreamID, []byte("foo")...)
	require.NoError(t, serverConn.SendDatagram(datagram))
	time.Sleep(scaleDuration(10 * time.Millisecond)) // give the datagram a chance to be delivered

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.DatagramParsed{
				QuarterStreamID: strID / 4,
				Raw:             qlog.RawInfo{Length: len(datagram), PayloadLength: 3},
			},
		},
		eventRecorder.Events(qlog.DatagramParsed{}),
	)
	eventRecorder.Clear()

	// don't use stream 0, since that makes it hard to test that the quarter stream ID is used
	str0, err := clientConn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	str0.Close()

	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	require.Equal(t, quic.StreamID(strID), str.StreamID())
	datagramStr := conn.TrackStream(str)

	// now open the stream...
	require.NoError(t, serverConn.SendDatagram(append(quarterStreamID, []byte("bar")...)))

	data, err := datagramStr.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)

	// now send a datagram
	require.NoError(t, datagramStr.SendDatagram([]byte("foobaz")))

	expected := quicvarint.Append([]byte{}, strID/4)
	expected = append(expected, []byte("foobaz")...)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.DatagramCreated{
				QuarterStreamID: strID / 4,
				Raw:             qlog.RawInfo{PayloadLength: 6, Length: len(expected)},
			},
		},
		eventRecorder.Events(qlog.DatagramCreated{}),
	)
	eventRecorder.Clear()

	data, err = serverConn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, data)
}

func TestConnDatagramFailures(t *testing.T) {
	t.Run("invalid varint", func(t *testing.T) {
		testConnDatagramFailures(t, []byte{128})
	})

	t.Run("invalid quarter stream ID", func(t *testing.T) {
		testConnDatagramFailures(t, quicvarint.Append([]byte{}, maxQuarterStreamID+1))
	})
}

func testConnDatagramFailures(t *testing.T, datagram []byte) {
	localConn, peerConn := newConnPair(t, withDatagrams())

	conn := newRawConn(localConn, true, nil, nopControlStrHandler, nil, nil)

	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	go conn.handleUnidirectionalStream(localStr, false)

	// Wait for SETTINGS to be received and datagram handling to start
	select {
	case <-conn.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}

	require.NoError(t, peerConn.SendDatagram(datagram))

	select {
	case <-peerConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(peerConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeDatagramError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

// The QPACK encoder and decoder streams are read, see section 4.2 of RFC 9204.
// We don't allow the peer to use the dynamic table, and we never refer to the dynamic table.
func TestConnQPACKStreams(t *testing.T) {
	t.Run("encoder stream: Set Dynamic Table Capacity 0", func(t *testing.T) {
		// The instruction is valid. The stream is then closed, which is a connection error.
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x20, 0x20}, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("encoder stream: closed", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, nil, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("encoder stream: reset", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x20}, &quic.StreamError{ErrorCode: 42}, ErrCodeClosedCriticalStream)
	})
	t.Run("encoder stream: closed inside an instruction", func(t *testing.T) {
		// Set Dynamic Table Capacity with a capacity that doesn't fit into the prefix
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x3f, 0x80}, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("encoder stream: capacity exceeds the limit", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x21}, nil, ErrCodeQPACKEncoderStreamError)
	})
	t.Run("encoder stream: large capacity", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x3f, 0xe1, 0x1f}, nil, ErrCodeQPACKEncoderStreamError)
	})
	t.Run("encoder stream: Insert with Name Reference", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0xc0, 0x03, 'f', 'o', 'o'}, nil, ErrCodeQPACKEncoderStreamError)
	})
	t.Run("encoder stream: Insert with Literal Name", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x43, 'f', 'o', 'o', 0x03, 'b', 'a', 'r'}, nil, ErrCodeQPACKEncoderStreamError)
	})
	t.Run("encoder stream: Duplicate", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKEncoderStream, []byte{0x00}, nil, ErrCodeQPACKEncoderStreamError)
	})
	t.Run("decoder stream: Stream Cancellation", func(t *testing.T) {
		// The instructions are valid. The stream is then closed, which is a connection error.
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, []byte{0x40, 0x7f, 0x81, 0x01}, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("decoder stream: closed", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, nil, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("decoder stream: reset", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, []byte{0x44}, &quic.StreamError{ErrorCode: 42}, ErrCodeClosedCriticalStream)
	})
	t.Run("decoder stream: closed inside an instruction", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, []byte{0x7f, 0x80}, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("decoder stream: stream ID too large", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, append([]byte{0x7f}, bytes.Repeat([]byte{0xff}, 9)...), nil, ErrCodeQPACKDecoderStreamError)
	})
	t.Run("decoder stream: Section Acknowledgment", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, []byte{0x80}, nil, ErrCodeQPACKDecoderStreamError)
	})
	t.Run("decoder stream: Insert Count Increment 0", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, []byte{0x00}, nil, ErrCodeQPACKDecoderStreamError)
	})
	t.Run("decoder stream: Insert Count Increment", func(t *testing.T) {
		testConnQPACKStream(t, streamTypeQPACKDecoderStream, []byte{0x01}, nil, ErrCodeQPACKDecoderStreamError)
	})
}

func testConnQPACKStream(t *testing.T, typ uint64, data []byte, streamEnd error, expectedErr ErrCode) {
	t.Helper()

	localConn, peerConn := newConnPair(t)
	conn := newRawConn(localConn, false, nil, nopControlStrHandler, nil, nil)
	str, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(append(quicvarint.Append(nil, typ), data...))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	switch streamEnd {
	case nil, io.EOF:
		go func() {
			defer close(done)
			conn.handleUnidirectionalStream(localStr, true)
		}()
		if streamEnd == io.EOF {
			require.NoError(t, str.Close())
		}
	default:
		// Read the stream type and the data before the stream is reset,
		// since a reset stream doesn't return the data that was not read yet.
		_, err := io.ReadFull(localStr, make([]byte, quicvarint.Len(typ)+len(data)))
		require.NoError(t, err)
		go func() {
			defer close(done)
			if typ == streamTypeQPACKEncoderStream {
				conn.handleQPACKEncoderStream(localStr)
			} else {
				conn.handleQPACKDecoderStream(localStr)
			}
		}()
		str.CancelWrite(1337)
	}
	expectConnClosedByPeer(t, peerConn, expectedErr)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// QUIC DATAGRAM frames are only sent once SETTINGS_H3_DATAGRAM was sent and received with a value of 1
// (section 2.1.1 of RFC 9297).
func TestConnSendDatagramRequiresSettings(t *testing.T) {
	t.Run("not enabled locally", func(t *testing.T) {
		clientConn, _ := newConnPair(t, withDatagrams())
		conn := newRawConn(clientConn, false, nil, nopControlStrHandler, nil, nil)
		require.EqualError(t, conn.sendDatagram(0, []byte("foo")), "http3: HTTP datagrams not enabled")
	})

	for _, peerSupport := range []bool{true, false} {
		t.Run(fmt.Sprintf("peer support: %t", peerSupport), func(t *testing.T) {
			clientConn, serverConn := newConnPair(t, withDatagrams())
			conn := newRawConn(clientConn, true, nil, nopControlStrHandler, nil, nil)

			// sending blocks until the peer's SETTINGS frame was received
			errChan := make(chan error, 1)
			go func() { errChan <- conn.sendDatagram(0, []byte("foo")) }()
			select {
			case err := <-errChan:
				t.Fatalf("sendDatagram returned before receiving the SETTINGS: %v", err)
			case <-time.After(scaleDuration(10 * time.Millisecond)):
			}

			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{Datagram: peerSupport}).Append(b)
			controlStr, err := serverConn.OpenUniStream()
			require.NoError(t, err)
			_, err = controlStr.Write(b)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			clientStr, err := clientConn.AcceptUniStream(ctx)
			require.NoError(t, err)
			go conn.handleUnidirectionalStream(clientStr, false)

			select {
			case err := <-errChan:
				if peerSupport {
					require.NoError(t, err)
					data, err := serverConn.ReceiveDatagram(ctx)
					require.NoError(t, err)
					require.Equal(t, append([]byte{0}, []byte("foo")...), data)
				} else {
					require.EqualError(t, err, "http3: peer doesn't support HTTP datagrams")
				}
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
		})
	}
}
