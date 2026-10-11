package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
	"github.com/AeonDave/mp-quic-go/testutils/events"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"

	"github.com/stretchr/testify/require"
)

// testFrameParserEOF checks that a stream ending before a frame results in an io.EOF,
// and a stream ending in the middle of a frame in an io.ErrUnexpectedEOF (section 7.1 of RFC 9114).
// Frames whose payload is parsed might also return an io.EOF if the stream ends in their payload.
func testFrameParserEOF(t *testing.T, data []byte) {
	t.Helper()
	for i := range data {
		b := make([]byte, i)
		copy(b, data[:i])
		fp := frameParser{r: bytes.NewReader(b)}
		_, err := fp.ParseNext(nil)
		if i == 0 {
			require.ErrorIs(t, err, io.EOF)
			continue
		}
		require.True(t, errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF), "unexpected error: %v", err)
	}
}

// A stream ending in the middle of the frame type, the frame length, or the payload of a frame that is skipped
// results in an io.ErrUnexpectedEOF.
func TestParserTruncatedFrame(t *testing.T) {
	data := quicvarint.Append(nil, 0x1f*7+0x21) // reserved frame type, encoded in 2 bytes
	data = quicvarint.Append(data, 0x1337)      // length, encoded in 2 bytes
	data = append(data, make([]byte, 0x1337)...)
	for _, n := range []int{1, 3, 4, 100, len(data) - 1} {
		fp := frameParser{r: bytes.NewReader(data[:n])}
		_, err := fp.ParseNext(nil)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.True(t, isTruncatedFrame(err))
	}
	fp := frameParser{r: bytes.NewReader(data)}
	_, err := fp.ParseNext(nil)
	require.ErrorIs(t, err, io.EOF)
	require.False(t, isTruncatedFrame(err))
}

func TestParserReservedFrameType(t *testing.T) {
	for _, ft := range []uint64{0x2, 0x6, 0x8, 0x9} {
		t.Run(fmt.Sprintf("type %#x", ft), func(t *testing.T) {
			var eventRecorder events.Recorder
			client, server := newConnPair(t, withDatagrams(), withServerRecorder(&eventRecorder))

			data := quicvarint.Append(nil, ft)
			data = quicvarint.Append(data, 6)
			data = append(data, []byte("foobar")...)

			fp := frameParser{
				streamID:  42,
				r:         bytes.NewReader(data),
				closeConn: client.CloseWithError,
			}
			_, err := fp.ParseNext(&eventRecorder)
			require.ErrorContains(t, err, "http3: reserved frame type")

			select {
			case <-server.Context().Done():
				require.ErrorIs(t,
					context.Cause(server.Context()),
					&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeFrameUnexpected)},
				)
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}

			require.Equal(t,
				[]qlogwriter.Event{
					qlog.FrameParsed{
						StreamID: 42,
						Raw:      qlog.RawInfo{Length: len(data), PayloadLength: 6},
						Frame:    qlog.Frame{Frame: qlog.ReservedFrame{Type: ft}},
					},
				},
				eventRecorder.Events(qlog.FrameParsed{}),
			)
		})
	}
}

func TestParserUnknownFrameType(t *testing.T) {
	data := quicvarint.Append(nil, 0xdead)
	data = quicvarint.Append(data, 6)
	data = append(data, []byte("foobar")...)
	data = quicvarint.Append(data, 0xbeef)
	data = quicvarint.Append(data, 3)
	data = append(data, []byte("baz")...)
	hf := &headersFrame{Length: 3}
	data = hf.Append(data)
	data = append(data, []byte("foo")...)

	r := bytes.NewReader(data)
	fp := frameParser{r: r}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, f)
	hf = f.(*headersFrame)
	require.Equal(t, uint64(3), hf.Length)
	payload := make([]byte, 3)
	_, err = io.ReadFull(r, payload)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), payload)
}

func TestParserPushFrames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frame  interface{ Append([]byte) []byte }
		qf     any
		pushID uint64
	}{
		{name: "CANCEL_PUSH", frame: &cancelPushFrame{PushID: 1337}, qf: qlog.CancelPushFrame{}, pushID: 1337},
		{name: "MAX_PUSH_ID", frame: &maxPushIDFrame{PushID: 1337}, qf: qlog.MaxPushIDFrame{}, pushID: 1337},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.frame.Append(nil)
			// incomplete data results in an io.EOF
			testFrameParserEOF(t, data)

			var eventRecorder events.Recorder
			fp := frameParser{streamID: 42, r: bytes.NewReader(data)}
			f, err := fp.ParseNext(&eventRecorder)
			require.NoError(t, err)
			require.Equal(t, tc.frame, f)
			require.Equal(t,
				[]qlogwriter.Event{
					qlog.FrameParsed{
						StreamID: 42,
						Raw:      qlog.RawInfo{Length: len(data), PayloadLength: quicvarint.Len(tc.pushID)},
						Frame:    qlog.Frame{Frame: tc.qf},
					},
				},
				eventRecorder.Events(qlog.FrameParsed{}),
			)
		})
	}

	t.Run("PUSH_PROMISE", func(t *testing.T) {
		var eventRecorder events.Recorder
		data := quicvarint.Append(nil, 0x5)
		data = quicvarint.Append(data, 6)
		headerLen := len(data)
		data = append(data, []byte("foobar")...)
		r := bytes.NewReader(data)
		fp := frameParser{streamID: 42, r: r}
		f, err := fp.ParseNext(&eventRecorder)
		require.NoError(t, err)
		require.Equal(t, &pushPromiseFrame{Length: 6}, f)
		// the payload is not consumed
		require.Equal(t, 6, r.Len())
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.FrameParsed{
					StreamID: 42,
					Raw:      qlog.RawInfo{Length: headerLen, PayloadLength: 6},
					Frame:    qlog.Frame{Frame: qlog.PushPromiseFrame{}},
				},
			},
			eventRecorder.Events(qlog.FrameParsed{}),
		)
	})
}

// The payload of GOAWAY, CANCEL_PUSH and MAX_PUSH_ID frames is a single variable-length integer.
// A frame that declares a different length is rejected, without waiting for a payload that is too long.
func TestParserSingleVarIntFrameInvalidLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  uint64
	}{
		{name: "GOAWAY", typ: 0x7},
		{name: "CANCEL_PUSH", typ: 0x3},
		{name: "MAX_PUSH_ID", typ: 0xd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, l := range []uint64{0, 9, 1 << 30} {
				data := quicvarint.Append(nil, tc.typ)
				data = quicvarint.Append(data, l)
				fp := frameParser{r: bytes.NewReader(data)}
				_, err := fp.ParseNext(nil)
				require.EqualError(t, err, fmt.Sprintf("%s frame: invalid length: %d", tc.name, l))
				var fe *frameError
				require.ErrorAs(t, err, &fe)
				require.Equal(t, tc.typ, fe.Type)
				require.True(t, isControlStreamFrame(err))
			}

			// the varint is shorter than the declared length
			data := quicvarint.Append(nil, tc.typ)
			data = quicvarint.Append(data, 2)
			data = quicvarint.Append(data, 1)
			data = append(data, 0)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext(nil)
			require.EqualError(t, err, fmt.Sprintf("%s frame: inconsistent length", tc.name))
		})
	}
}

func TestParserHeadersFrame(t *testing.T) {
	data := quicvarint.Append(nil, 1) // type byte
	data = quicvarint.Append(data, 0x1337)
	fp := frameParser{r: bytes.NewReader(data)}

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	// parse
	f1, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, f1)
	require.Equal(t, uint64(0x1337), f1.(*headersFrame).Length)

	// write and parse
	fp = frameParser{r: bytes.NewReader(f1.(*headersFrame).Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, f1, f2)
}

func TestDataFrame(t *testing.T) {
	data := quicvarint.Append(nil, 0) // type byte
	data = quicvarint.Append(data, 0x1337)
	fp := frameParser{r: bytes.NewReader(data)}

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	// parse
	f1, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, f1)
	require.Equal(t, uint64(0x1337), f1.(*dataFrame).Length)

	// write and parse
	fp = frameParser{r: bytes.NewReader(f1.(*dataFrame).Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, f1, f2)
}

func appendSetting(b []byte, key, value uint64) []byte {
	b = quicvarint.Append(b, key)
	b = quicvarint.Append(b, value)
	return b
}

func TestParserSettingsFrame(t *testing.T) {
	settings := appendSetting(nil, 13, 37)
	settings = appendSetting(settings, 0xdead, 0xbeef)
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	fp := frameParser{r: bytes.NewReader(data)}
	frame, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, frame)
	sf := frame.(*settingsFrame)
	require.Len(t, sf.Other, 2)
	require.Equal(t, uint64(37), sf.Other[uint64(13)])
	require.Equal(t, uint64(0xbeef), sf.Other[uint64(0xdead)])

	// write and parse
	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f2)
	sf2 := f2.(*settingsFrame)
	require.Len(t, sf2.Other, len(sf.Other))
	require.Equal(t, sf.Other, sf2.Other)
}

func TestParserSettingsFrameDuplicateSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		num  uint64
		val  uint64
	}{
		{
			name: "other setting",
			num:  13,
			val:  37,
		},
		{
			name: "extended connect",
			num:  settingExtendedConnect,
			val:  1,
		},
		{
			name: "max field section size",
			num:  settingMaxFieldSectionSize,
			val:  1337,
		},
		{
			name: "datagram",
			num:  settingDatagram,
			val:  1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := appendSetting(nil, tc.num, tc.val)
			settings = appendSetting(settings, tc.num, tc.val)
			data := quicvarint.Append(nil, 4) // type byte
			data = quicvarint.Append(data, uint64(len(settings)))
			data = append(data, settings...)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext(nil)
			require.EqualError(t, err, fmt.Sprintf("duplicate setting: %d", tc.num))
			require.ErrorAs(t, err, new(*settingsError))
		})
	}
}

// Settings that are only defined for HTTP/2 are a connection error of type H3_SETTINGS_ERROR,
// see section 7.2.4.1 of RFC 9114.
func TestParserSettingsFrameHTTP2Settings(t *testing.T) {
	for _, id := range []uint64{0x2, 0x3, 0x4, 0x5} {
		t.Run(fmt.Sprintf("setting %d", id), func(t *testing.T) {
			settings := appendSetting(nil, 0x21, 0) // reserved setting
			settings = appendSetting(settings, id, 0)
			data := quicvarint.Append(nil, 4) // type byte
			data = quicvarint.Append(data, uint64(len(settings)))
			data = append(data, settings...)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext(nil)
			require.EqualError(t, err, fmt.Sprintf("HTTP/2 setting: %d", id))
			require.ErrorAs(t, err, new(*settingsError))
		})
	}
}

// A SETTINGS frame whose payload ends inside a setting is a frame error, see section 7.1 of RFC 9114.
func TestParserSettingsFrameTruncatedSetting(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings []byte
	}{
		{name: "no value", settings: quicvarint.Append(nil, 0x1)},
		{name: "truncated identifier", settings: []byte{0x40}},
		{name: "truncated value", settings: append(quicvarint.Append(nil, 0x1), 0x80)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := quicvarint.Append(nil, 4) // type byte
			data = quicvarint.Append(data, uint64(len(tc.settings)))
			data = append(data, tc.settings...)
			fp := frameParser{r: bytes.NewReader(data)}
			_, err := fp.ParseNext(nil)
			require.ErrorIs(t, err, errTruncatedSettings)
			require.NotErrorIs(t, err, io.EOF)
			require.True(t, isControlStreamFrame(err))
		})
	}
}

func TestParserSettingsFrameMaxFieldSectionSize(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		testParserSettingsFrameMaxFieldSectionSize(t, false)
	})

	t.Run("with value", func(t *testing.T) {
		testParserSettingsFrameMaxFieldSectionSize(t, true)
	})
}

func testParserSettingsFrameMaxFieldSectionSize(t *testing.T, present bool) {
	var settings []byte
	if present {
		settings = appendSetting(nil, settingMaxFieldSectionSize, 1337)
	}
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	sf := f.(*settingsFrame)
	if present {
		require.EqualValues(t, 1337, sf.MaxFieldSectionSize)
	} else {
		require.EqualValues(t, -1, sf.MaxFieldSectionSize)
	}

	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, sf, f2)
}

func TestParserSettingsFrameDatagram(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testParserSettingsFrameDatagram(t, true)
	})
	t.Run("disabled", func(t *testing.T) {
		testParserSettingsFrameDatagram(t, false)
	})
}

func testParserSettingsFrameDatagram(t *testing.T, enabled bool) {
	var settings []byte
	switch enabled {
	case true:
		settings = appendSetting(nil, settingDatagram, 1)
	case false:
		settings = appendSetting(nil, settingDatagram, 0)
	}
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	sf := f.(*settingsFrame)
	require.Equal(t, enabled, sf.Datagram)

	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, sf, f2)
}

func TestParserSettingsFrameDatagramInvalidValue(t *testing.T) {
	settings := quicvarint.Append(nil, settingDatagram)
	settings = quicvarint.Append(settings, 1337)
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)
	fp := frameParser{r: bytes.NewReader(data)}
	_, err := fp.ParseNext(nil)
	require.EqualError(t, err, "invalid value for SETTINGS_H3_DATAGRAM: 1337")
	require.ErrorAs(t, err, new(*settingsError))
}

func TestParserSettingsFrameExtendedConnect(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testParserSettingsFrameExtendedConnect(t, true)
	})
	t.Run("disabled", func(t *testing.T) {
		testParserSettingsFrameExtendedConnect(t, false)
	})
}

func testParserSettingsFrameExtendedConnect(t *testing.T, enabled bool) {
	var settings []byte
	switch enabled {
	case true:
		settings = appendSetting(nil, settingExtendedConnect, 1)
	case false:
		settings = appendSetting(nil, settingExtendedConnect, 0)
	}
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	sf := f.(*settingsFrame)
	require.Equal(t, enabled, sf.ExtendedConnect)

	fp = frameParser{r: bytes.NewReader(sf.Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, sf, f2)
}

func TestParserSettingsFrameExtendedConnectInvalidValue(t *testing.T) {
	settings := quicvarint.Append(nil, settingExtendedConnect)
	settings = quicvarint.Append(settings, 1337)
	data := quicvarint.Append(nil, 4) // type byte
	data = quicvarint.Append(data, uint64(len(settings)))
	data = append(data, settings...)
	fp := frameParser{r: bytes.NewReader(data)}
	_, err := fp.ParseNext(nil)
	require.EqualError(t, err, "invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: 1337")
	require.ErrorAs(t, err, new(*settingsError))
}

func TestParserGoAwayFrame(t *testing.T) {
	data := quicvarint.Append(nil, 7) // type byte
	data = quicvarint.Append(data, uint64(quicvarint.Len(100)))
	data = quicvarint.Append(data, 100)

	// incomplete data results in an io.EOF
	testFrameParserEOF(t, data)

	fp := frameParser{r: bytes.NewReader(data)}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &goAwayFrame{}, f)
	require.Equal(t, quic.StreamID(100), f.(*goAwayFrame).StreamID)

	// write and parse
	fp = frameParser{r: bytes.NewReader(f.(*goAwayFrame).Append(nil))}
	f2, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.Equal(t, f, f2)
}

func TestParserPriorityUpdateFrame(t *testing.T) {
	var eventRecorder events.Recorder
	frame := &priorityUpdateFrame{ElementID: 12, PriorityFieldValue: "u=1, i"}
	payload := quicvarint.Append(nil, frame.ElementID)
	payload = append(payload, frame.PriorityFieldValue...)
	data := quicvarint.Append(nil, 0xf0700)
	data = quicvarint.Append(data, uint64(len(payload)))
	data = append(data, payload...)
	testFrameParserEOF(t, data)

	parsed, err := (&frameParser{streamID: 42, r: bytes.NewReader(data)}).ParseNext(&eventRecorder)
	require.NoError(t, err)
	require.Equal(t, frame, parsed)
	require.Equal(t,
		[]qlogwriter.Event{qlog.FrameParsed{
			StreamID: 42,
			Raw:      qlog.RawInfo{Length: len(data), PayloadLength: len(payload)},
			Frame: qlog.Frame{Frame: qlog.PriorityUpdateFrame{
				StreamID:           12,
				PriorityFieldValue: "u=1, i",
			}},
		}},
		eventRecorder.Events(qlog.FrameParsed{}),
	)

	data = quicvarint.Append(nil, 0xf0701)
	data = quicvarint.Append(data, 42) // the payload is intentionally omitted
	_, err = (&frameParser{r: bytes.NewReader(data)}).ParseNext(nil)
	require.ErrorIs(t, err, errPriorityUpdateForPush)
}

func FuzzFrameParser(f *testing.F) {
	corpus := ossfuzzseeds.New(f)

	frames := []interface{ Append([]byte) []byte }{
		&dataFrame{Length: 5},
		&headersFrame{Length: 3},
		&settingsFrame{
			MaxFieldSectionSize: 1337,
			Datagram:            true,
			ExtendedConnect:     true,
			Other:               map[uint64]uint64{0xdead: 0xbeef},
		},
		&goAwayFrame{StreamID: 42},
		&cancelPushFrame{PushID: 7},
		&maxPushIDFrame{PushID: 1337},
	}
	for _, fr := range frames {
		corpus.Add(fr.Append(nil))
	}
	pushPromise := quicvarint.Append(nil, 0x5)
	pushPromise = quicvarint.Append(pushPromise, 3)
	pushPromise = append(pushPromise, 0, 0, 0)
	corpus.Add(pushPromise)

	unknown := quicvarint.Append(nil, 0xdead)
	unknown = quicvarint.Append(unknown, 6)
	unknown = append(unknown, []byte("foobar")...)
	corpus.Add(unknown)

	f.Fuzz(func(t *testing.T, data []byte) {
		fp := frameParser{
			r:         bytes.NewReader(data),
			closeConn: func(quic.ApplicationErrorCode, string) error { return nil },
		}
		for {
			fr, err := fp.ParseNext(nil)
			if err != nil {
				return
			}

			switch f := fr.(type) {
			case *dataFrame:
				if _, err := io.CopyN(io.Discard, fp.r, int64(f.Length)); err != nil {
					return
				}
			case *headersFrame:
				// Type and length are each at least one varint byte; HTTP/3 caps the pair at frameHeaderLen.
				if f.headerLen < 2 || f.headerLen > frameHeaderLen {
					t.Fatalf("HEADERS: headerLen %d outside [2, %d]", f.headerLen, frameHeaderLen)
				}
				if _, err := io.CopyN(io.Discard, fp.r, int64(f.Length)); err != nil {
					return
				}
			case *settingsFrame:
				// Unset uses -1; a present SETTINGS_MAX_FIELD_SECTION_SIZE is non-negative (see parseSettingsFrame).
				if f.MaxFieldSectionSize != -1 && f.MaxFieldSectionSize < 0 {
					t.Fatalf("SETTINGS: invalid MaxFieldSectionSize %d", f.MaxFieldSectionSize)
				}
				// Known settings and HTTP/2 settings are never stored in Other on a successful parse.
				for id := range f.Other {
					switch id {
					case settingMaxFieldSectionSize, settingExtendedConnect, settingDatagram, 0x2, 0x3, 0x4, 0x5:
						t.Fatalf("SETTINGS: setting id %#x leaked into Other", id)
					}
				}
			case *goAwayFrame:
				// QUIC stream IDs fit in 62 bits; a negative value means uint64→int64 overflow in the parser.
				if f.StreamID < 0 {
					t.Fatalf("GOAWAY: negative StreamID %d", f.StreamID)
				}
			case *cancelPushFrame:
				if f.PushID > quicvarint.Max {
					t.Fatalf("CANCEL_PUSH: invalid push ID %d", f.PushID)
				}
			case *maxPushIDFrame:
				if f.PushID > quicvarint.Max {
					t.Fatalf("MAX_PUSH_ID: invalid push ID %d", f.PushID)
				}
			case *pushPromiseFrame:
				// the payload is not parsed
				if _, err := io.CopyN(io.Discard, fp.r, int64(f.Length)); err != nil {
					return
				}
			}
		}
	})
}
