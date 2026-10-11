package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"

	quic "github.com/AeonDave/mp-quic-go"
	"github.com/AeonDave/mp-quic-go/http3/qlog"
	"github.com/AeonDave/mp-quic-go/qlogwriter"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// FrameType is the frame type of a HTTP/3 frame
type FrameType uint64

type frame any

var errPriorityUpdateForPush = errors.New("http3: PRIORITY_UPDATE frame for push")

// The maximum length of an encoded HTTP/3 frame header is 16:
// The frame has a type and length field, both QUIC varints (maximum 8 bytes in length)
const frameHeaderLen = 16

type countingByteReader struct {
	quicvarint.Reader
	NumRead int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	b, err := r.Reader.ReadByte()
	if err == nil {
		r.NumRead++
	}
	return b, err
}

func (r *countingByteReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.NumRead += n
	return n, err
}

func (r *countingByteReader) Reset() {
	r.NumRead = 0
}

type frameParser struct {
	r         io.Reader
	streamID  quic.StreamID
	closeConn func(quic.ApplicationErrorCode, string) error
}

func (p *frameParser) ParseNext(qlogger qlogwriter.Recorder) (frame, error) {
	r := &countingByteReader{Reader: quicvarint.NewReader(p.r)}
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			// The stream ended in the middle of the frame type.
			if err == io.EOF && r.NumRead > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		l, err := quicvarint.Read(r)
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}

		switch t {
		case 0x0: // DATA
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw: qlog.RawInfo{
						Length:        int(l) + r.NumRead,
						PayloadLength: int(l),
					},
					Frame: qlog.Frame{Frame: qlog.DataFrame{}},
				})
			}
			return &dataFrame{Length: l}, nil
		case 0x1: // HEADERS
			return &headersFrame{
				Length:    l,
				headerLen: r.NumRead,
			}, nil
		case 0x4: // SETTINGS
			return parseSettingsFrame(r, l, p.streamID, qlogger)
		case 0x3: // CANCEL_PUSH
			id, err := parseSingleVarIntPayload(r, t, l, "CANCEL_PUSH")
			if err != nil {
				return nil, err
			}
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.CancelPushFrame{}},
				})
			}
			return &cancelPushFrame{PushID: id}, nil
		case 0x5: // PUSH_PROMISE
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.PushPromiseFrame{}},
				})
			}
			// Server push is not supported, and the payload is not read:
			// receiving a PUSH_PROMISE frame is always a connection error.
			return &pushPromiseFrame{Length: l}, nil
		case 0x7: // GOAWAY
			return parseGoAwayFrame(r, l, p.streamID, qlogger)
		case 0xf0700: // PRIORITY_UPDATE for a request stream
			return parsePriorityUpdateFrame(r, l, p.streamID, qlogger)
		case 0xf0701: // PRIORITY_UPDATE for a push stream
			return nil, errPriorityUpdateForPush
		case 0xd: // MAX_PUSH_ID
			id, err := parseSingleVarIntPayload(r, t, l, "MAX_PUSH_ID")
			if err != nil {
				return nil, err
			}
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.MaxPushIDFrame{}},
				})
			}
			return &maxPushIDFrame{PushID: id}, nil
		case 0x2, 0x6, 0x8, 0x9: // reserved frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.ReservedFrame{Type: t}},
				})
			}
			p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return nil, fmt.Errorf("http3: reserved frame type: %d", t)
		default:
			// unknown frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.UnknownFrame{Type: t}},
				})
			}
		}

		// skip over the payload
		if _, err := io.CopyN(io.Discard, r, int64(l)); err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		r.Reset()
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x0)
	return quicvarint.Append(b, f.Length)
}

type headersFrame struct {
	Length    uint64
	headerLen int // number of bytes read for type and length field
}

func (f *headersFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x1)
	return quicvarint.Append(b, f.Length)
}

const (
	// SETTINGS_MAX_FIELD_SECTION_SIZE
	settingMaxFieldSectionSize = 0x6
	// Extended CONNECT, RFC 9220
	settingExtendedConnect = 0x8
	// HTTP Datagrams, RFC 9297
	settingDatagram = 0x33
)

// A frameError is returned when a frame of a known type is malformed.
// The frame type is needed to determine the error code: frames that are not allowed on a stream
// are an error of type H3_FRAME_UNEXPECTED, whether they are malformed or not.
type frameError struct {
	Type uint64
	err  error
}

func (e *frameError) Error() string { return e.err.Error() }
func (e *frameError) Unwrap() error { return e.err }

// isControlStreamFrame says if err is a frameError for a frame type that is only allowed on the control stream.
// isTruncatedFrame says if a stream ended in the middle of a frame.
// If the stream was terminated cleanly, this is a connection error of type H3_FRAME_ERROR (section 7.1 of RFC 9114).
func isTruncatedFrame(err error) bool {
	return err == io.ErrUnexpectedEOF
}

func isControlStreamFrame(err error) bool {
	fe, ok := errors.AsType[*frameError](err)
	if !ok {
		return false
	}
	switch fe.Type {
	case 0x3, 0x4, 0x7, 0xd: // CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID
		return true
	}
	return false
}

// errTruncatedSettings is returned when a SETTINGS frame ends inside a setting.
var errTruncatedSettings = errors.New("http3: SETTINGS frame ends inside a setting")

// A settingsError is a semantic error in a SETTINGS frame.
// It is a connection error of type H3_SETTINGS_ERROR (section 7.2.4 of RFC 9114).
type settingsError struct {
	msg string
}

func (e *settingsError) Error() string { return e.msg }

type settingsFrame struct {
	MaxFieldSectionSize int64 // SETTINGS_MAX_FIELD_SECTION_SIZE, -1 if not set

	Datagram        bool              // HTTP Datagrams, RFC 9297
	ExtendedConnect bool              // Extended CONNECT, RFC 9220
	Other           map[uint64]uint64 // all settings that we don't explicitly recognize
}

const maxSettingsFrameSize = 8 << 10

func parseSettingsFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*settingsFrame, error) {
	if l > maxSettingsFrameSize {
		return nil, &frameError{Type: 0x4, err: fmt.Errorf("unexpected size for SETTINGS frame: %d", l)}
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	frame := &settingsFrame{MaxFieldSectionSize: -1}
	b := bytes.NewReader(buf)
	settingsFrame := qlog.SettingsFrame{MaxFieldSectionSize: -1}
	var readMaxFieldSectionSize, readDatagram, readExtendedConnect bool
	for b.Len() > 0 {
		// The payload was read completely, so an error here means that the frame ends inside a parameter.
		// This is a frame error (section 7.1 of RFC 9114), not the end of the stream.
		id, err := quicvarint.Read(b)
		if err != nil {
			return nil, &frameError{Type: 0x4, err: errTruncatedSettings}
		}
		val, err := quicvarint.Read(b)
		if err != nil {
			return nil, &frameError{Type: 0x4, err: errTruncatedSettings}
		}

		switch id {
		case 0x2, 0x3, 0x4, 0x5:
			// HTTP/2 settings that have no HTTP/3 equivalent (section 7.2.4.1 of RFC 9114)
			return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("HTTP/2 setting: %d", id)}}
		case settingMaxFieldSectionSize:
			if readMaxFieldSectionSize {
				return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("duplicate setting: %d", id)}}
			}
			readMaxFieldSectionSize = true
			frame.MaxFieldSectionSize = int64(val)
			settingsFrame.MaxFieldSectionSize = int64(val)
		case settingExtendedConnect:
			if readExtendedConnect {
				return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("duplicate setting: %d", id)}}
			}
			readExtendedConnect = true
			if val != 0 && val != 1 {
				return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: %d", val)}}
			}
			frame.ExtendedConnect = val == 1
			if qlogger != nil {
				settingsFrame.ExtendedConnect = new(frame.ExtendedConnect)
			}
		case settingDatagram:
			if readDatagram {
				return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("duplicate setting: %d", id)}}
			}
			readDatagram = true
			if val != 0 && val != 1 {
				return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("invalid value for SETTINGS_H3_DATAGRAM: %d", val)}}
			}
			frame.Datagram = val == 1
			if qlogger != nil {
				settingsFrame.Datagram = new(frame.Datagram)
			}
		default:
			if _, ok := frame.Other[id]; ok {
				return nil, &frameError{Type: 0x4, err: &settingsError{fmt.Sprintf("duplicate setting: %d", id)}}
			}
			if frame.Other == nil {
				frame.Other = make(map[uint64]uint64)
			}
			frame.Other[id] = val
		}
	}
	if qlogger != nil {
		settingsFrame.Other = maps.Clone(frame.Other)

		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw: qlog.RawInfo{
				Length:        r.NumRead,
				PayloadLength: int(l),
			},
			Frame: qlog.Frame{Frame: settingsFrame},
		})
	}
	return frame, nil
}

func (f *settingsFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x4)
	var l int
	if f.MaxFieldSectionSize >= 0 {
		l += quicvarint.Len(settingMaxFieldSectionSize) + quicvarint.Len(uint64(f.MaxFieldSectionSize))
	}
	for id, val := range f.Other {
		l += quicvarint.Len(id) + quicvarint.Len(val)
	}
	if f.Datagram {
		l += quicvarint.Len(settingDatagram) + quicvarint.Len(1)
	}
	if f.ExtendedConnect {
		l += quicvarint.Len(settingExtendedConnect) + quicvarint.Len(1)
	}
	b = quicvarint.Append(b, uint64(l))
	if f.MaxFieldSectionSize >= 0 {
		b = quicvarint.Append(b, settingMaxFieldSectionSize)
		b = quicvarint.Append(b, uint64(f.MaxFieldSectionSize))
	}
	if f.Datagram {
		b = quicvarint.Append(b, settingDatagram)
		b = quicvarint.Append(b, 1)
	}
	if f.ExtendedConnect {
		b = quicvarint.Append(b, settingExtendedConnect)
		b = quicvarint.Append(b, 1)
	}
	for id, val := range f.Other {
		b = quicvarint.Append(b, id)
		b = quicvarint.Append(b, val)
	}
	return b
}

type goAwayFrame struct {
	StreamID quic.StreamID
}

// parseSingleVarIntPayload parses the payload of a frame that consists of a single variable-length integer.
// Since such a payload is at most 8 bytes long, a frame that declares a longer (or an empty) payload
// is rejected without reading the payload.
func parseSingleVarIntPayload(r *countingByteReader, t, l uint64, name string) (uint64, error) {
	if l == 0 || l > 8 {
		return 0, &frameError{Type: t, err: fmt.Errorf("%s frame: invalid length: %d", name, l)}
	}
	startLen := r.NumRead
	val, err := quicvarint.Read(r)
	if err != nil {
		if err == io.EOF {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, err
	}
	if r.NumRead-startLen != int(l) {
		return 0, &frameError{Type: t, err: fmt.Errorf("%s frame: inconsistent length", name)}
	}
	return val, nil
}

func parseGoAwayFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*goAwayFrame, error) {
	frame := &goAwayFrame{}
	id, err := parseSingleVarIntPayload(r, 0x7, l, "GOAWAY")
	if err != nil {
		return nil, err
	}
	frame.StreamID = quic.StreamID(id)
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
			Frame:    qlog.Frame{Frame: qlog.GoAwayFrame{StreamID: frame.StreamID}},
		})
	}
	return frame, nil
}

func (f *goAwayFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x7)
	b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(f.StreamID))))
	return quicvarint.Append(b, uint64(f.StreamID))
}

// CANCEL_PUSH, section 7.2.3 of RFC 9114
type cancelPushFrame struct {
	PushID uint64
}

func (f *cancelPushFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x3)
	b = quicvarint.Append(b, uint64(quicvarint.Len(f.PushID)))
	return quicvarint.Append(b, f.PushID)
}

// PUSH_PROMISE, section 7.2.5 of RFC 9114.
// Only the frame header is parsed.
type pushPromiseFrame struct {
	Length uint64
}

// MAX_PUSH_ID, section 7.2.7 of RFC 9114
type maxPushIDFrame struct {
	PushID uint64
}

func (f *maxPushIDFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0xd)
	b = quicvarint.Append(b, uint64(quicvarint.Len(f.PushID)))
	return quicvarint.Append(b, f.PushID)
}

// PRIORITY_UPDATE, RFC 9218
type priorityUpdateFrame struct {
	ElementID          uint64
	PriorityFieldValue string
}

const maxPriorityUpdateFrameSize = 4 << 10

func parsePriorityUpdateFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*priorityUpdateFrame, error) {
	if l > maxPriorityUpdateFrameSize {
		return nil, fmt.Errorf("unexpected size for PRIORITY_UPDATE frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	id, n, err := quicvarint.Parse(buf)
	if err != nil {
		return nil, err
	}
	frame := &priorityUpdateFrame{
		ElementID:          id,
		PriorityFieldValue: string(buf[n:]),
	}
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
			Frame: qlog.Frame{Frame: qlog.PriorityUpdateFrame{
				StreamID:           quic.StreamID(frame.ElementID),
				PriorityFieldValue: frame.PriorityFieldValue,
			}},
		})
	}
	return frame, nil
}
