package wire

import (
	"io"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// ClosePathFrame is a CLOSE_PATH frame used to gracefully close a path.
// This is part of multipath QUIC extensions.
type ClosePathFrame struct {
	// PathID identifies which path to close
	PathID uint64
	// ErrorCode indicates the reason for closing (0 = normal close)
	ErrorCode uint64
	// ReasonPhrase is a human-readable explanation (optional)
	ReasonPhrase string
}

func parseClosePathFrame(b []byte, _ protocol.Version) (*ClosePathFrame, int, error) {
	startLen := len(b)

	// Parse PathID
	pathID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	// Parse ErrorCode
	errorCode, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	// Parse ReasonPhraseLength
	reasonLen, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	// Parse ReasonPhrase
	if reasonLen > 0 {
		if uint64(len(b)) < reasonLen {
			return nil, 0, io.EOF
		}
		reasonPhrase := string(b[:reasonLen])
		b = b[reasonLen:]

		frame := &ClosePathFrame{
			PathID:       pathID,
			ErrorCode:    errorCode,
			ReasonPhrase: reasonPhrase,
		}
		return frame, startLen - len(b), nil
	}

	frame := &ClosePathFrame{
		PathID:    pathID,
		ErrorCode: errorCode,
	}
	return frame, startLen - len(b), nil
}

func (f *ClosePathFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeClosePath))
	b = quicvarint.Append(b, f.PathID)
	b = quicvarint.Append(b, f.ErrorCode)
	b = quicvarint.Append(b, uint64(len(f.ReasonPhrase)))
	b = append(b, []byte(f.ReasonPhrase)...)
	return b, nil
}

// Length of a written frame
func (f *ClosePathFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeClosePath))) +
		protocol.ByteCount(quicvarint.Len(f.PathID)) +
		protocol.ByteCount(quicvarint.Len(f.ErrorCode)) +
		protocol.ByteCount(quicvarint.Len(uint64(len(f.ReasonPhrase)))) +
		protocol.ByteCount(len(f.ReasonPhrase))
}
