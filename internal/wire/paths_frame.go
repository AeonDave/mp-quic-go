package wire

import (
	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// PathsFrame is a PATHS frame used to synchronize active path information.
// This is part of multipath QUIC extensions.
type PathsFrame struct {
	// AvailablePaths is the number of paths available for sending
	AvailablePaths uint64
	// ActivePaths is the number of currently active paths
	ActivePaths uint64
}

func parsePathsFrame(b []byte, _ protocol.Version) (*PathsFrame, int, error) {
	startLen := len(b)

	// Parse AvailablePaths
	available, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	// Parse ActivePaths
	active, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	frame := &PathsFrame{
		AvailablePaths: available,
		ActivePaths:    active,
	}

	return frame, startLen - len(b), nil
}

func (f *PathsFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePaths))
	b = quicvarint.Append(b, f.AvailablePaths)
	b = quicvarint.Append(b, f.ActivePaths)
	return b, nil
}

// Length of a written frame
func (f *PathsFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePaths))) +
		protocol.ByteCount(quicvarint.Len(f.AvailablePaths)) +
		protocol.ByteCount(quicvarint.Len(f.ActivePaths))
}
